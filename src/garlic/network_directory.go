package garlic

// An iterative XOR directory over the existing ironwood mesh. Only bounded
// nearest-neighbor referrals and targeted GID queries are exchanged. Records
// are signed, expire, and are replicated to three closest reachable nodes.
// Both publication and lookup RPCs travel inside duplex Garlic circuits.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"
	"time"
)

const directoryReplicas = 3
const directoryWidth = 8
const maxDirectoryRecords = 4096

var ErrDirectoryUnavailable = errors.New("garlic: no reachable distributed directory peers")

type directoryMessage struct {
	ID     CircuitID
	GID    GID
	Store  *ServiceDescriptor `json:",omitempty"`
	Record *ServiceDescriptor `json:",omitempty"`
	Peers  [][]byte           `json:",omitempty"`
	Stored bool               `json:",omitempty"`
}
type directoryPending struct {
	circuit  CircuitID
	response chan directoryMessage
}

type NetworkRendezvous struct {
	g       *Garlic
	mu      sync.Mutex
	records map[GID]*ServiceDescriptor
	pending map[CircuitID]directoryPending
}

func newNetworkRendezvous(g *Garlic) *NetworkRendezvous {
	d := &NetworkRendezvous{g: g, records: make(map[GID]*ServiceDescriptor), pending: make(map[CircuitID]directoryPending)}
	go d.discover()
	return d
}

func (d *NetworkRendezvous) discover() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.g.stop:
			return
		case <-t.C:
			for i, p := range d.g.core.GetPeers() {
				if i >= 32 {
					break
				}
				if !p.Up || len(p.Key) != 32 {
					continue
				}
				select {
				case <-d.g.stop:
					return
				default:
				}
				if cap, err := d.g.QueryCapability(p.Key); err == nil && slices.Contains(cap.Versions, CapabilitySites) {
					_ = d.g.RequestGossip(p.Key)
				}
			}
			d.mu.Lock()
			d.pruneLocked()
			d.mu.Unlock()
		}
	}
}

func (d *NetworkRendezvous) pruneLocked() {
	now := uint64(time.Now().Unix())
	for gid, r := range d.records {
		if r.ExpiresAt < now {
			delete(d.records, gid)
		}
	}
}

func cloneDescriptor(r *ServiceDescriptor) *ServiceDescriptor {
	if r == nil {
		return nil
	}
	c := *r
	c.ServicePublicKey = bytes.Clone(r.ServicePublicKey)
	c.ServiceID = bytes.Clone(r.ServiceID)
	c.Signature = bytes.Clone(r.Signature)
	c.IntroPoints = make([]IntroPoint, len(r.IntroPoints))
	for i, p := range r.IntroPoints {
		c.IntroPoints[i].NodeKey = bytes.Clone(p.NodeKey)
	}
	return &c
}

func (d *NetworkRendezvous) store(gid GID, r *ServiceDescriptor) bool {
	if validateNetworkDescriptor(r, gid) != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	old := d.records[gid]
	if old != nil && (old.PublishedAt > r.PublishedAt || (old.PublishedAt == r.PublishedAt && old.ExpiresAt > r.ExpiresAt)) {
		return false
	}
	if old == nil && len(d.records) >= maxDirectoryRecords {
		return false
	}
	d.records[gid] = cloneDescriptor(r)
	return true
}

func validateNetworkDescriptor(record *ServiceDescriptor, gid GID) error {
	if record == nil {
		return ErrDescriptorTruncated
	}
	if err := VerifyServiceDescriptor(record, gid, uint64(time.Now().Unix())); err != nil {
		return err
	}
	if len(record.IntroPoints) == 0 {
		return ErrInvalidPath
	}
	for _, p := range record.IntroPoints {
		if len(p.NodeKey) != 32 {
			return ErrInvalidPath
		}
	}
	return nil
}

func (d *NetworkRendezvous) local(gid GID) *ServiceDescriptor {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	return cloneDescriptor(d.records[gid])
}

func closestDirectoryNodes(gid GID, nodes map[string][]byte, n int) [][]byte {
	all := make([][]byte, 0, len(nodes))
	for _, key := range nodes {
		if len(key) == 32 {
			all = append(all, key)
		}
	}
	distance := func(key []byte) [32]byte {
		h := sha256.Sum256(key)
		for i := range h {
			h[i] ^= gid[i+1]
		}
		return h
	}
	slices.SortFunc(all, func(a, b []byte) int { x, y := distance(a), distance(b); return bytes.Compare(x[:], y[:]) })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func (d *NetworkRendezvous) seeds() map[string][]byte {
	nodes := map[string][]byte{string(d.g.core.PublicKey()): d.g.core.PublicKey()}
	for _, p := range d.g.KnownPeers() {
		if len(p.NodeKey) == 32 {
			nodes[string(p.NodeKey)] = p.NodeKey
		}
	}
	for _, p := range d.g.core.GetPeers() {
		if p.Up && len(p.Key) == 32 {
			nodes[string(p.Key)] = p.Key
		}
	}
	return nodes
}

// handleRequest runs on the bounded site worker, never in core.ReadFrom.
func (d *NetworkRendezvous) handleRequest(circuit CircuitID, body []byte) {
	if len(body) > maxSiteDatagram-1 {
		return
	}
	var req directoryMessage
	if json.Unmarshal(body, &req) != nil || req.GID[0] != GIDVersion1 {
		return
	}
	res := directoryMessage{ID: req.ID, GID: req.GID}
	if req.Store != nil {
		res.Stored = d.store(req.GID, req.Store)
	}
	res.Record = d.local(req.GID)
	res.Peers = closestDirectoryNodes(req.GID, d.seeds(), directoryWidth)
	data, err := json.Marshal(res)
	if err != nil || len(data) > maxSiteDatagram-1 {
		return
	}
	_ = d.g.duplex.send(circuit, append([]byte{siteDirectoryResponse}, data...), true)
}

func (d *NetworkRendezvous) handleResponse(circuit CircuitID, body []byte) {
	var res directoryMessage
	if len(body) > maxSiteDatagram-1 || json.Unmarshal(body, &res) != nil {
		return
	}
	d.mu.Lock()
	p, ok := d.pending[res.ID]
	d.mu.Unlock()
	if !ok || p.circuit != circuit {
		return
	}
	select {
	case p.response <- res:
	default:
	}
}

func (d *NetworkRendezvous) rpc(ctx context.Context, peer []byte, gid GID, record *ServiceDescriptor) (directoryMessage, error) {
	if ctx.Err() != nil {
		return directoryMessage{}, ctx.Err()
	}
	cid, err := d.g.createSiteCircuitContext(ctx, peer)
	if err != nil {
		return directoryMessage{}, err
	}
	defer d.g.CloseCircuit(cid)
	id, err := randomCircuitID()
	if err != nil {
		return directoryMessage{}, err
	}
	ch := make(chan directoryMessage, 1)
	d.mu.Lock()
	if len(d.pending) >= 32 {
		d.mu.Unlock()
		return directoryMessage{}, ErrDirectoryUnavailable
	}
	d.pending[id] = directoryPending{cid, ch}
	d.mu.Unlock()
	defer func() { d.mu.Lock(); delete(d.pending, id); d.mu.Unlock() }()
	body, err := json.Marshal(directoryMessage{ID: id, GID: gid, Store: record})
	if err != nil {
		return directoryMessage{}, err
	}
	// Retransmit using fresh circuit counters; responses are matched to both
	// the request nonce and its authenticated reverse circuit.
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		if err := d.g.sendDuplex(cid, append([]byte{siteDirectoryRequest}, body...)); err != nil {
			return directoryMessage{}, err
		}
		select {
		case res := <-ch:
			if res.GID != gid {
				return directoryMessage{}, ErrDescriptorGIDMismatch
			}
			return res, nil
		case <-ticker.C:
		case <-timeout.C:
			return directoryMessage{}, ErrDirectoryUnavailable
		case <-ctx.Done():
			return directoryMessage{}, ctx.Err()
		case <-d.g.stop:
			return directoryMessage{}, net.ErrClosed
		}
	}
}

func (d *NetworkRendezvous) walk(ctx context.Context, gid GID) ([][]byte, *ServiceDescriptor) {
	nodes := d.seeds()
	self := string(d.g.core.PublicKey())
	visited := map[string]bool{self: true}
	reachable := map[string][]byte{self: d.g.core.PublicKey()}
	best := d.local(gid)
	for queries := 0; queries < 24; {
		var batch [][]byte
		for _, peer := range closestDirectoryNodes(gid, nodes, directoryWidth) {
			if !visited[string(peer)] {
				visited[string(peer)] = true
				batch = append(batch, peer)
				if len(batch) == 3 {
					break
				}
			}
		}
		if len(batch) == 0 || ctx.Err() != nil {
			break
		}
		type result struct {
			peer []byte
			res  directoryMessage
			err  error
		}
		results := make(chan result, len(batch))
		for _, peer := range batch {
			go func(peer []byte) { res, err := d.rpc(ctx, peer, gid, nil); results <- result{peer, res, err} }(peer)
			queries++
		}
		for range batch {
			r := <-results
			if r.err != nil {
				continue
			}
			reachable[string(r.peer)] = r.peer
			for _, peer := range r.res.Peers {
				if len(peer) == 32 && len(nodes) < 256 {
					nodes[string(peer)] = peer
				}
			}
			if record := r.res.Record; validateNetworkDescriptor(record, gid) == nil && (best == nil || record.PublishedAt > best.PublishedAt || (record.PublishedAt == best.PublishedAt && record.ExpiresAt > best.ExpiresAt)) {
				best = record
			}
		}
	}
	return closestDirectoryNodes(gid, reachable, directoryWidth), best
}

func (d *NetworkRendezvous) Publish(gid GID, record *ServiceDescriptor) error {
	if err := validateNetworkDescriptor(record, gid); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	peers, _ := d.walk(ctx, gid)
	stored, remote := 0, 0
	for _, peer := range peers {
		if bytes.Equal(peer, d.g.core.PublicKey()) {
			if d.store(gid, record) {
				stored++
			}
			continue
		}
		res, err := d.rpc(ctx, peer, gid, record)
		if err == nil && res.Stored {
			stored++
			remote++
		}
		if stored >= directoryReplicas && remote > 0 {
			return nil
		}
	}
	if remote == 0 {
		return ErrDirectoryUnavailable
	}
	return nil
}

func (d *NetworkRendezvous) Lookup(gid GID) (*ServiceDescriptor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return d.LookupContext(ctx, gid)
}

func (d *NetworkRendezvous) LookupContext(ctx context.Context, gid GID) (*ServiceDescriptor, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, record := d.walk(ctx, gid)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if record == nil {
		return nil, ErrGIDNotFound
	}
	return cloneDescriptor(record), nil
}
