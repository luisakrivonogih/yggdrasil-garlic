package garlic

// An iterative XOR directory over the existing ironwood mesh. Only bounded
// nearest-neighbor referrals and targeted GID queries are exchanged. Records
// are signed, expire, and are replicated to three closest reachable nodes.
// Both publication and lookup RPCs travel inside duplex Garlic circuits.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	ID    CircuitID
	GID   GID
	Store *ServiceDescriptor `json:",omitempty"`
	// Blinded records (version 2 GIDs, see blind.go): GID is then the
	// blinded index key, never the site's GID.
	StoreBlinded  *BlindedRecord     `json:",omitempty"`
	RecordBlinded *BlindedRecord     `json:",omitempty"`
	Record        *ServiceDescriptor `json:",omitempty"`
	Peers         [][]byte           `json:",omitempty"`
	Stored        bool               `json:",omitempty"`
}
type directoryPending struct {
	circuit  CircuitID
	response chan directoryMessage
}

type NetworkRendezvous struct {
	g       *Garlic
	mu      sync.Mutex
	records map[GID]*ServiceDescriptor
	blinded map[GID]*BlindedRecord
	pending map[CircuitID]directoryPending
}

func newNetworkRendezvous(g *Garlic) *NetworkRendezvous {
	d := &NetworkRendezvous{g: g, records: make(map[GID]*ServiceDescriptor), blinded: make(map[GID]*BlindedRecord), pending: make(map[CircuitID]directoryPending)}
	go d.discover()
	return d
}

func (d *NetworkRendezvous) discover() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	// Peers that did not answer (hidden or non-Garlic nodes) are not asked
	// again for a while, so they do not stall this loop on every tick.
	silent := map[string]time.Time{}
	for {
		select {
		case <-d.g.stop:
			return
		case <-t.C:
			// Hidden nodes contact only their trusted peers; relays also
			// contact their direct mesh peers.
			for i, key := range d.g.contactablePeers() {
				if i >= 32 {
					break
				}
				select {
				case <-d.g.stop:
					return
				default:
				}
				if until, ok := silent[string(key)]; ok && time.Now().Before(until) {
					continue
				}
				cap, err := d.g.QueryCapability(key)
				if err != nil {
					// A trusted peer that did not answer yet (often: this
					// node only just started and is not peered yet) is
					// asked again soon; other peers are left alone longer.
					backoff := 5 * time.Minute
					if d.g.isTrusted(key) {
						backoff = 10 * time.Second
					}
					silent[string(key)] = time.Now().Add(backoff)
					continue
				}
				delete(silent, string(key))
				if slices.Contains(cap.Versions, CapabilitySites) {
					_ = d.g.RequestGossip(key)
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
	for key, r := range d.blinded {
		if now > r.ExpiresAt+descriptorClockSkew {
			delete(d.blinded, key)
		}
	}
	for gid, r := range d.records {
		if descriptorExpired(r, now) {
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
		c.IntroPoints[i].RelayInfo = bytes.Clone(p.RelayInfo)
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
		if _, err := parseVerifiedRelayInfo(p.RelayInfo, p.NodeKey); err != nil {
			return err
		}
	}
	return nil
}

// storeBlinded keeps a blinded record if it is valid for key and newer
// than the one held.
func (d *NetworkRendezvous) storeBlinded(key GID, r *BlindedRecord) bool {
	if validateBlindedRecord(r, key, time.Now()) != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	old := d.blinded[key]
	if old != nil && old.PublishedAt > r.PublishedAt {
		return false
	}
	if old == nil && len(d.records)+len(d.blinded) >= maxDirectoryRecords {
		return false
	}
	c := *r
	d.blinded[key] = &c
	return true
}

func (d *NetworkRendezvous) localBlinded(key GID) *BlindedRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	if r := d.blinded[key]; r != nil {
		c := *r
		return &c
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

// seeds are the directory nodes this node can build circuits to: relays
// with usable verified relay information, plus itself in relay mode.
// Hidden nodes never act as directory storage.
func (d *NetworkRendezvous) seeds() map[string][]byte {
	nodes := map[string][]byte{}
	if !d.g.cfg.Hidden {
		nodes[string(d.g.core.PublicKey())] = d.g.core.PublicKey()
	}
	for _, p := range d.g.KnownPeers() {
		if len(p.NodeKey) != 32 {
			continue
		}
		if c, ok := d.g.knownRelay(p.NodeKey); ok && needSites(c) {
			nodes[string(p.NodeKey)] = p.NodeKey
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
	if json.Unmarshal(body, &req) != nil || (req.GID[0] != GIDVersion1 && req.GID[0] != gidBlindedIndex) {
		return
	}
	res := directoryMessage{ID: req.ID, GID: req.GID}
	if req.GID[0] == gidBlindedIndex {
		if req.StoreBlinded != nil {
			res.Stored = d.storeBlinded(req.GID, req.StoreBlinded)
		}
		res.RecordBlinded = d.localBlinded(req.GID)
	} else {
		if req.Store != nil {
			res.Stored = d.store(req.GID, req.Store)
		}
		res.Record = d.local(req.GID)
	}
	// Referrals carry each node's signed RelayInfo so the requester can
	// build circuits to them without contacting them first.
	for _, key := range closestDirectoryNodes(req.GID, d.seeds(), directoryWidth) {
		if raw := d.g.relayInfoRaw(key); raw != nil {
			res.Peers = append(res.Peers, raw)
		}
	}
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

func (d *NetworkRendezvous) rpc(ctx context.Context, peer []byte, gid GID, record *ServiceDescriptor, blinded *BlindedRecord) (directoryMessage, error) {
	if ctx.Err() != nil {
		return directoryMessage{}, ctx.Err()
	}
	cid, err := d.g.createSiteCircuitContext(ctx, peer)
	if err != nil {
		return directoryMessage{}, err
	}
	defer d.g.CloseCircuit(cid)
	start := time.Now()
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
	body, err := json.Marshal(directoryMessage{ID: id, GID: gid, Store: record, StoreBlinded: blinded})
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
			d.g.pathOutcome(cid, true, time.Since(start))
			if res.GID != gid {
				return directoryMessage{}, ErrDescriptorGIDMismatch
			}
			return res, nil
		case <-ticker.C:
		case <-timeout.C:
			d.g.pathOutcome(cid, false, 0)
			return directoryMessage{}, ErrDirectoryUnavailable
		case <-ctx.Done():
			return directoryMessage{}, ctx.Err()
		case <-d.g.stop:
			return directoryMessage{}, net.ErrClosed
		}
	}
}

// walkResult is the outcome of a directory walk: the closest reachable
// directory nodes, the newest record found, and enough bookkeeping to tell
// "nobody has this site" apart from "no directory node could be reached".
type walkResult struct {
	peers    [][]byte
	record   *ServiceDescriptor
	blinded  *BlindedRecord // for a blinded index key
	known    int            // other directory nodes known or learned during the walk
	asked    int            // how many of them were asked
	answered int            // how many of them answered
	lastErr  error          // the last failed request, if any
}

// unreachableErr explains a walk in which no other directory node
// answered, or returns nil if one did.
func (w walkResult) unreachableErr(g *Garlic) error {
	switch {
	case w.answered > 0:
		return nil
	case w.known == 0 && len(g.trustedPeerKeys()) == 0:
		return fmt.Errorf("%w: %w", ErrDirectoryUnavailable, ErrNoTrustedPeers)
	case w.known == 0:
		return fmt.Errorf("%w: no Garlic relays known yet (they are learned from the trusted peers within a minute or two; check getGarlicPeers)", ErrDirectoryUnavailable)
	case w.lastErr != nil:
		return fmt.Errorf("%w: none of the %d known relays answered: %w", ErrDirectoryUnavailable, w.known, w.lastErr)
	default:
		return fmt.Errorf("%w: none of the %d known relays answered", ErrDirectoryUnavailable, w.known)
	}
}

// walk queries directory nodes, closest to gid first. A lookup (untilFound)
// stops after the first round that returned a valid record: every replica
// holds the same signed record, and asking the remaining (possibly offline)
// nodes would only add their timeouts. Publication walks the whole
// neighbourhood to find the closest reachable nodes.
func (d *NetworkRendezvous) walk(ctx context.Context, gid GID, untilFound bool) walkResult {
	var w walkResult
	nodes := d.seeds()
	self := string(d.g.core.PublicKey())
	visited := map[string]bool{self: true}
	reachable := map[string][]byte{}
	if !d.g.cfg.Hidden {
		reachable[self] = d.g.core.PublicKey()
	}
	best := d.local(gid)
	if gid[0] == gidBlindedIndex {
		w.blinded = d.localBlinded(gid)
	}
	for queries := 0; queries < 24; {
		var batch [][]byte
		for _, peer := range d.g.failingLast(closestDirectoryNodes(gid, nodes, directoryWidth)) {
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
			go func(peer []byte) { res, err := d.rpc(ctx, peer, gid, nil, nil); results <- result{peer, res, err} }(peer)
			queries++
			w.asked++
		}
		for range batch {
			r := <-results
			if r.err != nil {
				w.lastErr = r.err
				continue
			}
			w.answered++
			reachable[string(r.peer)] = r.peer
			for _, raw := range r.res.Peers {
				if len(nodes) >= 256 {
					break
				}
				info, err := d.g.learnRelayInfo(raw, nil)
				if err != nil || !needSites(&info.Capability) {
					continue
				}
				nodes[string(info.NodeKey)] = bytes.Clone(info.NodeKey)
			}
			if record := r.res.Record; validateNetworkDescriptor(record, gid) == nil && (best == nil || record.PublishedAt > best.PublishedAt || (record.PublishedAt == best.PublishedAt && record.ExpiresAt > best.ExpiresAt)) {
				best = record
			}
			if b := r.res.RecordBlinded; gid[0] == gidBlindedIndex && validateBlindedRecord(b, gid, time.Now()) == nil && (w.blinded == nil || b.PublishedAt > w.blinded.PublishedAt) {
				w.blinded = b
			}
		}
		if untilFound && (best != nil || w.blinded != nil) {
			break
		}
	}
	w.known = len(nodes)
	if _, ok := nodes[self]; ok {
		w.known--
	}
	w.peers, w.record = closestDirectoryNodes(gid, reachable, directoryWidth), best
	return w
}

func (d *NetworkRendezvous) Publish(gid GID, record *ServiceDescriptor) error {
	if err := validateNetworkDescriptor(record, gid); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return d.publishAt(ctx, gid, record, nil)
}

// PublishBlinded publishes the descriptor of a version 2 GID as blinded
// records (blind.go): for the current day and, near its end, the next.
func (d *NetworkRendezvous) PublishBlinded(gid GID, record *ServiceDescriptor, key ed25519.PrivateKey) error {
	if gid[0] != GIDVersion2 {
		return d.Publish(gid, record)
	}
	if err := validateNetworkDescriptor(record, gid); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var first error
	for i, period := range blindPeriodsFor(time.Now()) {
		r, err := sealBlindedRecord(record, key, period)
		if err != nil {
			return err
		}
		if err := d.publishAt(ctx, blindedIndexKey(r.Index), nil, r); err != nil && i == 0 {
			first = err
		}
	}
	return first
}

// publishAt stores record (or the blinded record) at the directory nodes
// closest to key.
func (d *NetworkRendezvous) publishAt(ctx context.Context, key GID, record *ServiceDescriptor, blinded *BlindedRecord) error {
	w := d.walk(ctx, key, false)
	stored, remote := 0, 0
	var storeErr error
	for _, peer := range w.peers {
		if bytes.Equal(peer, d.g.core.PublicKey()) {
			// A relay never stores the records of sites it hosts itself:
			// they would show up in its directory before anywhere else.
			continue
		}
		res, err := d.rpc(ctx, peer, key, record, blinded)
		if err != nil {
			storeErr = err
		}
		if err == nil && res.Stored {
			stored++
			remote++
		}
		if stored >= directoryReplicas && remote > 0 {
			return nil
		}
	}
	if remote == 0 {
		if err := w.unreachableErr(d.g); err != nil {
			return err
		}
		if storeErr != nil {
			return fmt.Errorf("%w: storing the record failed: %w", ErrDirectoryUnavailable, storeErr)
		}
		return fmt.Errorf("%w: no directory relay accepted the record", ErrDirectoryUnavailable)
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
	var w walkResult
	if gid[0] == GIDVersion2 {
		// Ask for the blinded record of today, then yesterday and
		// tomorrow (clock differences around midnight UTC).
		var total walkResult
		for _, period := range blindLookupPeriods(time.Now()) {
			index, err := BlindPublicKey(gid[1:], period)
			if err != nil {
				return nil, err
			}
			w = d.walk(ctx, blindedIndexKey(index), true)
			if w.blinded != nil {
				if desc, err := openBlindedRecord(w.blinded, gid, time.Now()); err == nil {
					return desc, nil
				}
			}
			total.asked += w.asked
			total.answered += w.answered
			total.known = max(total.known, w.known)
			if w.lastErr != nil {
				total.lastErr = w.lastErr
			}
			if ctx.Err() != nil {
				break
			}
		}
		w = total
	} else {
		w = d.walk(ctx, gid, true)
		if w.record != nil {
			return cloneDescriptor(w.record), nil
		}
	}
	if ctx.Err() != nil {
		cause := "none answered"
		if w.answered > 0 {
			cause = fmt.Sprintf("%d answered but none has the site", w.answered)
		}
		if w.lastErr != nil {
			cause += "; last failure: " + w.lastErr.Error()
		}
		return nil, fmt.Errorf("garlic: site lookup timed out - asked %d of %d known directory relays, %s: %w", w.asked, w.known, cause, ctx.Err())
	}
	if err := w.unreachableErr(d.g); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: %d directory relay(s) answered but none has it - is the site running and published? check getGarlicServices on the hosting node", ErrGIDNotFound, w.answered)
}
