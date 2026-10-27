package garlic

// Site circuits use the existing hop-local forward onion and an independent
// reverse key at every hop. A reverse packet acquires one encrypted layer
// per hop; only the circuit creator can remove all of them. IDs, counters
// and keys differ per leg and direction. No service node address is sent
// to a client or placed in a directory record.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"sync"
	"time"

	iwt "github.com/Arceliar/ironwood/types"
)

const duplexLifetime = 3 * time.Minute
const maxSiteDatagram = 8192

func deriveReplyKey(secret []byte) ([]byte, error) {
	establish, err := DeriveKey(secret, nil, LabelCircuitEstablishHopLocal)
	if err != nil {
		return nil, err
	}
	return DeriveKey(establish, nil, "yggdrasil-garlic-hoplocal-data-reply-v1")
}

type returnRoute struct {
	previous, next []byte
	child          CircuitID
	key            []byte
	counter        uint64
	expires        time.Time
}

type returnOrigin struct {
	id      CircuitID
	first   []byte
	hops    []Hop
	windows []*ReplayWindow
	expires time.Time
}

type duplexState struct {
	g        *Garlic
	mu       sync.Mutex
	routes   map[CircuitID]*returnRoute
	children map[CircuitID]CircuitID
	origins  map[CircuitID]*returnOrigin
}

func newDuplexState(g *Garlic) *duplexState {
	return &duplexState{g: g, routes: make(map[CircuitID]*returnRoute), children: make(map[CircuitID]CircuitID), origins: make(map[CircuitID]*returnOrigin)}
}

func (s *duplexState) record(a circuitAction, from []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.routes[a.circuitID]; r != nil {
		return time.Now().Before(r.expires) && bytes.Equal(r.previous, from) && bytes.Equal(r.key, a.replyKey) && bytes.Equal(r.next, a.forwardTo) && r.child == a.nextCircuitID
	}
	if len(s.routes) >= s.g.cfg.MaxRelayCircuits {
		return false
	}
	if len(a.forwardTo) != 0 {
		if _, exists := s.children[a.nextCircuitID]; exists {
			return false
		}
	}
	counter, err := randomCounterOffset()
	if err != nil {
		return false
	}
	if len(a.forwardTo) != 0 {
		s.children[a.nextCircuitID] = a.circuitID
	}
	s.routes[a.circuitID] = &returnRoute{previous: bytes.Clone(from), next: bytes.Clone(a.forwardTo), child: a.nextCircuitID, key: a.replyKey, counter: counter, expires: time.Now().Add(duplexLifetime)}
	return true
}

func (s *duplexState) track(c *Circuit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	first := c.hops[0].LocalCircuitID
	if s.origins[first] != nil {
		return
	}
	windows := make([]*ReplayWindow, len(c.hops))
	for i := range windows {
		windows[i] = NewReplayWindow()
	}
	s.origins[first] = &returnOrigin{id: c.ID, first: bytes.Clone(c.hops[0].NodeKey), hops: slices.Clone(c.hops), windows: windows, expires: minTime(c.ExpiresAt, c.CreatedAt.Add(duplexLifetime))}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *duplexState) forget(id CircuitID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for leg, o := range s.origins {
		if o.id == id {
			delete(s.origins, leg)
		}
	}
}

func (s *duplexState) prune() {
	s.mu.Lock()
	now := time.Now()
	var retired []CircuitID
	for id, r := range s.routes {
		// Keep an expired binding until all of its in-flight forward
		// packets have expired, then reclaim its replay-table slot too.
		if now.After(r.expires.Add(s.g.cfg.PacketTTL)) {
			delete(s.children, r.child)
			delete(s.routes, id)
			retired = append(retired, id)
		}
	}
	for id, o := range s.origins {
		if now.After(o.expires) {
			delete(s.origins, id)
		}
	}
	s.mu.Unlock()
	if len(retired) > 0 {
		s.g.relayState.mu.Lock()
		for _, id := range retired {
			delete(s.g.relayState.circuits, id)
		}
		s.g.relayState.mu.Unlock()
	}
}

func (s *duplexState) send(id CircuitID, body []byte, terminal bool) error {
	s.mu.Lock()
	r := s.routes[id]
	if r == nil || time.Now().After(r.expires) || r.counter == math.MaxUint64 || (terminal && len(r.next) != 0) {
		s.mu.Unlock()
		return ErrCircuitExpired
	}
	counter := r.counter
	r.counter++
	key, previous := r.key, r.previous
	s.mu.Unlock()
	if len(body) > maxSiteDatagram+MaxPathLength*32 {
		return errors.New("garlic: reply too large")
	}
	sealed, err := Seal(key, counter, body, id[:])
	if err != nil {
		return err
	}
	packet := append([]byte{msgTypeCircuitReply}, id[:]...)
	packet = binary.BigEndian.AppendUint64(packet, counter)
	packet = append(packet, sealed...)
	s.g.sendCircuitData(packet, iwt.Addr(previous))
	return nil
}

func (s *duplexState) receive(from ed25519.PublicKey, packet []byte) {
	if len(packet) < 16+8+16 || len(packet) > maxSiteDatagram+MaxPathLength*32 {
		return
	}
	var id CircuitID
	copy(id[:], packet[:16])
	s.mu.Lock()
	origin := s.origins[id]
	parent, hasParent := s.children[id]
	r := s.routes[parent]
	validParent := hasParent && r != nil && bytes.Equal(r.next, from) && time.Now().Before(r.expires)
	s.mu.Unlock()
	if origin != nil && bytes.Equal(origin.first, from) && time.Now().Before(origin.expires) {
		body := packet[16:]
		// Replay windows are updated only after every layer authenticates.
		counters := make([]uint64, len(origin.hops))
		for i, h := range origin.hops {
			if len(body) < 24 {
				return
			}
			counter := binary.BigEndian.Uint64(body[:8])
			var err error
			body, err = Open(h.ReplyKey, counter, body[8:], h.LocalCircuitID[:])
			if err != nil {
				return
			}
			counters[i] = counter
		}
		for i, n := range counters {
			if !origin.windows[i].CheckAndSet(n) {
				return
			}
		}
		s.g.sites.enqueue(origin.id, body, true)
	} else if validParent {
		_ = s.send(parent, packet[16:], false)
	}
}

func (g *Garlic) sendDuplex(id CircuitID, payload []byte) error {
	if len(payload) > maxSiteDatagram {
		return errors.New("garlic: site datagram too large")
	}
	c, ok := g.circuits.Get(id)
	if !ok {
		return ErrCircuitNotFound
	}
	if time.Since(c.CreatedAt) >= duplexLifetime {
		return ErrCircuitExpired
	}
	g.duplex.track(c)
	g.mu.Lock()
	ephemeral := bytes.Clone(g.originEphemeral[id])
	g.mu.Unlock()
	if len(ephemeral) != KeySize {
		return ErrCircuitNotFound
	}
	onion, first, id, counter, expires, err := c.SealHopLocal(payload, g.cfg.PacketTTL)
	if err != nil {
		return err
	}
	body, err := buildCircuitDataBodyHopLocal(ephemeral, id, counter, expires, onion, g.cfg)
	if err != nil {
		return err
	}
	g.sendCircuitData(append([]byte{msgTypeDuplexData}, body...), iwt.Addr(first))
	return nil
}

// createSiteCircuit requires the configured number of distinct, upgraded
// hops, ending at gateway. It never silently downgrades to a direct path.
func (g *Garlic) createSiteCircuit(gateway []byte) (CircuitID, error) {
	return g.createSiteCircuitContext(g.sites.ctx, gateway)
}

func (g *Garlic) createSiteCircuitContext(ctx context.Context, gateway []byte) (CircuitID, error) {
	n := g.cfg.PathLength
	if n < 1 || n > MaxPathLength {
		return CircuitID{}, ErrInvalidPath
	}
	eligible := make(map[string]bool)
	for i, p := range g.KnownPeers() {
		if i >= 32 {
			break
		}
		cap, err := g.queryCapabilityContext(ctx, p.NodeKey)
		if err == nil && slices.Contains(cap.Versions, CapabilitySites) {
			eligible[string(p.NodeKey)] = true
		}
	}
	candidates := g.candidatePool()
	filtered := make([]HopCandidate, 0, len(candidates))
	for _, p := range candidates {
		if !bytes.Equal(p.NodeKey, gateway) && eligible[string(p.NodeKey)] {
			filtered = append(filtered, p)
		}
	}
	var nodes [][]byte
	if n > 1 {
		path, err := SelectPathWithGuardPolicy(filtered, n-1, g.cfg.MinHopCount)
		if err != nil {
			return CircuitID{}, err
		}
		for _, p := range path {
			nodes = append(nodes, p.NodeKey)
		}
	}
	nodes = append(nodes, bytes.Clone(gateway))
	path := make([]CapabilityMessage, len(nodes))
	for i, key := range nodes {
		cap, err := g.queryCapabilityContext(ctx, key)
		if err != nil {
			return CircuitID{}, err
		}
		if !slices.Contains(cap.Versions, CapabilitySites) {
			return CircuitID{}, errors.New("garlic: site circuit hop needs garlic-sites-v1")
		}
		path[i] = *cap
	}
	return g.CreateCircuit(path, nodes)
}
