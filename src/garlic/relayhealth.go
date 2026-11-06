package garlic

// Relay health and latency, learned from this node's own circuits.
//
// Relays other than trusted guards are never contacted directly, so how
// well one works is learned from end-to-end outcomes of circuits through
// it: a directory request answered or not, a site registration
// acknowledged or not, a site connection established or not, and how long
// the round trip took. Every non-guard hop of the path shares the outcome.
//
// Path selection uses this as a weight, never as a filter: a relay that
// recently failed is chosen less often, a faster one somewhat more often,
// but every eligible relay keeps a minimum chance. Always taking the "best"
// relay would put every circuit on the same few nodes, which helps an
// observer and lets one fast relay attract all traffic.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math"
	"slices"
	"sync"
	"time"
)

const (
	// relayFailHalfLife: a failure counts half as much after this long.
	relayFailHalfLife = 10 * time.Minute
	// relayRTTWeight is the EWMA weight of a new round-trip sample.
	relayRTTWeight = 0.3
	// relayMinWeight keeps every eligible relay selectable.
	relayMinWeight = 0.05
	// relayLatencyBoost caps how much more (or less) often a relay is
	// chosen for being faster (or slower) than the median.
	relayLatencyBoost = 2.0
)

type relayStat struct {
	fail     float64       // decaying failure score
	failAt   time.Time     // when fail was last decayed
	rtt      time.Duration // EWMA of round trips through this relay (0: unknown)
	ok       uint64        // successes seen
	failures uint64        // failures seen
	lastOK   time.Time
	lastFail time.Time
}

func (s *relayStat) decay(now time.Time) {
	if s.fail > 0 && !s.failAt.IsZero() {
		s.fail *= math.Pow(0.5, float64(now.Sub(s.failAt))/float64(relayFailHalfLife))
		if s.fail < 0.01 {
			s.fail = 0
		}
	}
	s.failAt = now
}

type relayHealth struct {
	mu    sync.Mutex
	stats map[string]*relayStat
}

func newRelayHealth() *relayHealth { return &relayHealth{stats: make(map[string]*relayStat)} }

func (h *relayHealth) stat(key []byte, now time.Time) *relayStat {
	s := h.stats[string(key)]
	if s == nil {
		if len(h.stats) >= 4096 {
			h.pruneLocked(now)
		}
		s = &relayStat{failAt: now}
		h.stats[string(key)] = s
	}
	s.decay(now)
	return s
}

func (h *relayHealth) pruneLocked(now time.Time) {
	for k, s := range h.stats {
		last := s.lastOK
		if s.lastFail.After(last) {
			last = s.lastFail
		}
		if now.Sub(last) > 24*time.Hour {
			delete(h.stats, k)
		}
	}
}

// success records that a circuit through keys worked, with its round trip
// (0 if not measured).
func (h *relayHealth) success(keys [][]byte, rtt time.Duration) {
	if h == nil {
		return
	}
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, k := range keys {
		s := h.stat(k, now)
		s.ok++
		s.lastOK = now
		s.fail /= 2
		if rtt > 0 {
			if s.rtt == 0 {
				s.rtt = rtt
			} else {
				s.rtt = time.Duration(float64(s.rtt)*(1-relayRTTWeight) + float64(rtt)*relayRTTWeight)
			}
		}
	}
}

// failure records that a circuit through keys did not work.
func (h *relayHealth) failure(keys [][]byte) {
	if h == nil {
		return
	}
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, k := range keys {
		s := h.stat(k, now)
		s.failures++
		s.lastFail = now
		s.fail++
	}
}

// RelayHealth is what this node has learned about one relay.
type RelayHealth struct {
	FailScore float64       // decaying recent failures (0 = none)
	RTT       time.Duration // typical round trip of paths through it (0 = unknown)
	Successes uint64
	Failures  uint64
	LastOK    time.Time
	LastFail  time.Time
}

func (h *relayHealth) get(key []byte) RelayHealth {
	if h == nil {
		return RelayHealth{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.stats[string(key)]
	if !ok {
		return RelayHealth{}
	}
	s.decay(time.Now())
	return RelayHealth{FailScore: s.fail, RTT: s.rtt, Successes: s.ok, Failures: s.failures, LastOK: s.lastOK, LastFail: s.lastFail}
}

// weights returns a selection weight per key: lower after recent failures,
// higher for lower latency than the median (bounded), never below
// relayMinWeight.
func (h *relayHealth) weights(keys [][]byte) []float64 {
	out := make([]float64, len(keys))
	stats := make([]RelayHealth, len(keys))
	var rtts []time.Duration
	for i, k := range keys {
		stats[i] = h.get(k)
		if stats[i].RTT > 0 {
			rtts = append(rtts, stats[i].RTT)
		}
	}
	var median time.Duration
	if len(rtts) > 0 {
		slices.Sort(rtts)
		median = rtts[len(rtts)/2]
	}
	for i, s := range stats {
		w := 1 / (1 + 3*s.FailScore)
		if median > 0 && s.RTT > 0 {
			f := float64(median) / float64(s.RTT)
			w *= min(relayLatencyBoost, max(1/relayLatencyBoost, f))
		}
		out[i] = max(relayMinWeight, w)
	}
	return out
}

// randFloat returns a uniform float64 in [0, 1) from crypto/rand.
func randFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

// weightedOrder returns the indexes 0..len(w)-1 in a random order where
// heavier entries tend to come first (weighted sampling without
// replacement).
func weightedOrder(w []float64) []int {
	idx := make([]int, len(w))
	for i := range idx {
		idx[i] = i
	}
	rest := slices.Clone(w)
	out := make([]int, 0, len(w))
	for len(idx) > 0 {
		var total float64
		for _, x := range rest {
			total += x
		}
		pick := len(idx) - 1
		r := randFloat() * total
		for i, x := range rest {
			if r < x {
				pick = i
				break
			}
			r -= x
		}
		out = append(out, idx[pick])
		idx = slices.Delete(idx, pick, pick+1)
		rest = slices.Delete(rest, pick, pick+1)
	}
	return out
}

// selectWeightedMiddles picks n middle hops: relays at least minHopCount
// mesh hops away, no two sharing a tree parent, drawn at random with the
// given weights (and a mild preference for farther relays).
func selectWeightedMiddles(pool []HopCandidate, n, minHopCount int, weight func([][]byte) []float64) ([]HopCandidate, error) {
	var cands []HopCandidate
	for _, c := range pool {
		if c.HopCount >= minHopCount {
			cands = append(cands, c)
		}
	}
	keys := make([][]byte, len(cands))
	for i, c := range cands {
		keys[i] = c.NodeKey
	}
	w := weight(keys)
	for i, c := range cands {
		w[i] *= min(2, 1+0.25*float64(max(0, c.HopCount-minHopCount)))
	}
	used := map[string]bool{}
	var selected []HopCandidate
	for _, i := range weightedOrder(w) {
		if len(selected) == n {
			break
		}
		c := cands[i]
		if p := string(c.TreeParent); p != "" && used[p] {
			continue
		}
		if slices.ContainsFunc(selected, func(s HopCandidate) bool { return bytes.Equal(s.NodeKey, c.NodeKey) }) {
			continue
		}
		selected = append(selected, c)
		if p := string(c.TreeParent); p != "" {
			used[p] = true
		}
	}
	if len(selected) < n {
		return nil, ErrInsufficientDiverseCandidates
	}
	return selected, nil
}

// orderByHealth returns keys in weighted random order (see weightedOrder).
func (g *Garlic) orderByHealth(keys [][]byte) [][]byte {
	out := make([][]byte, 0, len(keys))
	for _, i := range weightedOrder(g.health.weights(keys)) {
		out = append(out, keys[i])
	}
	return out
}

// pathOutcome records the outcome of using circuit id: every hop except
// the guard (checked directly) shares it.
func (g *Garlic) pathOutcome(id CircuitID, ok bool, rtt time.Duration) {
	c, found := g.circuits.Get(id)
	if !found {
		return
	}
	hops := c.HopKeys()
	if len(hops) > 1 {
		hops = hops[1:]
	}
	if ok {
		g.health.success(hops, rtt)
	} else {
		g.health.failure(hops)
	}
}

// failingLast keeps keys in order but moves relays with recent failures
// behind the others: they are still tried, just later.
func (g *Garlic) failingLast(keys [][]byte) [][]byte {
	var ok, failing [][]byte
	for _, k := range keys {
		if g.health.get(k).FailScore >= 1 {
			failing = append(failing, k)
		} else {
			ok = append(ok, k)
		}
	}
	return append(ok, failing...)
}
