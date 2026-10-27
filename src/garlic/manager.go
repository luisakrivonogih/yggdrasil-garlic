package garlic

// Garlic ties the protocol pieces from earlier phases to a running
// Yggdrasil node: it registers with core.Core's optional Garlic transport
// hook (src/core/garlic.go) and implements the request/response and
// circuit-relay logic in protocol.go over it. See
// docs/garlic-architecture.md §3.3 for why this is the only integration
// point needed, and §3.12 for the API shape this follows.
//
// Circuit construction here is deliberately non-interactive: the
// originator generates an independent ephemeral X25519 keypair for
// *every* hop (CreateCircuit) and computes ECDH against each hop's
// already-known long-term Garlic public key (learned via capability
// negotiation) to derive that hop's layer key. Only the first hop's
// ephemeral public key is sent up front; each subsequent hop's ephemeral
// key is carried inside the previous hop's encrypted layer, so a hop
// only learns it by successfully decrypting its own layer. Every hop can
// independently redo the same ECDH on receipt using its own long-term
// private key, so no telescoping handshake is needed to set up a
// circuit. Because the ephemeral key differs per hop, non-adjacent hops
// never observe a common ephemeral public key and cannot link a circuit
// by comparing them - see docs/garlic-protocol.md §4.1 and
// docs/garlic-threat-model.md's "Malicious relay" section for the full
// construction and its properties.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"slices"
	"sync"
	"time"

	iwt "github.com/Arceliar/ironwood/types"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// Config holds the tunable, DoS-relevant parameters for a Garlic
// instance. See docs/garlic-architecture.md §3.11 for the corresponding
// YAML config block.
type Config struct {
	PathLength           int
	CircuitLifetime      time.Duration
	MaxCircuits          int
	MaxCircuitsPerPeer   int
	MaxRelayCircuits     int
	PacketTTL            time.Duration
	MaxPacketsPerCircuit uint64
	MaxBytesPerCircuit   uint64
	RatePerSecond        float64
	RateBurst            float64
	MaxTrackedPeers      int
	CapabilityTimeout    time.Duration

	// PaddingEnabled controls per-hop packet size randomization (see
	// Envelope.PadToRandomRange's doc comment): both the originator and
	// every relay independently re-randomize the wire size of the
	// envelope they send within [MinPaddedSize, MaxPaddedSize], so a
	// given hop-to-hop link's packet sizes don't match the sizes seen on
	// the next link - a defense against size-based traffic correlation
	// (docs/garlic-threat-model.md, "Traffic correlation").
	PaddingEnabled bool
	MinPaddedSize  int
	MaxPaddedSize  int

	// JitterEnabled controls random delay before actually transmitting a
	// circuitData packet (origin send or relay forward), independently
	// re-rolled per packet - the timing half of the traffic-correlation
	// defense described on PaddingEnabled. Delivered via a bounded
	// worker pool (jitter.go), never by blocking the caller.
	JitterEnabled   bool
	MinJitter       time.Duration
	MaxJitter       time.Duration
	JitterQueueSize int

	// Discovery: gossip of known Garlic-capable peers, entirely over the
	// existing typeSessionGarlic channel (see discovery.go's doc
	// comment for why this can't be seen by non-Garlic parties).
	// MaxDiscoveredPeers bounds the local registry; GossipInterval and
	// GossipFanout control how often, and to how many already-verified
	// peers, this node proactively shares a sample of what it knows.
	MaxDiscoveredPeers int
	GossipInterval     time.Duration
	GossipFanout       int
	GossipSampleSize   int

	// MinHopCount is SelectPath's minimum mesh distance (see
	// SelectDiversePath) - a Sybil-resistance measure: a candidate too
	// close to this node (e.g. a direct peer) is more likely to be run
	// by the same operator or network than one several hops away.
	MinHopCount int

	// BootstrapPeers seeds the discovery registry at startup: this node
	// queries each entry (hex-encoded node key) for its Garlic
	// capability and, on success, immediately requests its known-peer
	// gossip sample (RequestGossip) - the one manual step needed before
	// AutoCreateCircuit has anything to work with, analogous to
	// Yggdrasil's own NodeConfig.Peers. Best-effort: an unreachable
	// bootstrap peer is simply skipped, not retried on a tight loop.
	BootstrapPeers []string

	// AutoPoolEnabled turns on the background circuit pool + rotation +
	// (if CoverTrafficEnabled) cover traffic. A node can still relay/
	// terminate for another node's auto-pool circuits with this off -
	// see CapabilityAutoCircuit's doc comment.
	AutoPoolEnabled bool
	// AutoPoolSize is how many circuits the pool maintains.
	AutoPoolSize int
	// AutoRotationInterval is how often one pool circuit (the oldest) is
	// retired and rebuilt - never the whole pool at once.
	AutoRotationInterval time.Duration

	// CoverTrafficEnabled sends a periodic dummy payload over every
	// auto-pool circuit, even when there's nothing real to send - raises
	// the cost of volume-based traffic correlation for auto-pool
	// circuits specifically (docs/garlic-threat-model.md's "Traffic
	// correlation" section already covers the general limits of this
	// class of defense).
	CoverTrafficEnabled bool
	// CoverTrafficInterval is the average spacing between cover packets
	// per circuit, randomized ±50% per send so it isn't perfectly
	// periodic (a fixed interval is itself a fingerprint).
	CoverTrafficInterval time.Duration
}

// DefaultConfig returns conservative defaults suitable for a small
// deployment.
func DefaultConfig() Config {
	return Config{
		PathLength:           3,
		CircuitLifetime:      10 * time.Minute,
		MaxCircuits:          1024,
		MaxCircuitsPerPeer:   64,
		MaxRelayCircuits:     4096,
		PacketTTL:            60 * time.Second,
		MaxPacketsPerCircuit: 100000,
		MaxBytesPerCircuit:   100 * 1024 * 1024,
		RatePerSecond:        50,
		RateBurst:            200,
		MaxTrackedPeers:      4096,
		CapabilityTimeout:    6 * time.Second,
		PaddingEnabled:       true,
		MinPaddedSize:        512,
		MaxPaddedSize:        1400,
		JitterEnabled:        true,
		MinJitter:            0,
		MaxJitter:            75 * time.Millisecond,
		JitterQueueSize:      1024,
		MaxDiscoveredPeers:   1024,
		GossipInterval:       30 * time.Second,
		GossipFanout:         2,
		GossipSampleSize:     16,
		MinHopCount:          2,
		AutoPoolEnabled:      false,
		AutoPoolSize:         3,
		AutoRotationInterval: 15 * time.Minute,
		CoverTrafficEnabled:  true,
		CoverTrafficInterval: 75 * time.Second,
	}
}

// jitterWorkers is the fixed size of the jitter scheduler's worker pool.
// Not exposed in Config: it bounds concurrency, not memory, and the
// queue size is the DoS-relevant knob.
const jitterWorkers = 16

var (
	ErrInvalidPath                  = errors.New("garlic: invalid circuit path")
	ErrCircuitNotFound              = errors.New("garlic: circuit not found")
	ErrCapabilityTimeout            = errors.New("garlic: capability request timed out")
	ErrRecvTimeout                  = errors.New("garlic: no message received before timeout")
	ErrPoolNotFound                 = errors.New("garlic: circuit pool not found")
	ErrEmptyPool                    = errors.New("garlic: circuit pool must have at least one path")
	ErrHopMissingAutoCircuitSupport = errors.New("garlic: candidate hop does not support CapabilityAutoCircuit")
	ErrHopMissingGarlicV3Support    = errors.New("garlic: candidate hop does not support CapabilityGarlicV3 (hop-local envelope format)")
)

// DeliveredMessage is an application payload that arrived because this
// node was the final hop of someone else's circuit. CircuitID is the
// value this node saw on the incoming leg of the wire - for an
// EnvelopeVersion2 (hop-local) circuit, that is the terminal leg's own
// independently-random LocalCircuitID, unrelated to the originator's own
// Circuit.ID (which is never itself placed on the wire under the
// hop-local format - see docs/garlic-protocol.md's "Hop-local envelope
// format" section). Do not expect this to match the value CreateCircuit
// returned to the originator.
type DeliveredMessage struct {
	CircuitID CircuitID
	Payload   []byte
}

// AutoDeliveredMessage is an application payload that arrived because
// this node was the final hop of someone else's auto-pool circuit (see
// AutoCreateCircuit). Kept entirely separate from DeliveredMessage/
// g.delivered - a cover-traffic packet is silently discarded before it
// ever reaches this type, and nothing sent via SendGarlicAuto ever
// reaches the plain g.delivered/RecvGarlic path either. As with
// DeliveredMessage, CircuitID is the terminal leg's own per-hop wire
// value for a hop-local circuit, not the originator's Circuit.ID - the
// two should never be expected to match.
type AutoDeliveredMessage struct {
	CircuitID CircuitID
	Payload   []byte
}

// autoPayloadKindReal/autoPayloadKindCover are the leading byte of every
// auto-pool circuit's Inner payload (see sendAutoPayload/deliverTagged) -
// entirely internal to this node's own auto-pool traffic, invisible to
// every intermediate hop (they never parse Inner) and meaningful only to
// the terminal hop that decrypts it.
const (
	autoPayloadKindReal  byte = 0
	autoPayloadKindCover byte = 1
)

// coverPayloadSize is the plaintext size of a cover packet's Inner
// content before AEAD encryption. AEAD ciphertext is indistinguishable
// from random regardless of plaintext content, and per-hop wire size is
// independently re-randomized by Config.PaddingEnabled/PadToRandomRange
// on top of this - a fixed small plaintext size is sufficient, no
// crypto/rand needed here.
const coverPayloadSize = 32

// Garlic is one node's Garlic Routing Overlay state. Construct with New;
// it registers itself with the given core.Core and is usable
// immediately.
type Garlic struct {
	core     *core.Core
	identity *Identity
	cfg      Config

	circuits    *CircuitManager
	relayState  *relayCircuitState
	limiter     *RateLimiter
	siteLimiter *RateLimiter
	rendezvous  Rendezvous
	scheduler   *jitterScheduler
	discovery   *discoveryRegistry
	security    SecurityCounters
	duplex      *duplexState
	directory   *NetworkRendezvous
	sites       *siteRouter

	delivered     chan DeliveredMessage
	autoDelivered chan AutoDeliveredMessage

	mu              sync.Mutex
	capabilityCache map[string]*CapabilityMessage
	pending         map[string]chan *CapabilityMessage
	capFlights      map[string]*capabilityFlight
	originEphemeral map[CircuitID][]byte
	pools           map[PoolID]*circuitPool
	autoPool        map[CircuitID]time.Time

	stop chan struct{}
}

// New constructs a Garlic instance bound to c, using identity as this
// node's long-term Garlic identity and rendezvous for service
// publish/lookup. It registers a handler with c immediately (see
// core.Core.SetGarlicHandler) and starts a background cleanup loop;
// call Close to stop both.
func New(c *core.Core, identity *Identity, cfg Config, rendezvous Rendezvous) *Garlic {
	g := &Garlic{
		core:            c,
		identity:        identity,
		cfg:             cfg,
		circuits:        NewCircuitManager(CircuitManagerConfig{MaxCircuits: cfg.MaxCircuits, MaxCircuitsPerPeer: cfg.MaxCircuitsPerPeer}),
		relayState:      newRelayCircuitState(cfg.MaxRelayCircuits),
		limiter:         NewRateLimiter(cfg.RatePerSecond, cfg.RateBurst, cfg.MaxTrackedPeers),
		siteLimiter:     NewRateLimiter(512, 1024, cfg.MaxTrackedPeers),
		rendezvous:      rendezvous,
		discovery:       newDiscoveryRegistry(cfg.MaxDiscoveredPeers, c.PublicKey()),
		delivered:       make(chan DeliveredMessage, 256),
		autoDelivered:   make(chan AutoDeliveredMessage, 256),
		capabilityCache: make(map[string]*CapabilityMessage),
		pending:         make(map[string]chan *CapabilityMessage),
		originEphemeral: make(map[CircuitID][]byte),
		pools:           make(map[PoolID]*circuitPool),
		autoPool:        make(map[CircuitID]time.Time),
		stop:            make(chan struct{}),
	}
	g.scheduler = newJitterScheduler(func(data []byte, addr net.Addr) error {
		_, err := c.WriteGarlic(data, addr)
		return err
	}, cfg.JitterQueueSize, jitterWorkers)
	g.duplex = newDuplexState(g)
	g.directory = newNetworkRendezvous(g)
	if g.rendezvous == nil {
		g.rendezvous = g.directory
	}
	g.sites = newSiteRouter(g)
	c.SetGarlicHandler(g.handleIncoming)
	go g.cleanupLoop()
	go g.bootstrap()
	go g.autoPoolLoop()
	return g
}

// Close unregisters from core.Core and stops the background cleanup
// loop and the jitter scheduler. It does not close the underlying
// core.Core.
func (g *Garlic) Close() {
	close(g.stop)
	g.sites.close()
	g.core.SetGarlicHandler(nil)
	g.scheduler.Stop()
}

// sendCircuitData transmits a circuitData wire message to addr, applying
// Config.JitterEnabled's random delay if configured. A jitter computation
// or scheduling failure falls back to sending immediately, so a
// misconfiguration degrades to unjittered delivery rather than dropping
// an otherwise-valid packet.
func (g *Garlic) sendCircuitData(msg []byte, addr net.Addr) {
	if peer, ok := addr.(iwt.Addr); ok && g.core != nil && bytes.Equal(peer, g.core.PublicKey()) {
		g.handleIncoming(g.core.PublicKey(), msg)
		return
	}
	var delay time.Duration
	if g.cfg.JitterEnabled {
		if d, err := randomJitter(g.cfg.MinJitter, g.cfg.MaxJitter); err == nil {
			delay = d
		}
	}
	if !g.scheduler.enqueue(msg, addr, delay) {
		_, _ = g.core.WriteGarlic(msg, addr)
	}
}

func (g *Garlic) cleanupLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	gossip := time.NewTicker(max(g.cfg.GossipInterval, time.Second))
	defer gossip.Stop()
	for {
		select {
		case <-t.C:
			g.duplex.prune()
			g.circuits.ExpireStale()
			g.relayState.expireStale(2 * g.cfg.CircuitLifetime)
			g.limiter.Cleanup(time.Hour)
			g.siteLimiter.Cleanup(time.Hour)
		case <-gossip.C:
			g.gossipTick()
		case <-g.stop:
			return
		}
	}
}

// gossipTick sends this node's known-peer sample to a few
// already-capability-verified peers (from capabilityCache, i.e. peers
// this node has itself confirmed answer garlic-v2 - never an unverified
// discovery candidate), so discovery propagates without needing a
// distributed directory.
func (g *Garlic) gossipTick() {
	g.mu.Lock()
	targets := make([]string, 0, len(g.capabilityCache))
	for key := range g.capabilityCache {
		targets = append(targets, key)
	}
	g.mu.Unlock()

	if len(targets) > g.cfg.GossipFanout {
		targets = targets[:g.cfg.GossipFanout]
	}
	for _, hexKey := range targets {
		peerKey, err := hex.DecodeString(hexKey)
		if err != nil {
			continue
		}
		_ = g.GossipAnnounce(peerKey)
	}
}

// bootstrapMaxAttempts bounds how many times bootstrap queries a single
// configured peer before giving up on it. A freshly-established mesh
// connection's very first capability request commonly races the
// underlying path discovery (see ironwood's pathfinder) and is lost -
// every other capability-querying test in this package retries for
// exactly this reason (see waitForCapability). Each attempt is already
// naturally paced by Config.CapabilityTimeout, so a handful of attempts
// is not the "tight loop" this field's doc comment disclaims - just
// enough to not depend on winning that race on the first try.
const bootstrapMaxAttempts = 3

// bootstrap resolves Config.BootstrapPeers into self-verified discovery
// entries: QueryCapability (records the entry as SelfVerified via
// handleCapabilityResponse) followed by RequestGossip, per peer,
// best-effort - up to bootstrapMaxAttempts per peer, then skipped for
// good (not retried again until the next process restart). Called once
// from New in its own goroutine so New itself returns immediately,
// matching this package's existing convention.
func (g *Garlic) bootstrap() {
	for _, hexKey := range g.cfg.BootstrapPeers {
		key, err := hex.DecodeString(hexKey)
		if err != nil {
			continue
		}
		var verified bool
		for attempt := 0; attempt < bootstrapMaxAttempts; attempt++ {
			if _, err := g.QueryCapability(key); err == nil {
				verified = true
				break
			}
		}
		if !verified {
			continue
		}
		_ = g.RequestGossip(key)
	}
}

// GossipAnnounce sends to as a sample of this node's known Garlic peers
// (Config.GossipSampleSize of them), so it can discover peers it hasn't
// directly queried itself. Intended to be called with an already
// capability-verified peer, though nothing technically prevents calling
// it otherwise - an unverified recipient simply can't parse the message
// if it isn't running src/garlic, same as any other Garlic message type.
func (g *Garlic) GossipAnnounce(to ed25519.PublicKey) error {
	sample := g.discovery.sample(g.cfg.GossipSampleSize)
	peers := make([]AnnouncePeer, len(sample))
	for i, p := range sample {
		peers[i] = AnnouncePeer{NodeKey: p.NodeKey, GarlicPublicKey: p.GarlicPublicKey}
	}
	body, err := (&AnnounceMessage{Peers: peers}).Marshal()
	if err != nil {
		return err
	}
	msg := append([]byte{msgTypeAnnounce}, body...)
	_, err = g.core.WriteGarlic(msg, iwt.Addr(to))
	return err
}

// RequestGossip asks peer to immediately send this node its known-peer
// gossip sample (msgTypeAnnounceRequest, empty body) - see
// docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md
// §4. A peer running code without this feature simply never answers;
// handleIncoming's switch has no default case, so an unrecognized type
// byte is already silently ignored (Go zero-value switch fallthrough) -
// no capability check needed before sending this specific message.
func (g *Garlic) RequestGossip(peer ed25519.PublicKey) error {
	_, err := g.core.WriteGarlic([]byte{msgTypeAnnounceRequest}, iwt.Addr(peer))
	return err
}

// KnownPeers returns every Garlic peer this node currently knows about,
// whether learned directly (a successful capability query) or via
// gossip from another peer (msgTypeAnnounce) - candidates for circuit
// hop selection, not yet capability-verified by this node itself unless
// QueryCapability has also been called for that specific key.
func (g *Garlic) KnownPeers() []DiscoveredPeer {
	return g.discovery.list()
}

// candidatePool builds a HopCandidate for every known/discovered peer
// this node has a resolved mesh path to, annotated with hop count and
// tree parent (see SelectDiversePath). A peer with no resolved path yet
// is skipped rather than scored with a meaningless zero.
func (g *Garlic) candidatePool() []HopCandidate {
	tree := g.core.GetTree()
	parentOf := make(map[string][]byte, len(tree))
	for _, t := range tree {
		parentOf[string(t.Key)] = t.Parent
	}

	known := g.discovery.list()
	pool := make([]HopCandidate, 0, len(known))
	for _, p := range known {
		hops, ok := g.HopCount(p.NodeKey)
		if !ok {
			continue
		}
		pool = append(pool, HopCandidate{
			NodeKey:         p.NodeKey,
			GarlicPublicKey: p.GarlicPublicKey,
			HopCount:        hops,
			TreeParent:      parentOf[string(p.NodeKey)],
			SelfVerified:    p.SelfVerified,
		})
	}
	return pool
}

// SelectPath chooses n topologically diverse circuit hops from this
// node's known/discovered Garlic peers (see SelectDiversePath and
// Config.MinHopCount). The result still needs each hop's capability
// re-verified (e.g. via QueryCapability) before CreateCircuit, in case a
// discovered/gossiped entry has gone stale.
func (g *Garlic) SelectPath(n int) ([]HopCandidate, error) {
	return SelectDiversePath(g.candidatePool(), n, g.cfg.MinHopCount)
}

// AutoCreateCircuit builds an n-hop circuit entirely from this node's
// discovery pool: SelectPathWithGuardPolicy chooses hops (first from
// self-verified candidates only), each is re-verified via QueryCapability
// (catching a stale/never-directly-contacted gossiped candidate before
// it's used, same as the manual createGarlicCircuit admin RPC already
// does - note QueryCapability reuses a cached answer when it has one, so
// this is not necessarily a fresh round trip per hop), and every hop must
// additionally advertise CapabilityGarlicV3 (this node only ever
// originates hop-local circuits - see CreateCircuit's own gate, which
// this check catches at selection time instead of one layer deeper) and
// CapabilityAutoCircuit - see
// docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md
// §6/§8 for why every position, not just the terminal one, is gated.
//
// Selection itself (SelectPathWithGuardPolicy/candidatePool) has no
// concept of protocol version - it only ever sees mesh topology - so a
// version-incompatible pick (a peer still on garlic-v2, not yet upgraded
// to the hop-local envelope format) is expected in a mixed-version mesh,
// not a reason to give up outright. On that failure the offending
// candidate is excluded and selection retried from the remaining pool,
// up to once per pool member - each retry strictly shrinks the pool, so
// this always terminates. If every retry is exhausted this way, the last
// version-related error is returned in preference to the generic
// "not enough candidates" SelectPathWithGuardPolicy would otherwise
// report, since it names the actual, actionable reason (upgrade that
// peer) rather than just the symptom.
func (g *Garlic) AutoCreateCircuit(n int) (CircuitID, error) {
	pool := g.candidatePool()
	excluded := map[string]bool{}
	var lastVersionErr error

	for {
		hops, err := SelectPathWithGuardPolicy(excludeCandidates(pool, excluded), n, g.cfg.MinHopCount)
		if err != nil {
			if lastVersionErr != nil {
				return CircuitID{}, lastVersionErr
			}
			return CircuitID{}, err
		}

		path := make([]CapabilityMessage, len(hops))
		nodeKeys := make([][]byte, len(hops))
		incompatible := false
		for i, h := range hops {
			capability, err := g.QueryCapability(h.NodeKey)
			if err != nil {
				return CircuitID{}, fmt.Errorf("hop %d: %w", i, err)
			}
			if !capability.SupportsGarlicV3() {
				lastVersionErr = fmt.Errorf("hop %d: %w", i, ErrHopMissingGarlicV3Support)
			} else if !capability.SupportsAutoCircuit() {
				lastVersionErr = fmt.Errorf("hop %d: %w", i, ErrHopMissingAutoCircuitSupport)
			} else {
				path[i] = *capability
				nodeKeys[i] = h.NodeKey
				continue
			}
			excluded[string(h.NodeKey)] = true
			incompatible = true
			break
		}
		if !incompatible {
			return g.CreateCircuit(path, nodeKeys)
		}
	}
}

// AutoPoolEntry is a point-in-time summary of one auto-pool circuit, for
// the getGarlicAutoPool admin RPC / dashboard.
type AutoPoolEntry struct {
	ID        CircuitID
	CreatedAt time.Time
	HopCount  int
}

// pruneAutoPool drops entries whose circuit is no longer tracked by
// CircuitManager - closed explicitly, or reaped by ExpireStale. Every
// size decision below depends on this running first, since an entry
// surviving in g.autoPool past its circuit's real lifetime would be
// counted as live.
//
// Lock order: g.mu is taken first, then CircuitManager's own internal
// mutex inside Get. CircuitManager holds no reference to *Garlic and
// never calls back into it (see circuit_manager.go), so no code path
// takes those two locks in the opposite order and this cannot deadlock.
func (g *Garlic) pruneAutoPool() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id := range g.autoPool {
		if _, ok := g.circuits.Get(id); !ok {
			delete(g.autoPool, id)
		}
	}
}

// AutoPoolStatus returns every circuit currently managed by the auto-pool
// loop, sorted by ascending circuit ID for stable admin/dashboard output
// (same reasoning as CircuitManager.List's doc comment). Entries whose
// circuit is already gone are pruned first, so this never reports a
// phantom circuit to an operator or the dashboard.
func (g *Garlic) AutoPoolStatus() []AutoPoolEntry {
	g.pruneAutoPool()

	g.mu.Lock()
	entries := make([]AutoPoolEntry, 0, len(g.autoPool))
	for id, at := range g.autoPool {
		entries = append(entries, AutoPoolEntry{ID: id, CreatedAt: at})
	}
	g.mu.Unlock()

	for i := range entries {
		if c, ok := g.circuits.Get(entries[i].ID); ok {
			entries[i].HopCount = len(c.HopKeys())
		}
	}
	slices.SortFunc(entries, func(a, b AutoPoolEntry) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return entries
}

// fillAutoPool adds at most *one* circuit to the auto-pool, and only if
// the pool is below Config.AutoPoolSize. Best-effort: a candidate
// shortage (ErrNoSelfVerifiedCandidates, ErrInsufficientDiverseCandidates,
// or any other AutoCreateCircuit failure) just leaves the pool under
// target until more peers are discovered - no tight retry loop. Pruned
// first, so a pool full of entries whose circuits have already been
// reaped is correctly seen as depleted and actually refilled.
//
// One per call, not "loop until full", is deliberate and is the same
// "never all at once" anti-correlation property rotateAutoPool's doc
// comment describes, applied to backfill. Building the whole pool inside
// a single call gives every pool circuit (approximately) one shared
// creation instant, and therefore one shared expiry instant
// Config.CircuitLifetime later: CircuitManager.ExpireStale reaps them in
// the same pass, the maintenance ticker rebuilds them all inside one
// tick, and the node emits a phase-locked burst of Config.AutoPoolSize
// simultaneous circuit builds once per CircuitLifetime, forever - a
// standing fingerprint tying those otherwise unrelated circuits to one
// originator. Topping up one circuit per call instead leans on
// autoPoolLoop's existing autoPoolFillRetryInterval maintenance cadence
// (which already fires repeatedly while the pool is below target) to
// finish the job over several ticks, which spreads creation - and hence
// expiry - across roughly (AutoPoolSize-1) x autoPoolFillRetryInterval
// with no separate per-circuit lifetime jitter needed.
//
// The tradeoff is that a cold start reaches full pool size a few seconds
// later than it otherwise would, since autoPoolLoop's one synchronous
// pre-loop call now creates a single circuit rather than all of them.
// That is accepted deliberately: nothing depends on the pool being at
// target size immediately, and cover traffic and SendGarlicAuto both
// work fine over a partially filled pool.
func (g *Garlic) fillAutoPool() {
	g.pruneAutoPool()

	g.mu.Lock()
	n := len(g.autoPool)
	g.mu.Unlock()
	if n >= g.cfg.AutoPoolSize {
		return
	}

	id, err := g.AutoCreateCircuit(g.cfg.PathLength)
	if err != nil {
		return
	}
	g.mu.Lock()
	g.autoPool[id] = time.Now()
	g.mu.Unlock()
}

// rotateAutoPool retires exactly one pool circuit (the oldest) per call
// and immediately tries to build one replacement (fillAutoPool adds at
// most one circuit per call) - never the whole pool at once, so a
// rotation tick isn't itself a burst-of-circuit-builds fingerprint (see
// the design doc §7).
func (g *Garlic) rotateAutoPool() {
	g.mu.Lock()
	var oldestID CircuitID
	var oldestAt time.Time
	first := true
	for id, at := range g.autoPool {
		if first || at.Before(oldestAt) {
			oldestID, oldestAt, first = id, at, false
		}
	}
	g.mu.Unlock()

	if first {
		g.fillAutoPool()
		return
	}

	g.CloseCircuit(oldestID)
	g.mu.Lock()
	delete(g.autoPool, oldestID)
	g.mu.Unlock()
	g.fillAutoPool()
}

// coverTrafficStagger returns one independently-drawn delay, uniform over
// [0, Config.CoverTrafficInterval), used to spread a single round of
// cover sends across the whole interval. Drawn separately per circuit -
// that independence is the entire point, so two pool circuits' cover
// packets are not scheduled for the same instant.
func (g *Garlic) coverTrafficStagger() time.Duration {
	span := int64(g.cfg.CoverTrafficInterval)
	if span <= 0 {
		return 0
	}
	return time.Duration(mrand.Int63n(span))
}

// sendCoverTraffic schedules one autoPayloadKindCover packet over every
// circuit currently in the auto-pool, each at its own independently drawn
// offset within Config.CoverTrafficInterval (coverTrafficStagger) rather
// than all at once.
//
// The staggering is the security-relevant part, not an optimization: with
// a shared timer and a tight send loop, an observer watching this node's
// links sees Config.AutoPoolSize cover packets leave for
// Config.AutoPoolSize *different* first hops within one scheduling
// instant, which is itself a correlation signal tying those otherwise
// unrelated circuits to one originator - the same "never all at once"
// concern rotateAutoPool's doc comment describes, applied to cover
// traffic. Design spec §8 requires per-circuit independent jitter for
// exactly this reason.
//
// Sends are best-effort and fire-and-forget: a failure (a hop temporarily
// unreachable, or the circuit rotated/expired out from under the pending
// timer) is not retried here; the next scheduled round tries again.
// Nothing needs cancelling at Close beyond the g.stop check below -
// time.AfterFunc's goroutine is short-lived and does not outlive its one
// send attempt, and sendAutoPayload already fails cleanly
// (ErrCircuitNotFound) on a circuit that no longer exists.
func (g *Garlic) sendCoverTraffic() {
	g.mu.Lock()
	ids := make([]CircuitID, 0, len(g.autoPool))
	for id := range g.autoPool {
		ids = append(ids, id)
	}
	g.mu.Unlock()

	for _, id := range ids {
		time.AfterFunc(g.coverTrafficStagger(), func() {
			select {
			case <-g.stop:
				return
			default:
			}
			_ = g.sendAutoPayload(id, autoPayloadKindCover, make([]byte, coverPayloadSize))
		})
	}
}

// coverTrafficDelay returns Config.CoverTrafficInterval jittered ±50%,
// setting how often a *round* of cover sends is scheduled. Within a
// round, each circuit's actual send is independently offset again by
// coverTrafficStagger, so this only paces the rounds - it is not itself
// what keeps two circuits' packets from coinciding.
func (g *Garlic) coverTrafficDelay() time.Duration {
	base := g.cfg.CoverTrafficInterval
	if base <= 0 {
		return time.Second
	}
	jitterRange := int64(base) // ±50% of base = a uniform draw over [0.5*base, 1.5*base]
	offset := mrand.Int63n(jitterRange) - jitterRange/2
	d := time.Duration(int64(base) + offset)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// autoPoolFillRetryInterval bounds how long autoPoolLoop waits before
// retrying fillAutoPool while the pool is still below Config.AutoPoolSize
// - deliberately decoupled from (and typically much shorter than)
// Config.AutoRotationInterval, which governs the steady-state cadence
// once the pool is already at target size. Without this, a freshly
// started node whose very first fillAutoPool call races
// bootstrap/discovery convergence (see bootstrapMaxAttempts's doc
// comment for the same class of mesh-convergence race) and loses would
// otherwise not retry again until a full AutoRotationInterval had
// elapsed - 15 minutes with the default config - even though candidates
// became available moments later. rotateAutoPool's "one circuit at a
// time" anti-fingerprint concern (see its doc comment) is specifically
// about steady-state rotation of an already-full pool; it doesn't apply
// to simply catching a still-filling pool up to target, so a faster
// cadence here doesn't undermine it.
const autoPoolFillRetryInterval = 2 * time.Second

// nextAutoPoolInterval picks how long autoPoolLoop should wait before its
// next fill-or-rotate action: autoPoolFillRetryInterval while the pool is
// below Config.AutoPoolSize, Config.AutoRotationInterval (floored at one
// second) once it's already full. Read fresh every time the rotate/fill
// timer fires (never on an unrelated loop wakeup - see autoPoolLoop),
// since belowTarget can only change as a result of that same fire, or of
// the pruning this does first.
//
// Note the deliberate relationship between the two configured periods:
// Config.AutoRotationInterval (15m by default) is *longer* than
// Config.CircuitLifetime (10m), so rotation is never what keeps the pool
// populated - pool circuits reach their own expiry and are reaped by
// CircuitManager.ExpireStale well before a rotation tick is due. Expiry-
// driven backfill (pruneAutoPool making belowTarget true, then this
// function's autoPoolFillRetryInterval catch-up cadence, driven by
// autoPoolLoop's maintenance ticker) is the primary refresh mechanism;
// rotation only adds anonymity-motivated turnover of an otherwise-healthy
// pool on top of it. Do not "fix" the ordering by shortening
// AutoRotationInterval below CircuitLifetime - that would make rotation
// fire against circuits that are still perfectly good, which is exactly
// the burst-of-rebuilds fingerprint rotateAutoPool's doc comment guards
// against.
func (g *Garlic) nextAutoPoolInterval() time.Duration {
	g.pruneAutoPool()

	g.mu.Lock()
	belowTarget := len(g.autoPool) < g.cfg.AutoPoolSize
	g.mu.Unlock()
	interval := max(g.cfg.AutoRotationInterval, time.Second)
	if belowTarget {
		interval = min(interval, autoPoolFillRetryInterval)
	}
	return interval
}

// autoPoolLoop maintains the auto-pool (fill on start, then keep filling
// on autoPoolFillRetryInterval - one circuit per call, see fillAutoPool -
// until the pool reaches Config.AutoPoolSize; once full, rotate one
// circuit at a time on Config.AutoRotationInterval) and, if
// Config.CoverTrafficEnabled, sends
// jittered cover traffic over every pool circuit. No-op entirely if
// Config.AutoPoolEnabled is false - a node can still relay/terminate for
// other nodes' auto-pool circuits without running this loop itself.
//
// Both timers - the rotate/fill timer and the cover-traffic timer - are
// created once, before the loop, and only ever Reset from inside their
// own case; neither is ever recreated on an unrelated wakeup. Recreating
// a timer at the top of every iteration restarts its countdown from zero
// each time some *other* case fires first, so any timer whose period is
// longer than this loop's fastest wakeup source would starve and never
// fire at all. That is not hypothetical here: the maintenance ticker
// described below wakes the loop every autoPoolFillRetryInterval (2s)
// unconditionally, which is shorter than Config.AutoRotationInterval and
// - at every realistic setting, including the 75s default - shorter than
// Config.CoverTrafficInterval too. Resetting coverTimer from within its
// own case still rerolls its delay freshly for every round, which is
// what coverTrafficDelay's per-round jitter needs; nothing about that
// jitter requires a brand-new Timer.
//
// A third, backfill-only maintenance ticker runs at
// autoPoolFillRetryInterval. It exists because circuits leave the pool on
// their own schedule (Config.CircuitLifetime, reaped by
// CircuitManager.ExpireStale from cleanupLoop) rather than on the
// rotate/fill timer's, and with the default config that expiry happens
// well before a rotation tick is due - see nextAutoPoolInterval's doc
// comment. Without a wakeup of its own, the loop would not even notice
// the pool had emptied until the next rotation tick, leaving the pool
// (and therefore cover traffic) dead for the difference between the two
// periods. It deliberately never rotates: rotation cadence stays exactly
// Config.AutoRotationInterval, and this only tops a depleted pool back up.
func (g *Garlic) autoPoolLoop() {
	if !g.cfg.AutoPoolEnabled {
		return
	}
	g.fillAutoPool()

	rotateTimer := time.NewTimer(g.nextAutoPoolInterval())
	defer rotateTimer.Stop()

	maintTicker := time.NewTicker(autoPoolFillRetryInterval)
	defer maintTicker.Stop()

	// A nil coverC blocks forever in the select below, so cover traffic
	// being disabled simply means that case never becomes ready.
	var coverTimer *time.Timer
	var coverC <-chan time.Time
	if g.cfg.CoverTrafficEnabled {
		coverTimer = time.NewTimer(g.coverTrafficDelay())
		defer coverTimer.Stop()
		coverC = coverTimer.C
	}

	for {
		select {
		case <-rotateTimer.C:
			g.pruneAutoPool()
			g.mu.Lock()
			belowTarget := len(g.autoPool) < g.cfg.AutoPoolSize
			g.mu.Unlock()
			if belowTarget {
				g.fillAutoPool()
			} else {
				g.rotateAutoPool()
			}
			rotateTimer.Reset(g.nextAutoPoolInterval())
		case <-maintTicker.C:
			g.pruneAutoPool()
			g.mu.Lock()
			belowTarget := len(g.autoPool) < g.cfg.AutoPoolSize
			g.mu.Unlock()
			if belowTarget {
				g.fillAutoPool()
			}
		case <-coverC:
			g.sendCoverTraffic()
			coverTimer.Reset(g.coverTrafficDelay())
		case <-g.stop:
			return
		}
	}
}

// Identity returns this node's long-term Garlic identity.
func (g *Garlic) Identity() *Identity {
	return g.identity
}

// handleIncoming is the core.GarlicHandler registered with core.Core. It
// must not block (see GarlicHandler's doc comment), so every branch here
// either returns immediately or hands off a bounded amount of work.
func (g *Garlic) handleIncoming(from ed25519.PublicKey, data []byte) {
	if len(data) == 0 {
		return
	}
	limiter := g.limiter
	if data[0] == msgTypeDuplexData || data[0] == msgTypeCircuitReply {
		limiter = g.siteLimiter
	}
	if !limiter.Allow(from) {
		return
	}
	switch data[0] {
	case msgTypeCapabilityRequest:
		resp := append([]byte{msgTypeCapabilityResponse}, g.processCapabilityRequest()...)
		_, _ = g.core.WriteGarlic(resp, iwt.Addr(from))
		// Capability negotiation was previously one-directional: this node
		// only ever recorded a peer as SelfVerified when IT sent the
		// request (handleCapabilityResponse). A peer that only ever
		// *asked* us - the common case for every node but the one at the
		// center of a star-shaped bootstrap topology - was never recorded
		// at all, so it could never be gossiped onward to anyone else,
		// and pure fan-out bootstrapping (every node pointed at one hub)
		// could never converge into a shared candidate pool. Answering a
		// request is exactly as strong an authentication signal as
		// receiving a response - ironwood's encrypted per-key session
		// already guarantees `from` is the real sender - so querying back
		// reuses the existing, already-reviewed QueryCapability/
		// handleCapabilityResponse path to record it symmetrically.
		// QueryCapability short-circuits on an existing cache entry, so
		// this is a no-op wire-traffic-wise once both sides already know
		// each other. Must run in its own goroutine: QueryCapability
		// blocks up to Config.CapabilityTimeout on a cache miss, and
		// handleIncoming must never block (see its own doc comment).
		go func() { _, _ = g.QueryCapability(from) }()
	case msgTypeCapabilityResponse:
		g.handleCapabilityResponse(from, data[1:])
	case msgTypeCircuitData:
		g.dispatchAction(g.processCircuitData(data[1:], msgTypeCircuitData), from)
	case msgTypeAnnounce:
		g.processAnnounce(data[1:])
	case msgTypeCircuitDataBundle:
		for _, action := range g.processCircuitDataBundle(data[1:]) {
			g.dispatchAction(action, from)
		}
	case msgTypeAnnounceRequest:
		_ = g.GossipAnnounce(from)
	case msgTypeCircuitDataV3:
		g.dispatchAction(g.processCircuitData(data[1:], msgTypeCircuitDataV3), from)
	case msgTypeDuplexData:
		g.dispatchAction(g.processCircuitData(data[1:], msgTypeDuplexData), from)
	case msgTypeCircuitReply:
		g.duplex.receive(from, data[1:])
	}
}

// dispatchAction carries out a single circuitAction: deliver locally, or
// forward to the next hop. actionDrop is a no-op (nothing to do). from
// is the peer this data arrived from - recorded as the relayed
// circuit's previous hop when forwarding, never used or stored for any
// other action kind.
func (g *Garlic) dispatchAction(action circuitAction, from ed25519.PublicKey) {
	if len(action.replyKey) != 0 {
		if !g.duplex.record(action, from) {
			return
		}
		if action.kind == actionDeliver {
			g.sites.enqueue(action.circuitID, action.payload, false)
			return
		}
	}
	switch action.kind {
	case actionDeliver:
		if action.tagged {
			g.deliverTagged(action.circuitID, action.payload)
			return
		}
		select {
		case g.delivered <- DeliveredMessage{CircuitID: action.circuitID, Payload: action.payload}:
		default:
		}
	case actionForward:
		g.relayState.recordForward(action.circuitID, from, action.forwardTo, len(action.forwardMsg))
		g.sendCircuitData(action.forwardMsg, iwt.Addr(action.forwardTo))
	}
}

// deliverTagged interprets a msgTypeCircuitDataV3 delivery's leading kind
// byte: a cover packet (autoPayloadKindCover) is silently discarded here
// - the whole point of continuous cover traffic is that it travels the
// full circuit depth and looks exactly like real traffic to every hop,
// including this delivery step, right up until this one deliberate
// discard. A malformed payload (empty, or an unrecognized kind byte) is
// dropped the same way any other malformed Garlic input is - no error,
// no observable difference from a legitimate cover discard.
func (g *Garlic) deliverTagged(id CircuitID, payload []byte) {
	if len(payload) == 0 {
		return
	}
	kind, real := payload[0], payload[1:]
	if kind != autoPayloadKindReal {
		return
	}
	select {
	case g.autoDelivered <- AutoDeliveredMessage{CircuitID: id, Payload: append([]byte(nil), real...)}:
	default:
	}
}

// RelayCircuits returns a snapshot of every circuit this node is
// currently relaying (i.e. is an intermediate hop for) - real, locally
// known previous/next hop and traffic data, never a fabricated full
// path. Used by the getGarlicCircuits admin handler.
func (g *Garlic) RelayCircuits() []RelayCircuitInfo {
	return g.relayState.snapshot()
}

// handleCapabilityResponse processes an inbound msgTypeCapabilityResponse.
//
// SelfVerified is recorded true only when g.pending[key] is set, i.e. a
// capability request this node itself sent (requestCapability) is still
// outstanding for that exact key. This gate is what makes the flag mean
// what discovery.go and docs/garlic-threat-model.md claim it means -
// "this node completed a handshake it initiated" - rather than merely
// "some key sent this node a well-formed packet". handleIncoming
// dispatches this message type for any peer that can open an ironwood
// session, so without the gate a single unsolicited response would
// permanently grant first-hop-guard eligibility (discoveryRegistry.record
// never downgrades SelfVerified back to false), defeating
// SelectPathWithGuardPolicy's whole purpose.
//
// An unsolicited - or too-late, after this node's own CapabilityTimeout
// already cleared g.pending - response is still worth remembering as an
// ordinary, gossip-tier discovery candidate: it grants no more trust than
// a msgTypeAnnounce entry the same peer could already inject itself via
// processAnnounce, and it still has to pass a real, this-node-initiated
// QueryCapability before it can be used as a hop.
func (g *Garlic) handleCapabilityResponse(from ed25519.PublicKey, body []byte) {
	msg, err := UnmarshalCapabilityMessage(body)
	if err != nil {
		return
	}
	key := hex.EncodeToString(from)

	g.mu.Lock()
	g.capabilityCache[key] = msg
	ch := g.pending[key]
	g.mu.Unlock()

	// A successful, self-reported garlic-v2 response is exactly the
	// verification discovery candidates need before they're worth
	// remembering - see discovery.go's doc comment.
	if msg.SupportsGarlicV2() && len(msg.PublicKey) > 0 {
		g.discovery.record(DiscoveredPeer{
			NodeKey:         append([]byte(nil), from...),
			GarlicPublicKey: msg.PublicKey,
			SelfVerified:    ch != nil,
		})
	}

	if ch != nil {
		select {
		case ch <- msg:
		default:
		}
	}
}

// QueryCapability asks peer which Garlic protocol versions it supports
// and, if any, its Garlic identity public key. It returns a cached
// result if one is already known, otherwise it sends a request and waits
// up to cfg.CapabilityTimeout. A timeout (ErrCapabilityTimeout) means
// peer should be treated as legacy: it must never be selected as a
// circuit hop or rendezvous point.
func (g *Garlic) QueryCapability(peer ed25519.PublicKey) (*CapabilityMessage, error) {
	return g.queryCapabilityContext(context.Background(), peer)
}

func (g *Garlic) queryCapabilityContext(ctx context.Context, peer ed25519.PublicKey) (*CapabilityMessage, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if g.core != nil && bytes.Equal(peer, g.core.PublicKey()) {
		return UnmarshalCapabilityMessage(g.processCapabilityRequest())
	}
	key := hex.EncodeToString(peer)
	g.mu.Lock()
	if cached, ok := g.capabilityCache[key]; ok {
		g.mu.Unlock()
		return cached, nil
	}
	g.mu.Unlock()
	return g.requestCapabilityContext(ctx, peer)
}

// PingCapability behaves like QueryCapability but always sends a fresh
// request - ignoring any cached result - and additionally reports the
// measured round-trip time. Intended for topology-aware hop selection
// (see HopCount), where a stale cached answer wouldn't reflect current
// latency. The result still updates the capability cache, same as
// QueryCapability.
func (g *Garlic) PingCapability(peer ed25519.PublicKey) (*CapabilityMessage, time.Duration, error) {
	start := time.Now()
	msg, err := g.requestCapability(peer)
	if err != nil {
		return nil, 0, err
	}
	return msg, time.Since(start), nil
}

type capabilityFlight struct {
	done    chan struct{}
	message *CapabilityMessage
	err     error
}

func (g *Garlic) requestCapability(peer ed25519.PublicKey) (*CapabilityMessage, error) {
	return g.requestCapabilityContext(context.Background(), peer)
}

func (g *Garlic) requestCapabilityContext(ctx context.Context, peer ed25519.PublicKey) (message *CapabilityMessage, resultErr error) {
	key := hex.EncodeToString(peer)
	ch := make(chan *CapabilityMessage, 1)
	g.mu.Lock()
	if g.capFlights == nil {
		g.capFlights = make(map[string]*capabilityFlight)
	}
	if flight := g.capFlights[key]; flight != nil {
		g.mu.Unlock()
		select {
		case <-flight.done:
			return flight.message, flight.err
		case <-g.stop:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	flight := &capabilityFlight{done: make(chan struct{})}
	g.capFlights[key] = flight
	g.pending[key] = ch
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.pending[key] == ch {
			delete(g.pending, key)
		}
		flight.message, flight.err = message, resultErr
		delete(g.capFlights, key)
		close(flight.done)
		g.mu.Unlock()
	}()

	if _, err := g.core.WriteGarlic([]byte{msgTypeCapabilityRequest}, iwt.Addr(peer)); err != nil {
		return nil, err
	}
	select {
	case msg := <-ch:
		return msg, nil
	case <-time.After(g.cfg.CapabilityTimeout):
		return nil, ErrCapabilityTimeout
	case <-g.stop:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// HopCount returns the number of mesh hops to peer, if this node has a
// cached path to it (e.g. from a prior capability query or any other
// traffic exchanged with that key) - see core.Core.GetPaths. ok is false
// if no path is cached yet; querying capability first typically resolves
// one as a side effect of the round trip.
func (g *Garlic) HopCount(peer ed25519.PublicKey) (hops int, ok bool) {
	return hopCountFromPaths(g.core.GetPaths(), peer)
}

func hopCountFromPaths(paths []core.PathEntryInfo, peer ed25519.PublicKey) (int, bool) {
	for _, p := range paths {
		if bytes.Equal(p.Key, peer) {
			return len(p.Path), true
		}
	}
	return 0, false
}

// CreateCircuit builds and tracks a new circuit over path, an ordered
// list of hops the caller has already confirmed (e.g. via
// QueryCapability) are Garlic-capable. It returns the circuit's ID, used
// with SendGarlic and CloseCircuit.
func (g *Garlic) CreateCircuit(path []CapabilityMessage, nodeKeys [][]byte) (CircuitID, error) {
	if len(path) == 0 || len(path) != len(nodeKeys) {
		return CircuitID{}, ErrInvalidPath
	}
	for i := range path {
		if !path[i].SupportsGarlicV3() {
			return CircuitID{}, ErrHopMissingGarlicV3Support
		}
	}

	ephemeralPubs := make([][]byte, len(path))
	ephemeralPrivs := make([][]byte, len(path))
	for i := range path {
		pub, priv, err := GenerateKeypair()
		if err != nil {
			return CircuitID{}, err
		}
		ephemeralPubs[i], ephemeralPrivs[i] = pub, priv
	}

	hops := make([]Hop, len(path))
	for i := range path {
		secret, err := ECDH(ephemeralPrivs[i], path[i].PublicKey)
		if err != nil {
			return CircuitID{}, err
		}
		key, err := deriveLayerKeyHopLocal(secret)
		if err != nil {
			return CircuitID{}, err
		}
		var nextEphemeral []byte
		if i+1 < len(path) {
			nextEphemeral = ephemeralPubs[i+1]
		}
		localID, err := randomCircuitID()
		if err != nil {
			return CircuitID{}, err
		}
		counterOffset, err := randomCounterOffset()
		if err != nil {
			return CircuitID{}, err
		}
		hops[i] = Hop{
			NodeKey:          nodeKeys[i],
			Key:              key,
			Counter:          counterOffset,
			NextEphemeralPub: nextEphemeral,
			LocalCircuitID:   localID,
		}
		hops[i].ReplyKey, _ = deriveReplyKey(secret)
	}

	c, err := g.circuits.Add(hops, g.cfg.CircuitLifetime, g.cfg.MaxPacketsPerCircuit, g.cfg.MaxBytesPerCircuit)
	if err != nil {
		return CircuitID{}, err
	}

	g.mu.Lock()
	g.originEphemeral[c.ID] = ephemeralPubs[0]
	g.mu.Unlock()
	return c.ID, nil
}

// CloseCircuit closes and stops tracking id.
func (g *Garlic) CloseCircuit(id CircuitID) {
	if g.duplex != nil {
		g.duplex.forget(id)
	}
	g.circuits.Close(id)
	g.mu.Lock()
	delete(g.originEphemeral, id)
	g.mu.Unlock()
}

// CreateCircuitPool builds len(paths) independent circuits (paths[i]/
// nodeKeys[i] passed to CreateCircuit exactly as if called separately -
// they need not share any hops) and groups them under one PoolID for
// SendGarlicMultipath. If any path fails to build, every circuit already
// created for this pool is closed and the error is returned - a pool is
// all-or-nothing, never partially built.
func (g *Garlic) CreateCircuitPool(paths [][]CapabilityMessage, nodeKeys [][][]byte) (PoolID, error) {
	if len(paths) == 0 || len(paths) != len(nodeKeys) {
		return 0, ErrEmptyPool
	}
	circuits := make([]CircuitID, 0, len(paths))
	for i := range paths {
		id, err := g.CreateCircuit(paths[i], nodeKeys[i])
		if err != nil {
			for _, c := range circuits {
				g.CloseCircuit(c)
			}
			return 0, err
		}
		circuits = append(circuits, id)
	}

	poolID, err := randomPoolID()
	if err != nil {
		for _, c := range circuits {
			g.CloseCircuit(c)
		}
		return 0, err
	}
	g.mu.Lock()
	g.pools[poolID] = newCircuitPool(circuits)
	g.mu.Unlock()
	return poolID, nil
}

// ClosePool closes every circuit in pool and stops tracking it.
func (g *Garlic) ClosePool(pool PoolID) {
	g.mu.Lock()
	p, ok := g.pools[pool]
	delete(g.pools, pool)
	g.mu.Unlock()
	if !ok {
		return
	}
	for _, id := range p.all() {
		g.CloseCircuit(id)
	}
}

// SendGarlicMultipath sends payload over the next circuit in pool
// (round-robin), so consecutive calls spread traffic across every path
// in the pool rather than concentrating it on one - see multipath.go's
// doc comment for why this matters against a Sybil or traffic-
// correlation adversary who doesn't control every path.
func (g *Garlic) SendGarlicMultipath(pool PoolID, payload []byte) error {
	g.mu.Lock()
	p, ok := g.pools[pool]
	g.mu.Unlock()
	if !ok {
		return ErrPoolNotFound
	}
	id, ok := p.nextCircuit()
	if !ok {
		return ErrPoolNotFound
	}
	return g.SendGarlic(id, payload)
}

// SendGarlic seals payload as one packet over the circuit id (previously
// created with CreateCircuit) and hands it to the jitter scheduler for
// transmission. A returned nil error means the packet was successfully
// sealed and queued (or sent immediately, if Config.JitterEnabled is
// false) - not that the first hop has received it, since
// Config.JitterEnabled delays the actual send.
func (g *Garlic) SendGarlic(id CircuitID, payload []byte) error {
	c, ok := g.circuits.Get(id)
	if !ok {
		return ErrCircuitNotFound
	}
	g.mu.Lock()
	ephemeralPub := g.originEphemeral[id]
	g.mu.Unlock()
	if ephemeralPub == nil {
		return ErrCircuitNotFound
	}

	onion, firstHop, legID, counter, expiration, err := c.SealHopLocal(payload, g.cfg.PacketTTL)
	if err != nil {
		return err
	}
	msg, err := buildCircuitDataMessageHopLocal(ephemeralPub, legID, counter, expiration, onion, g.cfg)
	if err != nil {
		return err
	}

	g.sendCircuitData(msg, iwt.Addr(firstHop))
	return nil
}

// SendGarlicMaxCoverMessages bounds the coverCount parameter to
// SendGarlicBundled, leaving room in the same MaxBundleMessages limit
// Bundle.Marshal itself enforces (see bundle.go) for the one real
// message every call also includes.
const SendGarlicMaxCoverMessages = MaxBundleMessages - 1

// SendGarlicBundled behaves like SendGarlic, but sends the real
// circuitData alongside coverCount cover entries (random bytes, sized
// like a real entry) in one Bundle - see processCircuitDataBundle's doc
// comment for why an observer, or even the receiving hop itself before
// it attempts decryption, cannot tell which bundled entry (if any) is
// real. coverCount is clamped to SendGarlicMaxCoverMessages.
func (g *Garlic) SendGarlicBundled(id CircuitID, payload []byte, coverCount int) error {
	if coverCount > SendGarlicMaxCoverMessages {
		coverCount = SendGarlicMaxCoverMessages
	}
	if coverCount < 0 {
		coverCount = 0
	}

	c, ok := g.circuits.Get(id)
	if !ok {
		return ErrCircuitNotFound
	}
	g.mu.Lock()
	ephemeralPub := g.originEphemeral[id]
	g.mu.Unlock()
	if ephemeralPub == nil {
		return ErrCircuitNotFound
	}

	onion, firstHop, legID, counter, expiration, err := c.SealHopLocal(payload, g.cfg.PacketTTL)
	if err != nil {
		return err
	}
	realEntry, err := buildCircuitDataBodyHopLocal(ephemeralPub, legID, counter, expiration, onion, g.cfg)
	if err != nil {
		return err
	}

	bundle := &Bundle{Messages: [][]byte{realEntry}}
	for range coverCount {
		if err := bundle.AddCoverMessage(len(realEntry)); err != nil {
			break // a full/oversized bundle still sends the real entry alone
		}
	}
	if err := shuffleBundleMessages(bundle); err != nil {
		return err
	}
	body, err := bundle.Marshal()
	if err != nil {
		return err
	}

	g.sendCircuitData(append([]byte{msgTypeCircuitDataBundle}, body...), iwt.Addr(firstHop))
	return nil
}

// buildCircuitDataMessage assembles the wire message for one circuitData
// packet: msgTypeCircuitData || ephemeralPub || Envelope. It performs no
// I/O, so it's testable without a running core.Core - see protocol.go's
// doc comment on why the pure/I/O split matters here. If cfg.PaddingEnabled,
// the envelope's wire size is independently re-randomized per call (see
// Envelope.PadToRandomRange); a padding failure (e.g. misconfigured
// Min/MaxPaddedSize) degrades to unpadded rather than failing the send.
func buildCircuitDataMessage(ephemeralPub []byte, id CircuitID, counter, expiration uint64, onion []byte, cfg Config) ([]byte, error) {
	body, err := buildCircuitDataBody(ephemeralPub, id, counter, expiration, onion, cfg)
	if err != nil {
		return nil, err
	}
	return append([]byte{msgTypeCircuitData}, body...), nil
}

// buildCircuitDataBody builds a circuitData message body - ephemeralPub
// || Envelope - without the leading msgTypeCircuitData byte. This is the
// exact shape processCircuitData (and, by extension, a Bundle entry in a
// msgTypeCircuitDataBundle message - see processCircuitDataBundle)
// expects; buildCircuitDataMessage is this plus the type byte, for a
// standalone (non-bundled) send.
func buildCircuitDataBody(ephemeralPub []byte, id CircuitID, counter, expiration uint64, onion []byte, cfg Config) ([]byte, error) {
	env := &Envelope{
		Version:       EnvelopeVersion1,
		CircuitID:     id,
		PacketCounter: counter,
		Expiration:    expiration,
		Body:          onion,
	}
	if cfg.PaddingEnabled {
		_ = env.PadToRandomRange(cfg.MinPaddedSize, cfg.MaxPaddedSize)
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(ephemeralPub)+len(envBytes))
	body = append(body, ephemeralPub...)
	body = append(body, envBytes...)
	return body, nil
}

// RecvGarlic waits up to timeout for the next payload delivered to this
// node as a circuit's final hop.
func (g *Garlic) RecvGarlic(timeout time.Duration) (*DeliveredMessage, error) {
	select {
	case m := <-g.delivered:
		return &m, nil
	case <-time.After(timeout):
		return nil, ErrRecvTimeout
	}
}

// sendAutoPayload seals a kind-tagged payload (see autoPayloadKindReal/
// autoPayloadKindCover) over circuit id and sends it as
// msgTypeCircuitDataV3 - the shared plumbing behind both SendGarlicAuto
// and the cover-traffic scheduler (Task 11). Mirrors SendGarlic's shape
// exactly except for the tag byte and the V3 outer type.
func (g *Garlic) sendAutoPayload(id CircuitID, kind byte, payload []byte) error {
	c, ok := g.circuits.Get(id)
	if !ok {
		return ErrCircuitNotFound
	}
	g.mu.Lock()
	ephemeralPub := g.originEphemeral[id]
	g.mu.Unlock()
	if ephemeralPub == nil {
		return ErrCircuitNotFound
	}

	tagged := make([]byte, 0, 1+len(payload))
	tagged = append(tagged, kind)
	tagged = append(tagged, payload...)

	onion, firstHop, legID, counter, expiration, err := c.SealHopLocal(tagged, g.cfg.PacketTTL)
	if err != nil {
		return err
	}
	body, err := buildCircuitDataBodyHopLocal(ephemeralPub, legID, counter, expiration, onion, g.cfg)
	if err != nil {
		return err
	}

	g.sendCircuitData(append([]byte{msgTypeCircuitDataV3}, body...), iwt.Addr(firstHop))
	return nil
}

// SendGarlicAuto sends a real application payload over an auto-pool
// circuit (previously created with AutoCreateCircuit). Delivered on the
// remote end via RecvGarlicAuto/g.autoDelivered - never the plain
// SendGarlic/RecvGarlic path, even if the same circuit ID were somehow
// reused (it can't be - auto-pool and manual circuits are never the
// same CircuitManager entry shared between the two APIs).
func (g *Garlic) SendGarlicAuto(id CircuitID, payload []byte) error {
	return g.sendAutoPayload(id, autoPayloadKindReal, payload)
}

// RecvGarlicAuto waits up to timeout for the next real (non-cover)
// payload delivered to this node as an auto-pool circuit's final hop.
func (g *Garlic) RecvGarlicAuto(timeout time.Duration) (*AutoDeliveredMessage, error) {
	select {
	case m := <-g.autoDelivered:
		return &m, nil
	case <-time.After(timeout):
		return nil, ErrRecvTimeout
	}
}

// PublishService signs and advertises this node's identity as reachable
// at introPoints for serviceID, returning the resulting GID. The
// descriptor is signed with this node's Garlic signing identity
// (Identity.SigningPrivateKey), never the X25519 circuit-hop key.
func (g *Garlic) PublishService(serviceID []byte, introPoints []IntroPoint, ttl time.Duration) (GID, error) {
	gid := ComputeGID(g.identity.SigningPublicKey, serviceID)
	now := uint64(time.Now().Unix())
	descriptor, err := SignServiceDescriptor(g.identity.SigningPublicKey, g.identity.SigningPrivateKey, serviceID, introPoints, now, now+uint64(ttl.Seconds()))
	if err != nil {
		return GID{}, err
	}
	if err := g.rendezvous.Publish(gid, descriptor); err != nil {
		return GID{}, err
	}
	return gid, nil
}

// LookupService returns the currently-published introduction points for
// gid, after verifying the descriptor the rendezvous returned actually
// matches gid, is validly signed, and is not expired (VerifyServiceDescriptor)
// - a malicious or buggy rendezvous cannot make this return
// attacker-controlled introduction points for a GID it doesn't hold the
// signing key for.
func (g *Garlic) LookupService(gid GID) ([]IntroPoint, error) {
	descriptor, err := g.rendezvous.Lookup(gid)
	if err != nil {
		return nil, err
	}
	if err := VerifyServiceDescriptor(descriptor, gid, uint64(time.Now().Unix())); err != nil {
		return nil, err
	}
	return descriptor.IntroPoints, nil
}

// Stats is a point-in-time summary of this node's Garlic circuit
// activity - live counts and cumulative traffic totals across
// currently-tracked circuits, plus the local-only security counters.
// Computed on demand from the same live circuit/relay tables GetStats
// always read - not a separately-maintained running total, so there's
// only one place this data can drift from reality.
type Stats struct {
	OriginatedCircuits int
	RelayedCircuits    int
	OriginatedPackets  uint64
	OriginatedBytes    uint64
	RelayedPackets     uint64
	RelayedBytes       uint64
	Security           SecurityCounterSnapshot
}

func (g *Garlic) GetStats() Stats {
	circuits := g.circuits.List()
	var origPackets, origBytes uint64
	for _, c := range circuits {
		p, b := c.TrafficStats()
		origPackets += p
		origBytes += b
	}

	relayed := g.relayState.snapshot()
	var relPackets, relBytes uint64
	for _, r := range relayed {
		relPackets += r.PacketsRelayed
		relBytes += r.BytesRelayed
	}

	return Stats{
		OriginatedCircuits: len(circuits),
		RelayedCircuits:    len(relayed),
		OriginatedPackets:  origPackets,
		OriginatedBytes:    origBytes,
		RelayedPackets:     relPackets,
		RelayedBytes:       relBytes,
		Security:           g.security.snapshot(),
	}
}

// OriginatedCircuits returns a snapshot of every circuit this node has
// originated (built itself, as opposed to relaying for someone else).
func (g *Garlic) OriginatedCircuits() []*Circuit {
	return g.circuits.List()
}
