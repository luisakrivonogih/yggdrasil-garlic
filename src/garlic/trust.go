package garlic

// Hidden mode, trusted peers and path construction.
//
// Hidden (client) mode, the default for the daemon, is the Garlic analogue
// of I2P's hidden mode: the node never answers capability or gossip
// requests, never relays or terminates anyone else's circuits, holds no
// onion key and never stores directory records. To any other node it looks
// exactly like a node that does not run Garlic at all. Only its trusted
// peers - which it contacts itself - learn that it uses Garlic.
//
// Relay mode is for public infrastructure (servers): it advertises a signed
// RelayInfo, gossips, relays circuits and serves the directory. Hosting
// sites on a relay is refused unless explicitly allowed, because a
// publicly listed relay's uptime would be linkable to the site's uptime.
//
// Path construction (buildPath) follows three rules in every mode:
//
//  1. The first hop (guard) is always a trusted peer, and the same guard is
//     kept for as long as it keeps working.
//  2. Every other hop is chosen only from verified RelayInfo already held
//     locally (gossip, directory referrals, site descriptors). Those hops
//     are never contacted directly, so none of them learns this node's key.
//  3. The guard is never the circuit's terminal hop.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

var (
	ErrHiddenMode          = errors.New("garlic: this node runs in hidden (client) mode and is not a relay")
	ErrNoTrustedPeers      = errors.New("garlic: no trusted Garlic peers configured - add one with addGarlicPeer or Garlic.TrustedPeers")
	ErrNoTrustedGuard      = errors.New("garlic: none of the trusted Garlic peers is reachable as a first hop")
	ErrUnknownRelay        = errors.New("garlic: no verified relay information for this hop")
	ErrUntrustedFirstHop   = errors.New("garlic: the first hop of a circuit must be a trusted peer")
	ErrServiceOnRelay      = errors.New("garlic: refusing to host a site on a public relay (it would link the site to this node); use Mode \"client\" or set AllowServicesOnRelay")
	ErrInvalidTrustedPeer  = errors.New("garlic: trusted peer key must be 32 bytes (the node's Yggdrasil public key from getSelf)")
	ErrTrustedPeerIsGarlic = errors.New("garlic: that is a Garlic onion key, not a node key - use the \"Public key\" from yggdrasilctl getSelf")
)

func needSites(c *CapabilityMessage) bool {
	return c.SupportsGarlicV3() && slices.Contains(c.Versions, CapabilitySites)
}

func needAuto(c *CapabilityMessage) bool {
	return c.SupportsGarlicV3() && c.SupportsAutoCircuit()
}

// supportedVersions lists the capabilities a relay advertises.
func supportedVersions() []string {
	return []string{CapabilityGarlicV2, CapabilityGarlicV3, CapabilityAutoCircuit, CapabilitySites}
}

// cachedRelay is a verified RelayInfo held locally.
type cachedRelay struct {
	capability  *CapabilityMessage
	raw         []byte
	publishedAt uint64
	expiresAt   uint64
}

// selfRelayInfo returns this node's current signed RelayInfo. It fails in
// hidden mode.
func (g *Garlic) selfRelayInfo() ([]byte, *RelayInfo, error) {
	if g.cfg.Hidden || g.onion == nil || g.core == nil {
		return nil, nil, ErrHiddenMode
	}
	key, err := g.onion.current()
	if err != nil {
		return nil, nil, err
	}
	g.selfInfoMu.Lock()
	defer g.selfInfoMu.Unlock()
	if g.selfInfo != nil && bytes.Equal(g.selfInfo.Capability.PublicKey, key.public) {
		return g.selfInfoRaw, g.selfInfo, nil
	}
	info := &RelayInfo{
		NodeKey:     bytes.Clone(g.core.PublicKey()),
		Capability:  CapabilityMessage{Versions: supportedVersions(), PublicKey: bytes.Clone(key.public)},
		PublishedAt: uint64(key.created.Unix()),
		ExpiresAt:   uint64(key.expires.Unix()),
	}
	if err := signRelayInfo(g.core, info); err != nil {
		return nil, nil, err
	}
	raw, err := info.Marshal()
	if err != nil {
		return nil, nil, err
	}
	g.selfInfo, g.selfInfoRaw = info, raw
	return raw, info, nil
}

// rememberRelay stores a verified RelayInfo, keeping the newest one per
// node, and records the node as a discovery candidate.
func (g *Garlic) rememberRelay(info *RelayInfo, raw []byte, selfVerified bool) {
	if g.core != nil && bytes.Equal(info.NodeKey, g.core.PublicKey()) {
		return
	}
	key := hex.EncodeToString(info.NodeKey)
	capability := &CapabilityMessage{Versions: slices.Clone(info.Capability.Versions), PublicKey: bytes.Clone(info.Capability.PublicKey)}
	g.mu.Lock()
	old := g.capabilityCache[key]
	if old == nil || info.PublishedAt >= old.publishedAt || !time.Now().Before(g.usableUntil(old.expiresAt)) {
		g.capabilityCache[key] = &cachedRelay{capability: capability, raw: bytes.Clone(raw), publishedAt: info.PublishedAt, expiresAt: info.ExpiresAt}
	}
	g.mu.Unlock()
	if info.Capability.SupportsGarlicV2() {
		g.discovery.record(DiscoveredPeer{
			NodeKey:         bytes.Clone(info.NodeKey),
			GarlicPublicKey: bytes.Clone(info.Capability.PublicKey),
			SelfVerified:    selfVerified,
			ExpiresAt:       time.Unix(int64(info.ExpiresAt), 0),
			RelayInfo:       bytes.Clone(raw),
		})
	}
}

// learnRelayInfo verifies raw (which must belong to node, if node is not
// nil) and remembers it. Used for relay information carried by site
// descriptors and directory referrals.
func (g *Garlic) learnRelayInfo(raw []byte, node []byte) (*RelayInfo, error) {
	info, err := parseVerifiedRelayInfo(raw, node)
	if err != nil {
		return nil, err
	}
	g.rememberRelay(info, raw, false)
	return info, nil
}

// knownRelay returns locally held, still-usable relay information for key,
// without any network traffic.
func (g *Garlic) knownRelay(key []byte) (*CapabilityMessage, bool) {
	if g.core != nil && bytes.Equal(key, g.core.PublicKey()) {
		_, info, err := g.selfRelayInfo()
		if err != nil {
			return nil, false
		}
		return &info.Capability, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.capabilityCache[hex.EncodeToString(key)]
	if c == nil || !time.Now().Before(g.usableUntil(c.expiresAt)) {
		return nil, false
	}
	return c.capability, true
}

// relayInfoRaw returns the signed RelayInfo bytes held for key (including
// this node's own, in relay mode).
func (g *Garlic) relayInfoRaw(key []byte) []byte {
	if g.core != nil && bytes.Equal(key, g.core.PublicKey()) {
		raw, _, err := g.selfRelayInfo()
		if err != nil {
			return nil
		}
		return raw
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.capabilityCache[hex.EncodeToString(key)]
	if c == nil || !time.Now().Before(g.usableUntil(c.expiresAt)) {
		return nil
	}
	return bytes.Clone(c.raw)
}

// parseTrustedKey validates a hex node key for the trusted set.
func (g *Garlic) parseTrustedKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalidTrustedPeer
	}
	if g.onion != nil {
		if cur, err := g.onion.current(); err == nil && bytes.Equal(cur.public, key) {
			return nil, ErrTrustedPeerIsGarlic
		}
	}
	g.mu.Lock()
	for _, c := range g.capabilityCache {
		if bytes.Equal(c.capability.PublicKey, key) {
			g.mu.Unlock()
			return nil, ErrTrustedPeerIsGarlic
		}
	}
	g.mu.Unlock()
	return key, nil
}

// trustedPeerKeys returns the current trusted set: configured and
// runtime-added keys, plus (with TrustOutboundPeers) every connected
// outbound, non-link-local mesh peer.
func (g *Garlic) trustedPeerKeys() [][]byte {
	g.trustMu.Lock()
	out := make([][]byte, 0, len(g.trusted))
	seen := make(map[string]bool, len(g.trusted))
	for k, key := range g.trusted {
		seen[k] = true
		out = append(out, bytes.Clone(key))
	}
	g.trustMu.Unlock()
	if g.cfg.TrustOutboundPeers && g.core != nil {
		for _, p := range g.core.GetPeers() {
			if !p.Up || p.Inbound || len(p.Key) != ed25519.PublicKeySize || isLinkLocalURI(p.URI) || seen[string(p.Key)] {
				continue
			}
			seen[string(p.Key)] = true
			out = append(out, bytes.Clone(p.Key))
		}
	}
	return out
}

func (g *Garlic) isTrusted(key []byte) bool {
	for _, k := range g.trustedPeerKeys() {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}

// isLinkLocalURI reports whether a peer URI points at a link-local address
// (typically a multicast-discovered LAN peer, which is not an explicit
// choice of the operator).
func isLinkLocalURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

// AddTrustedPeer verifies that key belongs to a reachable Garlic relay and
// then adds it to the runtime trusted set (the live equivalent of listing
// it in Garlic.TrustedPeers). Nothing is added if verification fails.
func (g *Garlic) AddTrustedPeer(hexKey string) ([]byte, error) {
	key, err := g.parseTrustedKey(hexKey)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < bootstrapMaxAttempts; attempt++ {
		if _, err = g.QueryCapability(key); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.Join(errors.New("garlic: the peer did not answer as a Garlic relay (is it reachable over the mesh and running in relay mode?)"), err)
	}
	g.trustMu.Lock()
	g.trusted[string(key)] = bytes.Clone(key)
	g.trustMu.Unlock()
	_ = g.RequestGossip(key)
	return key, nil
}

// RemoveTrustedPeer removes a runtime- or config-trusted key. It reports
// whether the key was present.
func (g *Garlic) RemoveTrustedPeer(hexKey string) bool {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return false
	}
	g.trustMu.Lock()
	defer g.trustMu.Unlock()
	_, ok := g.trusted[string(key)]
	delete(g.trusted, string(key))
	if bytes.Equal(g.guard, key) {
		g.guard = nil
	}
	return ok
}

// TrustedPeerKeys returns the trusted set as hex strings.
func (g *Garlic) TrustedPeerKeys() []string {
	keys := g.trustedPeerKeys()
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = hex.EncodeToString(k)
	}
	slices.Sort(out)
	return out
}

// CurrentGuard returns the trusted first hop currently in use, if any.
func (g *Garlic) CurrentGuard() []byte {
	g.trustMu.Lock()
	defer g.trustMu.Unlock()
	return bytes.Clone(g.guard)
}

// guardFor returns a trusted first hop satisfying need and not in exclude.
// The previous guard is reused while it remains usable; otherwise another
// trusted peer is chosen at random and becomes the new guard.
func (g *Garlic) guardFor(ctx context.Context, need func(*CapabilityMessage) bool, exclude [][]byte) ([]byte, *CapabilityMessage, error) {
	trusted := g.trustedPeerKeys()
	if len(trusted) == 0 {
		return nil, nil, ErrNoTrustedPeers
	}
	for i := len(trusted) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, nil, err
		}
		j := int(n.Int64())
		trusted[i], trusted[j] = trusted[j], trusted[i]
	}
	current := g.CurrentGuard()
	if current != nil {
		if i := slices.IndexFunc(trusted, func(k []byte) bool { return bytes.Equal(k, current) }); i > 0 {
			trusted[0], trusted[i] = trusted[i], trusted[0]
		}
	}
	for _, key := range trusted {
		if slices.ContainsFunc(exclude, func(e []byte) bool { return bytes.Equal(e, key) }) {
			continue
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		capability, err := g.queryCapabilityContext(ctx, key)
		if err != nil || !need(capability) {
			continue
		}
		g.trustMu.Lock()
		g.guard = bytes.Clone(key)
		g.trustMu.Unlock()
		return key, capability, nil
	}
	return nil, nil, ErrNoTrustedGuard
}

// buildPath selects an n-hop path: a trusted guard, then hops chosen only
// from locally held verified relay information, ending at terminal when
// terminal is not nil.
func (g *Garlic) buildPath(ctx context.Context, n int, terminal []byte, need func(*CapabilityMessage) bool) ([]CapabilityMessage, [][]byte, error) {
	if n < 1 || n > MaxPathLength {
		return nil, nil, ErrInvalidPath
	}
	var terminalCap *CapabilityMessage
	if terminal != nil {
		c, ok := g.knownRelay(terminal)
		if !ok {
			return nil, nil, ErrUnknownRelay
		}
		if !need(c) {
			return nil, nil, ErrHopMissingGarlicV3Support
		}
		terminalCap = c
		if n == 1 {
			if !g.isTrusted(terminal) {
				return nil, nil, ErrUntrustedFirstHop
			}
			return []CapabilityMessage{*c}, [][]byte{bytes.Clone(terminal)}, nil
		}
	}
	var exclude [][]byte
	if terminal != nil {
		exclude = append(exclude, terminal)
	}
	guardKey, guardCap, err := g.guardFor(ctx, need, exclude)
	if err != nil {
		return nil, nil, err
	}
	middles := n - 1
	if terminal != nil {
		middles = n - 2
	}
	path := []CapabilityMessage{*guardCap}
	keys := [][]byte{bytes.Clone(guardKey)}
	if middles > 0 {
		// Topological diversity (distinct tree parents) applies among the
		// randomly chosen middle hops. The guard is trusted and the
		// terminal is fixed by the caller, so neither constrains them.
		pool := g.candidatePool()
		filtered := make([]HopCandidate, 0, len(pool))
		for _, c := range pool {
			if bytes.Equal(c.NodeKey, guardKey) || (terminal != nil && bytes.Equal(c.NodeKey, terminal)) {
				continue
			}
			if capability, ok := g.knownRelay(c.NodeKey); ok && need(capability) {
				filtered = append(filtered, c)
			}
		}
		selected, err := selectDiversePathFrom(filtered, middles, g.cfg.MinHopCount, map[string]bool{})
		if err != nil {
			return nil, nil, g.explainMiddleShortage(err, filtered, middles)
		}
		for _, c := range selected {
			capability, _ := g.knownRelay(c.NodeKey)
			path = append(path, *capability)
			keys = append(keys, bytes.Clone(c.NodeKey))
		}
	}
	if terminal != nil {
		path = append(path, *terminalCap)
		keys = append(keys, bytes.Clone(terminal))
	}
	return path, keys, nil
}

// explainMiddleShortage says why no middle hop could be chosen. The usual
// cause in a small network is that every relay is a direct mesh peer of
// this node and so closer than MinHopCount.
func (g *Garlic) explainMiddleShortage(err error, pool []HopCandidate, need int) error {
	tooClose := 0
	for _, c := range pool {
		if c.HopCount < g.cfg.MinHopCount {
			tooClose++
		}
	}
	if tooClose > 0 {
		return fmt.Errorf("%w: need %d middle relay(s) at least %d mesh hops away, but %d of the %d other known relays are closer (directly peered relays cannot be middle hops: peer this node with fewer relays, or set Garlic.MinHopCount to 1)", err, need, g.cfg.MinHopCount, tooClose, len(pool))
	}
	return fmt.Errorf("%w: need %d middle relay(s) besides the first hop and the destination, %d known", err, need, len(pool))
}

// contactablePeers are the nodes this node may contact directly for
// discovery: only trusted peers in hidden mode; trusted peers plus direct
// mesh peers in relay mode (a public relay has nothing to hide from them).
func (g *Garlic) contactablePeers() [][]byte {
	keys := g.trustedPeerKeys()
	if g.cfg.Hidden || g.core == nil {
		return keys
	}
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		seen[string(k)] = true
	}
	for _, p := range g.core.GetPeers() {
		if p.Up && len(p.Key) == ed25519.PublicKeySize && !seen[string(p.Key)] {
			seen[string(p.Key)] = true
			keys = append(keys, bytes.Clone(p.Key))
		}
	}
	return keys
}

// treeDistance estimates the mesh distance between a and b from the
// spanning tree (parent links), for relays this node has never contacted
// and therefore has no cached path to.
func treeDistance(parentOf map[string][]byte, a, b []byte) (int, bool) {
	depthTo := func(k []byte) map[string]int {
		out := map[string]int{}
		cur := k
		for d := 0; d < 1024; d++ {
			if _, seen := out[string(cur)]; seen {
				return out
			}
			out[string(cur)] = d
			p, ok := parentOf[string(cur)]
			if !ok || len(p) == 0 || bytes.Equal(p, cur) {
				return out
			}
			cur = p
		}
		return out
	}
	da := depthTo(a)
	cur := b
	for d := 0; d < 1024; d++ {
		if x, ok := da[string(cur)]; ok {
			return x + d, true
		}
		p, ok := parentOf[string(cur)]
		if !ok || len(p) == 0 || bytes.Equal(p, cur) {
			return 0, false
		}
		cur = p
	}
	return 0, false
}

// trustedRefreshInterval paces hidden-mode gossip pulls from trusted peers.
const trustedRefreshInterval = 60 * time.Second
