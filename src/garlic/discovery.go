package garlic

// Discovery: gossip of known Garlic-capable peers, so a node can find
// candidates it has never directly queried, without any non-Garlic party
// ever seeing the exchange. This works entirely over the existing
// typeSessionGarlic channel (msgTypeAnnounce, handled the same way as
// every other Garlic message type) - a node that never runs src/garlic
// cannot construct, send, or even parse an announce message, so
// "only Garlic nodes discover Garlic nodes" holds by construction, the
// same way capability negotiation already does. It does not (and
// cannot) prevent a party that already knows a specific node's key from
// probing whether *that* key answers capability requests - that
// probeability is inherent to having an unauthenticated capability
// handshake at all, and is a separate concern from discovering
// previously-unknown nodes. See docs/garlic-architecture.md's
// discovery discussion for that distinction.

import (
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"sync"
	"time"
)

const (
	maxAnnouncePeers = 32
)

var (
	ErrTooManyAnnouncePeers = errors.New("garlic: too many announced peers")
	ErrAnnounceKeyTooLarge  = errors.New("garlic: announced relay info too large")
	ErrAnnounceTruncated    = errors.New("garlic: announce message truncated")
)

// AnnouncePeer is one entry in an AnnounceMessage: a relay's signed
// RelayInfo (see relayinfo.go). Every entry is verified against the
// relay's own node key before it is used, so a gossiping peer can withhold
// relays but cannot forge or alter their onion keys.
type AnnouncePeer struct {
	RelayInfo []byte
}

// AnnounceMessage is the body of a msgTypeAnnounce message: a bounded
// list of relays the sender knows about.
type AnnounceMessage struct {
	Peers []AnnouncePeer
}

// Marshal encodes the message as count(4) followed by, per peer,
// info_len(2)+bytes.
func (m *AnnounceMessage) Marshal() ([]byte, error) {
	if len(m.Peers) > maxAnnouncePeers {
		return nil, ErrTooManyAnnouncePeers
	}
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(m.Peers)))
	for _, p := range m.Peers {
		if len(p.RelayInfo) > maxRelayInfoSize {
			return nil, ErrAnnounceKeyTooLarge
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.RelayInfo)))
		buf = append(buf, p.RelayInfo...)
	}
	return buf, nil
}

// UnmarshalAnnounceMessage decodes a message produced by Marshal, never
// trusting a declared count or length before validating it against both
// the configured maximum and the bytes actually remaining.
func UnmarshalAnnounceMessage(data []byte) (*AnnounceMessage, error) {
	if len(data) < 4 {
		return nil, ErrAnnounceTruncated
	}
	count := binary.BigEndian.Uint32(data[:4])
	if count > maxAnnouncePeers {
		return nil, ErrTooManyAnnouncePeers
	}
	rest := data[4:]
	peers := make([]AnnouncePeer, 0, count)
	for range count {
		if len(rest) < 2 {
			return nil, ErrAnnounceTruncated
		}
		n := int(binary.BigEndian.Uint16(rest[:2]))
		rest = rest[2:]
		if n > maxRelayInfoSize {
			return nil, ErrAnnounceKeyTooLarge
		}
		if n > len(rest) {
			return nil, ErrAnnounceTruncated
		}
		peers = append(peers, AnnouncePeer{RelayInfo: append([]byte(nil), rest[:n]...)})
		rest = rest[n:]
	}
	return &AnnounceMessage{Peers: peers}, nil
}

// DiscoveredPeer is one entry in a discoveryRegistry.
type DiscoveredPeer struct {
	NodeKey         []byte
	GarlicPublicKey []byte
	LastSeen        time.Time
	// SelfVerified is true iff this node itself completed a capability
	// handshake with this peer (handleCapabilityResponse), as opposed to
	// only ever hearing about it secondhand via gossip (processAnnounce).
	// Never downgraded by record() once true - see its doc comment.
	SelfVerified bool
	// ExpiresAt is when the relay deletes the onion key in RelayInfo.
	ExpiresAt time.Time
	// RelayInfo is the relay's signed self-description, re-shared in gossip.
	RelayInfo []byte
}

// discoveryRegistry is the bounded set of Garlic peers this node has
// learned about, directly (a successful capability query) or indirectly
// (gossiped to it by another peer). Capacity-bounded like every other
// remote-input-driven collection in this package: recording a new peer
// once at capacity evicts the least-recently-seen entry rather than
// growing without bound.
type discoveryRegistry struct {
	mu      sync.Mutex
	max     int
	selfKey string
	peers   map[string]DiscoveredPeer
}

// newDiscoveryRegistry returns an empty registry bounded to max entries.
// selfKey is this node's own Yggdrasil node key (core.Core.PublicKey()) -
// record() silently drops any entry keyed by it, since a node's own key
// gossiped back to it (a stale echo from a peer that cached this node's
// pre-restart Garlic identity, or any other reflection) is never a
// legitimate distinct circuit-hop candidate. nil/empty is fine for tests
// that don't exercise self-filtering.
func newDiscoveryRegistry(max int, selfKey []byte) *discoveryRegistry {
	return &discoveryRegistry{max: max, selfKey: string(selfKey), peers: make(map[string]DiscoveredPeer)}
}

// record adds or refreshes a peer's entry, stamping LastSeen as now. A
// peer keyed by this registry's own selfKey is silently dropped - see
// newDiscoveryRegistry's doc comment. SelfVerified is never downgraded:
// once a peer has been personally capability-verified, a later
// secondhand gossip mention of the same key still leaves it marked
// self-verified.
func (r *discoveryRegistry) record(p DiscoveredPeer) {
	key := string(p.NodeKey)
	if r.selfKey != "" && key == r.selfKey {
		return
	}
	p.LastSeen = time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	existing, exists := r.peers[key]
	if !exists && len(r.peers) >= r.max {
		r.evictOldestLocked()
	}
	if exists && existing.SelfVerified {
		p.SelfVerified = true
	}
	// Never replace newer relay information with an older copy.
	if exists && existing.ExpiresAt.After(p.ExpiresAt) {
		p.ExpiresAt, p.RelayInfo, p.GarlicPublicKey = existing.ExpiresAt, existing.RelayInfo, existing.GarlicPublicKey
	}
	r.peers[key] = p
}

func (r *discoveryRegistry) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, p := range r.peers {
		if first || p.LastSeen.Before(oldestTime) {
			oldestKey, oldestTime, first = k, p.LastSeen, false
		}
	}
	if !first {
		delete(r.peers, oldestKey)
	}
}

// list returns every currently-tracked peer whose relay information has
// not expired; expired entries are dropped.
func (r *discoveryRegistry) list() []DiscoveredPeer {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	out := make([]DiscoveredPeer, 0, len(r.peers))
	for k, p := range r.peers {
		if !p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt) {
			delete(r.peers, k)
			continue
		}
		out = append(out, p)
	}
	return out
}

// sample returns up to n random peers (all of them, if fewer than n are
// known).
func (r *discoveryRegistry) sample(n int) []DiscoveredPeer {
	all := r.list()
	mrand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	if n >= len(all) {
		return all
	}
	return all[:n]
}
