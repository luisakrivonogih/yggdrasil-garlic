package garlic

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestAnnounceMessageMarshalUnmarshalRoundTrip(t *testing.T) {
	msg := &AnnounceMessage{Peers: []AnnouncePeer{
		{RelayInfo: newTestRelay(t).info(t, nil, time.Hour)},
		{RelayInfo: newTestRelay(t).info(t, nil, time.Hour)},
	}}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	got, err := UnmarshalAnnounceMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalAnnounceMessage returned error: %v", err)
	}
	if len(got.Peers) != len(msg.Peers) {
		t.Fatalf("got %d peers, want %d", len(got.Peers), len(msg.Peers))
	}
	for i := range msg.Peers {
		if !bytes.Equal(got.Peers[i].RelayInfo, msg.Peers[i].RelayInfo) {
			t.Errorf("peer %d RelayInfo differs after round trip", i)
		}
	}
}

func TestAnnounceMessageMarshalEmpty(t *testing.T) {
	msg := &AnnounceMessage{}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	got, err := UnmarshalAnnounceMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalAnnounceMessage returned error: %v", err)
	}
	if len(got.Peers) != 0 {
		t.Fatalf("got %d peers, want 0", len(got.Peers))
	}
}

func TestAnnounceMessageMarshalRejectsTooManyPeers(t *testing.T) {
	msg := &AnnounceMessage{Peers: make([]AnnouncePeer, maxAnnouncePeers+1)}
	if _, err := msg.Marshal(); err == nil {
		t.Fatal("expected error for too many peers, got nil")
	}
}

func TestAnnounceMessageMarshalRejectsOversizedKey(t *testing.T) {
	msg := &AnnounceMessage{Peers: []AnnouncePeer{{RelayInfo: make([]byte, maxRelayInfoSize+1)}}}
	if _, err := msg.Marshal(); err == nil {
		t.Fatal("expected error for oversized node key, got nil")
	}
}

func TestUnmarshalAnnounceMessageRejectsTruncated(t *testing.T) {
	if _, err := UnmarshalAnnounceMessage([]byte{2}); err == nil {
		t.Fatal("expected error for truncated announce, got nil")
	}
}

func TestUnmarshalAnnounceMessageRejectsCountExceedingMax(t *testing.T) {
	var data []byte
	data = binary.BigEndian.AppendUint32(data, 0xFFFFFFFF)
	if _, err := UnmarshalAnnounceMessage(data); err == nil {
		t.Fatal("expected error for count exceeding maxAnnouncePeers, got nil")
	}
}

func TestUnmarshalAnnounceMessageRejectsLengthExceedingBuffer(t *testing.T) {
	var data []byte
	data = binary.BigEndian.AppendUint32(data, 1)
	data = binary.BigEndian.AppendUint16(data, 200) // info_len claims 200 bytes that aren't there
	if _, err := UnmarshalAnnounceMessage(data); err == nil {
		t.Fatal("expected error for key length exceeding buffer, got nil")
	}
}

func TestDiscoveryRegistryRecordAndList(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga")})
	r.record(DiscoveredPeer{NodeKey: []byte("b"), GarlicPublicKey: []byte("gb")})

	peers := r.list()
	if len(peers) != 2 {
		t.Fatalf("list() returned %d peers, want 2", len(peers))
	}
}

func TestDiscoveryRegistryRecordUpdatesExisting(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga-old")})
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga-new")})

	peers := r.list()
	if len(peers) != 1 {
		t.Fatalf("list() returned %d peers, want 1 (same NodeKey should update, not duplicate)", len(peers))
	}
	if string(peers[0].GarlicPublicKey) != "ga-new" {
		t.Fatalf("GarlicPublicKey = %q, want %q", peers[0].GarlicPublicKey, "ga-new")
	}
}

func TestDiscoveryRegistryEvictsOldestWhenFull(t *testing.T) {
	r := newDiscoveryRegistry(2, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("old"), GarlicPublicKey: []byte("g")})
	// Force a distinguishable LastSeen ordering.
	time.Sleep(2 * time.Millisecond)
	r.record(DiscoveredPeer{NodeKey: []byte("newer"), GarlicPublicKey: []byte("g")})
	time.Sleep(2 * time.Millisecond)
	r.record(DiscoveredPeer{NodeKey: []byte("newest"), GarlicPublicKey: []byte("g")}) // should evict "old"

	peers := r.list()
	if len(peers) != 2 {
		t.Fatalf("list() returned %d peers, want 2 (capacity bound)", len(peers))
	}
	for _, p := range peers {
		if string(p.NodeKey) == "old" {
			t.Fatal("oldest entry was not evicted when registry was full")
		}
	}
}

func TestDiscoveryRegistrySampleBounded(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	for i := range 10 {
		r.record(DiscoveredPeer{NodeKey: []byte{byte(i)}, GarlicPublicKey: []byte("g")})
	}
	sample := r.sample(3)
	if len(sample) != 3 {
		t.Fatalf("sample(3) returned %d peers, want 3", len(sample))
	}
}

func TestDiscoveryRegistrySampleCappedByAvailable(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("g")})
	sample := r.sample(5)
	if len(sample) != 1 {
		t.Fatalf("sample(5) returned %d peers, want 1 (only one recorded)", len(sample))
	}
}

func TestDiscoveryRegistryRecordSelfVerifiedDefaultsFalse(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga")})

	peers := r.list()
	if len(peers) != 1 || peers[0].SelfVerified {
		t.Fatalf("SelfVerified = %v, want false for a plain gossip-recorded entry", peers[0].SelfVerified)
	}
}

func TestDiscoveryRegistryRecordSelfVerifiedTrue(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga"), SelfVerified: true})

	peers := r.list()
	if len(peers) != 1 || !peers[0].SelfVerified {
		t.Fatalf("SelfVerified = %v, want true", peers[0].SelfVerified)
	}
}

func TestDiscoveryRegistryRecordNeverDowngradesSelfVerified(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga"), SelfVerified: true})
	// A later gossip mention of the same key, unverified by us directly.
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga-refreshed"), SelfVerified: false})

	peers := r.list()
	if len(peers) != 1 {
		t.Fatalf("list() returned %d peers, want 1", len(peers))
	}
	if !peers[0].SelfVerified {
		t.Fatal("a later gossip-sourced record downgraded an existing self-verified entry, want it to stay true")
	}
	if string(peers[0].GarlicPublicKey) != "ga-refreshed" {
		t.Fatalf("GarlicPublicKey = %q, want %q (other fields still refresh)", peers[0].GarlicPublicKey, "ga-refreshed")
	}
}

// TestDiscoveryRegistryRecordDropsSelfKey is the regression test for a
// live-network finding: a node's own Yggdrasil node key can come back to
// it through gossip (msgTypeAnnounce) or a capability response - e.g.
// another peer still holding a stale AnnouncePeer entry for this node
// from before its own Garlic identity churned across a restart (Garlic
// keys are ephemeral unless Garlic.PrivateKey is configured). Recording
// that entry would let this node select itself as one of its own
// "diverse" circuit hops. selfKey must be dropped, not merely
// deduplicated.
func TestDiscoveryRegistryRecordDropsSelfKey(t *testing.T) {
	r := newDiscoveryRegistry(16, []byte("self"))
	r.record(DiscoveredPeer{NodeKey: []byte("self"), GarlicPublicKey: []byte("stale-garlic-key")})
	r.record(DiscoveredPeer{NodeKey: []byte("other"), GarlicPublicKey: []byte("g")})

	peers := r.list()
	if len(peers) != 1 {
		t.Fatalf("list() returned %d peers, want 1 (self-keyed entry must be dropped)", len(peers))
	}
	if string(peers[0].NodeKey) != "other" {
		t.Fatalf("list()[0].NodeKey = %q, want %q", peers[0].NodeKey, "other")
	}
}

// TestDiscoveryRegistryRecordWithoutSelfKeyDoesNotFilter guards against
// an over-eager fix: an empty/unset selfKey (nil, as in every other test
// in this file, and as a fresh registry would have before New() learns
// its core.Core's public key) must not accidentally match and drop
// legitimately empty-keyed input - it must simply not filter at all.
func TestDiscoveryRegistryRecordWithoutSelfKeyDoesNotFilter(t *testing.T) {
	r := newDiscoveryRegistry(16, nil)
	r.record(DiscoveredPeer{NodeKey: []byte("a"), GarlicPublicKey: []byte("ga")})

	peers := r.list()
	if len(peers) != 1 {
		t.Fatalf("list() returned %d peers, want 1", len(peers))
	}
}
