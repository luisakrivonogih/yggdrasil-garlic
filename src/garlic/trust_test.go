package garlic

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func TestRelayInfoRoundTripAndVerify(t *testing.T) {
	r := newTestRelay(t)
	raw := r.info(t, nil, time.Hour)
	info, err := parseVerifiedRelayInfo(raw, r.nodePub)
	if err != nil {
		t.Fatalf("valid relay info rejected: %v", err)
	}
	if !bytes.Equal(info.Capability.PublicKey, r.onionPub) || !needSites(&info.Capability) {
		t.Fatal("relay info fields did not round trip")
	}
	if _, err := parseVerifiedRelayInfo(raw, newTestRelay(t).nodePub); !errors.Is(err, ErrRelayInfoWrongNode) {
		t.Fatalf("relay info accepted for a different node: %v", err)
	}
	tampered := bytes.Clone(raw)
	tampered[40] ^= 1 // inside PublishedAt
	if _, err := parseVerifiedRelayInfo(tampered, nil); !errors.Is(err, ErrRelayInfoSignature) {
		t.Fatalf("tampered relay info accepted: %v", err)
	}
	if _, err := parseVerifiedRelayInfo(r.info(t, nil, -time.Second), nil); !errors.Is(err, ErrRelayInfoExpired) {
		t.Fatalf("expired relay info accepted: %v", err)
	}
	if _, err := parseVerifiedRelayInfo(r.info(t, nil, 8*24*time.Hour), nil); !errors.Is(err, ErrRelayInfoLifetime) {
		t.Fatalf("relay info with an excessive lifetime accepted: %v", err)
	}
}

// Real relays sign RelayInfo with their Yggdrasil node key through
// core.Core.SignGarlic; hidden nodes publish nothing at all.
func TestSelfRelayInfoSignedByNodeKeyAndHiddenModeSilent(t *testing.T) {
	c := newLinkedCoreForAutoCircuitTest(t)
	defer c.Stop()
	id, _ := NewIdentity()
	g := New(c, id, DefaultConfig(), NewStaticRendezvous())
	defer g.Close()
	raw := g.processCapabilityRequest()
	info, err := parseVerifiedRelayInfo(raw, c.PublicKey())
	if err != nil {
		t.Fatalf("relay's own RelayInfo does not verify against its node key: %v", err)
	}
	if !bytes.Equal(info.Capability.PublicKey, id.PublicKey) {
		t.Fatal("RelayInfo does not advertise the current onion key")
	}
	if id.PrivateKey != nil {
		t.Fatal("initial onion private key still held outside the rotating keyring")
	}

	c2 := newLinkedCoreForAutoCircuitTest(t)
	defer c2.Stop()
	hiddenCfg := DefaultConfig()
	hiddenCfg.Hidden = true
	id2, _ := NewIdentity()
	h := New(c2, id2, hiddenCfg, NewStaticRendezvous())
	defer h.Close()
	if h.processCapabilityRequest() != nil {
		t.Fatal("hidden node produced a capability response")
	}
	if err := h.GossipAnnounce(c.PublicKey()); !errors.Is(err, ErrHiddenMode) {
		t.Fatalf("hidden node sent gossip: %v", err)
	}
	if _, err := h.StartService(ServiceConfig{LocalAddr: "127.0.0.1:1"}); err != nil {
		t.Fatalf("hidden node refused to host a site: %v", err)
	}
	if _, err := g.StartService(ServiceConfig{LocalAddr: "127.0.0.1:1"}); !errors.Is(err, ErrServiceOnRelay) {
		t.Fatalf("relay agreed to host a site: %v", err)
	}
}

// A hidden node does not answer capability queries over the mesh, so it is
// indistinguishable from a node that does not run Garlic.
func TestHiddenNodeDoesNotAnswerCapabilityQueries(t *testing.T) {
	a := newLinkedCoreForAutoCircuitTest(t)
	defer a.Stop()
	b := newLinkedCoreForAutoCircuitTest(t)
	defer b.Stop()
	listenURL, _ := url.Parse("tcp://localhost:0")
	l, err := a.Listen(listenURL, "")
	if err != nil {
		t.Fatal(err)
	}
	peerURL, _ := url.Parse("tcp://" + l.Addr().String())
	if err := b.CallPeer(peerURL, ""); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*core.Core{a, b} {
		go func(n *core.Core) {
			buf := make([]byte, 65535)
			for {
				if _, _, err := n.ReadFrom(buf); err != nil {
					return
				}
			}
		}(n)
	}
	cfg := DefaultConfig()
	cfg.CapabilityTimeout = time.Second
	idA, _ := NewIdentity()
	gA := New(a, idA, cfg, NewStaticRendezvous())
	defer gA.Close()
	hidden := cfg
	hidden.Hidden = true
	idB, _ := NewIdentity()
	gB := New(b, idB, hidden, NewStaticRendezvous())
	defer gB.Close()
	// The hidden node can still query the relay.
	var ok bool
	for range 5 {
		if _, err := gB.QueryCapability(a.PublicKey()); err == nil {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatal("hidden node could not query a relay")
	}
	for range 3 {
		if _, err := gA.QueryCapability(b.PublicKey()); err == nil {
			t.Fatal("hidden node answered a capability query")
		}
	}
	for _, p := range gA.KnownPeers() {
		if bytes.Equal(p.NodeKey, b.PublicKey()) {
			t.Fatal("relay recorded the hidden node as a Garlic peer")
		}
	}
}

func TestOnionKeyRotationKeepsPreviousKeyDuringGraceThenWipesIt(t *testing.T) {
	g := newTestGarlic(t)
	payload := []byte("rotated")
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, payload, time.Minute)
	oldPriv := g.onion.keys[0].private

	now := time.Now()
	if changed, err := g.onion.rotate(now.Add(time.Hour)); err != nil || !changed {
		t.Fatalf("rotation did not create a new key (changed=%v, err=%v)", changed, err)
	}
	cur, _ := g.onion.current()
	if bytes.Equal(cur.public, g.identity.PublicKey) {
		t.Fatal("advertised onion key did not change after rotation")
	}
	if a := g.processCircuitData(msg, msgTypeCircuitData); a.kind != actionDeliver || !bytes.Equal(a.payload, payload) {
		t.Fatal("circuit built with the previous onion key stopped working during the grace period")
	}

	if _, err := g.onion.rotate(now.Add(3 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldPriv, make([]byte, len(oldPriv))) {
		t.Fatal("expired onion private key was not wiped from memory")
	}
	msg2, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, payload, time.Minute)
	if a := g.processCircuitData(msg2, msgTypeCircuitData); a.kind != actionDrop {
		t.Fatal("traffic for a deleted onion key could still be decrypted")
	}
}

func TestHiddenNodeNeverRelays(t *testing.T) {
	g := newTestGarlic(t)
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, []byte("x"), time.Minute)
	g.cfg.Hidden = true
	g.onion = nil
	if a := g.processCircuitData(msg, msgTypeCircuitData); a.kind != actionDrop {
		t.Fatal("hidden node decrypted a circuit layer")
	}
}

// buildPath puts a trusted guard first, takes every other hop from
// verified relay information only (no capability request is sent to
// them), and never uses the terminal as the guard.
func TestBuildPathTrustedGuardAndNoContactWithOtherHops(t *testing.T) {
	g := newTestGarlic(t)
	g.cfg.MinHopCount = 0
	guard, middle, terminal := newTestRelay(t), newTestRelay(t), newTestRelay(t)
	for _, r := range []*testRelay{guard, middle, terminal} {
		if _, err := g.learnRelayInfo(r.info(t, nil, 3*time.Hour), r.nodePub); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := g.buildPath(context.Background(), 3, terminal.nodePub, needSites); !errors.Is(err, ErrNoTrustedPeers) {
		t.Fatalf("path built without any trusted peer: %v", err)
	}
	g.trusted[string(guard.nodePub)] = bytes.Clone(guard.nodePub)
	path, keys, err := g.buildPath(context.Background(), 3, terminal.nodePub, needSites)
	if err != nil {
		t.Fatalf("buildPath returned error: %v", err)
	}
	if len(keys) != 3 || !bytes.Equal(keys[0], guard.nodePub) || !bytes.Equal(keys[1], middle.nodePub) || !bytes.Equal(keys[2], terminal.nodePub) {
		t.Fatalf("unexpected path %x", keys)
	}
	if !bytes.Equal(path[1].PublicKey, middle.onionPub) {
		t.Fatal("middle hop does not use the onion key from its signed RelayInfo")
	}
	if len(g.pending) != 0 {
		t.Fatal("buildPath contacted a hop directly")
	}
	// The only trusted peer is the terminal itself: it must not double as
	// the guard.
	if _, _, err := g.buildPath(context.Background(), 3, guard.nodePub, needSites); !errors.Is(err, ErrNoTrustedGuard) {
		t.Fatalf("terminal reused as guard: %v", err)
	}
	// A hop with no verified relay information cannot be the terminal.
	if _, _, err := g.buildPath(context.Background(), 2, newTestRelay(t).nodePub, needSites); !errors.Is(err, ErrUnknownRelay) {
		t.Fatalf("unknown terminal accepted: %v", err)
	}
}

func TestParseTrustedKeyRejectsOnionKey(t *testing.T) {
	g := newTestGarlic(t)
	r := newTestRelay(t)
	if _, err := g.learnRelayInfo(r.info(t, nil, time.Hour), r.nodePub); err != nil {
		t.Fatal(err)
	}
	if _, err := g.parseTrustedKey(hex.EncodeToString(r.onionPub)); !errors.Is(err, ErrTrustedPeerIsGarlic) {
		t.Fatalf("onion key accepted as a trusted node key: %v", err)
	}
	if _, err := g.parseTrustedKey("abcd"); !errors.Is(err, ErrInvalidTrustedPeer) {
		t.Fatalf("short key accepted: %v", err)
	}
	if _, err := g.parseTrustedKey(hex.EncodeToString(r.nodePub)); err != nil {
		t.Fatalf("valid node key rejected: %v", err)
	}
}

func TestIsLinkLocalURI(t *testing.T) {
	for uri, want := range map[string]bool{
		"tls://[fe80::1%25en0]:1234": true,
		"tcp://[fe80::abcd]:1":       true,
		"tls://1.2.3.4:443":          false,
		"tls://example.org:443":      false,
		"tls://[2001:db8::1]:443":    false,
	} {
		if got := isLinkLocalURI(uri); got != want {
			t.Errorf("isLinkLocalURI(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestTreeDistance(t *testing.T) {
	parent := map[string][]byte{"r": []byte("r"), "a": []byte("r"), "b": []byte("a"), "c": []byte("r")}
	for _, tc := range []struct {
		a, b string
		want int
	}{{"b", "c", 3}, {"a", "b", 1}, {"r", "r", 0}, {"b", "b", 0}} {
		if got, ok := treeDistance(parent, []byte(tc.a), []byte(tc.b)); !ok || got != tc.want {
			t.Errorf("treeDistance(%s,%s) = %d,%v want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	if _, ok := treeDistance(parent, []byte("b"), []byte("x")); ok {
		t.Error("distance to an unknown node reported as known")
	}
}

// When every other relay is a direct mesh peer (closer than MinHopCount),
// the error has to say so instead of a bare "not enough candidates".
func TestBuildPathExplainsRelaysTooClose(t *testing.T) {
	g := newTestGarlic(t)
	g.cfg.MinHopCount = 2 // the unit fixture has no mesh: every relay is at distance 0
	guard, middle, terminal := newTestRelay(t), newTestRelay(t), newTestRelay(t)
	for _, r := range []*testRelay{guard, middle, terminal} {
		if _, err := g.learnRelayInfo(r.info(t, nil, 3*time.Hour), r.nodePub); err != nil {
			t.Fatal(err)
		}
	}
	g.trusted[string(guard.nodePub)] = bytes.Clone(guard.nodePub)
	_, _, err := g.buildPath(context.Background(), 3, terminal.nodePub, needSites)
	if !errors.Is(err, ErrInsufficientDiverseCandidates) || !strings.Contains(err.Error(), "MinHopCount") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDirectoryWalkErrorsNameTheCause(t *testing.T) {
	g := newTestGarlic(t)
	if err := (walkResult{}).unreachableErr(g); !errors.Is(err, ErrDirectoryUnavailable) || !errors.Is(err, ErrNoTrustedPeers) {
		t.Fatalf("no trusted peers: %v", err)
	}
	g.trusted["k"] = []byte("k")
	if err := (walkResult{}).unreachableErr(g); !errors.Is(err, ErrDirectoryUnavailable) || !strings.Contains(err.Error(), "no Garlic relays known") {
		t.Fatalf("no relays known: %v", err)
	}
	if err := (walkResult{known: 3, lastErr: ErrNoTrustedGuard}).unreachableErr(g); !errors.Is(err, ErrNoTrustedGuard) {
		t.Fatalf("cause not wrapped: %v", err)
	}
	if err := (walkResult{known: 3, answered: 1}).unreachableErr(g); err != nil {
		t.Fatalf("a walk that reached a relay reported unreachable: %v", err)
	}
}
