package garlic

// Guard (first hop) selection against a real linked mesh: the first hop of
// every automatically built circuit must be a trusted peer that advertises
// the required protocol versions. A capability-verified but untrusted
// relay is never used as the first hop.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func newLinkedCoreForAutoCircuitTest(t *testing.T) *core.Core {
	t.Helper()
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatalf("GenerateSelfSignedCertificate returned error: %v", err)
	}
	logger := log.New(io.Discard, "", 0)
	c, err := core.New(cfg.Certificate, logger)
	if err != nil {
		t.Fatalf("core.New returned error: %v", err)
	}
	return c
}

// guardFixture links origin to each candidate and starts a Garlic relay on
// every node. trust selects which candidates the origin trusts.
func guardFixture(t *testing.T, candidates int, trust func(i int) bool) (*Garlic, []*Garlic, []*core.Core) {
	t.Helper()
	origin := newLinkedCoreForAutoCircuitTest(t)
	t.Cleanup(origin.Stop)
	listenURL, _ := url.Parse("tcp://localhost:0")
	listener, err := origin.Listen(listenURL, "")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	peerURL, _ := url.Parse("tcp://" + listener.Addr().String())
	nodes := []*core.Core{origin}
	for range candidates {
		c := newLinkedCoreForAutoCircuitTest(t)
		t.Cleanup(c.Stop)
		if err := c.CallPeer(peerURL, ""); err != nil {
			t.Fatalf("CallPeer returned error: %v", err)
		}
		nodes = append(nodes, c)
	}
	for _, n := range nodes {
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
	cfg.CapabilityTimeout = 2 * time.Second
	cfg.MinHopCount = 0
	var trusted []string
	for i := range candidates {
		if trust(i) {
			trusted = append(trusted, hex.EncodeToString(nodes[i+1].PublicKey()))
		}
	}
	originCfg := cfg
	originCfg.TrustedPeers = trusted
	id, _ := NewIdentity()
	gOrigin := New(origin, id, originCfg, NewStaticRendezvous())
	t.Cleanup(gOrigin.Close)
	var others []*Garlic
	for i := range candidates {
		id, _ := NewIdentity()
		g := New(nodes[i+1], id, cfg, NewStaticRendezvous())
		t.Cleanup(g.Close)
		others = append(others, g)
		var ok bool
		for range 5 {
			if _, err := gOrigin.QueryCapability(nodes[i+1].PublicKey()); err == nil {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("capability query against candidate %d never succeeded", i)
		}
	}
	return gOrigin, others, nodes
}

func TestAutoCreateCircuitRequiresTrustedGuard(t *testing.T) {
	gOrigin, _, _ := guardFixture(t, 1, func(int) bool { return false })
	if _, err := gOrigin.AutoCreateCircuit(1); !errors.Is(err, ErrNoTrustedPeers) {
		t.Fatalf("AutoCreateCircuit error = %v, want ErrNoTrustedPeers (a verified but untrusted relay must never be a first hop)", err)
	}
	if n := len(gOrigin.OriginatedCircuits()); n != 0 {
		t.Fatalf("%d circuits created without a trusted guard", n)
	}
}

func TestAutoCreateCircuitUsesTrustedGuard(t *testing.T) {
	gOrigin, _, nodes := guardFixture(t, 2, func(i int) bool { return i == 1 })
	id, err := gOrigin.AutoCreateCircuit(1)
	if err != nil {
		t.Fatalf("AutoCreateCircuit returned error: %v", err)
	}
	c, _ := gOrigin.circuits.Get(id)
	if hops := c.HopKeys(); len(hops) != 1 || !bytes.Equal(hops[0], nodes[2].PublicKey()) {
		t.Fatalf("first hop = %x, want the trusted peer %x", hops, nodes[2].PublicKey())
	}
	if !bytes.Equal(gOrigin.CurrentGuard(), nodes[2].PublicKey()) {
		t.Fatal("trusted first hop was not remembered as the current guard")
	}
}

// A trusted peer whose relay information lacks the hop-local envelope
// format (garlic-v3) is skipped; another trusted peer is used instead.
func TestAutoCreateCircuitSkipsTrustedGuardMissingGarlicV3(t *testing.T) {
	gOrigin, _, nodes := guardFixture(t, 2, func(int) bool { return true })
	key := hex.EncodeToString(nodes[1].PublicKey())
	gOrigin.mu.Lock()
	old := gOrigin.capabilityCache[key]
	gOrigin.capabilityCache[key] = &cachedRelay{
		capability:  &CapabilityMessage{Versions: []string{CapabilityGarlicV2, CapabilityAutoCircuit}, PublicKey: old.capability.PublicKey},
		raw:         old.raw,
		publishedAt: old.publishedAt + 1,
		expiresAt:   old.expiresAt,
	}
	gOrigin.mu.Unlock()
	// Both trusted peers answered just now, so the cached relay information
	// (not a fresh request) decides whether a guard is usable.
	gOrigin.trustMu.Lock()
	gOrigin.guardState = map[string]*guardCheck{string(nodes[1].PublicKey()): {seen: time.Now()}, string(nodes[2].PublicKey()): {seen: time.Now()}}
	gOrigin.trustMu.Unlock()
	for range 8 {
		id, err := gOrigin.AutoCreateCircuit(1)
		if err != nil {
			t.Fatalf("AutoCreateCircuit returned error: %v", err)
		}
		c, _ := gOrigin.circuits.Get(id)
		if bytes.Equal(c.HopKeys()[0], nodes[1].PublicKey()) {
			t.Fatal("a guard without garlic-v3 support was selected")
		}
		gOrigin.CloseCircuit(id)
	}
}

// A trusted guard that stops answering (went offline, or switched to
// hidden mode) must not be kept just because its signed relay information
// is still valid: the next circuit uses another trusted peer.
func TestGuardThatStopsAnsweringIsReplaced(t *testing.T) {
	gOrigin, _, nodes := guardFixture(t, 2, func(int) bool { return true })
	id, err := gOrigin.AutoCreateCircuit(1)
	if err != nil {
		t.Fatalf("AutoCreateCircuit returned error: %v", err)
	}
	gOrigin.CloseCircuit(id)
	first := gOrigin.CurrentGuard()
	for _, n := range nodes[1:] {
		if bytes.Equal(n.PublicKey(), first) {
			n.SetGarlicHandler(nil) // stops answering and relaying
		}
	}
	gOrigin.trustMu.Lock()
	gOrigin.guardState[string(first)].seen = time.Now().Add(-2 * guardRecheck)
	gOrigin.trustMu.Unlock()
	// The next circuit still goes through the cached guard while a
	// background liveness check runs; once that check goes unanswered the
	// guard is skipped.
	if id, err := gOrigin.AutoCreateCircuit(1); err == nil {
		gOrigin.CloseCircuit(id)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		gOrigin.trustMu.Lock()
		st := gOrigin.guardState[string(first)]
		failed := !st.checking && !st.failed.IsZero()
		gOrigin.trustMu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("liveness check of the silent guard never completed")
		}
		time.Sleep(50 * time.Millisecond)
	}

	id, err = gOrigin.AutoCreateCircuit(1)
	if err != nil {
		t.Fatalf("no circuit after the guard stopped answering: %v", err)
	}
	c, _ := gOrigin.circuits.Get(id)
	if bytes.Equal(c.HopKeys()[0], first) || bytes.Equal(gOrigin.CurrentGuard(), first) {
		t.Fatal("kept using a trusted guard that no longer answers")
	}
	for _, k := range gOrigin.TrustedPeerKeys() {
		if k == hex.EncodeToString(first) {
			return // still trusted: only skipped while it does not answer
		}
	}
	t.Fatal("a guard that stopped answering was removed from the trusted peers")
}
