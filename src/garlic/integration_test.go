package garlic_test

// Integration test (Phase 13 of the roadmap): a real multi-node
// Yggdrasil mesh, in-process, proving the whole pipeline end-to-end -
// not just each piece in isolation. Topology:
//
//	A (garlic origin) -- L1 (legacy) -- L2 (legacy) -- R (garlic relay) -- B (garlic destination)
//
// A and R are never directly peered; every packet between them - the
// capability negotiation, and every hop of the onion circuit - must
// transit L1 and L2, which never call garlic.New and have no idea
// Garlic exists. This is the direct, running proof of the core claim in
// docs/garlic-architecture.md §4: legacy nodes transparently carry
// Garlic traffic as ordinary encrypted mesh frames, requiring no
// changes and gaining no visibility into it.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

func newLinkedTestNode(t *testing.T) *core.Core {
	t.Helper()
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatalf("GenerateSelfSignedCertificate returned error: %v", err)
	}
	logger := log.New(io.Discard, "", 0)
	// gologme/log lazily writes this field on its first Output call. Set
	// it before the core starts concurrent listeners and connection logs.
	logger.SetCallDepth(2)
	c, err := core.New(cfg.Certificate, logger)
	if err != nil {
		t.Fatalf("core.New returned error: %v", err)
	}
	return c
}

// connectChain peers nodes[i] <- nodes[i+1] for consecutive pairs only,
// so any two non-adjacent nodes can only reach each other by transiting
// the ones between them.
func connectChain(t *testing.T, nodes []*core.Core) {
	t.Helper()
	for i := 0; i < len(nodes)-1; i++ {
		listenURL, err := url.Parse("tcp://localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		listener, err := nodes[i].Listen(listenURL, "")
		if err != nil {
			t.Fatalf("Listen returned error: %v", err)
		}
		peerURL, err := url.Parse("tcp://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := nodes[i+1].CallPeer(peerURL, ""); err != nil {
			t.Fatalf("CallPeer returned error: %v", err)
		}
	}
}

// pumpAll drives every node's ReadFrom loop, exactly as tun.queue()/
// tun.read() does in the real daemon (see docs/garlic-architecture.md
// §3.3) - without this, none of these nodes' underlying encrypted
// sessions with each other would ever be serviced, Garlic or otherwise.
func pumpAll(nodes []*core.Core) {
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
}

func waitForCapability(t *testing.T, g *garlic.Garlic, peer ed25519.PublicKey, maxWait time.Duration) *garlic.CapabilityMessage {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for time.Now().Before(deadline) {
		msg, err := g.QueryCapability(peer)
		if err == nil {
			return msg
		}
		lastErr = err
	}
	t.Fatalf("capability query never succeeded within %s: %v", maxWait, lastErr)
	return nil
}

func TestIntegrationSendGarlicThroughLegacyRelay(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeL1 := newLinkedTestNode(t)
	nodeL2 := newLinkedTestNode(t)
	nodeR := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeL1, nodeL2, nodeR, nodeB}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idR, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (R) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	// nodeL1 and nodeL2 deliberately get no garlic.New call: they are
	// plain, unmodified Yggdrasil nodes.
	gR := garlic.New(nodeR, idR, cfg, garlic.NewStaticRendezvous())
	defer gR.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()

	// A malformed garlic packet, sent before anything real, must not
	// crash or wedge the receiving node - confirmed by everything below
	// still working.
	if _, err := nodeA.WriteGarlic([]byte{0xFF, 0x00, 0x01, 0x02}, nodeR.LocalAddr()); err != nil {
		t.Fatalf("WriteGarlic (malformed) returned error: %v", err)
	}

	// A legacy node must never answer a capability request: it has no
	// handler registered, so core.Core silently drops the request, and
	// the querying side must see this as an ordinary timeout - the same
	// signal it gets for any other non-Garlic node.
	if _, err := gA.QueryCapability(nodeL1.PublicKey()); err == nil {
		t.Fatal("QueryCapability against a legacy node succeeded, want a timeout")
	}

	capR := waitForCapability(t, gA, nodeR.PublicKey(), 180*time.Second)
	if !capR.SupportsGarlicV2() {
		t.Fatal("R's capability response does not advertise garlic-v2")
	}
	if !bytes.Equal(capR.PublicKey, idR.PublicKey) {
		t.Fatalf("R's advertised public key = %x, want %x", capR.PublicKey, idR.PublicKey)
	}
	capB := waitForCapability(t, gA, nodeB.PublicKey(), 180*time.Second)
	if !capB.SupportsGarlicV2() {
		t.Fatal("B's capability response does not advertise garlic-v2")
	}

	circuitID, err := gA.CreateCircuit(
		[]garlic.CapabilityMessage{*capR, *capB},
		[][]byte{nodeR.PublicKey(), nodeB.PublicKey()},
	)
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}

	payload := []byte("hello bob, from alice, via garlic, through two legacy hops")
	if err := gA.SendGarlic(circuitID, payload); err != nil {
		t.Fatalf("SendGarlic returned error: %v", err)
	}

	delivered, err := gB.RecvGarlic(20 * time.Second)
	if err != nil {
		t.Fatalf("RecvGarlic returned error: %v", err)
	}
	if !bytes.Equal(delivered.Payload, payload) {
		t.Fatalf("delivered payload = %q, want %q", delivered.Payload, payload)
	}

	statsA := gA.GetStats()
	if statsA.OriginatedCircuits != 1 {
		t.Errorf("A's OriginatedCircuits = %d, want 1", statsA.OriginatedCircuits)
	}
	statsR := gR.GetStats()
	if statsR.RelayedCircuits != 1 {
		t.Errorf("R's RelayedCircuits = %d, want 1", statsR.RelayedCircuits)
	}
	statsB := gB.GetStats()
	// B is the terminal hop: it still runs relay-side replay bookkeeping
	// (its relay-table entry exists and still occupies a capacity slot),
	// but it never forwards a packet onward, so recordForward is never
	// called for it and it has no real previous/next hop to report.
	// relayCircuitState.snapshot deliberately excludes such entries
	// rather than surfacing them as phantom relays with zero traffic, so
	// the destination node reports no relayed circuits.
	if statsB.RelayedCircuits != 0 {
		t.Errorf("B's RelayedCircuits = %d, want 0 (B is the destination, not a relay - it never forwards)", statsB.RelayedCircuits)
	}
}

// TestIntegrationGossipDiscoversUnknownPeer proves discovery propagation
// end to end against a real mesh: A only ever talks directly to B, and B
// only ever talks directly to C - A never queries C's capability itself
// - yet after B gossips its known peers to A, A learns about C purely
// from that announce message.
func TestIntegrationGossipDiscoversUnknownPeer(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	nodeC := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB, nodeC}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all) // A -- B -- C
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	idC, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (C) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gC := garlic.New(nodeC, idC, cfg, garlic.NewStaticRendezvous())
	defer gC.Close()

	// A learns about B directly; B learns about C directly. A never
	// queries C.
	waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)
	waitForCapability(t, gB, nodeC.PublicKey(), 60*time.Second)

	for _, p := range gA.KnownPeers() {
		if bytes.Equal(p.NodeKey, nodeC.PublicKey()) {
			t.Fatal("A already knows about C before any gossip happened - test setup is invalid")
		}
	}

	if err := gB.GossipAnnounce(nodeA.PublicKey()); err != nil {
		t.Fatalf("GossipAnnounce returned error: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		for _, p := range gA.KnownPeers() {
			if bytes.Equal(p.NodeKey, nodeC.PublicKey()) && bytes.Equal(p.GarlicPublicKey, idC.PublicKey) {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("A never learned about C via gossip within the deadline; known peers: %+v", gA.KnownPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestIntegrationHubLearnsAboutRequesterWithoutQueryingItself proves the
// core fix directly: a node that only ever ANSWERS a capability request
// (never sends one itself) still ends up recording the requester as a
// self-verified discovery candidate. Before this fix, handleIncoming's
// msgTypeCapabilityRequest case only ever responded - it never recorded
// anything about the requester - so a node that nobody ever queried FROM
// (only queried BY others) could never learn about its own requesters at
// all, regardless of how much time passed.
func TestIntegrationHubLearnsAboutRequesterWithoutQueryingItself(t *testing.T) {
	nodeHub := newLinkedTestNode(t)
	nodeLeaf := newLinkedTestNode(t)
	all := []*core.Core{nodeHub, nodeLeaf}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idHub, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (Hub) returned error: %v", err)
	}
	idLeaf, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (Leaf) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gHub := garlic.New(nodeHub, idHub, cfg, garlic.NewStaticRendezvous())
	defer gHub.Close()
	gLeaf := garlic.New(nodeLeaf, idLeaf, cfg, garlic.NewStaticRendezvous())
	defer gLeaf.Close()

	// Leaf queries Hub - the ordinary, one-directional bootstrap
	// interaction. Hub never calls QueryCapability itself.
	waitForCapability(t, gLeaf, nodeHub.PublicKey(), 60*time.Second)

	// Hub must end up knowing about Leaf anyway, and as self-verified -
	// answering an authenticated request is exactly as strong a signal as
	// receiving an authenticated response.
	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		for _, p := range gHub.KnownPeers() {
			if bytes.Equal(p.NodeKey, nodeLeaf.PublicKey()) && p.SelfVerified {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Hub never recorded Leaf as self-verified after only answering its request; known peers: %+v", gHub.KnownPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestIntegrationStarTopologyConverges reproduces the exact real-world
// scenario this fix targets: every "leaf" node points its
// Config.BootstrapPeers at one central "hub" (the common, natural
// topology when several independently-installed servers are each told
// "bootstrap against this one already-running node"), and the hub itself
// has no BootstrapPeers of its own. Before this fix, the hub could never
// learn about any leaf (each leaf only ever queried it, never the other
// way around), so it had nothing to gossip and the leaves could never
// discover each other - the star could never converge into a shared
// candidate pool, no matter how long it ran. With the fix, once both
// leaves have queried the hub, a leaf that pulls gossip from the hub
// learns about the *other* leaf too.
func TestIntegrationStarTopologyConverges(t *testing.T) {
	nodeHub := newLinkedTestNode(t)
	nodeLeafA := newLinkedTestNode(t)
	nodeLeafC := newLinkedTestNode(t)
	all := []*core.Core{nodeHub, nodeLeafA, nodeLeafC}
	for _, n := range all {
		defer n.Stop()
	}
	// Star: both leaves connect only to the hub, never to each other.
	connectChain(t, []*core.Core{nodeLeafA, nodeHub})
	connectChain(t, []*core.Core{nodeHub, nodeLeafC})
	pumpAll(all)

	idHub, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (Hub) returned error: %v", err)
	}
	idLeafA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (LeafA) returned error: %v", err)
	}
	idLeafC, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (LeafC) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gHub := garlic.New(nodeHub, idHub, cfg, garlic.NewStaticRendezvous())
	defer gHub.Close()
	gLeafA := garlic.New(nodeLeafA, idLeafA, cfg, garlic.NewStaticRendezvous())
	defer gLeafA.Close()
	gLeafC := garlic.New(nodeLeafC, idLeafC, cfg, garlic.NewStaticRendezvous())
	defer gLeafC.Close()

	// Both leaves bootstrap against the hub - exactly matching
	// Config.BootstrapPeers pointed at one already-running node. The hub
	// itself never initiates anything.
	waitForCapability(t, gLeafA, nodeHub.PublicKey(), 60*time.Second)
	waitForCapability(t, gLeafC, nodeHub.PublicKey(), 60*time.Second)

	// waitForCapability above only confirms each leaf's OWN outbound
	// query succeeded - it says nothing about the hub's *reciprocal*
	// query back to that leaf, which the fix fires in its own goroutine
	// (handleIncoming must not block) and can still be in flight. Wait
	// for the hub to have actually recorded both leaves before pulling
	// gossip from it, or this test races the fix it's meant to exercise.
	hubDeadline := time.Now().Add(10 * time.Second)
	for {
		knowsA, knowsC := false, false
		for _, p := range gHub.KnownPeers() {
			if bytes.Equal(p.NodeKey, nodeLeafA.PublicKey()) && p.SelfVerified {
				knowsA = true
			}
			if bytes.Equal(p.NodeKey, nodeLeafC.PublicKey()) && p.SelfVerified {
				knowsC = true
			}
		}
		if knowsA && knowsC {
			break
		}
		if time.Now().After(hubDeadline) {
			t.Fatalf("hub never recorded both leaves as self-verified; known peers: %+v", gHub.KnownPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}

	for _, p := range gLeafA.KnownPeers() {
		if bytes.Equal(p.NodeKey, nodeLeafC.PublicKey()) {
			t.Fatal("LeafA already knows about LeafC before any gossip pull happened - test setup is invalid")
		}
	}

	// LeafA pulls gossip from the hub - the same RequestGossip call
	// bootstrap() itself makes after a successful QueryCapability.
	if err := gLeafA.RequestGossip(nodeHub.PublicKey()); err != nil {
		t.Fatalf("RequestGossip returned error: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		for _, p := range gLeafA.KnownPeers() {
			if bytes.Equal(p.NodeKey, nodeLeafC.PublicKey()) && bytes.Equal(p.GarlicPublicKey, idLeafC.PublicKey) {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("LeafA never learned about LeafC via the hub within the deadline; known peers: %+v", gLeafA.KnownPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestIntegrationAnnounceRequestTriggersImmediateGossipAnnounce(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	nodeC := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB, nodeC}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all) // A -- B -- C
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	idC, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (C) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gC := garlic.New(nodeC, idC, cfg, garlic.NewStaticRendezvous())
	defer gC.Close()

	// B learns about C directly. A learns about B directly, but never
	// queries C, and critically: B never queries A either, so (unlike
	// TestIntegrationGossipDiscoversUnknownPeer) A is NOT in B's
	// capabilityCache and B's periodic gossipTick would never target A.
	waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)
	waitForCapability(t, gB, nodeC.PublicKey(), 60*time.Second)

	for _, p := range gA.KnownPeers() {
		if bytes.Equal(p.NodeKey, nodeC.PublicKey()) {
			t.Fatal("A already knows about C before any gossip happened - test setup is invalid")
		}
	}

	if err := gA.RequestGossip(nodeB.PublicKey()); err != nil {
		t.Fatalf("RequestGossip returned error: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		for _, p := range gA.KnownPeers() {
			if bytes.Equal(p.NodeKey, nodeC.PublicKey()) && bytes.Equal(p.GarlicPublicKey, idC.PublicKey) {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("A never learned about C via RequestGossip's pull within the deadline; known peers: %+v", gA.KnownPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestIntegrationSelectPathAgainstRealTopology proves SelectPath's
// core.Core.GetTree()/GetPaths() integration works against a real mesh,
// not just SelectDiversePath's already-unit-tested selection algorithm
// in isolation.
func TestIntegrationSelectPathAgainstRealTopology(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	nodeC := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB, nodeC}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all) // A -- B -- C
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	idC, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (C) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	cfg.MinHopCount = 0 // this test's tiny topology has no room for a real distance filter

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gC := garlic.New(nodeC, idC, cfg, garlic.NewStaticRendezvous())
	defer gC.Close()

	// A needs a resolved mesh path to a candidate (not just knowledge of
	// its key) before SelectPath can score it - direct contact resolves
	// one as a side effect, same as real usage would after discovering
	// candidates via gossip.
	waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)
	waitForCapability(t, gA, nodeC.PublicKey(), 60*time.Second)

	// This deliberately does not assert a *specific* outcome (which of
	// B/C gets picked at n=1, or whether both pass the shared-tree-parent
	// check at n=2): both depend on this tiny topology's exact,
	// non-deterministic-across-runs tree shape, which isn't something
	// this test controls or should reverse-engineer. The sorting and
	// diversity-filtering *behavior* is already deterministically proven
	// against controlled inputs in selection_test.go. What this test
	// exists to prove is narrower and topology-independent: that
	// candidatePool pulls real core.Core.GetTree()/GetPaths() data end
	// to end and SelectPath returns a legitimate, known candidate from
	// it, not a stub or an empty pool.
	selected, err := gA.SelectPath(1)
	if err != nil {
		t.Fatalf("SelectPath returned error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("SelectPath returned %d hops, want 1", len(selected))
	}
	hop := selected[0]
	if !bytes.Equal(hop.NodeKey, nodeB.PublicKey()) && !bytes.Equal(hop.NodeKey, nodeC.PublicKey()) {
		t.Fatalf("selected hop %x is neither B nor C", hop.NodeKey)
	}
	if len(hop.GarlicPublicKey) == 0 {
		t.Fatal("selected hop has no GarlicPublicKey - candidatePool didn't carry real discovery data through")
	}
}

func TestIntegrationCandidatePoolCarriesSelfVerifiedThrough(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all) // A -- B
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	cfg.MinHopCount = 0 // A and B are direct peers here (hop count 1), below the default distance filter

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()

	// A directly capability-queries B, which resolves a real mesh path
	// AND records B as self-verified (Task 1/2's handleCapabilityResponse
	// change).
	waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)

	selected, err := gA.SelectPath(1)
	if err != nil {
		t.Fatalf("SelectPath returned error: %v", err)
	}
	if len(selected) != 1 || !selected[0].SelfVerified {
		t.Fatalf("SelectPath(1) = %+v, want one self-verified candidate (B, directly queried by A)", selected)
	}
}

// TestIntegrationMultipathSpreadsTraffic proves SendGarlicMultipath
// actually delivers over two independent paths against a real mesh, not
// just that circuitPool's round-robin index advances correctly in
// isolation (already covered by multipath_test.go).
func TestIntegrationMultipathSpreadsTraffic(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	nodeC := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB, nodeC}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all) // A -- B -- C (C reachable from A transparently through B)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	idC, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (C) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gC := garlic.New(nodeC, idC, cfg, garlic.NewStaticRendezvous())
	defer gC.Close()

	capB := waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)
	capC := waitForCapability(t, gA, nodeC.PublicKey(), 60*time.Second)

	pool, err := gA.CreateCircuitPool(
		[][]garlic.CapabilityMessage{{*capB}, {*capC}},
		[][][]byte{{nodeB.PublicKey()}, {nodeC.PublicKey()}},
	)
	if err != nil {
		t.Fatalf("CreateCircuitPool returned error: %v", err)
	}
	defer gA.ClosePool(pool)

	const messagesPerDest = 3
	for i := range 2 * messagesPerDest {
		payload := []byte{byte(i)}
		if err := gA.SendGarlicMultipath(pool, payload); err != nil {
			t.Fatalf("SendGarlicMultipath call %d returned error: %v", i, err)
		}
	}

	countB := countDelivered(t, gB, messagesPerDest, 20*time.Second)
	countC := countDelivered(t, gC, messagesPerDest, 20*time.Second)
	if countB != messagesPerDest {
		t.Errorf("B received %d messages, want %d (round-robin should split evenly)", countB, messagesPerDest)
	}
	if countC != messagesPerDest {
		t.Errorf("C received %d messages, want %d (round-robin should split evenly)", countC, messagesPerDest)
	}
}

// TestIntegrationSendGarlicBundledDeliversAmongCover proves
// SendGarlicBundled's real entry survives a real mesh trip - decrypt,
// replay-window, and forward logic all still fire correctly - while
// mixed in with cover entries that the receiving hop must (and does)
// silently fail to decrypt and discard, exactly once, with no
// duplicate/garbage deliveries.
func TestIntegrationSendGarlicBundledDeliversAmongCover(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}

	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()

	capB := waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)

	circuitID, err := gA.CreateCircuit([]garlic.CapabilityMessage{*capB}, [][]byte{nodeB.PublicKey()})
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}

	payload := []byte("hello bob, hidden among cover traffic")
	if err := gA.SendGarlicBundled(circuitID, payload, 5); err != nil {
		t.Fatalf("SendGarlicBundled returned error: %v", err)
	}

	delivered, err := gB.RecvGarlic(20 * time.Second)
	if err != nil {
		t.Fatalf("RecvGarlic returned error: %v", err)
	}
	if !bytes.Equal(delivered.Payload, payload) {
		t.Fatalf("delivered payload = %q, want %q", delivered.Payload, payload)
	}

	// Nothing else should ever arrive: the 5 cover entries must never
	// decrypt into a delivery.
	if extra, err := gB.RecvGarlic(500 * time.Millisecond); err == nil {
		t.Fatalf("unexpected second delivery: %+v", extra)
	}
}

// TestIntegrationSendGarlicAutoThenRecvGarlicAutoRoundTrips proves the
// tagged auto-pool delivery path (SendGarlicAuto -> msgTypeCircuitDataV3
// -> deliverTagged -> g.autoDelivered -> RecvGarlicAuto) round-trips a
// real payload over a real mesh, and - just as importantly - that this
// traffic never surfaces on B's plain RecvGarlic/g.delivered channel,
// which the existing SendGarlic/RecvGarlic path uses instead.
func TestIntegrationSendGarlicAutoThenRecvGarlicAutoRoundTrips(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()

	capB := waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)
	if !capB.SupportsAutoCircuit() {
		t.Fatal("B's capability response does not advertise CapabilityAutoCircuit")
	}

	circuitID, err := gA.CreateCircuit([]garlic.CapabilityMessage{*capB}, [][]byte{nodeB.PublicKey()})
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}

	if err := gA.SendGarlicAuto(circuitID, []byte("auto-hello")); err != nil {
		t.Fatalf("SendGarlicAuto returned error: %v", err)
	}
	msg, err := gB.RecvGarlicAuto(10 * time.Second)
	if err != nil {
		t.Fatalf("RecvGarlicAuto returned error: %v", err)
	}
	if string(msg.Payload) != "auto-hello" {
		t.Fatalf("Payload = %q, want %q", msg.Payload, "auto-hello")
	}
	// msg.CircuitID is the terminal leg's own hop-local CircuitID
	// (hops[len(hops)-1].LocalCircuitID for this test's single-hop
	// circuit), independently random from the sender's own bookkeeping
	// handle `circuitID` (Circuit.ID, from NewCircuit's own
	// randomCircuitID call) - the two are never expected to match under
	// the hop-local envelope design (2026-08-24 plan): Circuit.ID is
	// never itself placed on the wire. The payload check above is this
	// test's real correctness assertion.

	// Nothing sent via SendGarlicAuto should ever surface on B's plain
	// RecvGarlic channel.
	if _, err := gB.RecvGarlic(200 * time.Millisecond); !errors.Is(err, garlic.ErrRecvTimeout) {
		t.Fatalf("RecvGarlic err = %v, want ErrRecvTimeout (auto-pool traffic must stay off the manual delivery channel)", err)
	}
}

func TestIntegrationBootstrapPeersRecordedAsSelfVerified(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	// B must exist and be Garlic-capable before A starts, since A's
	// bootstrap step (launched from New, best-effort) queries it once.
	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		for _, p := range gA.KnownPeers() {
			if bytes.Equal(p.NodeKey, nodeB.PublicKey()) && p.SelfVerified {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("A never recorded its configured BootstrapPeers entry as self-verified; known peers: %+v", gA.KnownPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestIntegrationAutoCreateCircuitUsesSelfVerifiedGuard(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	cfg.MinHopCount = 0 // this tiny topology has no room for a real distance filter

	gA := garlic.New(nodeA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(nodeB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()

	waitForCapability(t, gA, nodeB.PublicKey(), 60*time.Second)

	id, err := gA.AutoCreateCircuit(1)
	if err != nil {
		t.Fatalf("AutoCreateCircuit returned error: %v", err)
	}

	var found *garlic.Circuit
	for _, c := range gA.OriginatedCircuits() {
		if c.ID == id {
			found = c
		}
	}
	if found == nil {
		t.Fatal("AutoCreateCircuit's returned ID is not in OriginatedCircuits()")
	}
	hops := found.HopKeys()
	if len(hops) != 1 || !bytes.Equal(hops[0], nodeB.PublicKey()) {
		t.Fatalf("hops = %x, want [%x] (B, the only self-verified candidate)", hops, nodeB.PublicKey())
	}
}

func TestIntegrationAutoCreateCircuitFailsWithoutSelfVerifiedCandidate(t *testing.T) {
	nodeA := newLinkedTestNode(t) // deliberately unpeered - candidatePool() will be empty
	defer nodeA.Stop()

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	gA := garlic.New(nodeA, idA, garlic.DefaultConfig(), garlic.NewStaticRendezvous())
	defer gA.Close()

	if _, err := gA.AutoCreateCircuit(1); !errors.Is(err, garlic.ErrNoSelfVerifiedCandidates) {
		t.Fatalf("err = %v, want ErrNoSelfVerifiedCandidates", err)
	}
}

func TestIntegrationAutoPoolFillsToTargetSize(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = 1
	cfgA.CoverTrafficEnabled = false // isolate fill/rotate behavior from cover-traffic noise
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if len(gA.AutoPoolStatus()) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool never reached target size 1; status: %+v", gA.AutoPoolStatus())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestIntegrationAutoPoolFillStaggersCircuitCreation is the regression
// test for expiry-driven backfill rebuilding the whole pool as one
// synchronized burst.
//
// fillAutoPool used to loop until the pool reached Config.AutoPoolSize
// inside a single call, so every pool circuit shared (approximately) one
// creation instant - and therefore one expiry instant Config.
// CircuitLifetime later. CircuitManager.ExpireStale then reaped them all
// in the same pass and autoPoolLoop's maintenance ticker rebuilt them all
// within one 2-second tick, giving the node a permanent, phase-locked
// burst of AutoPoolSize simultaneous circuit builds once per
// CircuitLifetime: exactly the "never all at once" correlation
// fingerprint rotateAutoPool's doc comment and the design spec call out
// for steady-state rotation, reintroduced for backfill.
//
// fillAutoPool now adds at most one circuit per call and leans on the
// maintenance ticker's own autoPoolFillRetryInterval (2s) cadence to top
// the rest up over several ticks, so creation times - and hence expiry
// times - are naturally spread out.
//
// The assertion is deliberately a loose lower bound rather than an exact
// schedule. autoPoolLoop has two independent wakeup sources that can each
// drive a fill while the pool is below target (the maintenance ticker,
// and the rotate/fill timer, which nextAutoPoolInterval caps at
// autoPoolFillRetryInterval while below target), and those two can land in
// the same instant - so a pool of three fills in at least two distinct
// ~2s-apart rounds, not necessarily three. One second is therefore
// comfortably below the ~2s the fixed code produces and enormously above
// the sub-millisecond span the old fill-in-one-call code produced.
func TestIntegrationAutoPoolFillStaggersCircuitCreation(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	const poolSize = 3
	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = poolSize
	cfgA.AutoRotationInterval = 5 * time.Minute // rotation must never churn CreatedAt during this test
	cfgA.CoverTrafficEnabled = false            // isolate fill behavior from cover-traffic noise
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	var entries []garlic.AutoPoolEntry
	deadline := time.Now().Add(30 * time.Second)
	for {
		entries = gA.AutoPoolStatus()
		if len(entries) == poolSize {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool never reached target size %d; status: %+v", poolSize, entries)
		}
		time.Sleep(100 * time.Millisecond)
	}

	first, last := entries[0].CreatedAt, entries[0].CreatedAt
	for _, e := range entries[1:] {
		if e.CreatedAt.Before(first) {
			first = e.CreatedAt
		}
		if e.CreatedAt.After(last) {
			last = e.CreatedAt
		}
	}
	const minSpan = time.Second
	if span := last.Sub(first); span < minSpan {
		t.Fatalf("pool circuits' CreatedAt span = %s, want at least %s: all %d circuits were built in one burst, so they will also expire in one burst; entries=%+v", span, minSpan, poolSize, entries)
	}
}

func TestIntegrationAutoPoolRotatesOneCircuitAtATime(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = 2 // two circuits, both through the only candidate B, so rotation has something to distinguish
	cfgA.AutoRotationInterval = 1100 * time.Millisecond
	cfgA.CoverTrafficEnabled = false
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	var before []garlic.AutoPoolEntry
	deadline := time.Now().Add(15 * time.Second)
	for {
		before = gA.AutoPoolStatus()
		if len(before) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool never reached target size 2; status: %+v", before)
		}
		time.Sleep(100 * time.Millisecond)
	}

	time.Sleep(1500 * time.Millisecond) // past one rotation tick, comfortably short of a second one

	after := gA.AutoPoolStatus()
	if len(after) != 2 {
		t.Fatalf("AutoPoolStatus() after rotation = %d entries, want 2 (pool stays at target size)", len(after))
	}
	changed := 0
	for _, a := range after {
		stillPresent := false
		for _, b := range before {
			if a.ID == b.ID {
				stillPresent = true
			}
		}
		if !stillPresent {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("%d circuits changed after ~1 rotation interval, want exactly 1 (before=%+v after=%+v)", changed, before, after)
	}
}

// TestIntegrationAutoPoolPrunesExpiredCircuits is the regression test for
// the auto-pool's most consequential failure mode: g.autoPool is a map
// the auto-pool loop maintains itself, but circuits leave
// CircuitManager on their own schedule - Config.CircuitLifetime, reaped
// by CircuitManager.ExpireStale from cleanupLoop. Before pruning existed,
// every size decision (fill, rotate-vs-fill, AutoPoolStatus) counted
// those already-reaped entries as live, so the pool reported itself full
// while holding nothing but phantom IDs, never backfilled, and cover
// traffic over it silently failed with ErrCircuitNotFound forever.
//
// The reap is simulated with CloseCircuit rather than waited for:
// CloseCircuit removes the circuit from CircuitManager exactly as
// ExpireStale's _remove does - leaving g.autoPool's entry behind, which
// is the whole bug - and cleanupLoop's real ExpireStale only runs on a
// 30-second ticker, far too coarse to hang a test on. Config.
// CircuitLifetime is still set short so the circuits really are past
// their lifetime at that point, matching what ExpireStale would act on.
//
// Config.AutoRotationInterval is deliberately much longer than
// Config.CircuitLifetime here, mirroring the shipped defaults (15m vs
// 10m): rotation must not be what rescues the pool, so recovery below is
// genuinely the expiry-driven backfill path.
func TestIntegrationAutoPoolPrunesExpiredCircuits(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	const poolSize = 2
	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = poolSize
	cfgA.CircuitLifetime = 2 * time.Second
	cfgA.AutoRotationInterval = 60 * time.Second // never fires during this test
	cfgA.CoverTrafficEnabled = false
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	livePoolIDs := func() (entries []garlic.AutoPoolEntry, phantom []garlic.CircuitID) {
		entries = gA.AutoPoolStatus()
		tracked := map[garlic.CircuitID]bool{}
		for _, c := range gA.OriginatedCircuits() {
			tracked[c.ID] = true
		}
		for _, e := range entries {
			if !tracked[e.ID] {
				phantom = append(phantom, e.ID)
			}
		}
		return entries, phantom
	}

	var filled []garlic.AutoPoolEntry
	deadline := time.Now().Add(20 * time.Second)
	for {
		filled = gA.AutoPoolStatus()
		if len(filled) == poolSize {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool never reached target size %d; status: %+v", poolSize, filled)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Past the configured lifetime: every circuit built above is now
	// expired and is exactly what ExpireStale would remove next.
	time.Sleep(cfgA.CircuitLifetime + 500*time.Millisecond)
	for _, e := range filled {
		gA.CloseCircuit(e.ID)
	}

	// The direct assertion: the pool must not still be reporting the
	// circuits that just left CircuitManager.
	if entries, phantom := livePoolIDs(); len(phantom) != 0 {
		t.Fatalf("AutoPoolStatus() reports %d circuit(s) no longer tracked by CircuitManager (%x); pool: %+v", len(phantom), phantom, entries)
	}

	// ...and, having correctly noticed it is below target, it must
	// actually backfill rather than sitting empty until a rotation tick
	// that is a full AutoRotationInterval away.
	deadline = time.Now().Add(25 * time.Second)
	for {
		entries, phantom := livePoolIDs()
		if len(entries) == poolSize && len(phantom) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool did not backfill to %d live circuits after its circuits were reaped; entries=%+v phantom=%x", poolSize, entries, phantom)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntegrationCoverTrafficNeverReachesRecvGarlicAuto(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = 1
	cfgA.CoverTrafficEnabled = true
	cfgA.CoverTrafficInterval = 300 * time.Millisecond // fast, for test purposes
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	deadline := time.Now().Add(15 * time.Second)
	for len(gA.AutoPoolStatus()) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool never reached target size 1; status: %+v", gA.AutoPoolStatus())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Cover traffic has had several intervals to fire (real packets, real
	// circuit, both nodes up) - none of it must ever surface as a real
	// delivery on B's auto channel.
	if _, err := gB.RecvGarlicAuto(2 * time.Second); !errors.Is(err, garlic.ErrRecvTimeout) {
		t.Fatalf("RecvGarlicAuto err = %v, want ErrRecvTimeout (cover packets must never surface as a real delivery)", err)
	}
}

// TestIntegrationCoverTrafficActuallyFiresFromAutoPoolLoop is the
// regression test for autoPoolLoop starving its own cover-traffic timer.
//
// The loop used to recreate coverTimer at the top of every iteration and
// stop it at the bottom. That is only safe while nothing else wakes the
// loop more often than Config.CoverTrafficInterval - which is exactly why
// the rotate/fill timer is instead created once and only Reset inside its
// own case. Adding the backfill maintenance ticker (a hard
// autoPoolFillRetryInterval = 2s wakeup, unconditional) broke that
// invariant for coverTimer: at the shipped 75s interval (jittered into
// roughly [37.5s, 112.5s]) the 2s tick always won the race, tore
// coverTimer down and rebuilt it from zero, and cover traffic was never
// sent at any realistic configuration.
//
// Directly unit-testing sendCoverTraffic cannot catch this - the bug is
// in the surrounding select, not in the send - so this test runs the real
// autoPoolLoop, with the real 2s maintenance ticker at its normal
// unmodified production cadence, and only shortens the *configured* cover
// interval.
//
// Config.CoverTrafficInterval is 5s rather than a few hundred ms on
// purpose. coverTrafficDelay floors its result at one second, so any
// interval below ~2s would produce a round delay shorter than the 2s
// maintenance tick and the old code would have (accidentally) passed. 5s
// jitters to [2.5s, 7.5s], which is always strictly longer than the
// maintenance tick - the same relationship the shipped 75s default has,
// just faster to test.
//
// Cover packets are discarded at the terminal hop and never reach
// RecvGarlicAuto (see TestIntegrationCoverTrafficNeverReachesRecvGarlicAuto),
// so the send is observed on the sender instead: Circuit.Seal is the only
// thing in the package that increments a circuit's packet counter, and
// building a circuit never calls it, so any increase in
// Stats.OriginatedPackets here is necessarily a real cover send.
// Config.AutoRotationInterval is set long so no pool circuit is closed
// mid-test (GetStats sums over live circuits only).
func TestIntegrationCoverTrafficActuallyFiresFromAutoPoolLoop(t *testing.T) {
	nodeA := newLinkedTestNode(t)
	nodeB := newLinkedTestNode(t)
	all := []*core.Core{nodeA, nodeB}
	for _, n := range all {
		defer n.Stop()
	}
	connectChain(t, all)
	pumpAll(all)

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(nodeB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.BootstrapPeers = []string{hex.EncodeToString(nodeB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = 1
	cfgA.AutoRotationInterval = 5 * time.Minute // no rotation during the test: a closed circuit takes its counters with it
	cfgA.CoverTrafficEnabled = true
	cfgA.CoverTrafficInterval = 5 * time.Second
	gA := garlic.New(nodeA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	deadline := time.Now().Add(20 * time.Second)
	for len(gA.AutoPoolStatus()) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("auto-pool never reached target size 1; status: %+v", gA.AutoPoolStatus())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Nothing in this test ever calls SendGarlic/SendGarlicAuto, and the
	// circuit build itself does not Seal, so this is 0 in practice - read
	// it rather than assumed, so the assertion below is about the delta.
	baseline := gA.GetStats().OriginatedPackets

	// Worst case is one full round delay (7.5s) plus one full per-circuit
	// stagger (5s) after the pool filled, so 60s is a wide margin.
	deadline = time.Now().Add(60 * time.Second)
	for {
		if got := gA.GetStats().OriginatedPackets; got > baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("OriginatedPackets never rose above baseline %d within 60s: autoPoolLoop never actually sent cover traffic over the pool circuit", baseline)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func countDelivered(t *testing.T, g *garlic.Garlic, want int, maxWait time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	count := 0
	for count < want && time.Now().Before(deadline) {
		if _, err := g.RecvGarlic(1 * time.Second); err == nil {
			count++
		}
	}
	return count
}
