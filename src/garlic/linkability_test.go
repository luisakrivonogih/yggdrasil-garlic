package garlic

// Tests proving the per-hop ephemeral key property Part 1 of the
// hardening task exists to guarantee: non-adjacent relays never observe
// a common ephemeral public key, and a relay cannot derive another
// hop's session key from what it actually receives. See
// docs/superpowers/specs/2026-08-09-garlic-crypto-hardening-design.md
// section A.

import (
	"bytes"
	"testing"
)

// hopGarlicFor returns a minimal *Garlic usable to call
// processCircuitData as the given hop identity, independent of any
// running core.Core or admin socket.
func hopGarlicFor(id *Identity) *Garlic {
	return &Garlic{
		identity:   id,
		onion:      testOnion(id),
		cfg:        DefaultConfig(),
		relayState: newRelayCircuitState(1024),
		delivered:  make(chan DeliveredMessage, 16),
	}
}

// buildThreeHopOriginator returns a *Garlic configured to originate
// circuits, plus three independent hop Identities the circuit will run
// over (each with its own real X25519 keypair, so the test can inspect
// what each hop's own view of the wire traffic actually is).
func buildThreeHopOriginator(t *testing.T) (originator *Garlic, hopIdentities []*Identity) {
	t.Helper()
	originatorID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (originator) returned error: %v", err)
	}
	g := &Garlic{
		identity:        originatorID,
		cfg:             DefaultConfig(),
		circuits:        NewCircuitManager(CircuitManagerConfig{MaxCircuits: 16, MaxCircuitsPerPeer: 16}),
		relayState:      newRelayCircuitState(1024),
		originEphemeral: make(map[CircuitID][]byte),
		delivered:       make(chan DeliveredMessage, 16),
	}

	hops := make([]*Identity, 3)
	for i := range hops {
		id, err := NewIdentity()
		if err != nil {
			t.Fatalf("NewIdentity (hop %d) returned error: %v", i, err)
		}
		hops[i] = id
	}
	return g, hops
}

func buildTestPath(hopIdentities []*Identity) ([]CapabilityMessage, [][]byte) {
	path := make([]CapabilityMessage, len(hopIdentities))
	nodeKeys := make([][]byte, len(hopIdentities))
	for i, id := range hopIdentities {
		path[i] = CapabilityMessage{Versions: []string{CapabilityGarlicV2, CapabilityGarlicV3}, PublicKey: id.PublicKey}
		nodeKeys[i] = []byte{byte('A' + i)} // stand-in Yggdrasil routing key
	}
	return path, nodeKeys
}

func TestNonAdjacentHopsCannotLinkViaEphemeralKeys(t *testing.T) {
	g, hopIDs := buildThreeHopOriginator(t)
	path, nodeKeys := buildTestPath(hopIDs)

	circuitID, err := g.CreateCircuit(path, nodeKeys)
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}
	c, ok := g.circuits.Get(circuitID)
	if !ok {
		t.Fatal("circuit not found after CreateCircuit")
	}
	onion, _, legID, counter, expiration, err := c.SealHopLocal([]byte("hello"), g.cfg.PacketTTL)
	if err != nil {
		t.Fatalf("SealHopLocal returned error: %v", err)
	}
	e1Pub := g.originEphemeral[circuitID]
	bodyToHop1, err := buildCircuitDataBodyHopLocal(e1Pub, legID, counter, expiration, onion, g.cfg)
	if err != nil {
		t.Fatalf("buildCircuitDataBodyHopLocal returned error: %v", err)
	}
	e1 := append([]byte(nil), bodyToHop1[:KeySize]...)

	hop1 := hopGarlicFor(hopIDs[0])
	action1 := hop1.processCircuitData(bodyToHop1, msgTypeCircuitData)
	if action1.kind != actionForward {
		t.Fatalf("hop1 action = %v, want actionForward", action1.kind)
	}
	e2 := append([]byte(nil), action1.forwardMsg[1:1+KeySize]...)

	hop2 := hopGarlicFor(hopIDs[1])
	action2 := hop2.processCircuitData(action1.forwardMsg[1:], msgTypeCircuitData)
	if action2.kind != actionForward {
		t.Fatalf("hop2 action = %v, want actionForward", action2.kind)
	}
	e3 := append([]byte(nil), action2.forwardMsg[1:1+KeySize]...)

	hop3 := hopGarlicFor(hopIDs[2])
	action3 := hop3.processCircuitData(action2.forwardMsg[1:], msgTypeCircuitData)
	if action3.kind != actionDeliver {
		t.Fatalf("hop3 action = %v, want actionDeliver", action3.kind)
	}
	if !bytes.Equal(action3.payload, []byte("hello")) {
		t.Fatalf("delivered payload = %q, want %q", action3.payload, "hello")
	}

	// Each hop's message used a distinct ephemeral key.
	if bytes.Equal(e1, e2) || bytes.Equal(e2, e3) || bytes.Equal(e1, e3) {
		t.Fatalf("ephemeral keys not all distinct: e1=%x e2=%x e3=%x", e1, e2, e3)
	}

	// Hop 1's observed set is {e1, e2} (e1: what it received; e2: what it
	// had to forward on). Hop 3 only ever observes {e3}. The two sets
	// must not intersect - this is the anti-linkability property itself:
	// colluding hop1+hop3 (non-adjacent) cannot link the circuit by
	// comparing ephemeral keys.
	for _, seen := range [][]byte{e1, e2} {
		if bytes.Equal(seen, e3) {
			t.Fatalf("hop1 observed an ephemeral key (%x) that hop3 also sees - circuits are linkable", seen)
		}
	}
}

func TestRelay1CannotDeriveRelay2SessionKey(t *testing.T) {
	g, hopIDs := buildThreeHopOriginator(t)
	path, nodeKeys := buildTestPath(hopIDs[:2])

	circuitID, err := g.CreateCircuit(path, nodeKeys)
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}
	c, _ := g.circuits.Get(circuitID)
	onion, _, legID, counter, expiration, err := c.SealHopLocal([]byte("payload"), g.cfg.PacketTTL)
	if err != nil {
		t.Fatalf("SealHopLocal returned error: %v", err)
	}
	e1Pub := g.originEphemeral[circuitID]
	bodyToHop1, err := buildCircuitDataBodyHopLocal(e1Pub, legID, counter, expiration, onion, g.cfg)
	if err != nil {
		t.Fatalf("buildCircuitDataBodyHopLocal returned error: %v", err)
	}

	hop1 := hopGarlicFor(hopIDs[0])
	action1 := hop1.processCircuitData(bodyToHop1, msgTypeCircuitData)
	if action1.kind != actionForward {
		t.Fatalf("hop1 action = %v, want actionForward", action1.kind)
	}
	e2 := action1.forwardMsg[1 : 1+KeySize]

	// The only Diffie-Hellman computation relay1 could actually attempt
	// with key material it possesses is ECDH(relay1's own identity
	// private key, e2) - it has no other private scalar available. That
	// must not equal hop 2's real session key.
	wrongSecret, err := ECDH(hopIDs[0].PrivateKey, e2)
	if err != nil {
		t.Fatalf("ECDH returned error: %v", err)
	}
	wrongKey, err := deriveLayerKeyHopLocal(wrongSecret)
	if err != nil {
		t.Fatalf("deriveLayerKey returned error: %v", err)
	}

	realSecret, err := ECDH(hopIDs[1].PrivateKey, e2)
	if err != nil {
		t.Fatalf("ECDH returned error: %v", err)
	}
	realKey, err := deriveLayerKeyHopLocal(realSecret)
	if err != nil {
		t.Fatalf("deriveLayerKey returned error: %v", err)
	}

	if bytes.Equal(wrongKey, realKey) {
		t.Fatal("relay1 derived the same session key as relay2 using only its own identity key - session keys are not hop-isolated")
	}
}

func TestDifferentHopsGetDifferentEphemeralPublicKeys(t *testing.T) {
	g, hopIDs := buildThreeHopOriginator(t)
	path, nodeKeys := buildTestPath(hopIDs)

	circuitID, err := g.CreateCircuit(path, nodeKeys)
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}
	c, _ := g.circuits.Get(circuitID)
	if len(c.hops) != 3 {
		t.Fatalf("circuit has %d hops, want 3", len(c.hops))
	}
	e1 := g.originEphemeral[circuitID]
	e2 := c.hops[0].NextEphemeralPub
	e3 := c.hops[1].NextEphemeralPub
	if len(c.hops[2].NextEphemeralPub) != 0 {
		t.Errorf("final hop NextEphemeralPub = %x, want empty", c.hops[2].NextEphemeralPub)
	}
	if bytes.Equal(e1, e2) || bytes.Equal(e2, e3) || bytes.Equal(e1, e3) {
		t.Fatalf("CreateCircuit reused an ephemeral public key across hops: e1=%x e2=%x e3=%x", e1, e2, e3)
	}
}
