package garlic

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// buildTestCircuitData constructs a circuitData message *body* - i.e.
// everything processCircuitData expects, which is the wire message with
// its leading msgTypeCircuitData byte already stripped, matching how
// handleIncoming calls it (data[1:]) - for a path of relayIdentities
// (each a *Identity), terminating in payload, so relay-logic tests can
// feed realistic input to processCircuitData without a real core.Core.
func buildTestCircuitData(t *testing.T, relayIdentities []*Identity, nodeKeys [][]byte, payload []byte, ttl time.Duration) (body []byte, circuitID CircuitID) {
	t.Helper()
	// Mirrors Garlic.CreateCircuit: one independent ephemeral keypair per
	// hop, chained via NextEphemeralPub, rather than one keypair reused
	// for the whole path - see linkability_test.go for what this chain
	// exists to prevent.
	ephemeralPubs := make([][]byte, len(relayIdentities))
	ephemeralPrivs := make([][]byte, len(relayIdentities))
	for i := range relayIdentities {
		pub, priv, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair returned error: %v", err)
		}
		ephemeralPubs[i], ephemeralPrivs[i] = pub, priv
	}
	hops := make([]Hop, len(relayIdentities))
	for i, id := range relayIdentities {
		secret, err := ECDH(ephemeralPrivs[i], id.PublicKey)
		if err != nil {
			t.Fatalf("ECDH returned error: %v", err)
		}
		key, err := deriveLayerKey(secret)
		if err != nil {
			t.Fatalf("deriveLayerKey returned error: %v", err)
		}
		var nextEphemeral []byte
		if i+1 < len(relayIdentities) {
			nextEphemeral = ephemeralPubs[i+1]
		}
		hops[i] = Hop{NodeKey: nodeKeys[i], Key: key, NextEphemeralPub: nextEphemeral}
	}
	c, err := NewCircuit(hops, time.Minute, 100, 100000)
	if err != nil {
		t.Fatalf("NewCircuit returned error: %v", err)
	}
	onion, _, counter, err := c.Seal(payload)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	env := &Envelope{
		Version:       EnvelopeVersion1,
		CircuitID:     c.ID,
		PacketCounter: counter,
		Expiration:    uint64(time.Now().Add(ttl).Unix()),
		Body:          onion,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	body = append(append([]byte(nil), ephemeralPubs[0]...), envBytes...)
	return body, c.ID
}

// newTestGarlic returns a *Garlic with just enough state set up to
// exercise its pure relay-decision logic (processCircuitData,
// processCapabilityRequest, handleCapabilityResponse) - no real core.Core
// involved. The full wiring to a running node is covered separately by
// the integration tests, which construct a *Garlic via New.
//
// The maps New would normally allocate are allocated here too, so a test
// can seed them directly (e.g. g.pending, to stand in for a capability
// request this node had genuinely sent) without tripping over a nil map.
func newTestGarlic(t *testing.T) *Garlic {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	cfg := DefaultConfig()
	return &Garlic{
		identity:        id,
		cfg:             cfg,
		onion:           newOnionKeyring(time.Hour, time.Hour, id.PublicKey, id.PrivateKey),
		trusted:         make(map[string][]byte),
		circuits:        NewCircuitManager(CircuitManagerConfig{MaxCircuits: cfg.MaxCircuits, MaxCircuitsPerPeer: cfg.MaxCircuitsPerPeer}),
		relayState:      newRelayCircuitState(1024),
		delivered:       make(chan DeliveredMessage, 256),
		autoDelivered:   make(chan AutoDeliveredMessage, 256),
		discovery:       newDiscoveryRegistry(1024, nil),
		capabilityCache: make(map[string]*cachedRelay),
		pending:         make(map[string]chan *CapabilityMessage),
		originEphemeral: make(map[CircuitID][]byte),
		pools:           make(map[PoolID]*circuitPool),
		autoPool:        make(map[CircuitID]time.Time),
		stop:            make(chan struct{}),
	}
}

func TestProcessCircuitDataTerminalHopDelivers(t *testing.T) {
	g := newTestGarlic(t)
	payload := []byte("hello bob")
	msg, circuitID := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, payload, time.Minute)

	action := g.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionDeliver {
		t.Fatalf("action.kind = %v, want actionDeliver", action.kind)
	}
	if action.circuitID != circuitID {
		t.Fatalf("action.circuitID = %d, want %d", action.circuitID, circuitID)
	}
	if !bytes.Equal(action.payload, payload) {
		t.Fatalf("action.payload = %q, want %q", action.payload, payload)
	}
}

func TestProcessCircuitDataIntermediateHopForwards(t *testing.T) {
	relay := newTestGarlic(t)
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	destNodeKey := []byte("dest-node-key")
	payload := []byte("hello bob")

	msg, _ := buildTestCircuitData(t,
		[]*Identity{relay.identity, destID},
		[][]byte{[]byte("relay-node-key"), destNodeKey},
		payload, time.Minute)

	action := relay.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionForward {
		t.Fatalf("action.kind = %v, want actionForward", action.kind)
	}
	if !bytes.Equal(action.forwardTo, destNodeKey) {
		t.Fatalf("action.forwardTo = %q, want %q", action.forwardTo, destNodeKey)
	}
	if len(action.forwardMsg) == 0 {
		t.Fatal("action.forwardMsg is empty")
	}

	// The forwarded message must itself be a valid circuitData message
	// that the destination can process to completion (proves the relay
	// correctly reconstructed the next envelope, not just that it didn't
	// crash).
	final := destID
	finalGarlic := &Garlic{identity: final, onion: testOnion(final), relayState: newRelayCircuitState(1024)}
	finalAction := finalGarlic.processCircuitData(action.forwardMsg[1:], msgTypeCircuitData) // strip the msgTypeCircuitData prefix, as handleIncoming would
	if finalAction.kind != actionDeliver {
		t.Fatalf("final hop action.kind = %v, want actionDeliver", finalAction.kind)
	}
	if !bytes.Equal(finalAction.payload, payload) {
		t.Fatalf("final hop payload = %q, want %q", finalAction.payload, payload)
	}
}

func TestProcessCircuitDataForwardAppliesRandomPadding(t *testing.T) {
	relay := newTestGarlic(t) // DefaultConfig: PaddingEnabled, [512, 1400]
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}

	sizes := map[int]bool{}
	for range 20 {
		msg, _ := buildTestCircuitData(t,
			[]*Identity{relay.identity, destID},
			[][]byte{[]byte("relay-node-key"), []byte("dest-node-key")},
			[]byte("payload"), time.Minute)
		action := relay.processCircuitData(msg, msgTypeCircuitData)
		if action.kind != actionForward {
			t.Fatalf("action.kind = %v, want actionForward", action.kind)
		}
		sizes[len(action.forwardMsg)] = true
	}
	if len(sizes) < 2 {
		t.Fatalf("got %d distinct forwarded message size(s) across 20 calls, want variety from per-hop padding randomization", len(sizes))
	}
}

func TestProcessCircuitDataForwardPaddingWithinConfiguredRange(t *testing.T) {
	relay := newTestGarlic(t)
	relay.cfg.MinPaddedSize = 1000
	relay.cfg.MaxPaddedSize = 1200
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}

	msg, _ := buildTestCircuitData(t,
		[]*Identity{relay.identity, destID},
		[][]byte{[]byte("relay-node-key"), []byte("dest-node-key")},
		[]byte("payload"), time.Minute)
	action := relay.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionForward {
		t.Fatalf("action.kind = %v, want actionForward", action.kind)
	}

	envSize := len(action.forwardMsg) - 1 - KeySize // strip msgType byte and ephemeral pubkey
	if envSize < relay.cfg.MinPaddedSize || envSize > relay.cfg.MaxPaddedSize {
		t.Fatalf("forwarded envelope size = %d, want in [%d, %d]", envSize, relay.cfg.MinPaddedSize, relay.cfg.MaxPaddedSize)
	}
}

func TestProcessCircuitDataForwardSkipsPaddingWhenDisabled(t *testing.T) {
	relay := newTestGarlic(t)
	relay.cfg.PaddingEnabled = false
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}

	msg, _ := buildTestCircuitData(t,
		[]*Identity{relay.identity, destID},
		[][]byte{[]byte("relay-node-key"), []byte("dest-node-key")},
		[]byte("payload"), time.Minute)
	action := relay.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionForward {
		t.Fatalf("action.kind = %v, want actionForward", action.kind)
	}

	forwardedEnv, err := Unmarshal(action.forwardMsg[1+KeySize:])
	if err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if len(forwardedEnv.Padding) != 0 {
		t.Fatalf("forwarded envelope has %d bytes of padding, want 0 (padding disabled)", len(forwardedEnv.Padding))
	}
}

// buildCircuitDataMissingNextHopEphemeral constructs a circuitData
// message body for a 2-hop path (relayIdentity -> destNodeKey) whose
// first hop's layer has a non-empty NextHop (there is a real next hop,
// destNodeKey) but a nil NextEphemeralPub - a state Garlic.CreateCircuit
// itself never produces (it always sets NextEphemeralPub to the next
// hop's real ephemeral key whenever NextHop is non-empty), but one a
// malicious or buggy originator could construct directly via the Hop
// struct, same as this helper does.
func buildCircuitDataMissingNextHopEphemeral(t *testing.T, relayIdentity *Identity, destNodeKey []byte) []byte {
	t.Helper()
	ephemeralPub, ephemeralPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair returned error: %v", err)
	}
	secret, err := ECDH(ephemeralPriv, relayIdentity.PublicKey)
	if err != nil {
		t.Fatalf("ECDH returned error: %v", err)
	}
	key, err := deriveLayerKey(secret)
	if err != nil {
		t.Fatalf("deriveLayerKey returned error: %v", err)
	}
	hops := []Hop{
		// NextEphemeralPub deliberately left nil, unlike CreateCircuit's
		// construction, even though a second hop (and therefore a
		// non-empty NextHop) follows.
		{NodeKey: []byte("relay-node-key"), Key: key, NextEphemeralPub: nil},
		{NodeKey: destNodeKey, Key: make([]byte, KeySize)},
	}
	c, err := NewCircuit(hops, time.Minute, 100, 100000)
	if err != nil {
		t.Fatalf("NewCircuit returned error: %v", err)
	}
	onion, _, counter, err := c.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	env := &Envelope{
		Version:       EnvelopeVersion1,
		CircuitID:     c.ID,
		PacketCounter: counter,
		Expiration:    uint64(time.Now().Add(time.Minute).Unix()),
		Body:          onion,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	return append(append([]byte(nil), ephemeralPub...), envBytes...)
}

// TestProcessCircuitDataDropsMissingNextHopEphemeral exercises the
// len(layer.NextHopEphemeral) != KeySize guard added alongside the
// chained-ephemeral-key fix (see linkability_test.go): a decrypted layer
// that asks to be forwarded (NextHop set) but carries no next-hop
// ephemeral key must be dropped, not forwarded with a truncated/absent
// ephemeral prefix downstream.
//
// Note: only the "absent" (nil, wire-encoded as has_next_ephemeral=0)
// case is reachable here. LayerPlaintext's wire encoding is a 1-byte
// presence flag followed by either zero bytes or exactly KeySize bytes
// (see layer.go's marshal/unmarshalLayerPlaintext) - there is no
// encoding for a "wrong, non-KeySize, non-zero length" NextHopEphemeral,
// so unmarshalLayerPlaintext can never produce one; any attempt to build
// one via Hop.NextEphemeralPub fails earlier, at EncryptLayer/marshal
// (ErrInvalidNextHopEphemeralSize). The guard's "!= KeySize" phrasing
// still matches exactly one reachable case in practice (len == 0), which
// is what this test constructs.
func TestProcessCircuitDataDropsMissingNextHopEphemeral(t *testing.T) {
	relay := newTestGarlic(t)
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}

	msg := buildCircuitDataMissingNextHopEphemeral(t, relay.identity, destID.PublicKey)
	action := relay.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionDrop {
		t.Fatalf("action.kind = %v, want actionDrop (NextHop set but NextHopEphemeral missing)", action.kind)
	}
}

func TestProcessCircuitDataDropsWrongRecipient(t *testing.T) {
	g := newTestGarlic(t)
	other, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	msg, _ := buildTestCircuitData(t, []*Identity{other}, [][]byte{[]byte("someone-else")}, []byte("payload"), time.Minute)

	action := g.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionDrop {
		t.Fatalf("action.kind = %v, want actionDrop (message encrypted for a different identity)", action.kind)
	}
	if got := g.security.snapshot().AuthFailures; got != 1 {
		t.Fatalf("security.AuthFailures = %d, want 1", got)
	}
}

func TestProcessCircuitDataDropsReplay(t *testing.T) {
	g := newTestGarlic(t)
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, []byte("payload"), time.Minute)

	first := g.processCircuitData(msg, msgTypeCircuitData)
	if first.kind != actionDeliver {
		t.Fatalf("first action.kind = %v, want actionDeliver", first.kind)
	}
	second := g.processCircuitData(msg, msgTypeCircuitData)
	if second.kind != actionDrop {
		t.Fatalf("second (replayed) action.kind = %v, want actionDrop", second.kind)
	}
	if got := g.security.snapshot().ReplayDrops; got != 1 {
		t.Fatalf("security.ReplayDrops = %d, want 1", got)
	}
}

func TestProcessCircuitDataDropsExpired(t *testing.T) {
	g := newTestGarlic(t)
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, []byte("payload"), -time.Minute)

	action := g.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionDrop {
		t.Fatalf("action.kind = %v, want actionDrop (expired)", action.kind)
	}
	if got := g.security.snapshot().ExpiredPackets; got != 1 {
		t.Fatalf("security.ExpiredPackets = %d, want 1", got)
	}
}

func TestProcessCircuitDataDropsMalformedTooShort(t *testing.T) {
	g := newTestGarlic(t)
	action := g.processCircuitData([]byte{1, 2, 3}, msgTypeCircuitData)
	if action.kind != actionDrop {
		t.Fatalf("action.kind = %v, want actionDrop (too short to contain an ephemeral key)", action.kind)
	}
	if got := g.security.snapshot().MalformedPackets; got != 1 {
		t.Fatalf("security.MalformedPackets = %d, want 1", got)
	}
}

func TestProcessCircuitDataDropsMalformedEnvelope(t *testing.T) {
	g := newTestGarlic(t)
	junk := make([]byte, KeySize+10)
	action := g.processCircuitData(junk, msgTypeCircuitData)
	if action.kind != actionDrop {
		t.Fatalf("action.kind = %v, want actionDrop (malformed envelope)", action.kind)
	}
	if got := g.security.snapshot().MalformedPackets; got != 1 {
		t.Fatalf("security.MalformedPackets = %d, want 1", got)
	}
}

func TestProcessCircuitDataDropsWhenRelayTableFull(t *testing.T) {
	g := newTestGarlic(t)
	g.relayState = newRelayCircuitState(0) // no room for any circuit
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, []byte("payload"), time.Minute)

	action := g.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionDrop {
		t.Fatalf("action.kind = %v, want actionDrop (relay circuit table full)", action.kind)
	}
	if got := g.security.snapshot().RelayTableFull; got != 1 {
		t.Fatalf("security.RelayTableFull = %d, want 1", got)
	}
}

func TestProcessCircuitDataV3ForwardPreservesMessageType(t *testing.T) {
	relay := newTestGarlic(t)
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	destNodeKey := []byte("dest-node-key")
	payload := []byte("hello bob")

	msg, _ := buildTestCircuitData(t,
		[]*Identity{relay.identity, destID},
		[][]byte{[]byte("relay-node-key"), destNodeKey},
		payload, time.Minute)

	action := relay.processCircuitData(msg, msgTypeCircuitDataV3)
	if action.kind != actionForward {
		t.Fatalf("action.kind = %v, want actionForward", action.kind)
	}
	if got := action.forwardMsg[0]; got != msgTypeCircuitDataV3 {
		t.Fatalf("forwardMsg[0] = %d, want msgTypeCircuitDataV3 (%d) - forwarding must preserve the inbound type, never hardcode msgTypeCircuitData", got, msgTypeCircuitDataV3)
	}
}

func TestProcessCircuitDataPlainForwardStillUsesPlainType(t *testing.T) {
	// Regression: the existing msgTypeCircuitData path must be completely
	// unaffected by this task.
	relay := newTestGarlic(t)
	destID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	destNodeKey := []byte("dest-node-key")
	payload := []byte("hello bob")

	msg, _ := buildTestCircuitData(t,
		[]*Identity{relay.identity, destID},
		[][]byte{[]byte("relay-node-key"), destNodeKey},
		payload, time.Minute)

	action := relay.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionForward {
		t.Fatalf("action.kind = %v, want actionForward", action.kind)
	}
	if got := action.forwardMsg[0]; got != msgTypeCircuitData {
		t.Fatalf("forwardMsg[0] = %d, want msgTypeCircuitData (%d)", got, msgTypeCircuitData)
	}
}

func TestProcessCircuitDataV3DeliverIsTagged(t *testing.T) {
	g := newTestGarlic(t)
	payload := []byte("hello bob")
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, payload, time.Minute)

	action := g.processCircuitData(msg, msgTypeCircuitDataV3)
	if action.kind != actionDeliver {
		t.Fatalf("action.kind = %v, want actionDeliver", action.kind)
	}
	if !action.tagged {
		t.Fatal("action.tagged = false, want true for a msgTypeCircuitDataV3 delivery")
	}
}

func TestProcessCircuitDataPlainDeliverIsNotTagged(t *testing.T) {
	g := newTestGarlic(t)
	payload := []byte("hello bob")
	msg, _ := buildTestCircuitData(t, []*Identity{g.identity}, [][]byte{g.identity.PublicKey}, payload, time.Minute)

	action := g.processCircuitData(msg, msgTypeCircuitData)
	if action.kind != actionDeliver {
		t.Fatalf("action.kind = %v, want actionDeliver", action.kind)
	}
	if action.tagged {
		t.Fatal("action.tagged = true, want false for a plain msgTypeCircuitData delivery")
	}
}

func TestProcessCircuitDataHopLocalForwardsNextLegMetadata(t *testing.T) {
	relayID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (relay) returned error: %v", err)
	}
	nextID, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (next hop) returned error: %v", err)
	}

	ephemeralPub, ephemeralPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair returned error: %v", err)
	}
	secret, err := ECDH(ephemeralPriv, relayID.PublicKey)
	if err != nil {
		t.Fatalf("ECDH returned error: %v", err)
	}
	relayKey, err := deriveLayerKeyHopLocal(secret)
	if err != nil {
		t.Fatalf("deriveLayerKeyHopLocal returned error: %v", err)
	}

	nextLegID := CircuitID{7, 7, 7}
	layer := &LayerPlaintext{
		NextHop:             nextID.PublicKey,
		NextHopEphemeral:    make([]byte, KeySize),
		Inner:               []byte("forwarded ciphertext placeholder"),
		NextLocalCircuitID:  nextLegID[:],
		NextLocalCounter:    123,
		NextLocalExpiration: uint64(time.Now().Add(5 * time.Minute).Unix()),
	}
	ciphertext, err := EncryptLayerHopLocal(relayKey, 0, layer)
	if err != nil {
		t.Fatalf("EncryptLayerHopLocal returned error: %v", err)
	}
	env := &Envelope{
		Version:       EnvelopeVersion2,
		CircuitID:     CircuitID{1, 1, 1},
		PacketCounter: 0,
		Expiration:    uint64(time.Now().Add(time.Minute).Unix()),
		Body:          ciphertext,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	body := append(append([]byte(nil), ephemeralPub...), envBytes...)

	relay := hopGarlicFor(relayID)
	action := relay.processCircuitData(body, msgTypeCircuitData)
	if action.kind != actionForward {
		t.Fatalf("action.kind = %v, want actionForward", action.kind)
	}

	forwardedEnv, err := Unmarshal(action.forwardMsg[1+KeySize:])
	if err != nil {
		t.Fatalf("Unmarshal (forwarded envelope) returned error: %v", err)
	}
	if forwardedEnv.Version != EnvelopeVersion2 {
		t.Fatalf("forwarded Envelope.Version = %d, want EnvelopeVersion2", forwardedEnv.Version)
	}
	if forwardedEnv.CircuitID != nextLegID {
		t.Fatalf("forwarded Envelope.CircuitID = %x, want %x (NextLocalCircuitID, not the incoming leg's ID)", forwardedEnv.CircuitID, nextLegID)
	}
	if forwardedEnv.PacketCounter != 123 {
		t.Fatalf("forwarded Envelope.PacketCounter = %d, want 123 (NextLocalCounter, not the incoming leg's counter)", forwardedEnv.PacketCounter)
	}
	if forwardedEnv.Expiration != layer.NextLocalExpiration {
		t.Fatalf("forwarded Envelope.Expiration = %d, want %d (NextLocalExpiration, not the incoming leg's expiration)", forwardedEnv.Expiration, layer.NextLocalExpiration)
	}
}

func TestProcessAnnounceRecordsPeers(t *testing.T) {
	g := newTestGarlic(t)
	msg := &AnnounceMessage{Peers: []AnnouncePeer{
		{RelayInfo: newTestRelay(t).info(t, nil, time.Hour)},
		{RelayInfo: newTestRelay(t).info(t, nil, time.Hour)},
	}}
	body, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	g.processAnnounce(body)

	peers := g.discovery.list()
	if len(peers) != 2 {
		t.Fatalf("discovery registry has %d peers, want 2", len(peers))
	}
}

func TestProcessAnnounceIgnoresMalformedInput(t *testing.T) {
	g := newTestGarlic(t)
	g.processAnnounce([]byte{0xFF, 0xFF}) // must not panic
	if len(g.discovery.list()) != 0 {
		t.Fatalf("discovery registry has %d peers, want 0 for malformed input", len(g.discovery.list()))
	}
}

func TestProcessAnnounceSkipsEmptyKeyEntries(t *testing.T) {
	g := newTestGarlic(t)
	msg := &AnnounceMessage{Peers: []AnnouncePeer{{RelayInfo: nil}}}
	body, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	g.processAnnounce(body)

	if len(g.discovery.list()) != 0 {
		t.Fatalf("discovery registry has %d peers, want 0 (entry with empty NodeKey must be skipped)", len(g.discovery.list()))
	}
}

// Gossip cannot forge or alter a relay's onion key: an entry whose
// signature does not verify against its own node key is ignored.
func TestProcessAnnounceRejectsTamperedRelayInfo(t *testing.T) {
	g := newTestGarlic(t)
	raw := newTestRelay(t).info(t, nil, time.Hour)
	raw[len(raw)-70] ^= 0xFF // flip a byte inside the onion key
	body, err := (&AnnounceMessage{Peers: []AnnouncePeer{{RelayInfo: raw}}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	g.processAnnounce(body)
	if n := len(g.discovery.list()); n != 0 {
		t.Fatalf("tampered relay info was accepted (%d peers)", n)
	}
}

func TestProcessAnnounceRejectsExpiredRelayInfo(t *testing.T) {
	g := newTestGarlic(t)
	body, err := (&AnnounceMessage{Peers: []AnnouncePeer{{RelayInfo: newTestRelay(t).info(t, nil, -time.Minute)}}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	g.processAnnounce(body)
	if n := len(g.discovery.list()); n != 0 {
		t.Fatalf("expired relay info was accepted (%d peers)", n)
	}
}

func TestProcessCapabilityRequestSilentInHiddenMode(t *testing.T) {
	g := newTestGarlic(t)
	g.cfg.Hidden = true
	g.onion = nil
	if resp := g.processCapabilityRequest(); resp != nil {
		t.Fatalf("hidden node answered a capability request: %x", resp)
	}
}

// capabilityResponseBody returns a well-formed, fully-capable
// msgTypeCapabilityResponse body - i.e. the best-case input
// handleCapabilityResponse can be handed, so a test asserting it is *not*
// recorded as self-verified is isolating solicitation, nothing else.
func capabilityResponseBody(t *testing.T, relay *testRelay) []byte {
	t.Helper()
	return relay.info(t, nil, time.Hour)
}

func selfVerifiedFor(g *Garlic, nodeKey []byte) (found, selfVerified bool) {
	for _, p := range g.discovery.list() {
		if bytes.Equal(p.NodeKey, nodeKey) {
			return true, p.SelfVerified
		}
	}
	return false, false
}

func TestHandleCapabilityResponseSolicitedIsSelfVerified(t *testing.T) {
	g := newTestGarlic(t)
	relay := newTestRelay(t)
	peerNode := []byte(relay.nodePub)

	// Stand in for requestCapability having just sent a request to this
	// exact key and still waiting on it.
	g.pending[hex.EncodeToString(peerNode)] = make(chan *CapabilityMessage, 1)

	g.handleCapabilityResponse(peerNode, capabilityResponseBody(t, relay))

	found, selfVerified := selfVerifiedFor(g, peerNode)
	if !found {
		t.Fatal("solicited capability response did not record a discovery entry at all")
	}
	if !selfVerified {
		t.Error("SelfVerified = false for a response to a request this node had outstanding, want true")
	}
}

// TestHandleCapabilityResponseUnsolicitedIsNotSelfVerified is the
// regression test for the branch's headline anti-Sybil property: an
// attacker who can open an ironwood session to this node can send a
// msgTypeCapabilityResponse it was never asked for. If that were enough
// to set SelfVerified, one unsolicited packet would permanently buy
// first-hop-guard eligibility (discoveryRegistry.record never downgrades
// SelfVerified), and SelectPathWithGuardPolicy's guarantee would be void.
func TestHandleCapabilityResponseUnsolicitedIsNotSelfVerified(t *testing.T) {
	g := newTestGarlic(t)
	relay := newTestRelay(t)
	peerNode := []byte(relay.nodePub)

	// Deliberately no g.pending entry: this node never asked.
	g.handleCapabilityResponse(peerNode, capabilityResponseBody(t, relay))

	if _, selfVerified := selfVerifiedFor(g, peerNode); selfVerified {
		t.Fatal("SelfVerified = true for an unsolicited capability response; one unrequested packet must never grant first-hop-guard eligibility")
	}
}

// A capability response must be signed by the node that sent it: a relay
// cannot answer with somebody else's RelayInfo.
func TestHandleCapabilityResponseRejectsForeignRelayInfo(t *testing.T) {
	g := newTestGarlic(t)
	sender := bytes.Repeat([]byte{0xAB}, ed25519.PublicKeySize)
	other := newTestRelay(t)
	g.pending[hex.EncodeToString(sender)] = make(chan *CapabilityMessage, 1)
	g.handleCapabilityResponse(sender, capabilityResponseBody(t, other))
	if len(g.discovery.list()) != 0 {
		t.Fatal("accepted a RelayInfo that belongs to a different node than the responder")
	}
}

// A response that arrives after this node's own CapabilityTimeout already
// gave up (requestCapability's deferred delete cleared g.pending) is
// indistinguishable, from this function's perspective, from a wholly
// unsolicited one - and must be treated the same way.
func TestHandleCapabilityResponseAfterTimeoutIsNotSelfVerified(t *testing.T) {
	g := newTestGarlic(t)
	relay := newTestRelay(t)
	peerNode := []byte(relay.nodePub)
	key := hex.EncodeToString(peerNode)

	g.pending[key] = make(chan *CapabilityMessage, 1)
	delete(g.pending, key) // requestCapability's timeout path

	g.handleCapabilityResponse(peerNode, capabilityResponseBody(t, relay))

	if _, selfVerified := selfVerifiedFor(g, peerNode); selfVerified {
		t.Fatal("SelfVerified = true for a response that arrived after this node's request had already timed out, want false")
	}
}
