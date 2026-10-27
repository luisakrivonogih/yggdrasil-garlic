package garlic

// In-band Garlic message types (Phase 6/7 of the roadmap): every
// typeSessionGarlic-tagged packet's payload starts with one of these
// bytes. This is entirely internal to src/garlic - core.Core never
// inspects it, it just delivers the opaque payload to whoever registered
// via SetGarlicHandler (see docs/garlic-architecture.md §3.3).
//
// This file holds the *pure* decision logic: given already-received
// bytes and this node's own state, decide what to do next (deliver,
// forward, or drop) without performing any I/O itself. manager.go is the
// thin wrapper that actually calls core.Core.WriteGarlic with the
// results. Separating the two makes the security-relevant logic - replay
// checks, expiry, decrypt-failure handling - testable without a running
// mesh.

import (
	"errors"
	"time"
)

const (
	msgTypeCapabilityRequest byte = iota + 1
	msgTypeCapabilityResponse
	msgTypeCircuitData
	msgTypeAnnounce
	msgTypeCircuitDataBundle
	// msgTypeAnnounceRequest asks the recipient to immediately send back
	// a msgTypeAnnounce with its known-peer sample (empty body) - a
	// "pull" complementing the existing periodic gossipTick "push", so a
	// freshly bootstrapped node (not yet in anyone's capabilityCache, so
	// never a gossipTick target) can populate its candidate pool in one
	// round trip. See docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md §4.
	msgTypeAnnounceRequest
	// msgTypeCircuitDataV3 is the auto-pool circuit wire type - see §8 of
	// the same design doc and Task 6/7 of its implementation plan.
	msgTypeCircuitDataV3
	msgTypeDuplexData
	msgTypeCircuitReply
)

// circuitDataMinSize is the minimum length of a circuitData message body
// (after the type byte): an ephemeral public key plus at least an empty
// Envelope's fixed header.
const circuitDataMinSize = KeySize + envelopeFixedHeaderSize

var (
	ErrNotForThisIdentity = errors.New("garlic: message not encrypted for this identity")
	ErrPacketExpired      = errors.New("garlic: packet expired")
	ErrReplayed           = errors.New("garlic: packet replayed or circuit table full")
)

type actionKind int

const (
	actionDrop actionKind = iota
	actionDeliver
	actionForward
)

// circuitAction is the outcome of processing one circuitData message:
// either nothing further to do (actionDrop - never explained further, see
// docs/garlic-architecture.md §17 on not leaking which check failed),
// deliver payload locally (this node is the circuit's final hop), or
// forward forwardMsg to forwardTo (this node is an intermediate hop).
type circuitAction struct {
	kind       actionKind
	circuitID  CircuitID
	payload    []byte
	forwardTo  []byte
	forwardMsg []byte
	// tagged is true iff this action arose from a msgTypeCircuitDataV3
	// packet - only actionDeliver consults it (see manager.go's
	// dispatchAction/deliverTagged); forwarding already preserves the
	// type byte directly in forwardMsg.
	tagged        bool
	replyKey      []byte
	nextCircuitID CircuitID
}

// processCircuitData decides what to do with the body of a
// msgTypeCircuitData or msgTypeCircuitDataV3 message (i.e. everything
// after that leading type byte) - msgType is that leading byte, needed
// so a forwarded packet echoes the same type it arrived as (never
// hardcoded - see docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md
// §8) and so a terminal delivery knows whether to tag the resulting
// circuitAction. It performs no I/O.
func (g *Garlic) processCircuitData(body []byte, msgType byte) circuitAction {
	if len(body) < circuitDataMinSize {
		g.security.malformedPackets.Add(1)
		return circuitAction{kind: actionDrop}
	}
	ephemeralPub := body[:KeySize]
	env, err := Unmarshal(body[KeySize:])
	if err != nil {
		g.security.malformedPackets.Add(1)
		return circuitAction{kind: actionDrop}
	}
	if time.Now().Unix() > int64(env.Expiration) {
		g.security.expiredPackets.Add(1)
		return circuitAction{kind: actionDrop}
	}

	circuitID := env.CircuitID
	window, ok := g.relayState.replayWindowFor(circuitID)
	if !ok {
		g.security.relayTableFull.Add(1)
		return circuitAction{kind: actionDrop}
	}
	if !window.CheckAndSet(env.PacketCounter) {
		g.security.replayDrops.Add(1)
		return circuitAction{kind: actionDrop}
	}

	secret, err := ECDH(g.identity.PrivateKey, ephemeralPub)
	if err != nil {
		g.security.authFailures.Add(1)
		return circuitAction{kind: actionDrop}
	}

	switch env.Version {
	case EnvelopeVersion1:
		return g.processCircuitDataLegacy(secret, env, msgType)
	case EnvelopeVersion2:
		a := g.processCircuitDataHopLocal(secret, env, msgType)
		if msgType == msgTypeDuplexData && a.kind != actionDrop {
			a.replyKey, _ = deriveReplyKey(secret)
		}
		return a
	default:
		// Unreachable: Unmarshal already rejects any other Version.
		g.security.malformedPackets.Add(1)
		return circuitAction{kind: actionDrop}
	}
}

// processCircuitDataLegacy handles an EnvelopeVersion1 message: unchanged
// from processCircuitData's original body (deriveLayerKey/DecryptLayer,
// verbatim CircuitID/PacketCounter/Expiration forwarding). Kept only so
// this node can still relay another, not-yet-upgraded peer's legacy
// circuit - see EnvelopeVersion1's doc comment (envelope.go).
func (g *Garlic) processCircuitDataLegacy(secret []byte, env *Envelope, msgType byte) circuitAction {
	circuitID := env.CircuitID
	key, err := deriveLayerKey(secret)
	if err != nil {
		g.security.authFailures.Add(1)
		return circuitAction{kind: actionDrop}
	}
	// Wrong key (message wasn't encrypted for us), tampered
	// ciphertext, or malformed plaintext all look identical here by
	// design - see ErrNotForThisIdentity's doc comment.
	layer, err := DecryptLayer(key, env.PacketCounter, env.Body)
	if err != nil {
		g.security.authFailures.Add(1)
		return circuitAction{kind: actionDrop}
	}
	if len(layer.NextHop) == 0 {
		return circuitAction{kind: actionDeliver, circuitID: circuitID, payload: layer.Inner, tagged: msgType == msgTypeCircuitDataV3}
	}
	// A well-formed intermediate layer always carries the next hop's
	// ephemeral key; anything else is malformed or malicious input,
	// treated identically to any other unforwardable message.
	if len(layer.NextHopEphemeral) != KeySize {
		return circuitAction{kind: actionDrop}
	}
	nextEnv := &Envelope{
		Version:       EnvelopeVersion1,
		CircuitID:     env.CircuitID,
		PacketCounter: env.PacketCounter,
		Expiration:    env.Expiration,
		Body:          layer.Inner,
	}
	// Independently re-randomize this hop's outgoing wire size (see
	// Config.PaddingEnabled's doc comment) - a config error here (e.g.
	// MaxPaddedSize too small for this body) degrades to unpadded
	// forwarding rather than dropping an otherwise-valid packet.
	if g.cfg.PaddingEnabled {
		_ = nextEnv.PadToRandomRange(g.cfg.MinPaddedSize, g.cfg.MaxPaddedSize)
	}
	nextBytes, err := nextEnv.Marshal()
	if err != nil {
		g.security.malformedPackets.Add(1)
		return circuitAction{kind: actionDrop}
	}
	forwardMsg := make([]byte, 0, 1+KeySize+len(nextBytes))
	forwardMsg = append(forwardMsg, msgType)
	forwardMsg = append(forwardMsg, layer.NextHopEphemeral...)
	forwardMsg = append(forwardMsg, nextBytes...)
	return circuitAction{kind: actionForward, circuitID: circuitID, forwardTo: layer.NextHop, forwardMsg: forwardMsg}
}

// processCircuitDataHopLocal handles an EnvelopeVersion2 message:
// deriveLayerKeyHopLocal/DecryptLayerHopLocal, and - the actual fix this
// plan exists for - forwards using the just-decrypted layer's
// NextLocalCircuitID/NextLocalCounter/NextLocalExpiration instead of
// copying env's own (incoming-leg) values. See
// docs/superpowers/specs/2026-08-24-garlic-hop-local-metadata-design.md.
func (g *Garlic) processCircuitDataHopLocal(secret []byte, env *Envelope, msgType byte) circuitAction {
	circuitID := env.CircuitID
	key, err := deriveLayerKeyHopLocal(secret)
	if err != nil {
		g.security.authFailures.Add(1)
		return circuitAction{kind: actionDrop}
	}
	layer, err := DecryptLayerHopLocal(key, env.PacketCounter, env.Body)
	if err != nil {
		g.security.authFailures.Add(1)
		return circuitAction{kind: actionDrop}
	}
	if len(layer.NextHop) == 0 {
		return circuitAction{kind: actionDeliver, circuitID: circuitID, payload: layer.Inner, tagged: msgType == msgTypeCircuitDataV3}
	}
	if len(layer.NextHopEphemeral) != KeySize {
		return circuitAction{kind: actionDrop}
	}
	if len(layer.NextLocalCircuitID) != 16 {
		return circuitAction{kind: actionDrop}
	}
	var nextID CircuitID
	copy(nextID[:], layer.NextLocalCircuitID)
	nextEnv := &Envelope{
		Version:       EnvelopeVersion2,
		CircuitID:     nextID,
		PacketCounter: layer.NextLocalCounter,
		Expiration:    layer.NextLocalExpiration,
		Body:          layer.Inner,
	}
	if g.cfg.PaddingEnabled {
		_ = nextEnv.PadToRandomRange(g.cfg.MinPaddedSize, g.cfg.MaxPaddedSize)
	}
	nextBytes, err := nextEnv.Marshal()
	if err != nil {
		g.security.malformedPackets.Add(1)
		return circuitAction{kind: actionDrop}
	}
	forwardMsg := make([]byte, 0, 1+KeySize+len(nextBytes))
	forwardMsg = append(forwardMsg, msgType)
	forwardMsg = append(forwardMsg, layer.NextHopEphemeral...)
	forwardMsg = append(forwardMsg, nextBytes...)
	return circuitAction{kind: actionForward, circuitID: circuitID, forwardTo: layer.NextHop, forwardMsg: forwardMsg, nextCircuitID: nextID}
}

// buildCircuitDataMessageHopLocal is buildCircuitDataMessage's
// counterpart for the hop-local envelope format: same shape
// (msgTypeCircuitData || ephemeralPub || Envelope), EnvelopeVersion2
// instead of EnvelopeVersion1.
func buildCircuitDataMessageHopLocal(ephemeralPub []byte, id CircuitID, counter, expiration uint64, onion []byte, cfg Config) ([]byte, error) {
	body, err := buildCircuitDataBodyHopLocal(ephemeralPub, id, counter, expiration, onion, cfg)
	if err != nil {
		return nil, err
	}
	return append([]byte{msgTypeCircuitData}, body...), nil
}

// buildCircuitDataBodyHopLocal is buildCircuitDataBody's counterpart for
// the hop-local envelope format.
func buildCircuitDataBodyHopLocal(ephemeralPub []byte, id CircuitID, counter, expiration uint64, onion []byte, cfg Config) ([]byte, error) {
	env := &Envelope{
		Version:       EnvelopeVersion2,
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

// processAnnounce parses body and records every valid peer entry into
// this node's discovery registry, seeding future circuit-hop candidates
// this node has never directly queried. It performs no network I/O.
// Malformed input, or an entry with an empty key, is silently skipped -
// there is no response to send on an unauthenticated gossip channel (see
// docs/garlic-architecture.md §17), and this is best-effort discovery,
// not a trust decision (every candidate is still capability-verified
// before it's ever used as a circuit hop).
func (g *Garlic) processAnnounce(body []byte) {
	msg, err := UnmarshalAnnounceMessage(body)
	if err != nil {
		return
	}
	for _, p := range msg.Peers {
		if len(p.NodeKey) == 0 || len(p.GarlicPublicKey) == 0 {
			continue
		}
		g.discovery.record(DiscoveredPeer{
			NodeKey:         p.NodeKey,
			GarlicPublicKey: p.GarlicPublicKey,
			SelfVerified:    false,
		})
	}
}

// processCircuitDataBundle decides what to do with the body of a
// msgTypeCircuitDataBundle message: a Bundle whose entries are each
// shaped like a circuitData body (ephemeralPub || Envelope). Every entry
// is run through the exact same processCircuitData used for a
// non-bundled message - no new cryptography, no weaker guarantees - so
// a cover entry (random bytes, indistinguishable in shape from a real
// one) simply fails to decrypt and drops silently, exactly as a
// corrupted or misdirected message already does. This is what makes a
// bundle a real "garlic" rather than a single onion stream: an observer
// who can't decrypt any entry has no way to tell how many of them, if
// any, are real. See docs/garlic-protocol.md §7 and Bundle's own doc
// comment. Returns every non-drop action found, in bundle order; a
// caller acts on each independently (deliver locally, or forward - to
// potentially different next hops, since bundled entries need not
// belong to the same circuit).
func (g *Garlic) processCircuitDataBundle(body []byte) []circuitAction {
	bundle, err := UnmarshalBundle(body)
	if err != nil {
		return nil
	}
	var actions []circuitAction
	for _, sub := range bundle.Messages {
		if action := g.processCircuitData(sub, msgTypeCircuitData); action.kind != actionDrop {
			actions = append(actions, action)
		}
	}
	return actions
}

// processCapabilityRequest returns the marshaled CapabilityMessage this
// node advertises in response to a capability request. It performs no I/O.
func (g *Garlic) processCapabilityRequest() []byte {
	msg := &CapabilityMessage{
		Versions:  []string{CapabilityGarlicV2, CapabilityGarlicV3, CapabilityAutoCircuit, CapabilitySites},
		PublicKey: g.identity.PublicKey,
	}
	// A fixed, well-formed message built from this node's own identity
	// can't fail to marshal (both fields are always within bounds), so a
	// marshal error here would indicate a bug rather than bad input.
	payload, err := msg.Marshal()
	if err != nil {
		panic("garlic: failed to marshal own capability message: " + err.Error())
	}
	return payload
}
