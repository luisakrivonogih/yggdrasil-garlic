package garlic

// Layered (onion) encryption on top of the single-layer AEAD primitives in
// crypto.go (Phase 4 of the roadmap). A hop can only recover its own
// LayerPlaintext - it never sees the plaintext of any layer further in,
// and it never sees which hops came before it. This file does not decide
// how per-hop keys are established for a real circuit (that's circuit
// construction, Phase 5) - it takes already-derived per-hop keys as input.

import (
	"encoding/binary"
	"errors"
)

// MaxNextHopSize and MaxLayerInnerSize bound LayerPlaintext's variable
// fields, for the same reason Envelope bounds Body/Padding: a declared
// length must be rejected before it drives an allocation, not merely once
// it exceeds the buffer. MaxLayerInnerSize matches MaxBodySize, since Inner
// is either an application payload or another layer's ciphertext, and both
// ultimately travel inside an Envelope.Body.
const (
	MaxNextHopSize    = 256
	MaxLayerInnerSize = MaxBodySize
)

var (
	ErrEmptyPath                     = errors.New("garlic: onion path must have at least one hop")
	ErrLayerTooShort                 = errors.New("garlic: layer plaintext shorter than fixed header")
	ErrLayerTruncated                = errors.New("garlic: layer plaintext truncated")
	ErrNextHopTooLarge               = errors.New("garlic: next-hop field exceeds maximum size")
	ErrLayerInnerTooLarge            = errors.New("garlic: layer inner field exceeds maximum size")
	ErrInvalidNextHopEphemeralSize   = errors.New("garlic: next-hop ephemeral key has invalid size")
	ErrInvalidNextHopEphemeralFlag   = errors.New("garlic: invalid next-hop-ephemeral presence flag")
	ErrInvalidNextLocalCircuitIDSize = errors.New("garlic: next-local circuit ID has invalid size")
	ErrInvalidNextLocalFlag          = errors.New("garlic: invalid next-local-metadata presence flag")
	ErrLegExpirationCountMismatch    = errors.New("garlic: leg expiration count does not match hop count")
)

// Hop is one hop of a path used to build an onion (see BuildOnion). Key
// and Counter must follow Seal's nonce-reuse rules: Key must be unique to
// this hop within this circuit, and Counter must never repeat under that
// Key.
type Hop struct {
	NodeKey          []byte    // this hop's Yggdrasil public key (routing address)
	Key              []byte    // per-hop symmetric key, already derived (e.g. via ECDH + deriveLayerKey)
	ReplyKey         []byte    // independent reverse-direction key; only used by duplex circuits
	Counter          uint64    // nonce/replay counter for this hop's layer
	NextEphemeralPub []byte    // ephemeral X25519 pubkey for the hop that follows this one; nil for the final hop
	LocalCircuitID   CircuitID // this hop's own leg identifier for the hop-local envelope format (EnvelopeVersion2) - the CircuitID this hop is told to expect on its incoming leg. Unused by the legacy (EnvelopeVersion1) format.
}

// LayerPlaintext is what a hop recovers after decrypting its layer:
// either forwarding instructions (NextHop and NextHopEphemeral set,
// Inner is the ciphertext to forward there) or, for the final hop, the
// delivered payload (NextHop and NextHopEphemeral both empty, Inner is
// the payload itself). NextHopEphemeral only ever becomes visible to
// the hop that decrypts this exact layer - see docs/superpowers/specs/
// 2026-08-09-garlic-crypto-hardening-design.md section A for why this
// is what gives non-adjacent hops no ephemeral key in common.
type LayerPlaintext struct {
	NextHop          []byte
	NextHopEphemeral []byte
	Inner            []byte
	// NextLocalCircuitID/NextLocalCounter/NextLocalExpiration are set only
	// by the hop-local marshal/unmarshal pair (marshalHopLocal/
	// unmarshalLayerPlaintextHopLocal), for a non-terminal hop: the
	// CircuitID/PacketCounter/Expiration this hop must write into the
	// outgoing Envelope when it forwards to NextHop. Never set by the
	// legacy marshal/unmarshal pair. See
	// docs/superpowers/specs/2026-08-24-garlic-hop-local-metadata-design.md.
	NextLocalCircuitID  []byte
	NextLocalCounter    uint64
	NextLocalExpiration uint64
}

func (l *LayerPlaintext) marshal() ([]byte, error) {
	if len(l.NextHop) > MaxNextHopSize {
		return nil, ErrNextHopTooLarge
	}
	if len(l.NextHopEphemeral) != 0 && len(l.NextHopEphemeral) != KeySize {
		return nil, ErrInvalidNextHopEphemeralSize
	}
	if len(l.Inner) > MaxLayerInnerSize {
		return nil, ErrLayerInnerTooLarge
	}
	buf := make([]byte, 0, 4+len(l.NextHop)+1+len(l.NextHopEphemeral)+4+len(l.Inner))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(l.NextHop)))
	buf = append(buf, l.NextHop...)
	if len(l.NextHopEphemeral) == KeySize {
		buf = append(buf, 1)
		buf = append(buf, l.NextHopEphemeral...)
	} else {
		buf = append(buf, 0)
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(l.Inner)))
	buf = append(buf, l.Inner...)
	return buf, nil
}

// marshalHopLocal encodes the same legacy prefix marshal already
// produces, followed by a hasNextLocal(1) flag and, if
// NextLocalCircuitID is set, NextLocalCircuitID(16) NextLocalCounter(8)
// NextLocalExpiration(8).
func (l *LayerPlaintext) marshalHopLocal() ([]byte, error) {
	prefix, err := l.marshal()
	if err != nil {
		return nil, err
	}
	if len(l.NextLocalCircuitID) == 0 {
		return append(prefix, 0), nil
	}
	if len(l.NextLocalCircuitID) != 16 {
		return nil, ErrInvalidNextLocalCircuitIDSize
	}
	buf := make([]byte, 0, len(prefix)+1+16+8+8)
	buf = append(buf, prefix...)
	buf = append(buf, 1)
	buf = append(buf, l.NextLocalCircuitID...)
	buf = binary.BigEndian.AppendUint64(buf, l.NextLocalCounter)
	buf = binary.BigEndian.AppendUint64(buf, l.NextLocalExpiration)
	return buf, nil
}

func unmarshalLayerPlaintext(data []byte) (*LayerPlaintext, error) {
	l, _, err := parseLayerPlaintextPrefix(data)
	return l, err
}

// parseLayerPlaintextPrefix parses the NextHop/NextHopEphemeral/Inner
// prefix shared by both the legacy and hop-local LayerPlaintext wire
// shapes, returning any not-yet-parsed trailing bytes so each format's
// own unmarshal function can interpret them differently (nothing, for
// the legacy shape; NextLocalCircuitID/NextLocalCounter/
// NextLocalExpiration, for the hop-local shape). This is a pure refactor
// of what unmarshalLayerPlaintext already did inline - behavior for the
// legacy shape is unchanged, verified by the existing layer_test.go/
// FuzzLayerPlaintextUnmarshal suite passing unmodified.
func parseLayerPlaintextPrefix(data []byte) (*LayerPlaintext, []byte, error) {
	if len(data) < 4 {
		return nil, nil, ErrLayerTooShort
	}
	nextHopLen := binary.BigEndian.Uint32(data[:4])
	rest := data[4:]
	if nextHopLen > MaxNextHopSize {
		return nil, nil, ErrNextHopTooLarge
	}
	if uint64(nextHopLen) > uint64(len(rest)) {
		return nil, nil, ErrLayerTruncated
	}
	l := &LayerPlaintext{}
	if nextHopLen > 0 {
		l.NextHop = append([]byte(nil), rest[:nextHopLen]...)
	}
	rest = rest[nextHopLen:]

	if len(rest) < 1 {
		return nil, nil, ErrLayerTruncated
	}
	hasNextEphemeral := rest[0]
	rest = rest[1:]
	switch hasNextEphemeral {
	case 1:
		if uint64(KeySize) > uint64(len(rest)) {
			return nil, nil, ErrLayerTruncated
		}
		l.NextHopEphemeral = append([]byte(nil), rest[:KeySize]...)
		rest = rest[KeySize:]
	case 0:
		// no next-hop ephemeral key - terminal hop.
	default:
		return nil, nil, ErrInvalidNextHopEphemeralFlag
	}

	if len(rest) < 4 {
		return nil, nil, ErrLayerTruncated
	}
	innerLen := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if innerLen > MaxLayerInnerSize {
		return nil, nil, ErrLayerInnerTooLarge
	}
	if uint64(innerLen) > uint64(len(rest)) {
		return nil, nil, ErrLayerTruncated
	}
	if innerLen > 0 {
		l.Inner = append([]byte(nil), rest[:innerLen]...)
	}
	rest = rest[innerLen:]
	return l, rest, nil
}

// unmarshalLayerPlaintextHopLocal decodes a layer plaintext produced by
// marshalHopLocal: the legacy prefix, plus a trailing hasNextLocal(1)
// flag and, if set, NextLocalCircuitID(16) NextLocalCounter(8)
// NextLocalExpiration(8).
func unmarshalLayerPlaintextHopLocal(data []byte) (*LayerPlaintext, error) {
	l, rest, err := parseLayerPlaintextPrefix(data)
	if err != nil {
		return nil, err
	}
	if len(rest) < 1 {
		return nil, ErrLayerTruncated
	}
	hasNextLocal := rest[0]
	rest = rest[1:]
	switch hasNextLocal {
	case 1:
		const nextLocalSize = 16 + 8 + 8
		if len(rest) < nextLocalSize {
			return nil, ErrLayerTruncated
		}
		l.NextLocalCircuitID = append([]byte(nil), rest[:16]...)
		l.NextLocalCounter = binary.BigEndian.Uint64(rest[16:24])
		l.NextLocalExpiration = binary.BigEndian.Uint64(rest[24:32])
	case 0:
		// terminal hop - no next leg.
	default:
		return nil, ErrInvalidNextLocalFlag
	}
	return l, nil
}

// EncryptLayer encodes and encrypts layer under key/counter, producing the
// ciphertext a hop receives for this layer. See Seal for the nonce-reuse
// requirement on (key, counter).
func EncryptLayer(key []byte, counter uint64, layer *LayerPlaintext) ([]byte, error) {
	pt, err := layer.marshal()
	if err != nil {
		return nil, err
	}
	return Seal(key, counter, pt, nil)
}

// DecryptLayer decrypts and parses a layer ciphertext produced by
// EncryptLayer with the same key and counter.
func DecryptLayer(key []byte, counter uint64, ciphertext []byte) (*LayerPlaintext, error) {
	pt, err := Open(key, counter, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return unmarshalLayerPlaintext(pt)
}

// EncryptLayerHopLocal is EncryptLayer's counterpart for the hop-local
// format: same AEAD call, marshalHopLocal instead of marshal.
func EncryptLayerHopLocal(key []byte, counter uint64, layer *LayerPlaintext) ([]byte, error) {
	pt, err := layer.marshalHopLocal()
	if err != nil {
		return nil, err
	}
	return Seal(key, counter, pt, nil)
}

// DecryptLayerHopLocal is DecryptLayer's counterpart for the hop-local
// format: same AEAD call, unmarshalLayerPlaintextHopLocal instead of
// unmarshalLayerPlaintext.
func DecryptLayerHopLocal(key []byte, counter uint64, ciphertext []byte) (*LayerPlaintext, error) {
	pt, err := Open(key, counter, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return unmarshalLayerPlaintextHopLocal(pt)
}

// BuildOnion constructs a layered-encrypted onion for path hops, with
// payload as the innermost content. hops[0] is the first hop the sender
// transmits the returned ciphertext to; hops[len(hops)-1] is the final hop,
// which recovers payload with an empty NextHop. Each intermediate hop i
// recovers NextHop == hops[i+1].NodeKey and a still-encrypted Inner to
// forward there unchanged.
func BuildOnion(hops []Hop, payload []byte) ([]byte, error) {
	if len(hops) == 0 {
		return nil, ErrEmptyPath
	}

	inner := payload
	for i := len(hops) - 1; i >= 0; i-- {
		var nextHop []byte
		if i+1 < len(hops) {
			nextHop = hops[i+1].NodeKey
		}
		ct, err := EncryptLayer(hops[i].Key, hops[i].Counter, &LayerPlaintext{
			NextHop:          nextHop,
			NextHopEphemeral: hops[i].NextEphemeralPub,
			Inner:            inner,
		})
		if err != nil {
			return nil, err
		}
		inner = ct
	}
	return inner, nil
}

// BuildOnionHopLocal is BuildOnion's counterpart for the hop-local
// format. legExpirations must have exactly len(hops) entries:
// legExpirations[0] is the leg the caller (the circuit originator) writes
// directly into the first outer Envelope; legExpirations[i] for i>=1 is
// embedded into hop (i-1)'s layer as NextLocalExpiration, the value hop
// (i-1) must write when it forwards to hop i. hops[i].LocalCircuitID and
// hops[i].Counter (at call time) are embedded the same way, for i>=1, as
// NextLocalCircuitID/NextLocalCounter.
func BuildOnionHopLocal(hops []Hop, payload []byte, legExpirations []uint64) ([]byte, error) {
	if len(hops) == 0 {
		return nil, ErrEmptyPath
	}
	if len(legExpirations) != len(hops) {
		return nil, ErrLegExpirationCountMismatch
	}

	inner := payload
	for i := len(hops) - 1; i >= 0; i-- {
		layer := &LayerPlaintext{
			NextHopEphemeral: hops[i].NextEphemeralPub,
			Inner:            inner,
		}
		if i+1 < len(hops) {
			layer.NextHop = hops[i+1].NodeKey
			nextID := hops[i+1].LocalCircuitID
			layer.NextLocalCircuitID = nextID[:]
			layer.NextLocalCounter = hops[i+1].Counter
			layer.NextLocalExpiration = legExpirations[i+1]
		}
		ct, err := EncryptLayerHopLocal(hops[i].Key, hops[i].Counter, layer)
		if err != nil {
			return nil, err
		}
		inner = ct
	}
	return inner, nil
}
