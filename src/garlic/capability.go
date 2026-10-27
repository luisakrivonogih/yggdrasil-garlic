package garlic

// Capability negotiation message format (Phase 6 of the roadmap, see
// docs/garlic-architecture.md §3.4): an in-band request/response,
// structurally mirroring how src/core's own NodeInfo protocol works,
// reaching any node by key regardless of hop count. A node that never
// responds (or responds without CapabilityGarlicV2) is treated as
// legacy and never selected as a circuit hop or rendezvous point - see
// (*Garlic) in manager.go for the request/response exchange itself; this
// file is only the wire message the two sides exchange.

import "errors"

// CapabilityGarlicV2 is the capability string a Garlic-v2-capable node
// advertises. Bumped from garlic-v1 as part of the crypto hardening
// pass (per-hop ephemeral keys, wider CircuitID, new HKDF labels) - see
// docs/superpowers/specs/2026-08-09-garlic-crypto-hardening-design.md.
// There is deliberately no v1/v2 dual negotiation: a peer that doesn't
// advertise garlic-v2 is treated as legacy and never selected as a
// circuit hop or rendezvous point.
const CapabilityGarlicV2 = "garlic-v2"

// CapabilityGarlicV3 is advertised by a node whose code understands the
// hop-local envelope format (EnvelopeVersion2, src/garlic/envelope.go) -
// see docs/superpowers/specs/2026-08-24-garlic-hop-local-metadata-design.md.
// This name is unrelated to msgTypeCircuitDataV3 (src/garlic/protocol.go,
// the auto-pool cover-traffic wire tag from the autonomous-routing work) -
// the two "v3"s are two entirely different, coincidentally-numbered
// version counters. A node that hasn't advertised garlic-v3 is never
// selected as a hop for a circuit this node originates (manager.go's
// CreateCircuit) - new circuits are always built in the hop-local format
// once available, never intentionally falling back to garlic-v2's global
// CircuitID/PacketCounter/Expiration.
const CapabilityGarlicV3 = "garlic-v3"

// CapabilityAutoCircuit is advertised by a node whose code understands
// the auto-pool wire path (msgTypeAnnounceRequest, msgTypeCircuitDataV3
// - see protocol.go) - independent of whether this operator has chosen
// to originate auto-pool circuits or cover traffic themselves
// (Config.AutoPoolEnabled/CoverTrafficEnabled). Every position in an
// auto-built circuit, not just the terminal hop, must advertise this
// before being selected - see
// docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md
// §8 for why the compatibility argument requires gating every position.
const CapabilityAutoCircuit = "garlic-v2-auto"

// CapabilitySites gates every hop of bidirectional site circuits and the
// distributed descriptor protocol. Legacy circuits keep their wire format.
const CapabilitySites = "garlic-sites-v1"

const (
	maxCapabilityVersions   = 16
	maxCapabilityVersionLen = 32
	maxCapabilityKeyLen     = 64
)

var (
	ErrTooManyCapabilityVersions  = errors.New("garlic: too many capability versions")
	ErrCapabilityVersionTooLong   = errors.New("garlic: capability version string too long")
	ErrCapabilityKeyTooLong       = errors.New("garlic: capability public key too long")
	ErrCapabilityMessageTruncated = errors.New("garlic: capability message truncated")
)

// CapabilityMessage is what a node advertises about itself: which
// protocol versions it supports, and (if any) its Garlic identity public
// key, so a peer that decides to use it as a circuit hop already has the
// key it needs for per-hop ECDH.
type CapabilityMessage struct {
	Versions  []string
	PublicKey []byte
}

// SupportsGarlicV2 reports whether the message advertises
// CapabilityGarlicV2.
func (m *CapabilityMessage) SupportsGarlicV2() bool {
	for _, v := range m.Versions {
		if v == CapabilityGarlicV2 {
			return true
		}
	}
	return false
}

// SupportsGarlicV3 reports whether the message advertises
// CapabilityGarlicV3.
func (m *CapabilityMessage) SupportsGarlicV3() bool {
	for _, v := range m.Versions {
		if v == CapabilityGarlicV3 {
			return true
		}
	}
	return false
}

// SupportsAutoCircuit reports whether the message advertises
// CapabilityAutoCircuit.
func (m *CapabilityMessage) SupportsAutoCircuit() bool {
	for _, v := range m.Versions {
		if v == CapabilityAutoCircuit {
			return true
		}
	}
	return false
}

// Marshal encodes the message as: version_count(1), then per version
// len(1)+bytes, then key_len(1)+bytes.
func (m *CapabilityMessage) Marshal() ([]byte, error) {
	if len(m.Versions) > maxCapabilityVersions {
		return nil, ErrTooManyCapabilityVersions
	}
	if len(m.PublicKey) > maxCapabilityKeyLen {
		return nil, ErrCapabilityKeyTooLong
	}
	var buf []byte
	buf = append(buf, byte(len(m.Versions)))
	for _, v := range m.Versions {
		if len(v) > maxCapabilityVersionLen {
			return nil, ErrCapabilityVersionTooLong
		}
		buf = append(buf, byte(len(v)))
		buf = append(buf, v...)
	}
	buf = append(buf, byte(len(m.PublicKey)))
	buf = append(buf, m.PublicKey...)
	return buf, nil
}

// UnmarshalCapabilityMessage decodes a message produced by Marshal, never
// trusting a declared count or length before validating it against both
// the configured maximum and the bytes actually remaining.
func UnmarshalCapabilityMessage(data []byte) (*CapabilityMessage, error) {
	if len(data) < 1 {
		return nil, ErrCapabilityMessageTruncated
	}
	n := int(data[0])
	if n > maxCapabilityVersions {
		return nil, ErrTooManyCapabilityVersions
	}
	rest := data[1:]

	versions := make([]string, 0, n)
	for range n {
		if len(rest) < 1 {
			return nil, ErrCapabilityMessageTruncated
		}
		vlen := int(rest[0])
		rest = rest[1:]
		if vlen > maxCapabilityVersionLen {
			return nil, ErrCapabilityVersionTooLong
		}
		if vlen > len(rest) {
			return nil, ErrCapabilityMessageTruncated
		}
		versions = append(versions, string(rest[:vlen]))
		rest = rest[vlen:]
	}

	if len(rest) < 1 {
		return nil, ErrCapabilityMessageTruncated
	}
	klen := int(rest[0])
	rest = rest[1:]
	if klen > maxCapabilityKeyLen {
		return nil, ErrCapabilityKeyTooLong
	}
	if klen > len(rest) {
		return nil, ErrCapabilityMessageTruncated
	}
	pub := append([]byte(nil), rest[:klen]...)

	return &CapabilityMessage{Versions: versions, PublicKey: pub}, nil
}
