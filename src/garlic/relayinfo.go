package garlic

// Signed relay information. A public relay advertises its current onion
// key (the X25519 key originators use for per-hop ECDH) and protocol
// versions in a RelayInfo signed by its own Yggdrasil node key. Because the
// binding "node key -> onion key" is signed, it can travel through gossip,
// directory referrals and site descriptors and still be verified by anyone.
// An originator therefore never needs to contact a middle or terminal hop
// before building a circuit through it: only the trusted first hop ever
// sees the originator's own node key.
//
// Onion keys rotate (see onionkeys.go). ExpiresAt is the moment the relay
// deletes the matching private key, so a RelayInfo is only usable for a
// circuit that ends comfortably before ExpiresAt (see usableRelayInfo).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const (
	relayInfoVersion1 = 1
	// relayInfoDomain separates RelayInfo statements from every other
	// statement signed with core.Core.SignGarlic.
	relayInfoDomain = "relay-info-v1\x00"
	// maxRelayInfoLifetime bounds ExpiresAt-PublishedAt so a relay cannot
	// advertise one onion key "forever" and defeat rotation.
	maxRelayInfoLifetime = 7 * 24 * 60 * 60
	// relayInfoClockSkew tolerates small clock differences between nodes.
	relayInfoClockSkew = 5 * 60
	maxRelayInfoSize   = 1024
)

var (
	ErrRelayInfoTruncated = errors.New("garlic: relay info truncated")
	ErrRelayInfoVersion   = errors.New("garlic: unsupported relay info version")
	ErrRelayInfoSignature = errors.New("garlic: relay info signature invalid")
	ErrRelayInfoExpired   = errors.New("garlic: relay info expired or not yet valid")
	ErrRelayInfoLifetime  = errors.New("garlic: relay info lifetime too long")
	ErrRelayInfoOnionKey  = errors.New("garlic: relay info has no valid onion key")
	ErrRelayInfoWrongNode = errors.New("garlic: relay info belongs to a different node")
	ErrRelayInfoTooLarge  = errors.New("garlic: relay info too large")
)

// RelayInfo is a relay's signed self-description.
type RelayInfo struct {
	NodeKey     ed25519.PublicKey
	Capability  CapabilityMessage // Versions + current onion PublicKey
	PublishedAt uint64
	ExpiresAt   uint64
	Signature   []byte
}

func (r *RelayInfo) signedBytes() ([]byte, error) {
	if len(r.NodeKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidSigningKeySize
	}
	capability, err := r.Capability.Marshal()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 1+ed25519.PublicKeySize+16+2+len(capability))
	buf = append(buf, relayInfoVersion1)
	buf = append(buf, r.NodeKey...)
	buf = binary.BigEndian.AppendUint64(buf, r.PublishedAt)
	buf = binary.BigEndian.AppendUint64(buf, r.ExpiresAt)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(capability)))
	buf = append(buf, capability...)
	return buf, nil
}

// Marshal returns the wire encoding: signedBytes || signature(64).
func (r *RelayInfo) Marshal() ([]byte, error) {
	b, err := r.signedBytes()
	if err != nil {
		return nil, err
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return nil, ErrRelayInfoSignature
	}
	return append(b, r.Signature...), nil
}

// UnmarshalRelayInfo parses (but does not verify) a RelayInfo.
func UnmarshalRelayInfo(data []byte) (*RelayInfo, error) {
	if len(data) > maxRelayInfoSize {
		return nil, ErrRelayInfoTooLarge
	}
	const fixed = 1 + ed25519.PublicKeySize + 16 + 2
	if len(data) < fixed+ed25519.SignatureSize {
		return nil, ErrRelayInfoTruncated
	}
	if data[0] != relayInfoVersion1 {
		return nil, ErrRelayInfoVersion
	}
	r := &RelayInfo{NodeKey: bytes.Clone(data[1 : 1+ed25519.PublicKeySize])}
	rest := data[1+ed25519.PublicKeySize:]
	r.PublishedAt = binary.BigEndian.Uint64(rest[:8])
	r.ExpiresAt = binary.BigEndian.Uint64(rest[8:16])
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if n+ed25519.SignatureSize != len(rest) {
		return nil, ErrRelayInfoTruncated
	}
	capability, err := UnmarshalCapabilityMessage(rest[:n])
	if err != nil {
		return nil, err
	}
	r.Capability = *capability
	r.Signature = bytes.Clone(rest[n:])
	return r, nil
}

// signRelayInfo signs r with the node's Yggdrasil key via c.
func signRelayInfo(c *core.Core, r *RelayInfo) error {
	return signRelayInfoWith(c.SignGarlic, r)
}

// signRelayInfoWith signs r using sign, which must implement
// core.Core.SignGarlic's domain-separated signature.
func signRelayInfoWith(sign func([]byte) []byte, r *RelayInfo) error {
	b, err := r.signedBytes()
	if err != nil {
		return err
	}
	r.Signature = sign(append([]byte(relayInfoDomain), b...))
	return nil
}

// VerifyRelayInfo checks the signature, lifetime and validity window of r
// at time now (unix seconds).
func VerifyRelayInfo(r *RelayInfo, now uint64) error {
	b, err := r.signedBytes()
	if err != nil {
		return err
	}
	msg := make([]byte, 0, len(core.GarlicSignaturePrefix)+len(relayInfoDomain)+len(b))
	msg = append(msg, core.GarlicSignaturePrefix...)
	msg = append(msg, relayInfoDomain...)
	msg = append(msg, b...)
	if len(r.Signature) != ed25519.SignatureSize || !ed25519.Verify(r.NodeKey, msg, r.Signature) {
		return ErrRelayInfoSignature
	}
	if r.ExpiresAt < r.PublishedAt || r.ExpiresAt-r.PublishedAt > maxRelayInfoLifetime {
		return ErrRelayInfoLifetime
	}
	if r.PublishedAt > now+relayInfoClockSkew || now > r.ExpiresAt {
		return ErrRelayInfoExpired
	}
	if len(r.Capability.PublicKey) != KeySize {
		return ErrRelayInfoOnionKey
	}
	return nil
}

// parseVerifiedRelayInfo parses and verifies raw, optionally requiring it
// to belong to node (nil skips that check).
func parseVerifiedRelayInfo(raw []byte, node []byte) (*RelayInfo, error) {
	r, err := UnmarshalRelayInfo(raw)
	if err != nil {
		return nil, err
	}
	if node != nil && !bytes.Equal(r.NodeKey, node) {
		return nil, ErrRelayInfoWrongNode
	}
	if err := VerifyRelayInfo(r, uint64(time.Now().Unix())); err != nil {
		return nil, err
	}
	return r, nil
}

// usableUntil is the latest moment a circuit may be created with this
// relay's onion key: the key must outlive the circuit and every packet in
// flight on it.
func (g *Garlic) usableUntil(expiresAt uint64) time.Time {
	return time.Unix(int64(expiresAt), 0).Add(-(g.cfg.CircuitLifetime + g.cfg.PacketTTL + time.Minute))
}
