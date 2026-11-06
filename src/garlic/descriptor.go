package garlic

// Signed service descriptors (Part 3 of the hardening task): the
// authenticated binding between a GID and the introduction points a
// client should trust for it. A Rendezvous implementation is untrusted
// storage/relay - it can withhold, reorder, or serve a stale copy, but
// it cannot forge a descriptor for a GID it doesn't hold the signing
// key for, because the GID is derived from the signing public key
// (self-certifying, ComputeGID) and the descriptor is Ed25519-signed by
// that same key. See docs/superpowers/specs/
// 2026-08-09-garlic-crypto-hardening-design.md section D for the full
// rationale, in particular what is and isn't part of the signed
// payload - no rendezvous-added metadata is ever signed.

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

const (
	maxServiceIDSize = 64
	// MaxDescriptorLifetime bounds ExpiresAt-PublishedAt (seconds) so a
	// service can't mint a descriptor "valid" for an unreasonable span.
	MaxDescriptorLifetime = 7 * 24 * 60 * 60
)

const ServiceDescriptorVersion1 uint8 = 1

// ServiceDescriptorVersion2 adds each introduction relay's signed
// RelayInfo, so clients never contact the relay before building a circuit.
const ServiceDescriptorVersion2 uint8 = 2

var (
	ErrServiceIDTooLarge            = errors.New("garlic: service ID exceeds maximum size")
	ErrUnsupportedDescriptorVersion = errors.New("garlic: unsupported service descriptor version")
	ErrInvalidSigningKeySize        = errors.New("garlic: invalid signing public key size")
	ErrDescriptorLifetimeTooLong    = errors.New("garlic: service descriptor lifetime exceeds maximum")
	ErrInvalidDescriptorSignature   = errors.New("garlic: service descriptor signature invalid")
	ErrDescriptorGIDMismatch        = errors.New("garlic: service descriptor does not match requested GID")
	ErrDescriptorExpired            = errors.New("garlic: service descriptor expired")
	ErrDescriptorNotYetValid        = errors.New("garlic: service descriptor published in the future")
	ErrDescriptorTruncated          = errors.New("garlic: service descriptor truncated")
)

// ServiceDescriptor is the signed, self-certifying binding between a
// service's GID and its current introduction points.
type ServiceDescriptor struct {
	Version          uint8
	ServicePublicKey ed25519.PublicKey // GID = ComputeGID(ServicePublicKey, ServiceID)
	ServiceID        []byte
	IntroPoints      []IntroPoint
	PublishedAt      uint64
	ExpiresAt        uint64
	Signature        []byte // ed25519, over signedBytes()
}

// signedBytes returns the descriptor's canonical encoding with
// Signature omitted - exactly what SignServiceDescriptor signs and what
// VerifyServiceDescriptor re-derives from a received descriptor to
// check the signature against. No field the rendezvous itself might add
// (receipt timestamps, sequence numbers, storage hints) is ever part of
// this encoding.
func (d *ServiceDescriptor) signedBytes() ([]byte, error) {
	if len(d.ServicePublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidSigningKeySize
	}
	if len(d.ServiceID) > maxServiceIDSize {
		return nil, ErrServiceIDTooLarge
	}
	if len(d.IntroPoints) > MaxIntroPoints {
		return nil, ErrTooManyIntroPoints
	}

	buf := []byte{d.Version}
	buf = append(buf, d.ServicePublicKey...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(d.ServiceID)))
	buf = append(buf, d.ServiceID...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(d.IntroPoints)))
	for _, p := range d.IntroPoints {
		if len(p.NodeKey) > maxCapabilityKeyLen {
			return nil, ErrCapabilityKeyTooLong
		}
		buf = append(buf, byte(len(p.NodeKey)))
		buf = append(buf, p.NodeKey...)
		if d.Version >= ServiceDescriptorVersion2 {
			if len(p.RelayInfo) > maxRelayInfoSize {
				return nil, ErrRelayInfoTooLarge
			}
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.RelayInfo)))
			buf = append(buf, p.RelayInfo...)
		}
	}
	buf = binary.BigEndian.AppendUint64(buf, d.PublishedAt)
	buf = binary.BigEndian.AppendUint64(buf, d.ExpiresAt)
	return buf, nil
}

// unmarshalServiceDescriptorFields parses the signedBytes() encoding
// back into field values, without a Signature (there is none in that
// encoding) or version-specific dispatch beyond checking Version. This
// exists for fuzz coverage of the encoding's bounds-checking - nothing
// in this package currently deserializes a ServiceDescriptor from raw
// bytes in production (descriptors flow through Rendezvous as Go
// structs, not wire bytes), but the encoding shares the same untrusted-
// length-prefix shape as every parser in this package that does, so it
// gets the same fuzz discipline.
func unmarshalServiceDescriptorFields(data []byte) (*ServiceDescriptor, error) {
	if len(data) < 1+ed25519.PublicKeySize {
		return nil, ErrDescriptorTruncated
	}
	d := &ServiceDescriptor{Version: data[0]}
	if d.Version != ServiceDescriptorVersion1 && d.Version != ServiceDescriptorVersion2 {
		return nil, ErrUnsupportedDescriptorVersion
	}
	rest := data[1:]
	d.ServicePublicKey = append(ed25519.PublicKey(nil), rest[:ed25519.PublicKeySize]...)
	rest = rest[ed25519.PublicKeySize:]

	if len(rest) < 4 {
		return nil, ErrDescriptorTruncated
	}
	serviceIDLen := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if serviceIDLen > maxServiceIDSize {
		return nil, ErrServiceIDTooLarge
	}
	if uint64(serviceIDLen) > uint64(len(rest)) {
		return nil, ErrDescriptorTruncated
	}
	d.ServiceID = append([]byte(nil), rest[:serviceIDLen]...)
	rest = rest[serviceIDLen:]

	if len(rest) < 4 {
		return nil, ErrDescriptorTruncated
	}
	pointCount := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if pointCount > MaxIntroPoints {
		return nil, ErrTooManyIntroPoints
	}
	d.IntroPoints = make([]IntroPoint, 0, pointCount)
	for range pointCount {
		if len(rest) < 1 {
			return nil, ErrDescriptorTruncated
		}
		n := int(rest[0])
		rest = rest[1:]
		if n > maxCapabilityKeyLen {
			return nil, ErrCapabilityKeyTooLong
		}
		if n > len(rest) {
			return nil, ErrDescriptorTruncated
		}
		point := IntroPoint{NodeKey: append([]byte(nil), rest[:n]...)}
		rest = rest[n:]
		if d.Version >= ServiceDescriptorVersion2 {
			if len(rest) < 2 {
				return nil, ErrDescriptorTruncated
			}
			m := int(binary.BigEndian.Uint16(rest[:2]))
			rest = rest[2:]
			if m > maxRelayInfoSize {
				return nil, ErrRelayInfoTooLarge
			}
			if m > len(rest) {
				return nil, ErrDescriptorTruncated
			}
			if m > 0 {
				point.RelayInfo = append([]byte(nil), rest[:m]...)
			}
			rest = rest[m:]
		}
		d.IntroPoints = append(d.IntroPoints, point)
	}

	if len(rest) < 16 {
		return nil, ErrDescriptorTruncated
	}
	d.PublishedAt = binary.BigEndian.Uint64(rest[:8])
	d.ExpiresAt = binary.BigEndian.Uint64(rest[8:16])
	return d, nil
}

// SignServiceDescriptor builds and signs a ServiceDescriptor for
// serviceID/introPoints, valid from publishedAt to expiresAt (span
// capped at MaxDescriptorLifetime), using signingPrivateKey.
func SignServiceDescriptor(signingPublicKey ed25519.PublicKey, signingPrivateKey ed25519.PrivateKey, serviceID []byte, introPoints []IntroPoint, publishedAt, expiresAt uint64) (*ServiceDescriptor, error) {
	if expiresAt < publishedAt || expiresAt-publishedAt > MaxDescriptorLifetime {
		return nil, ErrDescriptorLifetimeTooLong
	}
	d := &ServiceDescriptor{
		Version:          ServiceDescriptorVersion2,
		ServicePublicKey: signingPublicKey,
		ServiceID:        serviceID,
		IntroPoints:      introPoints,
		PublishedAt:      publishedAt,
		ExpiresAt:        expiresAt,
	}
	toSign, err := d.signedBytes()
	if err != nil {
		return nil, err
	}
	d.Signature = ed25519.Sign(signingPrivateKey, toSign)
	return d, nil
}

// VerifyServiceDescriptor checks that d is a validly-signed descriptor
// for gid, with a lifetime within MaxDescriptorLifetime, published no
// later than now, and not expired as of now. This is the client-side
// trust boundary: Rendezvous.Lookup returns d unverified (the
// rendezvous is untrusted), and every caller of Lookup must run the
// result through this before trusting d.IntroPoints.
//
// The lifetime check is enforced here, not just in the
// SignServiceDescriptor convenience constructor, because
// SignServiceDescriptor is not the only way to produce a
// *ServiceDescriptor: a service holding its own signing key could build
// one directly and call ed25519.Sign on it, bypassing
// SignServiceDescriptor's cap entirely. Checking here is what actually
// stops a self-signed, unreasonably-long-lived descriptor from being
// trusted.
func VerifyServiceDescriptor(d *ServiceDescriptor, gid GID, now uint64) error {
	if d.Version != ServiceDescriptorVersion1 && d.Version != ServiceDescriptorVersion2 {
		return ErrUnsupportedDescriptorVersion
	}
	if ComputeGID(d.ServicePublicKey, d.ServiceID) != gid {
		return ErrDescriptorGIDMismatch
	}
	toVerify, err := d.signedBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(d.ServicePublicKey, toVerify, d.Signature) {
		return ErrInvalidDescriptorSignature
	}
	if d.ExpiresAt < d.PublishedAt || d.ExpiresAt-d.PublishedAt > MaxDescriptorLifetime {
		return ErrDescriptorLifetimeTooLong
	}
	// Host, directory relays and clients each check against their own
	// clock. Without a tolerance, a host whose clock ran a second ahead of a
	// relay's had every record refused, and a client whose clock lagged
	// dropped every fresh record, as if the site was not published at all.
	if d.PublishedAt > now+descriptorClockSkew {
		return ErrDescriptorNotYetValid
	}
	if descriptorExpired(d, now) {
		return ErrDescriptorExpired
	}
	return nil
}

// descriptorClockSkew is the clock difference between nodes tolerated
// when checking a descriptor's validity window (as for RelayInfo).
const descriptorClockSkew = relayInfoClockSkew

func descriptorExpired(d *ServiceDescriptor, now uint64) bool {
	return now > d.ExpiresAt+descriptorClockSkew
}
