package garlic

// Garlic Service ID (Phase 10 of the roadmap, see
// docs/garlic-architecture.md §3.8): a self-certifying identifier,
// computable by anyone who knows a service's Garlic public key and
// service ID, that never reveals or derives from the underlying
// Yggdrasil IPv6 address (address.AddrForKey/GetKey are untouched - this
// is a wholly separate namespace).

import (
	"crypto/ed25519"
	"encoding/base32"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
)

// GIDVersion1: a BLAKE2b-256 digest of the site key and service ID.
const GIDVersion1 uint8 = 1

// GIDVersion2: the site's Ed25519 public key itself, so that clients can
// derive the per-day blinded keys its descriptors are stored under in the
// directory (see blind.go). Directory nodes never see such a GID.
const GIDVersion2 uint8 = 2

// ComputeGIDv2 returns the version 2 GID of a site key.
func ComputeGIDv2(publicKey ed25519.PublicKey) GID {
	var g GID
	g[0] = GIDVersion2
	copy(g[1:], publicKey)
	return g
}

const gidDomainSeparator = "yggdrasil-garlic-v1-gid"

// GID is a canonical, fixed-size Garlic Service ID: a version byte
// followed by a 32-byte BLAKE2b-256 digest.
type GID [1 + 32]byte

var (
	ErrInvalidGIDLength      = errors.New("garlic: invalid GID length")
	ErrUnsupportedGIDVersion = errors.New("garlic: unsupported GID version")
)

var gidEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ComputeGID computes the canonical GID for a service identified by
// publicKey (its Garlic identity public key) and serviceID (an
// application-chosen identifier distinguishing multiple services under
// the same key).
func ComputeGID(publicKey, serviceID []byte) GID {
	h, _ := blake2b.New256(nil)
	_, _ = h.Write([]byte(gidDomainSeparator))
	_, _ = h.Write(publicKey)
	_, _ = h.Write(serviceID)
	sum := h.Sum(nil)

	var g GID
	g[0] = GIDVersion1
	copy(g[1:], sum)
	return g
}

// String returns the GID's canonical (unpadded base32) encoding.
func (g GID) String() string {
	return gidEncoding.EncodeToString(g[:])
}

// ParseGID parses a GID from its canonical string encoding, rejecting
// malformed input and unsupported versions.
func ParseGID(s string) (GID, error) {
	b, err := gidEncoding.DecodeString(s)
	if err != nil {
		return GID{}, err
	}
	if len(b) != len(GID{}) {
		return GID{}, ErrInvalidGIDLength
	}
	var g GID
	copy(g[:], b)
	switch g[0] {
	case GIDVersion1:
	case GIDVersion2:
		if _, err := new(edwards25519.Point).SetBytes(g[1:]); err != nil {
			return GID{}, ErrInvalidGIDLength
		}
	default:
		return GID{}, ErrUnsupportedGIDVersion
	}
	return g, nil
}
