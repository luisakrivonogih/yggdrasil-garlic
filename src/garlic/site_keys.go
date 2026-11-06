package garlic

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Every hosted site signs with its own key. A site's descriptor, TLS
// certificate and relay registration carry only that key, so two sites of
// the same node share no key material anyone else can see: they cannot be
// linked to each other, or to this node, cryptographically.
//
// The keys are derived from the node's Garlic.SigningPrivateKey and the
// site's Name (and optional ServiceID) with HKDF-SHA256, so the config only
// needs a name per site and every domain stays stable for as long as the
// signing key and the name stay the same. Without the signing key the
// derived keys are independent random-looking keys; whoever holds the
// signing key can link all of them, so it must stay secret.

const siteKeyInfo = "yggdrasil-garlic-site-key-v1\x00"

// MaxSiteNameSize bounds a site's Name.
const MaxSiteNameSize = 64

var ErrSiteNameTooLong = errors.New("garlic: site name too long")

// SiteSigningKey returns the signing key of the site called name. The
// unnamed site without a ServiceID is the node's default domain and uses
// the signing key itself (its domain predates per-site keys).
func SiteSigningKey(signing ed25519.PrivateKey, name string, serviceID []byte) (ed25519.PrivateKey, error) {
	if len(name) > MaxSiteNameSize {
		return nil, ErrSiteNameTooLong
	}
	if len(serviceID) > maxServiceIDSize {
		return nil, ErrServiceIDTooLarge
	}
	if name == "" && len(serviceID) == 0 {
		return signing, nil
	}
	info := make([]byte, 0, len(siteKeyInfo)+2+len(name)+len(serviceID))
	info = append(info, siteKeyInfo...)
	info = binary.BigEndian.AppendUint16(info, uint16(len(name)))
	info = append(info, name...)
	info = append(info, serviceID...)
	seed, err := hkdf.Key(sha256.New, signing.Seed(), nil, string(info), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SiteGID returns the GID (and so the domain) of this node's site called
// name, with an optional ServiceID.
func (g *Garlic) SiteGID(name string, serviceID []byte) (GID, error) {
	key, err := SiteSigningKey(g.identity.SigningPrivateKey, name, serviceID)
	if err != nil {
		return GID{}, err
	}
	return ComputeGID(key.Public().(ed25519.PublicKey), serviceID), nil
}
