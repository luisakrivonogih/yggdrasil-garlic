package garlic

import (
	"errors"
	"fmt"
	"strings"
)

// DomainSuffix reserves the automatic, self-certifying service namespace.
// Human-readable names directly under .yggg belong to a separate, future
// registration protocol; they must never be interpreted as hash addresses.
const DomainSuffix = ".domains.yggg"

const domainLabelLength = (len(GID{})*8 + 4) / 5

var ErrInvalidDomain = errors.New("garlic: invalid hash domain")

// Domain returns the lowercase DNS name for this GID. The 53-character
// unpadded base32 label includes the GID version and its full 256-bit hash.
func (g GID) Domain() string {
	return strings.ToLower(g.String()) + DomainSuffix
}

// ParseDomain accepts exactly <gid>.domains.yggg, case-insensitively, with
// an optional DNS root dot. It accepts hostnames, not URLs, host:port pairs,
// subdomains or human-readable .yggg registrations. Re-encoding rejects
// nonzero unused base32 bits, ensuring one label per GID modulo DNS case.
func ParseDomain(domain string) (GID, error) {
	if len(domain) != domainLabelLength+len(DomainSuffix) &&
		len(domain) != domainLabelLength+len(DomainSuffix)+1 {
		return GID{}, ErrInvalidDomain
	}
	for i := range len(domain) {
		if domain[i] >= 0x80 {
			return GID{}, ErrInvalidDomain
		}
	}
	name := strings.ToLower(strings.TrimSuffix(domain, "."))
	if !strings.HasSuffix(name, DomainSuffix) {
		return GID{}, ErrInvalidDomain
	}
	label := strings.TrimSuffix(name, DomainSuffix)
	if len(label) != domainLabelLength {
		return GID{}, ErrInvalidDomain
	}
	for i := range len(label) {
		if !((label[i] >= 'a' && label[i] <= 'z') || (label[i] >= '2' && label[i] <= '7')) {
			return GID{}, ErrInvalidDomain
		}
	}
	gid, err := ParseGID(strings.ToUpper(label))
	if err != nil {
		return GID{}, fmt.Errorf("%w: %w", ErrInvalidDomain, err)
	}
	if gid.Domain() != name {
		return GID{}, ErrInvalidDomain
	}
	return gid, nil
}

// LookupDomain resolves a hash domain through the existing rendezvous and
// verifies the descriptor's signature, GID binding and expiry before
// returning introduction points. This does not map names to node IPv6s.
func (g *Garlic) LookupDomain(domain string) ([]IntroPoint, error) {
	gid, err := ParseDomain(domain)
	if err != nil {
		return nil, err
	}
	return g.LookupService(gid)
}
