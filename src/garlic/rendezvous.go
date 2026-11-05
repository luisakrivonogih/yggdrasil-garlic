package garlic

// Rendezvous abstraction (Phase 9 of the roadmap, extended by Part 3 of
// the crypto hardening pass): endpoint discovery decoupled from circuit
// construction. A Rendezvous implementation is untrusted storage/relay
// - it can withhold, reorder, or serve a stale descriptor, but every
// descriptor it hands back is independently verified by the caller
// (VerifyServiceDescriptor, descriptor.go) before its IntroPoints are
// trusted. A DHT-backed implementation is future work behind the same
// interface.

import (
	"errors"
	"sync"
)

// MaxIntroPoints bounds how many introduction points a single
// descriptor may list, so a remote publisher can't make a Rendezvous
// implementation store unbounded per-GID state.
const MaxIntroPoints = 16

var (
	ErrGIDNotFound        = errors.New("garlic: GID not found")
	ErrTooManyIntroPoints = errors.New("garlic: too many introduction points")
)

// IntroPoint is one introduction point for a Garlic service: a
// Garlic-capable node willing to forward circuit-extension requests to
// the service on its behalf, without itself being the service's
// Yggdrasil address.
type IntroPoint struct {
	NodeKey []byte
	// RelayInfo is the introduction relay's signed RelayInfo, so a client
	// can build a circuit to it without contacting it directly.
	RelayInfo []byte `json:",omitempty"`
}

// Rendezvous maps Garlic Service IDs (GID) to their current signed
// service descriptor.
type Rendezvous interface {
	// Publish advertises descriptor as gid's current service descriptor.
	// A later Publish for the same gid replaces the previous one.
	Publish(gid GID, descriptor *ServiceDescriptor) error
	// Lookup returns the currently-published descriptor for gid,
	// unverified - the caller must run it through
	// VerifyServiceDescriptor before trusting its IntroPoints. Returns
	// ErrGIDNotFound if nothing has been published for gid.
	Lookup(gid GID) (*ServiceDescriptor, error)
}

// StaticRendezvous is an in-memory Rendezvous implementation, suitable
// for local testing and small statically-configured deployments
// independent of any distributed directory. It performs no verification
// and no expiry enforcement of its own - see Lookup's doc comment; it
// is deliberately as "dumb" as a real untrusted rendezvous would be, so
// tests against it exercise the actual client-side trust boundary. It
// is safe for concurrent use.
type StaticRendezvous struct {
	mu      sync.Mutex
	entries map[GID]*ServiceDescriptor
}

// NewStaticRendezvous returns an empty StaticRendezvous.
func NewStaticRendezvous() *StaticRendezvous {
	return &StaticRendezvous{entries: make(map[GID]*ServiceDescriptor)}
}

func (s *StaticRendezvous) Publish(gid GID, descriptor *ServiceDescriptor) error {
	if len(descriptor.IntroPoints) > MaxIntroPoints {
		return ErrTooManyIntroPoints
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[gid] = descriptor
	return nil
}

// Lookup returns whatever is currently stored for gid, including a
// descriptor whose ExpiresAt has already passed - StaticRendezvous does
// not check expiry itself (see the type's doc comment). Callers must
// verify via VerifyServiceDescriptor.
func (s *StaticRendezvous) Lookup(gid GID) (*ServiceDescriptor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.entries[gid]
	if !ok {
		return nil, ErrGIDNotFound
	}
	return d, nil
}
