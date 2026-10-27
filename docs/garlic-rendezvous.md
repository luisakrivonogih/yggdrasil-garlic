# Garlic Routing Overlay — Rendezvous

## Purpose

A Garlic service (Bob) should not have to publish his real Yggdrasil
IPv6 address as the price of being reachable through Garlic — that would
defeat the point. The `Rendezvous` abstraction decouples "how do I find
this service" from "what is its underlying network address."

```go
// src/garlic/rendezvous.go
type Rendezvous interface {
    Publish(gid GID, descriptor *ServiceDescriptor) error
    Lookup(gid GID) (*ServiceDescriptor, error)
}
```

**Note on this signature (updated as of the crypto-hardening pass):**
this interface used to carry plain `Publish(gid, []IntroPoint, ttl)` /
`Lookup(gid) ([]IntroPoint, error)` — no signature anywhere, so a
malicious or compromised rendezvous could return attacker-controlled
introduction points for any GID. It now carries a signed
`*ServiceDescriptor` instead; see "Descriptor authentication" below for
what that closes and what it doesn't.

`GID` (`docs/garlic-protocol.md` §6) is a self-certifying identifier —
`BLAKE2b-256(domain_separator || garlic_signing_public_key ||
service_id)` — computable by anyone who already knows the service's
Ed25519 *signing* public key and chosen `service_id`, without querying
any directory. (GID binds to this signing key, not the X25519
circuit-ECDH key the rest of Garlic uses — see "Descriptor
authentication" below for why that's what makes it self-certifying.) The
directory (`Rendezvous`) maps that GID to the service's current signed
`ServiceDescriptor`, which itself carries the `IntroPoint`s (node keys of
Garlic-capable relays willing to help establish contact with the
service) among other fields.

The same GID has an automatic DNS-shaped address,
`<hash>.domains.yggg`, with a lowercase base32 first label.
`Garlic.LookupDomain` parses this address and calls the same verified
`LookupService` path. See [Garlic hash domains](garlic-domains.md) for the
format and admin commands, and [Garlic websites](garlic-sites.md) for
distributed discovery and browser access.

## Descriptor authentication

`ServiceDescriptor` (`src/garlic/descriptor.go`):

```go
type ServiceDescriptor struct {
    Version          uint8
    ServicePublicKey ed25519.PublicKey // GID = ComputeGID(ServicePublicKey, ServiceID)
    ServiceID        []byte
    IntroPoints      []IntroPoint
    PublishedAt      uint64
    ExpiresAt        uint64
    Signature        []byte // ed25519, over everything above
}
```

`GID = ComputeGID(descriptor.ServicePublicKey, descriptor.ServiceID)` —
the same hash construction as before, now bound to a service's Ed25519
signing key (`Identity.SigningPublicKey`, `src/garlic/identity.go` —
generated independently of the X25519 circuit-ECDH keypair, never
derived from it) instead of the X25519 key. This is what makes the GID
self-certifying: nobody can produce a descriptor that both signs
correctly *and* hashes to a given GID without holding that GID's signing
private key.

**The rendezvous does not verify anything — it's the thing being
defended against.** `StaticRendezvous.Publish`/`Lookup` store and return
the descriptor verbatim, exactly as the old `IntroPoint`-list version
did; the trust boundary moved to the *client*, not the storage layer.
`Garlic.PublishService` (`src/garlic/manager.go`) builds the descriptor
and signs it with `identity.SigningPrivateKey` before calling
`Rendezvous.Publish`. `Garlic.LookupService` runs every descriptor a
`Rendezvous` returns through `VerifyServiceDescriptor`
(`src/garlic/descriptor.go`) before trusting its `IntroPoints`:

1. recomputes the GID from the returned descriptor's own
   `ServicePublicKey`/`ServiceID` and rejects on mismatch
   (`ErrDescriptorGIDMismatch`);
2. verifies the Ed25519 signature over the descriptor's own wire
   encoding, with `Signature` itself omitted from what's signed
   (`ErrInvalidDescriptorSignature`) — no rendezvous-added metadata
   (receipt timestamps, sequence numbers, storage hints) is ever part of
   the signed form, so a rendezvous can't influence what's verified by
   adding fields of its own;
3. checks `ExpiresAt` against the local clock (`ErrDescriptorExpired`).

Only after all three checks pass does `LookupService` return
`descriptor.IntroPoints` to the caller. Descriptor lifetime is itself
bounded — `ExpiresAt - PublishedAt` is capped by `MaxDescriptorLifetime`
(`src/garlic/descriptor.go`) — so a service can't mint a descriptor
"valid" for an unreasonable span either.

**What this does and does not defend against:** a malicious or
compromised rendezvous can still withhold a descriptor entirely, reorder
which one it serves if multiple were ever published, or serve a
stale-but-still-validly-signed one (nothing here defeats availability
attacks, only forgery). It cannot fabricate a descriptor for a GID it
doesn't hold the signing key for, and it cannot tamper with a genuine
descriptor's `IntroPoints` without invalidating the signature.

## `StaticRendezvous` for isolated tests

`src/garlic/rendezvous.go`. An in-memory, unverified map, safe for
concurrent use, capacity-bounded per publication
(`MaxIntroPoints = 16`, so a single `Publish` call can't make the
implementation store unbounded state). This is intentionally the
simplest possible implementation — it exists so circuit-construction and
capability-negotiation logic could be built and tested (including the
full `Garlic.PublishService`/`LookupService` API and the admin-socket
`publishGarlicService`/`lookupGarlicService` handlers) completely
independent of any distributed system, per the phased plan in
`docs/garlic-architecture.md` §26.

`StaticRendezvous` is explicitly selected by isolated tests. It has an obvious
limitation as a real deployment mechanism: it only knows about
publications made to *that specific node's own in-memory map* — it is
not shared across the network. Two nodes each running `StaticRendezvous`
have no way to discover each other's published services unless something
outside this project synchronizes their maps (e.g. a shared config file,
or an out-of-band channel).

## `NetworkRendezvous` in the daemon

Passing nil to `garlic.New`, as the daemon now does, selects the
distributed backend in `src/garlic/network_directory.go`. It uses
iterative XOR-nearest lookups and up to three replicas, targeted RPCs
inside Garlic circuits, verified signed descriptors, expiry, freshness
checks and bounded storage. Direct mesh peers seed Garlic discovery and
return bounded neighbor referrals. Website hosts refresh their records
and placement automatically. No shared config or descriptor copying is
required between a website and its clients. Full details and the privacy
boundary are in [Garlic websites](garlic-sites.md).

## Threat-relevant properties of the interface itself

Independent of which implementation backs it:

- **A rendezvous operator learns which GIDs are looked up, and roughly
  when.** `Lookup` necessarily reveals the GID being queried to whatever
  implements `Rendezvous`. This is true of any name-resolution system and
  is called out again in `docs/garlic-threat-model.md`.
- **Publishing is itself a fingerprint.** The act of calling `Publish`
  for a GID reveals that *some* Garlic identity controls that GID, to
  whatever sees the publication (for `StaticRendezvous`, nothing beyond
  the local node; for a future distributed implementation, potentially
  many nodes).
- **Introduction points are a trust boundary**, covered in
  `docs/garlic-threat-model.md` under "Malicious introduction point" —
  they learn that they've been designated as a way to reach a particular
  GID, and see connection-establishment traffic destined for it, but
  (given the circuit-hop design in `docs/garlic-protocol.md` §4) do not
  themselves decrypt application payload unless they are also the
  circuit's terminal hop.
- **Forgery is not among the rendezvous's remaining capabilities.**
  Interface-level authentication (see "Descriptor authentication" above)
  means this property now holds for *any* `Rendezvous` implementation,
  not just `StaticRendezvous` — a future distributed backend inherits it
  automatically, since verification happens in `Garlic.LookupService`,
  outside any particular `Rendezvous` implementation. What a rendezvous
  (of any kind) can still do is withhold, reorder, or serve a stale
  descriptor — availability and freshness are not solved by signing.

## Relation to the earlier DHT proposal

Ironwood supplies mesh routing rather than a public descriptor storage
API. The implemented directory therefore routes its small bounded
records and referral RPCs over that mesh through Garlic circuits. It
preserves the existing `Rendezvous` interface and descriptor signatures.
The added website section of `garlic-threat-model.md` describes directory
exposure, relay exposure, Sybil/availability limitations and browser scope.
