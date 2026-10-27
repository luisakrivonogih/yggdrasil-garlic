# Garlic Hidden Services — Design

Status: **historical design; transport superseded by the site implementation.**

Naming update: the first naming stage is now implemented as
`<hash>.domains.yggg`; see [Garlic hash domains](../../garlic-domains.md).
This replaces the `<base32-gid>.garlic.ygg` spelling throughout this
historical design. The implemented transport instead uses two duplex
Garlic circuits joined at a relay, with end-to-end QUIC/TLS and a
distributed XOR directory. See [Garlic websites](../../garlic-sites.md)
for the current architecture; the static inbound tunnels below were not built.

This adds I2P-eepsite-style hidden services to the Garlic Routing
Overlay: content reachable at `<base32-gid>.garlic.ygg`, one physical
operator able to host several such services that do not cryptographically
or topologically implicate each other, and services unreachable by
default until an operator explicitly publishes one. It builds directly on
`src/garlic`'s existing `Identity`/`GID`/`ServiceDescriptor`/`Rendezvous`
primitives (`docs/garlic-rendezvous.md`) and on the deferred tunnel-
separation work already scoped in
`docs/superpowers/backlog/2026-08-24-garlic-tunnel-separation-request.md`
— this document *is* that backlog item's design pass, narrowed and made
concrete against a real product goal (hidden services) instead of a
standalone hardening exercise.

Assumes the reader has read `docs/garlic-architecture.md`,
`docs/garlic-protocol.md`, `docs/garlic-threat-model.md`,
`docs/garlic-rendezvous.md`, and the backlog document above. Does not
repeat their content except where this design changes it.

## 1. Motivation

An operator wants to run something reachable the way an I2P eepsite or
Tor onion service is: a stable name derived from a public key, not from
the underlying node's real network address, with no publicly reachable
service by default. Today `src/garlic` has the naming primitive (`GID`,
already a self-certifying base32 identifier — `docs/garlic-rendezvous.md`)
and the directory primitive (`Rendezvous`/`ServiceDescriptor`,
`PublishService`/`LookupService`) but no way for a client to actually
*reach* a published service: `IntroPoint` today is just a bare node key,
and `CreateCircuit` requires the caller to already know the full hop path
including the terminal hop — there is no protocol step that turns
"GID's descriptor says these are its introduction points" into an actual
connection to GID's operator. Nor is there a request/response or
streaming abstraction above the existing single-shot
`SendGarlic`/`RecvGarlic` datagram API, which real HTTP browsing needs.

## 2. Non-goals

- **No Tor-style third-party rendezvous relay role.** The existing
  `Rendezvous` interface already plays the directory/NetDB role; nothing
  else needs a dedicated "meeting point" hop. See §4.
- **No TUN integration.** Hidden services are reached via a local HTTP
  proxy (§9) and the streaming API (§7), not by routing real IPv6 traffic
  through Garlic — same non-goal as
  `docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md`.
- **No proof-of-work admission control in v1.** §8 covers why flooding a
  published service is a real new concern and what v1 does about it
  (independent per-hop rate limiting + lease rotation); PoW-gated stream
  opens are noted as a natural v2 hardening step, not built here.
- **No "stealth" no-gossip closed mode.** §11 distinguishes "not hosting"
  (v1, default) from "not participating in discovery gossip at all"
  (would also cripple the profile's own ability to build outbound
  circuits — a real trade-off, deliberately left for a future request if
  ever actually needed).
- **No solution to website fingerprinting or global passive traffic
  analysis.** A real bidirectional HTTP stream has far more shape than
  today's padded datagrams; this is a known, generally-unsolved problem
  class for any low-latency anonymity network and is not claimed to be
  solved here. See §13.
- **Does not make egress-IP correlation impossible**, only easy to avoid
  using infrastructure Yggdrasil already supports (§12). Genuine network-
  path diversity is the operator's responsibility.
- **No new DHT implementation.** §6 specifies what a distributed
  `Rendezvous` backend must provide; its detailed wire design is
  deferred to its own pass, per `docs/garlic-rendezvous.md`'s existing
  recommendation to reuse ironwood's DHT machinery.

## 3. Architecture overview

```
Bob (service operator)                          Alice (client)
   |                                                 |
   builds N InboundTunnel (§4)                       |
   |                                                  |
   publishes LeaseSet (§5) --> Rendezvous <-- looks up LeaseSet (§5)
   (directory, existing Rendezvous interface)        |
                                                  builds own OutboundTunnel
                                                  (existing CreateCircuit,
                                                   unchanged)
                                                       |
                                          StreamOpen addressed to
                                          {gateway, LocalTunnelID} (§7)
                                                       |
                                          gateway relays hop-by-hop using
                                          the tunnel's static per-hop keys
                                          (§4) down to Bob
                                                       |
                                          Bob replies the same way, using
                                          a reply lease Alice included
```

No separate rendezvous-point relay is ever contacted by both sides in the
same session (unlike Tor onion services). `LookupService` already gives
Alice everything she needs to address Bob directly through his own
published gateway — this is the I2P model, not the Tor model, and it is
simpler to build: one fewer relay role, no rendezvous-circuit
choreography, no risk of the directory-lookup role and the meeting-point
role becoming the same identifiable thing.

## 4. Inbound tunnels: static per-hop tunnel keys

**The core problem this section solves:** today's `Circuit`/`Seal`
(`circuit.go`) is single-sender by construction — the layer keys are
derived from ephemeral ECDH secrets that only the circuit's *originator*
holds (`CreateCircuit`, `manager.go`). Alice cannot inject a message into
a circuit Bob built; there is no mechanism for it. An inbound tunnel must
accept messages from senders it never negotiated with individually.

**Design:** a new circuit variant, `InboundTunnel`, built by the
*destination* (Bob) exactly like today's `CreateCircuit` (hop-by-hop
ECDH against each hop's long-term `Identity.PublicKey`, same as now) with
one addition — at build time, each hop also receives (over the same
already-encrypted per-hop channel used for the rest of the build
handshake) a **static tunnel key**, valid for that tunnel's lifetime, and
a **hop-local tunnel ID** (`LocalTunnelID`, 16 bytes, independently random
per hop — same shape and same hop-local discipline as
`docs/superpowers/specs/2026-08-24-garlic-hop-local-metadata-design.md`
already established for `CircuitID`; see the explicit warning below).
Concretely, `deriveLayerKey`'s existing two-stage HKDF
(`ECDH secret -> LabelCircuitEstablish -> LabelCircuitDataSend`) gains a
sibling label:

```go
// crypto.go
const LabelTunnelKey = "garlic-tunnel-key-v1" // new

func deriveTunnelKey(ecdhSecret []byte) ([]byte, error) {
    establishSecret, err := DeriveKey(ecdhSecret, nil, LabelCircuitEstablish)
    if err != nil {
        return nil, err
    }
    return DeriveKey(establishSecret, nil, LabelTunnelKey)
}
```

Each hop, on build, stores `(LocalTunnelID) -> (tunnelKey, nextHop,
nextLocalTunnelID, expiresAt)` in a new bounded table
(`inboundTunnelState`, same shape and same capacity-bounded discipline as
`relayCircuitState` — reuse that pattern, do not invent a second one).
**This table is what makes the gateway "externally addressable":** any
sender who reaches a hop with a valid `LocalTunnelID` gets processed
using that hop's stored `tunnelKey`, with no need to have been the
tunnel's builder. Forwarding logic is otherwise identical to today's
`processCircuitData`/`actionForward` — decrypt one AEAD layer with the
stored key, get `Inner` + the next hop's `LocalTunnelID`, forward.

**Why the tunnel key must not simply be the same thing as an ordinary
circuit's layer key:** an ordinary layer key is used for exactly one
`Seal` sequence, all counters chosen by one party (the originator) who
controls monotonicity. A tunnel key here is used across many independent
messages from many unrelated senders (Alice, plus anyone else who looked
up the same LeaseSet), so **there is no single party who can guarantee a
monotonic counter** — replay protection at each inbound-tunnel hop must
use the same sliding-window `ReplayWindow` (`replay.go`) already used at
the Garlic-message level, keyed per `(LocalTunnelID)`, not a shared
per-tunnel monotonic counter. This is a real, deliberate scope difference
from ordinary circuits, not an oversight — call it out explicitly in the
implementation and in `docs/garlic-threat-model.md`.

**Hop-local ID discipline — required, not optional:** the value Alice
puts on the wire to reach the gateway is meaningful *only* to the
gateway. Each hop that forwards further down the tunnel translates to
*its own* locally-chosen `LocalTunnelID` for the next hop, exactly as the
hop-local envelope work already does for regular circuits. Two colluding
non-adjacent hops on the same inbound tunnel must not be able to compare
IDs and confirm they're on the same tunnel. **This is a direct, easy-to-
miss regression risk**: naively "reusing one ID end-to-end so Alice's
single wire value routes all the way to Bob" is exactly the bug
`docs/superpowers/specs/2026-08-24-garlic-hop-local-metadata-design.md`
just finished eliminating for `CircuitID`. A dedicated test
(`TestInboundTunnelLocalIDsDifferPerHop`, mirroring that spec's own
regression tests) is required before this ships.

**Mandatory rotation:** `InboundTunnel` lifetime is deliberately much
shorter than ordinary `CircuitLifetime` (suggested default: 3–5 minutes,
tuned at implementation time) and **rotation is not configurable off** —
per explicit decision, since the static tunnel key's exposure window is
this design's main forward-secrecy cost (a hop compromised after many
messages have passed compromises all of them, not just future ones,
unlike an ordinary per-session circuit key). Short mandatory lifetime is
the mitigation; `docs/garlic-threat-model.md` must state this trade-off
plainly rather than imply it's solved.

## 5. LeaseSet

`ServiceDescriptor` (`descriptor.go`) changes shape — `IntroPoints
[]IntroPoint` (bare node keys) is replaced with `Leases []Lease`:

```go
type Lease struct {
    GatewayNodeKey  []byte    // real node key of the tunnel's first hop
    GatewayTunnelID [16]byte  // LocalTunnelID meaningful to that gateway
    ExpiresAt       uint64
}

type ServiceDescriptor struct {
    Version          uint8 // bump to 2
    ServicePublicKey ed25519.PublicKey
    ServiceID        []byte
    Leases           []Lease // was IntroPoints []IntroPoint
    PublishedAt      uint64
    ExpiresAt        uint64
    Signature        []byte
}
```

No compatibility shim needed — nothing depends on the v1 shape in
production (`StaticRendezvous` is documented as a test/small-deployment
stub, `docs/garlic-rendezvous.md`). `MaxIntroPoints` becomes
`MaxLeases` (same bound, same purpose: cap what a `Publish` call can make
a `Rendezvous` implementation store). `PublishService`/`LookupService`
(`manager.go`) sign/verify `Leases` in place of `IntroPoints`; all
existing descriptor-authentication properties
(`docs/garlic-rendezvous.md` "Descriptor authentication") are unchanged
— a rendezvous still cannot forge a descriptor for a GID it doesn't hold
the signing key for, and still cannot tamper with `Leases` without
invalidating the signature.

Bob republishes his LeaseSet whenever his `InboundTunnel` pool rotates
(§4) — each republish carries whichever leases are currently live, so a
client's lookup is never stale by more than one lease's lifetime.

## 6. Distributed Rendezvous (interface requirements; detailed design deferred)

`StaticRendezvous` only knows about publications made to its own node —
a GID published on one machine is not discoverable from any other, which
makes hidden services non-functional beyond localhost. A real backend is
required for this feature to have any practical value.

Per `docs/garlic-rendezvous.md`'s own "Future direction," the intended
approach is a new `Rendezvous` implementation (`DHTRendezvous`) backed by
ironwood's existing DHT-style routing machinery, **not** a second
distributed system built from scratch. The `Rendezvous` interface
(`Publish`/`Lookup`) does not change — this is a second implementation of
an existing interface, so nothing that consumes it (`PublishService`,
`LookupService`, the admin handlers, circuit construction) needs to
change.

This document fixes only the requirements a `DHTRendezvous` must meet,
consistent with `docs/garlic-rendezvous.md`'s own threat-relevant
properties list:

- Bounded storage per GID (inherits `MaxLeases`).
- Enforced `ExpiresAt`, so stale/abandoned descriptors eventually drop
  out of the DHT rather than accumulating forever.
- No operation that lets a casual participant enumerate *every* published
  GID — only targeted lookup by already-known GID. (A DHT that supports
  range/prefix queries over its own keyspace would violate this; the
  implementation must not expose one for GIDs even if the underlying DHT
  library technically could.)
- Lookup traffic is only ever seen by the (bounded, hash-determined) set
  of DHT nodes responsible for that GID's keyspace region, not
  broadcast — same "who learns what" shape `docs/garlic-rendezvous.md`
  already documents for the single-node stub, just spread across more
  parties.

**Explicitly deferred, not designed here:** exact DHT record wire format,
republish/expiry cadence against DHT churn, and the threat-model
implications of many-nodes-can-serve-a-lookup (this materially changes
the "malicious rendezvous" analysis in `docs/garlic-threat-model.md` —
now *any* node responsible for a GID's keyspace region is a potential
malicious-rendezvous instance, not one operator-chosen static map).
`docs/garlic-rendezvous.md` already says this needs its own threat-model
pass before implementation; that stands. v1 of hidden services can ship
against `StaticRendezvous` for local/small-deployment testing (as today)
while `DHTRendezvous` is designed and built as a following, independently
reviewable phase — the `Rendezvous` interface boundary is exactly what
makes that safe to sequence this way.

## 7. Connect protocol and streaming layer

**Stream open.** New message type `msgTypeStreamOpen` (`protocol.go`,
next `iota`). Alice, holding a `Lease{gateway, tunnelID}` from Bob's
LeaseSet, builds her own ordinary `OutboundTunnel` (existing
`CreateCircuit`/`AutoCreateCircuit`, unchanged) ending at the gateway,
and sends a `StreamOpen` payload through it:

```go
type StreamOpenMessage struct {
    GatewayTunnelID  [16]byte     // routes into Bob's inbound tunnel
    StreamID         [16]byte     // random, scoped to this stream
    ReplyLease       Lease        // how Bob should reach Alice back
    EphemeralPublicKey []byte     // X25519, for this stream's own layer key
}
```

The gateway forwards this exactly like any other inbound-tunnel payload
(§4) — it does not parse `StreamOpenMessage`, it only routes on
`GatewayTunnelID`. Bob, as the tunnel's terminal hop, decrypts it,
derives a per-stream key via ECDH against `EphemeralPublicKey` (same
`deriveLayerKey` shape as ordinary circuits — a stream's data-carrying
key *is* single-sender/single-session per §4's distinction between tunnel
keys and stream keys), and accepts or rejects the stream.

**Streaming framing.** Per explicit decision, v1 needs full duplex
streams (HTTP keep-alive, large responses), not one-shot datagrams. New
`StreamData` frames carry a monotonic per-stream sequence number and an
ack field (design mirrors a minimal TCP-like layer, deliberately not
reusing the circuit's own `PacketCounter` — that counter's job is replay-
window position within one AEAD key's usage, not application-level
ordering):

```go
type StreamData struct {
    StreamID  [16]byte
    Seq       uint64
    Ack       uint64 // highest contiguous Seq the sender has received
    Fin       bool
    Payload   []byte
}
```

`Stream` (`stream.go`, new) exposes `io.ReadWriteCloser` to callers —
`Garlic.Dial(gid GID) (*Stream, error)` for a client, and the server-side
accept path feeding `Garlic.Services` (§9). Retransmission/reorder
handling follows the same shape as any minimal reliable-stream-over-
datagram design; exact windowing constants are an implementation-time
decision, not fixed here.

**Every `Dial` call also builds an ephemeral inbound tunnel of its own**
— `ReplyLease` above has to point at *something*, and an inbound tunnel
(§4) is the only mechanism this design has for "reachable by someone who
isn't the tunnel's own builder." This applies to **any** caller of
`Dial`, not just nodes that host a service — a purely client/browsing
profile still needs a reply path to receive Bob's response at all. This
is a materially different category from a *published* inbound tunnel
(§10) though: it is built on demand per `Dial` call, its `Lease` is
handed only to the one peer being dialed (inline, inside that one
`StreamOpenMessage`), and it is **never** given to `PublishService`/any
`Rendezvous` — nobody can discover it exists without Alice herself having
already directly told them. §10's "closed by default" claim is about
this *published/discoverable* category only; see §10 for the resulting,
now-precise scope of that claim.

**Tunnel rotation transparent to a live stream (the point flagged in
review as a real security/UX tension):** a `Stream` is bound to a
`StreamID`+ephemeral key, not to the specific `InboundTunnel` used to
open it. When Bob rotates his inbound tunnel pool (§4, mandatory), a
*new* `StreamOpen`-equivalent re-binding happens transparently — Bob
signals a still-open stream's continuation over his new lease the same
way he'd signal a fresh reply lease, keyed by the existing `StreamID`
(encrypted end-to-end, never visible to any hop). **Residual risk,
documented rather than hidden:** a hop present on both Bob's old and new
inbound tunnel (more likely on a small network, exactly the user's real
4-node deployment) could attempt traffic-timing/volume correlation across
the rotation even without ever seeing `StreamID` in the clear. Mitigate
by preferring hop sets disjoint from the previous tunnel's when rotating
(reuse the existing diversity-aware selection, `selection.go`); do not
claim this eliminates the risk, only raises its cost — same honesty
standard as every other correlation caveat in this document.

**Resource bounds (delegated design decision, made explicit here):**
same bounded-capacity discipline as every other piece of this codebase —
max concurrent streams per inbound tunnel and per profile, max buffered/
un-acked bytes per stream, idle-stream timeout, all attacker-controlled
counts capped up front (mirrors `MaxCircuits`, `MaxDiscoveredPeers`,
`relayCircuitState`'s capacity bound). No unbounded attacker-controlled
map anywhere in this feature.

## 8. Anti-abuse: no propagated blacklist

A published LeaseSet is, by design, discoverable by anyone who knows or
brute-force-guesses... no — GID is a keyed hash of the signing public
key, not brute-forceable — but by anyone who *legitimately looks it up*.
That is a meaningfully larger and more easily-triggered audience than
"peers who specifically negotiated a circuit through you," and is a new
class of exposure this codebase hasn't had before. A propagated
"blacklist this sender backward through the tunnel" mechanism was
considered and **rejected**: hops don't and shouldn't learn a stable
sender identity to blacklist (defeats the point of onion routing), and a
hop-trusts-Bob's-say-so blacklist both leaks "Bob rejected identity X" as
new correlatable metadata and gives Bob a censorship lever over hops that
have no way to verify his claim.

**v1 defenses, all local/uncoordinated:**
- Each hop enforces its own `RateLimiter` per `LocalTunnelID`
  independently — no coordination, no new message type, nothing reported
  anywhere.
- Lease rotation (§4, already mandatory) is itself the abuse response: if
  a specific lease is being flooded, Bob simply stops republishing it and
  the abuser loses access on next lookup. Zero new protocol surface.
- `StreamOpen`/`StreamData` resource bounds (§7) cap the cost of any
  single abusive sender regardless of volume.

**Deferred, not built:** proof-of-work-gated stream admission (real
precedent: Tor v3 onion services ship exactly this since 0.4.7) — noted
as the natural v2 escalation if local rate-limiting plus rotation proves
insufficient in practice, not built speculatively now.

## 9. Naming and local proxy

`GID.String()`/`ParseGID()` (`gid.go`) already produce and parse the
canonical base32 identifier — **zero new code** for the address format
itself; `<gid>.garlic.ygg` is just `GID.String() + ".garlic.ygg"`.

**Client side — local HTTP proxy** (new, `src/garlic/proxy` package,
wired in from `cmd/yggdrasil/main.go` behind a new config block, off by
default):

```go
type HiddenServiceProxyConfig struct {
    Enabled bool
    Listen  string // e.g. "127.0.0.1:4444", analogous to Dashboard.Listen
}
```

Intercepts requests whose `Host` ends in `.garlic.ygg`, strips the
suffix, `ParseGID`s the remainder, `LookupService`s it, `Dial`s a
`Stream` (§7), and pipes HTTP bytes through. **Must sanitize outgoing
headers** (strip/neutralize `Referer` across different GIDs, don't forward
anything that could leak the real Yggdrasil address, isolate cookies per
GID the same way Tor Browser isolates per first-party domain) — flagged
explicitly because a proxy that blindly forwards HTTP is a real, easy-to-
miss leak vector distinct from anything at the Garlic protocol layer.

**Server side — server tunnel:**

```go
type ServiceConfig struct {
    ServiceID string // hex; ComputeGID(identity.SigningPublicKey, serviceID) is the GID
    LocalAddr string // e.g. "127.0.0.1:8080" - an ordinary local HTTP server
}
```

An inbound stream accepted for a configured service's GID is forwarded
byte-for-byte to `LocalAddr` — the same "server tunnel" shape as Tor's
`HiddenServicePort` / I2P's server tunnels. The operator runs whatever
they already run (nginx, a static file server) unmodified; this feature
only handles getting bytes to and from it privately.

## 10. Reachability: closed by default

`Garlic.Services` (§9) empty is the default — a profile with no
configured services never calls `PublishService` and never builds a
*published* inbound tunnel, and is therefore not a reachable, discoverable
destination by construction. "Opening" a service is exactly adding one
`ServiceConfig` entry; no separate flag is needed.

This claim is specifically about the published/discoverable category
(§9's `Leases` that end up in a `LeaseSet`, handed to `Rendezvous`). It
does **not** mean the profile builds zero inbound tunnels ever — per §7,
any outbound `Dial` (i.e. any actual browsing through the local proxy)
builds its own short-lived, unpublished reply tunnel on demand, purely so
the peer being dialed can answer. That tunnel's `Lease` is only ever
handed directly to that one peer, inline in the request; it is never
given to a `Rendezvous`, never listed in any `ServiceDescriptor`, and
nobody can find it without Alice already having contacted them. A
"closed" profile that never dials anything builds none of these either —
the distinguishing property is *discoverability*, not *tunnel count*.

**Explicit scope note, resolved during review:** "closed" means *not
hosting*, not *invisible to the Garlic overlay*. A closed profile still
participates in discovery gossip (`GossipAnnounce`/`processAnnounce`) —
it needs to, in order to build its own outbound circuits/streams to
browse other services. A stricter "opt out of gossip entirely" mode would
also remove the profile's own ability to act as a client, which nobody
asked for; it's called out in §2 as explicitly out of scope rather than
silently assumed away.

## 11. Multi-profile hosting

Per explicit decision, "looks like a different node" means full
indistinguishability from a *directly connected peer* — not achievable
by any amount of Garlic-layer cleverness within one `core.Core` (one
process = one Ed25519 node identity = one spanning-tree position, by
ironwood's own design). The only real way to get this property is **N
independent `(core.Core, Garlic)` pairs**, each with its own persisted
`Identity`/`PrivateKey`/`SigningPrivateKey`, each joining the mesh as a
genuinely separate node. This is already possible today by hand (running
multiple `yggdrasil` processes with different configs); what's missing is
orchestration.

**New: a profile-pool config and runner**, e.g. `cmd/yggdrasil-profiles`
or a mode of the existing `cmd/yggdrasil` binary:

```go
type ProfilePoolConfig struct {
    Profiles []ProfileConfig
}

type ProfileConfig struct {
    ConfigFile string   // this profile's own NodeConfig, unmodified shape
    // egress diversity is expressed entirely via the profile's own
    // Peers list using mechanisms that already exist (below) - no new
    // per-profile egress fields needed.
}
```

Runs N `(core.Core, Garlic)` pairs as goroutine-isolated instances inside
one OS process (simpler to build/deploy/upgrade atomically than N
systemd units; does not weaken the mesh-identity-separation property,
since that property comes from N distinct `core.Core` objects, not from
N distinct OS processes).

**Egress diversity uses existing, already-shipped Yggdrasil features —
no new core code:**
- `socks://`/`sockstls://` peer URIs (`src/core/link_socks.go`, already
  implemented) route a profile's peering connection through a distinct
  SOCKS5 endpoint: `socks://127.0.0.1:9050/yggdrasil.su:62486`. An
  operator points each profile at a different SOCKS endpoint (separate
  VPN tunnels, separate Tor SOCKS ports, whatever they already run and
  trust) to present genuinely different source IPs to shared peers.
- `sintf`/`InterfacePeers` (`src/core/link_tcp.go`'s `dialerFor`, already
  implemented) bind a peering connection to a specific local interface,
  if the host has multiple real public IPs.

**New: a startup diversity check** in the profile-pool runner — if two
configured profiles' `Peers` entries resolve to the same literal
`host:port` **and** neither is routed through a distinct
`socks://`/`sintf`, log a loud warning naming both profiles. Fail-loud,
not silent, matching this project's existing convention (`install.sh`'s
own recent fix for exactly this kind of silent-failure class).

**New: independent per-profile jitter.** Each profile's own connection/
reconnect timing, `GossipAnnounce` schedule, and `InboundTunnel` rotation
schedule are seeded independently (not derived from a shared clock/seed)
so N profiles starting together don't produce a visible lockstep pattern.

**Explicitly acknowledged, not solved:** if all N profiles share the same
SOCKS/VPN provider, the correlation just moves to that provider — real
diversity requires genuinely different providers/paths, which is
operator infrastructure, not something this codebase can enforce. Also
acknowledged: software version, restart timing, and spanning-tree
convergence patterns remain a secondary fingerprinting signal even after
IP is fixed — "raises the cost, does not create Sybil-proof separation,"
the same honesty standard `docs/superpowers/backlog/2026-08-24-garlic-tunnel-separation-request.md`
already applies to route-selection Sybil resistance.

**Practical note for small networks:** on a network with only a handful
of total nodes (e.g. a real 4-node test deployment), this entire property
is close to moot regardless of implementation quality — there is no
meaningful anonymity set to hide multiple profiles' traffic within. This
matters for a real public-scale deployment; it should not be over-
engineered around for small test networks.

## 12. Capability negotiation and compatibility

New capability string, additive per the existing pattern
(`CapabilityAutoCircuit` is the precedent):

```go
const CapabilityHiddenServices = "garlic-hs-v1"
func (m *CapabilityMessage) SupportsHiddenServices() bool { ... }
```

A hop is only usable as an `InboundTunnel` gateway/relay hop, or as a
`StreamOpen`/`StreamData` recipient, if it advertises
`CapabilityHiddenServices` — same reasoning as
`docs/superpowers/specs/2026-08-23-garlic-autonomous-routing-design.md`
§8 gives for gating every position on `CapabilityAutoCircuit`: an old
node acting as an intermediate relay would forward opaque bytes
correctly by accident either way, but an old node as the *terminal* hop
of what it thinks is an ordinary circuit would mis-handle
`msgTypeStreamOpen`'s payload. Gating on capability everywhere sidesteps
needing to reason about which position is actually risky.

- `Garlic.Enabled = false`: unaffected, unchanged.
- `Garlic.Services` empty (§10, default): a node never originates
  `InboundTunnel`/`StreamOpen` traffic, but (matching the autonomous-
  routing precedent) can still be selected as a relay/gateway hop for
  *someone else's* inbound tunnel if it advertises the capability —
  hosting and relaying are independent facts, same as today's existing
  auto-pool/manual-circuit relationship.
- Existing `SendGarlic`/`RecvGarlic`/`CreateCircuit`/manual
  `createGarlicCircuit`, and the auto-pool machinery from the autonomous-
  routing feature: zero wire or behavior change. Fully isolated via the
  new message types (`msgTypeStreamOpen`, stream-data framing) and new
  per-tunnel state tables, exactly as `msgTypeCircuitDataV3` was kept
  isolated from the pre-existing manual circuit path.

## 13. Threat model updates (consolidated)

To be folded into `docs/garlic-threat-model.md` at implementation time.
Every item below was raised and resolved during this design's review;
listed together here so nothing gets lost between spec and
implementation.

- **Egress-IP correlation (§11).** A direct peer trivially observes N
  Yggdrasil identities connecting from one source IP regardless of any
  Garlic-layer property — mitigated via existing SOCKS/interface
  features, not eliminated; residual risk if egress paths share a
  provider. This is the cheapest correlation signal available to *any*
  peer, not just one positioned on a specific circuit, and is a stepping
  stone toward correlating a specific GID to a specific operator once
  combined with inbound-tunnel-terminal-hop exposure (next item).
- **Inbound-tunnel terminal-hop exposure.** The last hop before Bob
  necessarily learns Bob's real node key (inherent to Yggdrasil transport
  delivery, unchanged from today's existing "last hop knows destination
  address" limitation). On a small network this hop is drawn from a tiny
  pool, materially weakening the practical anonymity set — call this out
  plainly rather than let the protocol-level design imply more privacy
  than a small deployment can actually provide.
- **Hop-local tunnel/stream ID discipline (§4).** Must not regress the
  `CircuitID` linkability fix; requires its own dedicated test before
  shipping.
- **Static per-hop tunnel key forward secrecy (§4).** Longer exposure
  window than an ordinary circuit's per-session key; mitigated by
  mandatory short rotation, not eliminated.
- **Publicly-discoverable-LeaseSet flooding (§8).** New attack surface —
  anyone who legitimately looks up a GID gets a working entry point.
  Mitigated by local per-hop rate limiting and lease rotation; PoW
  admission deferred as a v2 escalation.
- **Stream continuity across tunnel rotation (§7).** A hop present on
  both the old and new inbound tunnel could attempt traffic-timing
  correlation across the rotation even with the stream ID fully
  encrypted end-to-end. Mitigated by preferring disjoint hop sets on
  rotation; not eliminated.
- **Streaming-layer resource exhaustion (§7).** New per-stream state
  (reorder/ack buffers) must follow the same bounded-capacity discipline
  as every other table in this codebase.
- **HTTP-specific leakage via the local proxy (§9).** Headers/cookies
  forwarded blindly could deanonymize or cross-link separate GIDs;
  requires explicit sanitization, not assumed safe by default.
- **DHT rendezvous lookup exposure (§6, future phase).** Once
  `DHTRendezvous` exists, lookups are visible to whichever DHT nodes are
  responsible for a GID's keyspace region — a materially different
  "malicious rendezvous" shape than today's single operator-chosen
  static map; requires its own threat-model pass before that phase
  ships, as `docs/garlic-rendezvous.md` already anticipated.
- **Website fingerprinting / traffic analysis (§2).** Explicitly not
  solved; real HTTP traffic shape is a known, hard, generally-unsolved
  problem for low-latency anonymity networks. Do not claim otherwise —
  consistent with the project-wide instruction not to claim absolute
  anonymity.
- **Multi-profile fingerprinting beyond IP (§11).** Software version,
  restart timing, and spanning-tree convergence remain secondary
  correlation signals even after egress-IP diversity is fixed. Raises
  cost; does not eliminate.

## 14. Testing strategy (high level — full cases at plan time)

- `crypto.go`/`tunnel.go`: `deriveTunnelKey` produces a value independent
  of `deriveLayerKey` from the same ECDH secret (domain separation
  actually holds); `TestInboundTunnelLocalIDsDifferPerHop` (§4's
  mandatory regression test).
- `tunnel.go`: replay protection at a tunnel hop rejects a repeated
  `PacketCounter` from *any* sender sharing that `LocalTunnelID`, not
  just the original opener; `inboundTunnelState` capacity is bounded
  (mirrors existing `relayCircuitState` bound tests).
- `lease.go`/`descriptor.go`: `ServiceDescriptor` v2 round-trips with
  `Leases`; existing GID/signature verification tests extended, not
  replaced.
- `stream.go`: stream survives simulated tunnel rotation (new lease,
  same `StreamID`, transparent to the caller's `io.ReadWriteCloser`);
  out-of-order `StreamData` reassembles correctly; a stream exceeding its
  buffer/idle bounds is torn down, not allowed to grow unbounded
  (fuzz-style, matching this package's existing "malformed input never
  panics, allocations stay bounded" convention).
- `protocol.go`: legacy node (no `CapabilityHiddenServices`) never
  selected as an inbound-tunnel hop or `StreamOpen` recipient — extends
  the existing capability-gating test pattern from the autonomous-routing
  feature.
- Integration: full round trip against a real multi-node linked-core
  mesh (same `newLinkedTestNode`/`connectChain` fixture shape already
  used throughout `src/garlic`) — Bob publishes, Alice looks up, dials,
  exchanges an HTTP-shaped request/response, tunnel rotates mid-stream,
  stream survives.
- `proxy` package: `.garlic.ygg` Host-header parsing/GID extraction;
  header sanitization strips the specific fields called out in §9 (table-
  driven, one case per field).

## 15. Implementation phases

Staged per this project's existing convention (see the tunnel-separation
backlog's own §25) — each phase independently testable and mergeable
before the next begins:

1. **Inbound tunnels** (§4): static tunnel keys, hop-local tunnel IDs,
   mandatory rotation. No LeaseSet, no streaming yet — testable via a
   direct admin RPC that opens a raw tunnel and sends one tagged message.
2. **LeaseSet** (§5): `ServiceDescriptor` v2, `PublishService`/
   `LookupService` updated. Still against `StaticRendezvous`.
3. **Connect protocol + streaming** (§7, §8): `StreamOpen`/`StreamData`,
   resource bounds, local rate limiting, rotation-transparent streams.
4. **Naming + proxy + server tunnel** (§9, §10): `.garlic.ygg` local
   proxy, `Garlic.Services` config, header sanitization.
5. **Multi-profile orchestration** (§11): profile-pool runner, egress-
   diversity startup check, independent jitter. Independent of phases
   1–4 in principle, but only useful once there's something to host.
6. **Distributed Rendezvous** (§6): `DHTRendezvous`, its own threat-model
   pass first, per `docs/garlic-rendezvous.md`.

## 16. Docs to update at implementation time

- `docs/garlic-protocol.md`: new §§ for `msgTypeStreamOpen`/
  `StreamData` wire format, `LeaseSet`/`Lease`, `CapabilityHiddenServices`.
- `docs/garlic-rendezvous.md`: `IntroPoint` → `Lease` throughout;
  `DHTRendezvous` section once phase 6 lands.
- `docs/garlic-threat-model.md`: all of §13 above.
- `docs/garlic-architecture.md`: new component overview section
  referencing this document, same as it references the autonomous-
  routing and crypto-hardening designs today.
- `docs/superpowers/backlog/2026-08-24-garlic-tunnel-separation-request.md`:
  mark superseded by this document once phases 1–3 land (its core asks —
  hop-local tunnel state, separate outbound/inbound construction, lease
  rotation — are addressed here).
