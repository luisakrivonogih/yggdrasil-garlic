# Garlic Routing Overlay — Threat Model

This system is **privacy-enhanced routing**. It is not described as
"anonymous" anywhere in this project, and this document is why: several
of the adversary classes below retain real capability. Treat every
"mitigated" claim below as bounded by its stated adversary, not absolute.

Scope: this analyzes what's actually implemented (`docs/garlic-protocol.md`),
not the aspirational full design in `docs/garlic-architecture.md`.

## Passive observer (watches network traffic, not a participant)

**Can see:** that two Yggdrasil nodes are exchanging encrypted traffic.
Packet sizes and timing on links it can observe. Whether a given link
carries `typeSessionGarlic`-tagged traffic is **not** visible from
payload content alone — the tag byte is inside the `encrypted` package's
per-session ciphertext (`golang.org/x/crypto`-based box seal in
`ironwood/encrypted/session.go`), exactly like the tag byte for ordinary
IPv6 traffic or NodeInfo queries. This part of the original doc's claim
holds.

**Correction from an earlier version of this document — read carefully,
this is not a property Garlic adds or can fix:** ironwood's `network`
package (the layer *below* `encrypted`, doing tree/DHT-based routing) is
**not** payload encryption and does not hide *who is talking to whom*.
The wire `traffic` struct (`ironwood/network/traffic.go`) carries
`source publicKey` and `dest publicKey` as plain, unencrypted fields
alongside the (encrypted) `payload` — only the payload is protected by
`encrypted`'s session layer. Route discovery is worse: when a node has
no cached path to a destination, it sends a `pathLookup{source, dest}`
that gets **multicast to a bloom-filter-scoped subset of the tree**
(`network/pathfinder.go`, `_sendLookup`/`_handleLookup`) — meaning
several real intermediate nodes, not just the two endpoints, see the
plaintext key pair "A wants to reach B" as a matter of normal protocol
operation, not a compromise. **Any node that decodes a `traffic` or
`pathLookup` packet - which every relay does as part of ordinary
forwarding - has `source`/`dest` sitting in memory**, whether or not its
own forwarding logic happens to need them (for already-pathed
`traffic`, the fast path only consults `path`/`peerPort` and doesn't
need `source`/`dest` to forward correctly - but the fields are decoded
into the struct regardless, and nothing stops a modified build from
logging them). This is true of vanilla Yggdrasil today, independent of
Garlic entirely, and it materially affects every "can this relay learn
who's talking to whom" question below - see `docs/garlic-security.md`'s
discussion of what this changes.

**Cannot see (still true):** the plaintext of any onion layer, or which
of possibly several bundled messages correspond to which real sender.
The above correction is about *routing metadata* (which keys exchanged
traffic), not payload.

## Malicious relay (one Garlic-capable circuit hop, not colluding)

**Can see:** the previous hop's node key (whoever sent it the packet, at
the ironwood/transport level — this is unavoidable, someone has to
address the message), the next hop's node key (from its own peeled
`LayerPlaintext.NextHop`), and packet timing/size at its own position in
the circuit.

**Cannot see:** anything about hops before the previous one or after the
next one, or the payload of any other layer (proven directly by
`TestBuildOnionHopCannotDecryptAnotherHopsLayer`). Cannot distinguish "I
am hop 2 of 5" from "I am hop 2 of 2" from the message alone.

**Fixed — per-hop ephemeral keys.** Per `docs/garlic-protocol.md` §4.1,
a circuit's originator now generates an independent ephemeral X25519
keypair for *every* hop. A hop only learns the next hop's ephemeral
public key by successfully decrypting its own layer - it is never
carried as a value shared unchanged across the whole circuit. Two
non-adjacent colluding relays (e.g. hop 1 and hop 3 of a 3-hop circuit)
therefore have no ephemeral public key in common to compare
(`TestNonAdjacentHopsCannotLinkViaEphemeralKeys`). Adjacent hops (hop 1
and hop 2) unavoidably share knowledge of the ephemeral key *between*
them - hop 1 must relay hop 2's ephemeral public key onward as part of
ordinary forwarding - but hop 1 never learns hop 2's corresponding
private key, and so cannot derive hop 2's session key
(`TestRelay1CannotDeriveRelay2SessionKey`). This is the same property a
Tor-style (non-Sphinx) telescoping circuit gives; it is not full Sphinx-
style blinding, which would also hide the next hop's ephemeral public
key from its immediate predecessor - see the crypto hardening design
spec for why that additional step wasn't judged necessary here.

**This closes ephemeral-key linkability specifically — it does not make
circuits unlinkable in general.** The `Envelope`'s `CircuitID` (16
bytes), `PacketCounter`, and `Expiration` fields sit outside the per-hop
AEAD-encrypted layer entirely (they are not part of `Body`, the only
field the layer AEAD covers) and are copied verbatim, unchanged, by
every relay that forwards the circuit (`docs/garlic-protocol.md` §4.3:
a forwarding hop rebuilds the outgoing `Envelope` with "the same
`CircuitID`, `PacketCounter`, and `Expiration`"). Two colluding
non-adjacent relays can therefore still trivially confirm they're on the
same circuit by comparing these three fields byte-for-byte, even though
they now share no ephemeral key. Nothing in this hardening pass rewrites
`CircuitID` (or the other two fields) per hop the way, e.g., Tor rewrites
circuit IDs at each relay; closing this is a concrete item for a future
pass, not something the ephemeral-key fix above addresses.

## Malicious relay / availability attacker

Separate from the confidentiality/linkability question above: any relay
on a circuit path can, at will:

- drop packets it's asked to forward,
- delay packets by an arbitrary amount before forwarding,
- reorder packets relative to how it received them,
- selectively drop or delay only packets on one particular circuit while
  forwarding others normally,
- stop forwarding for a circuit entirely, at any point, with no
  notification to anyone.

Garlic has no mechanism to distinguish a relay doing any of the above
deliberately from an ordinary network failure (a dropped UDP datagram, a
congested link, a peer that legitimately went offline) - both present
identically to the originator and to every other hop. This is not a gap
specific to this implementation; no purely reactive circuit protocol
without an independent liveness/acknowledgment channel can make this
distinction, and Garlic does not have one. A circuit that stops
producing traffic is evidence of *something* having gone wrong, not
evidence of which of these causes it was.

## Mesh-path intermediate node (not a chosen circuit hop, sits on the route between two of them)

This category didn't exist in the original version of this document and
follows directly from the correction above. When circuit hop *i* sends a
`msgTypeCircuitData` message to hop *i+1*, that's one ironwood
`encrypted` session, and per the mesh routing layer's own design, it may
transit any number of ordinary Yggdrasil nodes at the `network` layer to
get there (`docs/garlic-compatibility.md` calls this "role 1"). Per the
correction above, **any one of those in-between nodes can see the real
node keys of hop *i* and hop *i+1*** (via `traffic.source`/`dest`, or via
a `pathLookup` if no path was cached yet) — the same visibility a
"malicious relay" (a chosen Garlic hop) has into its *own* immediate
neighbors, except this adversary never had to be selected as a circuit
hop at all. It still cannot decrypt the `encrypted` session payload
(so no `LayerPlaintext`, no onion content), and it still can't tell
which position in the circuit it's observing traffic for, or correlate
it to a specific circuit ID without also being one of the two Garlic
identities exchanging that traffic. But it can build a graph of
"Garlic-tagged-looking traffic volumes between key X and key Y" (traffic
*is* observable in size/timing/existence even without decrypting it or
knowing it's Garlic) for every hop-pair a circuit's path happens to
route through — for free, without running any Garlic code, just by
sitting in the right place in the mesh topology.

**Why this matters for path selection:** an adversary doesn't need to be
*chosen* as a Garlic hop to gain this visibility for a given hop-pair —
they only need to be topologically positioned on the route ironwood's
routing would pick between two chosen hops. This is a concrete point in
favor of the "topologically diverse hop selection" idea discussed
separately (see the conversation this document was updated from) as a
way to make an adversary's job harder without needing every relay to run
Garlic-aware code.

## Malicious introduction point

Not exercised by any current code path beyond `Rendezvous.Publish` — see
`docs/garlic-rendezvous.md`. An introduction point learns that it has
been designated for a given GID and observes lookup/connection-setup
traffic naming that GID, but under the current circuit-hop model, only
decrypts application payload if it also happens to be the circuit's
terminal hop (not automatic — an intro point and a circuit's final hop
are different concepts that are not currently linked by any code).

## Malicious endpoint (the circuit's final hop / the service itself)

**Learns:** the full payload delivered to it (it's the intended
recipient — this is not a leak, it's the point) and the identity of
whichever node is immediately before it in the circuit (the previous
hop's key, same as any relay). **Does not learn:** the true originator's
identity, unless the circuit has fewer than 2 hops (a 1-hop "circuit" —
supported, see `TestBuildOnionSingleHop` — gives the sole hop full
visibility into both ends; this is expected of a 1-hop path and is why
`Config.PathLength` defaults to 3, not 1).

## Malicious client

A remote peer sending this node arbitrary Garlic protocol messages,
without being a chosen circuit hop for anything this node originated.
What's mitigated today, and what remains future work:

**Mitigated today:**

- **Circuit creation flood / circuit state exhaustion** —
  `CircuitManager` enforces `MaxCircuits` (global) and
  `MaxCircuitsPerPeer` (per first-hop peer); `relayCircuitState`
  enforces a capacity bound on how many circuits this node will track
  replay state for as a relay, refusing new circuit IDs once full
  (`TestCircuitManagerEnforcesMaxCircuits`, `TestRelayCircuitStateBoundedCapacity`).
- **Per-source message flooding** — `handleIncoming` gates *every*
  incoming Garlic message (capability requests/responses, circuit data,
  announces, bundles) behind a per-peer token-bucket `RateLimiter`,
  keyed by the sending node's Ed25519 key, before any type-specific
  processing runs (`src/garlic/ratelimit.go`; defaults
  `RatePerSecond`=50, `RateBurst`=200, `MaxTrackedPeers`=4096). Once
  `MaxTrackedPeers` distinct peers are being tracked, a request from a
  new peer is denied outright (fails closed) rather than growing the
  bucket table without bound. This applies uniformly to whatever message
  type a peer sends, including the circuit-open/circuit-teardown cycling
  the ceiling-based mitigation above is meant to bound.
- **Malformed packets / oversized declared lengths** — every parser in
  `src/garlic` (`Envelope`, `LayerPlaintext`, `CapabilityMessage`,
  `Bundle`, `AnnounceMessage`, `ServiceDescriptor`'s field encoding)
  validates a declared length against both a fixed maximum and the
  bytes actually present *before* using it to size an allocation or
  slice operation. For `Envelope`, `LayerPlaintext`, `CapabilityMessage`,
  `Bundle`, and `ServiceDescriptor`'s field encoding this is proven
  continuously by the `Fuzz*` targets in `fuzz_test.go`, whose only
  invariant is "never panics, never allocates unboundedly";
  `AnnounceMessage` (`discovery.go`) does the same declared-count/
  declared-length validation by inspection but does not yet have a
  dedicated fuzz harness.
- **Excessive nesting** — `MaxPathLength` (8) bounds circuit depth;
  onion construction cost is therefore bounded independent of anything a
  remote peer controls.
- **Huge bundles** — `Bundle`'s `message_count` and per-message length
  are both bounded (`MaxBundleMessages`, `MaxBundleMessageSize`).
- **Huge GID counts / excessive service publishing** — `MaxIntroPoints`
  bounds a single descriptor's introduction-point list;
  `StaticRendezvous` stores one descriptor per GID (a later `Publish`
  replaces, not accumulates).
- **Replay-cache exhaustion** — `ReplayWindow` is a fixed 2048-bit
  bitmap regardless of how far or erratically an attacker drives the
  counter (`TestReplayWindowMemoryStaysBounded`); the relay-side table
  of these windows is itself capacity-bounded (above).
- **CPU exhaustion during X25519/AEAD** — bounded indirectly by the
  circuit/path-length caps above: the amount of ECDH/AEAD work a single
  message can force is a function of `MaxPathLength`, not attacker-
  controlled input size.
- **Gossip-pull amplification** (`msgTypeAnnounceRequest`,
  `docs/garlic-protocol.md` §11.1) — answering a pull request costs this
  node one outbound `GossipAnnounce`, itself bounded to
  `Config.GossipSampleSize` entries (default 16), always well under
  `maxAnnouncePeers` (32) — the same fixed cap that already bounds every
  `msgTypeAnnounce` body. This is a small, fixed amplification factor per
  request, gated by the same per-peer `RateLimiter` covering every other
  incoming message type above, not a new unbounded-response category.

**Future work, not currently implemented:**

- The per-peer `RateLimiter` above shares one budget across every
  message type from a given peer - it has no separate, tighter
  sub-budget for circuit-creation traffic specifically. A peer can still
  spend its entire rate allowance on opening and tearing down circuits
  repeatedly, up to the shared rate/burst limit, rather than being
  throttled harder for that pattern than for, say, capability requests.
- No proof-of-work or other admission cost on acquiring a new peer
  identity: rate limiting and the `MaxCircuits`/`MaxCircuitsPerPeer`/
  `MaxTrackedPeers` ceilings all key off of a peer's Ed25519 node key, so
  none of them raise the cost of the underlying resource (a fresh
  keypair) an unvetted-but-Garlic-capable attacker would cycle through to
  get a fresh budget.
- Service descriptor publishing (`PublishService`) has no rate limit of
  its own beyond whatever the `Rendezvous` implementation in use chooses
  to enforce - `StaticRendezvous` enforces none. Today this is reachable
  only via this node's own local admin socket, not by a remote peer
  (`docs/garlic-rendezvous.md`: no wire message type exists for a remote
  `Publish`/`Lookup`), so it's not yet a live remote "malicious client"
  surface - but it would become one the moment any future `Rendezvous`
  implementation makes `Publish`/`Lookup` reachable over the network, as
  `docs/garlic-rendezvous.md`'s "Future direction" section discusses.

## Global passive adversary (observes a large fraction of the network)

Retains real capability, **more than the pre-correction version of this
document implied.** Because ironwood's own routing layer exposes real
source/dest keys to intermediate nodes (see the correction above), a
global adversary doesn't need to compromise payload encryption at all —
observing enough of the mesh already gives it the same
"key X talked to key Y, this much data, at this time" graph an adversary
watching an unencrypted network would have, for every hop-to-hop link a
circuit's path touches, chosen-hop or not. Multi-hop relaying still
raises the cost of correlating a circuit's *true* endpoints specifically
(the adversary has to link multiple such hop-pair observations into one
circuit, which requires more than any single vantage point gives it) but
this project does **not** claim to defeat a global adversary.

Since this section was first written, `Config.PaddingEnabled` and
`Config.JitterEnabled` (both default on) are wired into the actual send
and relay-forward path (`docs/garlic-protocol.md` §9): every packet's
wire size is independently re-randomized per hop
(`Envelope.PadToRandomRange`), and every packet's send is independently
delayed by a random amount before transmission
(`src/garlic/jitter.go`). `SendGarlicBundled` (§7 of the protocol doc)
additionally lets a real message travel alongside cover entries an
observer cannot distinguish from it. These raise the cost of the
size/timing correlation a global adversary would otherwise get for
free, but do **not** defeat one: there is no fixed-interval batching
(a determined adversary can still average over enough samples to erode
jitter's effect), padding ranges are configurable and therefore
fingerprintable if left at non-default values, and bundling only
helps for calls that actually opt into `SendGarlicBundled` with a
non-zero `coverCount` — `SendGarlic`'s plain path sends one real packet
with no chaff. A global adversary correlating enough traffic over
enough time is not something this project claims to defeat, and this
document should be read accordingly: real cost has been added, not a
guarantee.

## Traffic correlation / traffic confirmation

An adversary who can watch traffic at both the entry and exit of a
circuit simultaneously can attempt classic timing/size correlation to
confirm (not just suspect) that two observed flows are the same
circuit. This project now has four independent mitigations against this
attack, each raising its cost without eliminating it — some engaged by
default, others available on request:

- **Per-hop size re-randomization** (`Config.PaddingEnabled`,
  `docs/garlic-protocol.md` §9): breaks the naive "same size in and out
  at every hop" correlation signal. Does not hide the *distribution* of
  sizes a sustained flow produces — an adversary with enough samples on
  both ends can still attempt statistical (not exact) size correlation.
- **Per-packet jitter** (`Config.JitterEnabled`, same section): breaks
  exact send-timestamp correlation across hops. A bounded worker pool
  and queue mean jitter is skipped (packet sent immediately) once the
  queue is full under load — an adversary who can induce that load
  degrades this defense as a side effect.
- **Cover traffic via bundling** (`SendGarlicBundled`,
  `docs/garlic-protocol.md` §7): opt-in per call — a caller that never
  sets `coverCount > 0` gets none of this benefit, and even with cover
  traffic, an adversary correlating *volume* (not individual packet
  identity) across many bundles over time is not addressed. Chaff
  entries are random bytes that fail decryption (and drop) at the
  circuit's first hop, so this only ever adds cover volume on the
  origin→hop-1 link — links deeper in the circuit see none of it.
- **Auto-pool cover traffic** (`Config.CoverTrafficEnabled`, default
  **on**, `docs/garlic-protocol.md` §11.3): a structurally different
  mechanism from bundling, and default-on rather than opt-in — real,
  validly-encrypted `msgTypeCircuitDataV3` traffic sent automatically
  over every circuit in the auto-pool (when `Config.AutoPoolEnabled`),
  which reaches the terminal hop and is discarded there
  (`deliverTagged`), so unlike bundling it covers a circuit's full depth,
  not just its first link. This is unrelated to, and does not require,
  ever calling `SendGarlicBundled` — an operator who never touches the
  bundling API still gets this cover traffic if auto-pool circuits are
  running. It changes *reach and default*, not the *class* of guarantee:
  still a real, fixed-size, jittered-interval cost rather than a formal
  anonymity-set mechanism, and an adversary correlating volume across
  many rotations of the pool over time is no more addressed by this than
  by bundling.

None of this amounts to a mixnet with formal anonymity-set guarantees.
This is a standard limitation of onion routing without a dedicated
mixing protocol (fixed-size, fixed-interval batching with a real
anonymity set), not specific to this implementation, but it remains
real: a sufficiently patient, sufficiently well-positioned adversary
retains a statistical correlation attack.

## Active timing/watermark attacker

Distinct from the passive correlation adversary above: a relay (or any
on-path node) that *actively* manipulates the timing of packets it
forwards, rather than merely observing them, to inject or detect a
timing pattern ("watermark") that survives the hops in between.

`Config.JitterEnabled`'s random pre-send delay defends against a
*passive* observer trying to correlate exact send timestamps across two
points it watches. It does **not** defend against an adversary that can
selectively delay chosen packets - such an adversary can, in principle,
impose its own timing pattern on a flow regardless of what jitter any
single hop adds on top, since the watermark is injected by the attacker
controlling one hop's forwarding delay, not inferred from otherwise-
unperturbed timing. Nothing in this implementation detects or defends
against this specifically. Do not read the jitter defense described
above as covering this case - it does not, and no claim to the contrary
appears anywhere else in this document or in `docs/garlic-protocol.md`.

## Replay

Mitigated for the threat it targets (a captured packet being
retransmitted to trigger duplicate processing): every hop maintains a
bounded 2048-bit sliding-window `ReplayWindow` keyed by
`(circuit ID, packet counter)` (`docs/garlic-protocol.md` §5), proven by
`TestProcessCircuitDataDropsReplay` and the `ReplayWindow` unit tests.
Not a defense against an adversary who can prevent the *original* packet
from arriving and substitute their own timing (that's a routing/
availability concern, separate from replay).

## Packet tagging (attacker marks a packet to trace it through the network)

An AEAD-authenticated ciphertext cannot be modified without detection —
`Seal`/`Open` (and by extension `EncryptLayer`/`DecryptLayer`) reject any
tampered input (`TestOpenRejectsTamperedCiphertext`,
`TestDecryptLayerRejectsTamperedCiphertext`). An attacker who can't
forge a valid tag can't tag a packet in a way that survives to the next
hop; a hop that receives a tampered packet drops it rather than
forwarding a marked one.

## Route manipulation (attacker tries to influence path selection)

Circuit paths are chosen entirely by the **originator** — there is no
path-selection input an intermediate or remote party can inject.
`CreateCircuit` still takes an explicit, caller-supplied hop list, so
whoever builds that list is responsible for its quality; but a caller
now has a real option instead of picking hops by hand:
`Garlic.SelectPath(n)` (`docs/garlic-protocol.md` §10) builds that list
from topologically diverse candidates automatically. This does not
close route manipulation as a category (an adversary still cannot
inject path-selection input either way, so there's nothing new to
manipulate), but it does mean "diverse selection" is no longer purely
aspirational — it exists and a caller must actively choose not to use
it.

`Garlic.AutoCreateCircuit` (`docs/garlic-protocol.md` §11), exposed as
the `createGarlicCircuitAuto` admin RPC, goes further: it calls
`SelectPathWithGuardPolicy` (§10) and
`CreateCircuit` in one step, with no hop list for the caller to supply
at all, and — when `Config.AutoPoolEnabled` is set — `autoPoolLoop` calls
it automatically in the background with no caller present at all.
`SelectPath` previously had exactly one caller, in a test; automatic,
diverse selection is now materially easier to reach, and for an
auto-pool-enabled node happens by default rather than by opt-in call.
This still does not make it *mandatory*: the manual, explicit-hop-list
`createGarlicCircuit` admin RPC is unchanged and remains available, and
nothing prevents a caller from using it instead. Route manipulation
itself is unaffected either way regardless of which of the three paths
(manual list, `SelectPath` library call, or `AutoCreateCircuit`) built a
given circuit — there is still no path-selection input an intermediate
or remote party can inject into any of them.

## Sybil nodes

An adversary running many Garlic-capable nodes can bias a naive
path-selection strategy toward paths it controls end-to-end. Three real,
partial mitigations now exist, alongside real remaining gaps:

- **`SelectDiversePath`** (`docs/garlic-protocol.md` §10,
  `src/garlic/selection.go`) prefers topologically distant candidates
  (mesh hop count via `core.Core.GetPaths()`) and rejects picking two
  candidates that share an immediate spanning-tree parent
  (`core.Core.GetTree()`). This raises the cost of the *simplest* Sybil
  strategy — deploying several identities on the same link or local
  segment and hoping a naive selector picks more than one of them.
- **Multipath pools** (`docs/garlic-protocol.md` §10,
  `src/garlic/multipath.go`) mean an adversary controlling one path in a
  pool sees only the fraction of traffic routed over that path, not the
  whole conversation — it must control *every* path in the pool to
  reconstruct the full picture, which is strictly more expensive than
  controlling a single circuit.
- **Self-verified/gossiped trust tiers with a first-hop guard policy**
  (`docs/garlic-protocol.md` §10, `src/garlic/discovery.go`,
  `src/garlic/selection.go`) — every discovered peer now carries a
  `SelfVerified` flag: true only if this node itself completed a
  capability handshake with it (`handleCapabilityResponse`), false for a
  peer only ever heard about secondhand via gossip (`processAnnounce`);
  `discoveryRegistry.record` never downgrades an existing `true` back to
  `false` on a later secondhand mention. `SelectPathWithGuardPolicy`
  (used by `AutoCreateCircuit`) restricts the first hop specifically to
  self-verified candidates — falling back to `ErrNoSelfVerifiedCandidates`
  if this node has none — while the remaining hops are still drawn from
  the full pool (self-verified + gossiped), diversity-checked against the
  guard's tree parent the same way `SelectDiversePath` already checks
  candidates against each other. This narrows the specific case of an
  adversary seeding a target's discovery pool with Sybil identities
  purely through gossip and hoping one lands in the most sensitive
  position, the first hop: a gossip-only Sybil can no longer become a
  guard for this node's auto-built circuits without also being
  personally capability-verified by it first.

**How much "self-verified" narrows over time:** the flag is only ever set
by a capability response to a request this node itself had outstanding
(`handleCapabilityResponse` gates on `Garlic.pending`), so it cannot be
claimed by an unsolicited packet — but it is set by *any* such exchange,
including the per-hop `QueryCapability` that `AutoCreateCircuit` performs
on middle-hop candidates it drew from the gossiped tier. A gossip-sourced
candidate that gets selected into any non-guard position of any auto-built
circuit is therefore promoted to self-verified as a side effect of that
circuit being built, and `discoveryRegistry.record` never downgrades it
again. Across many circuits and rotations, the self-verified set drifts
toward "every peer this node has ever successfully built through" rather
than staying "peers this node deliberately sought out". Each promotion
still costs the adversary a real handshake this node initiated, so the
guard restriction keeps its meaning — an attacker cannot inject itself —
but the practical bar it enforces erodes toward "has been contacted at
least once", which is weaker than the phrase "self-verified" suggests on
its own. Nothing here expires or re-scores an entry, so the drift is
one-directional.

**What remains genuinely unmitigated:** neither `SelectDiversePath` nor
the guard policy has any concept of IP/ASN diversity or real-world
operator identity — an adversary who deploys nodes with genuinely
diverse tree positions (not sharing a tree parent, not close in hop
count) defeats `SelectDiversePath` entirely, since tree position is the
only signal available, and propagating a hop's real IP through gossip
would itself be a privacy cost for relay operators (a deliberate design
choice, not an oversight — see `docs/garlic-protocol.md` §8). Self-
verification is likewise not a resource cost: it only requires that a
node answer a capability handshake, something any Sybil identity can do
as cheaply as a legitimate one — becoming self-verified narrows *how* an
adversary must attack (get personally verified by the target, not merely
gossiped to it) without making that meaningfully harder to achieve than
running one more node and waiting to be queried. There is no reputation
system, no proof-of-work or other resource cost to registering as a
Garlic node, and no mechanism that makes running many identities
expensive. Treat Sybil resistance here as "raises the bar above picking
uniformly at random or whatever answered first, and above being gossiped
into the guard position specifically," not as solved.

## Intersection attacks

An adversary who observes a target's activity over multiple
sessions/circuits and correlates what's common across them (classic
intersection-attack methodology) is not defended against by anything
that identifies "this traffic came from a client, not a relay" — which
is the structural property intersection attacks exploit. This project's
mitigation is architectural, not a dedicated intersection-attack
defense: every Garlic-capable node is, by construction, both a
potential circuit originator *and* a relay for other nodes' circuits
(there is no separate "client-only" mode) — so an adversary observing
"key X sent/received Garlic-tagged traffic at time T" cannot conclude
from that alone whether X was the real source/destination or simply
relaying for someone else. This narrows what an intersection attack can
conclude from participation alone, but does **not** defeat one: an
adversary who can also correlate size/timing/volume across sessions
(the "Traffic correlation" section above) can still narrow down which
of a node's flows are its own versus relayed, especially against a
target with low relayed-traffic volume where "this node is relaying
right now" is itself a distinguishing signal. `Config.CircuitLifetime`
bounds how long a single circuit lives, which limits — but does not
eliminate — how much traffic correlates to one circuit's identity
across sessions. Deliberate circuit-rotation *policy* (when to build a
new circuit, how much to relay for others as camouflage) is left to the
caller; nothing in this version enforces one.

## Summary table

| Adversary | Real capability retained |
|---|---|
| Passive observer | Sees traffic exists, sizes, timing; not payload. Cannot see the Garlic tag itself (inside the encrypted session) |
| Single malicious relay (chosen Garlic hop) | Sees its own hop's real-key neighbors (unavoidable, via ironwood's own unencrypted `source`/`dest` fields, not something Garlic hides); cannot decrypt other layers; per-hop ephemeral keys mean non-adjacent colluding hops share no ephemeral key to compare (2026-08-09 pass); for circuits built with the hop-local envelope format (`EnvelopeVersion2`/`garlic-v3`, 2026-08-24 pass), `CircuitID`/`PacketCounter`/`Expiration` are also independent per leg - two non-adjacent colluding hops observe different values for all three fields on the same logical packet, and cannot recover a non-adjacent leg's values without the adjacent hop's key. A legacy `EnvelopeVersion1` circuit (relayed on behalf of a not-yet-upgraded peer) still exhibits the old verbatim-copy behavior for that circuit specifically - this node itself never originates one. |
| Malicious relay / availability attacker | Any hop can drop, delay, or reorder a circuit's traffic at will, or stop forwarding for it entirely - indistinguishable from an ordinary network failure, since Garlic has no independent liveness/acknowledgment channel |
| Mesh-path intermediate node (not a chosen hop) | Same real-key-pair visibility as a malicious relay, for any hop-pair its position sits between - without ever being selected as a circuit hop |
| Malicious introduction point | Sees GID lookups; payload only if also the terminal hop |
| Malicious endpoint | Sees delivered payload (expected) and its own previous hop |
| Malicious client (uninvolved remote peer) | Circuit-flood, oversized-length, deep-nesting, huge-bundle, replay-cache-exhaustion, and gossip-pull-amplification vectors are bounded by fixed caps and a per-peer rate limiter, both fuzz/unit-test proven; no admission cost exists for acquiring a fresh peer identity, and the rate limiter shares one budget across all message types rather than specifically throttling circuit-creation churn |
| Global passive adversary | Real capability - routing metadata (who talks to whom) is not encrypted at the ironwood network layer at all; per-hop padding/jitter/bundling (default on) raise the cost of correlation but do not defeat a patient, well-positioned adversary |
| Traffic correlation | Raised cost via default-on per-hop size randomization and send jitter, plus cover traffic - opt-in per call via `SendGarlicBundled` (first-link only), or default-on for auto-pool circuits via `Config.CoverTrafficEnabled` (full circuit depth) - not a mixnet, statistical correlation over enough samples remains possible |
| Active timing/watermark attacker | Not defended against - jitter only protects against a passive observer; an adversary that actively delays chosen packets to imprint a detectable pattern is unaffected by anything in this implementation |
| Replay | Mitigated within the bounded replay window |
| Packet tagging | Mitigated by AEAD authentication |
| Route manipulation | N/A - no path-selection input an intermediate/remote party can inject either way; automatic selection (`SelectPath`, or now `AutoCreateCircuit`/`createGarlicCircuitAuto`) is available and materially easier to reach than before, but the manual `createGarlicCircuit` path is unchanged and neither is mandatory |
| Sybil | Partially mitigated - `SelectDiversePath` (tree-position diversity), multipath pools, and a self-verified/gossiped trust split with a first-hop guard policy (`SelectPathWithGuardPolicy`) raise the cost of the simplest strategies; no IP/ASN diversity, reputation, or resource-cost mechanism exists, and self-verification itself costs an adversary nothing beyond answering a handshake |
| Intersection attacks | Narrowed, not defeated - every node is structurally both a possible originator and a relay for others, so participation alone doesn't distinguish "this is my traffic" from "I'm relaying"; still erodable via traffic-correlation across sessions |

## Hop-local envelope metadata: what it does and does not close

Closing the `CircuitID`/`PacketCounter`/`Expiration` verbatim-copy signal
(above) removes one specific, cheap correlation technique available to two
colluding non-adjacent Garlic relays. It does **not** change what a global
passive adversary observing the underlying Yggdrasil/ironwood mesh can see:
`ironwood/network`'s `traffic` structure still exposes source/destination
node keys, volume, and timing at every hop, regardless of Garlic envelope
version - see "Global passive adversary" above. Hop-local envelope
metadata raises the cost of one specific *metadata-comparison* attack; it
is not a mixnet and does not defend against traffic confirmation via
timing/volume correlation, which remains covered by padding, jitter, and
cover traffic (with their own, separately-documented limits) rather than
by this mechanism.

Teardown was already hop-local before this pass, by construction: there is
no explicit teardown message in the protocol at all.
`Garlic.CloseCircuit` only clears the *originator's* local bookkeeping
(`Circuit`/`originEphemeral` map entries); every relay forgets a circuit
purely via `relaystate.go`'s local `expireStale` timeout, independent of
any other hop. A relay never learns anything about a circuit's teardown
beyond its own two immediate neighbors aging out.

A further, more specific residual: each hop's packet counter starts at
an independent random offset (`randomCounterOffset`,
`src/garlic/circuit.go`) but increments by exactly 1 per packet, so the
*difference* between any two legs' counters is constant for the life of
the circuit. A pair of colluding non-adjacent relays who anchor even one
confident packet pairing (e.g. via the timing correlation already
discussed above) can recover that constant delta and thereafter label
every subsequent packet pair on the same circuit for free, without
needing to repeat whatever technique produced the original anchor. This
is deliberate, documented scope from the original design (per-leg
values are independently random, not required to defeat a
bootstrapped-correlation attack specifically) - not a regression from
before this pass (which had a delta of exactly 0, needing no anchoring
observation at all to correlate every packet), but worth naming
precisely rather than leaving a reader to assume this specific technique
is fully closed.

## Website transport and distributed directory

The implemented website path is described in [Garlic websites](garlic-sites.md).
It uses two outbound duplex circuits meeting at a relay, plus end-to-end
QUIC/TLS. This supersedes the historical static inbound-tunnel proposal.

The directory sees a GID and signed descriptor, including its signing key
and relay node keys. It does not receive the hosting node's key or IPv6
address. Directory RPCs arrive over Garlic circuits, so the server sees
the preceding hop rather than a directly addressed publication from the
host. This does not eliminate timing correlation, targeted withholding,
stale-but-unexpired records, Sybil placement or eclipse attacks. XOR
placement and replication provide neither consensus nor Sybil resistance.
Bootstrap reachability and enough independent upgraded hops are required.
All records are verified on storage and lookup, old publications cannot
overwrite newer ones, and expired records are removed. Hosts republish
after restarts and changes in the known directory population.

The relay learns the GID and which two terminal circuit legs it bridges,
their immediate previous hops, timings, packet sizes and traffic volumes.
It can drop or delay packets. End-to-end TLS authenticates the service's
signing key against the hash domain and protects application data from
that relay. Registering a public descriptor also requires an ownership
signature bound to the relay and exact terminal circuit ID. A copied
descriptor cannot rebind the service to an attacker's circuit.

Reverse circuit traffic has a separately derived key, hop-local IDs and
independent counters at each leg. Every hop wraps a layer and the origin
authenticates all layers before accepting replay counters. It verifies
the immediate first-hop source. Return state is pinned to its authenticated
neighbor/key mapping and expires; the configured hop count is never
silently reduced. Existing timing, counter-delta, adjacent-hop, physical
IP and small-anonymity-set limitations still apply. QUIC connection IDs
and flow tokens are visible at the joining relay; this is not protection
against a global observer or application/website fingerprinting.

Input-driven state is bounded: 4096 directory records, 32 outstanding
directory RPCs, four site workers with 256 queued events, 1024 relay
registrations, 2048 relay flows, 64 local client transports, 64 hosted
services, 64 accepted QUIC connections and 128 active streams per hosted
service. QUIC receive windows, datagrams, referrals, lookup breadth,
record lifetimes and return routing tables have independent bounds.
Site packets use a separate 512 packets/second per-peer token bucket
with a 1024-packet burst. These are resource controls, not a proof of
resistance to sustained distributed flooding.

The HTTP proxy accepts only loopback listeners and validated hash hosts;
no unknown name is retried using public DNS or a direct TCP connection.
Only fixed, operator-configured backend addresses on virtual ports 80/443
can be reached. HTTP forwarding headers and cross-site Referer/Origin are
removed; HTTP cookies become host-only because public browsers do not
recognize `.domains.yggg` as a public suffix. HTTPS CONNECT is opaque and
cannot enforce those HTTP header/cookie rules. The PAC sends ordinary
Internet domains directly, so those destinations are outside Garlic.
An ordinary browser's speculative networking, extensions, fingerprinting
and storage isolation are not controlled by this code. No Tor Browser
equivalence or claim of absolute anonymity is made.
