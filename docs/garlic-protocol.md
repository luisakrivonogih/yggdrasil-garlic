# Garlic Routing Overlay — Protocol Specification v1

Status: experimental. Describes what is actually implemented in
`src/garlic` as of this writing, not an aspirational future design. See
`docs/garlic-architecture.md` for the integration rationale and
`docs/garlic-threat-model.md` for what this protocol does and does not
protect against.

All integers are big-endian. All byte offsets are 0-indexed. "MUST NOT
panic" applies to every parser described here regardless of input.

## 1. Transport framing

Every Garlic message travels as the payload of a `core.Core.WriteGarlic`
call, which core.go tags with a single byte (`typeSessionGarlic`) ahead of
it before handing it to ironwood's already end-to-end-encrypted
`PacketConn`. That tag byte is core.go's concern, not this document's —
everything below describes the bytes *after* that tag, i.e. what a
registered `core.GarlicHandler` receives.

The first byte of that payload is the **Garlic message type**
(`src/garlic/protocol.go`):

| Value | Name | Meaning |
|-------|------|---------|
| `0x01` | `msgTypeCapabilityRequest` | "Do you support Garlic, and what's your public key?" No body. |
| `0x02` | `msgTypeCapabilityResponse` | Answer to the above; body is a `CapabilityMessage` (§3). |
| `0x03` | `msgTypeCircuitData` | One onion-routed packet; body is described in §4. |
| `0x04` | `msgTypeAnnounce` | Gossip of known Garlic-capable peers; body is an `AnnounceMessage` (§8). |
| `0x05` | `msgTypeCircuitDataBundle` | Several `msgTypeCircuitData`-shaped entries (real traffic mixed with cover entries) carried together; body is a `Bundle` (§7). |
| `0x06` | `msgTypeAnnounceRequest` | Gossip *pull*: ask the recipient to immediately send back a `msgTypeAnnounce`. No body (§11.1). |
| `0x07` | `msgTypeCircuitDataV3` | Auto-pool circuit data; wire-identical to `msgTypeCircuitData`, distinguished only by this type byte (§11.2). |

Any other value, or an empty payload, is silently dropped by
`Garlic.handleIncoming` — no error, no response, matching the "generic
protocol errors" requirement (§17 of the original brief).

## 2. Garlic Envelope

`src/garlic/envelope.go`. The structure every `msgTypeCircuitData`
message's onion-layer ciphertext is wrapped in on the wire.
`Envelope.PadTo` normalizes to a fixed size; `Envelope.PadToRandomRange`
picks a fresh random target size in `[min, max]` on every call instead —
this is what `Config.PaddingEnabled` actually drives on the send/relay
path (§9), so consecutive envelopes on the same link don't share a
size an observer could use as a fingerprint.

```
offset  size  field
0       1     version            (1 = legacy global-ID format; 2 = hop-local format - see "Hop-local envelope format" below. This node always originates version 2 once every hop supports it.)
1       16    circuit_id         (CircuitID, 128-bit random value)
17      8     packet_counter     (uint64)
25      8     expiration         (uint64, Unix seconds)
33      4     body_len           (uint32)
37      body_len   body          (opaque - AEAD ciphertext at the layer level)
37+body_len  4      padding_len  (uint32)
...     padding_len  padding    (opaque, ignored on decode)
```

Fixed header size: 37 bytes (`envelopeFixedHeaderSize = 1 + 16 + 8 + 8 + 4`).
`MaxBodySize` and `MaxPaddingSize` are both
65535 (matching `core.Core.MTU()`'s own cap) — `Unmarshal` rejects a
declared `body_len`/`padding_len` against this cap *before* checking it
against the actual remaining buffer, so an attacker's claimed length can
never drive an allocation before it's validated.

`Unmarshal` never aliases its input: `Body`/`Padding` are always copied
out, so mutating the caller's buffer after `Unmarshal` returns cannot
retroactively corrupt the parsed `Envelope`.

## 3. CapabilityMessage

`src/garlic/capability.go`. The body of a `msgTypeCapabilityResponse`
message.

```
offset  size  field
0       1     version_count           (max 16)
1       ...   per version: len(1) + bytes   (max 32 bytes each)
...     1     key_len                 (max 64)
...     key_len   public_key
```

`Versions` currently only ever contains the single string
`"garlic-v2"` (`CapabilityGarlicV2`) in this implementation, but the
format allows a future node to advertise several. `PublicKey` is the
responder's long-term Garlic X25519 public key (§6).

A **timeout** (no response within `Config.CapabilityTimeout`, default 6s)
is the only signal a querying node has that a peer is legacy or
Garlic-disabled — indistinguishable from an unresponsive Garlic-capable
node, by design (there is nothing to distinguish; both cases mean "do not
use this node as a circuit hop").

## 4. Circuit data message (onion routing)

Body of a `msgTypeCircuitData` message:

```
offset  size       field
0       32         ephemeral_public_key   (X25519, KeySize)
32      ...        Envelope (§2), whose Body is this hop's layer ciphertext
```

`circuitDataMinSize = 32 + 37 = 69` bytes (`KeySize + envelopeFixedHeaderSize`)
is the minimum a well-formed message can be; anything shorter is dropped
immediately.

### 4.1 Per-hop key derivation (chained per-hop ephemeral, non-interactive)

The circuit's originator generates an **independent ephemeral X25519
keypair per hop** (not one for the whole circuit). For hop *i* with
long-term Garlic public key `P_i` (learned via §3), the originator
computes:

```
secret_i          = X25519(ephemeral_i_private, P_i)
establish_secret_i = HKDF-SHA256(secret_i, salt=nil, info="yggdrasil-garlic-v2-circuit-establish")
key_i              = HKDF-SHA256(establish_secret_i, salt=nil, info="yggdrasil-garlic-v2-circuit-data-send")
```

Only `ephemeral_1_public` is sent as the wire prefix to hop 1 (§4, byte
offset 0). Every other hop's ephemeral public key,
`ephemeral_{i+1}_public`, is carried *inside* hop *i*'s own encrypted
layer as `LayerPlaintext.next_hop_ephemeral` (§4.2) — a hop only learns
the next hop's ephemeral key by successfully decrypting its own layer,
never before. Hop *i*, on receipt, independently computes the same
`secret_i` via `X25519(P_i_private, ephemeral_i_public)`
(Diffie-Hellman symmetry) and the same `key_i` via the identical
two-stage HKDF chain — no interactive handshake is needed to establish
`key_i`.

This gives the property that non-adjacent hops (e.g. hop 1 and hop 3 of
a 3-hop circuit) never observe a common ephemeral public key and cannot
link a circuit by comparing them — see
`docs/garlic-threat-model.md`'s "Malicious relay" section and
`TestNonAdjacentHopsCannotLinkViaEphemeralKeys`
(`src/garlic/linkability_test.go`). It is the same shape as Tor's
classical (non-Sphinx) telescoping circuit construction: an immediate
predecessor hop necessarily relays its successor's ephemeral public key
as plain routing information (it has to, to address the next hop) but
never learns that key's private half.

`LabelCircuitDataRecv` (`"yggdrasil-garlic-v2-circuit-data-recv"`) is
reserved in the same derivation chain for a future reply/return path —
no circuit today carries traffic in that direction, so it is currently
unused.

This derivation chain (`LabelCircuitEstablish`/`LabelCircuitDataSend`) is
used for `EnvelopeVersion1` circuits. `EnvelopeVersion2` (hop-local)
circuits use a distinct chain, `LabelCircuitEstablishHopLocal`/
`LabelCircuitDataSendHopLocal` - see "Hop-local envelope format" below
for why the two are kept cryptographically separate rather than merely
version-tagged.

### 4.2 Layer plaintext

`src/garlic/layer.go`. What `key_i` decrypts `Envelope.Body` into:

```
offset  size          field
0       4             next_hop_len          (max 256)
4       next_hop_len  next_hop_key          (empty ⟺ this is the terminal hop)
...     1             has_next_ephemeral    (0 or 1)
...     0 or 32       next_hop_ephemeral    (present ⟺ has_next_ephemeral == 1;
                                              the ephemeral X25519 pubkey for the
                                              hop after this one)
...     4             inner_len             (max 65535, = MaxBodySize)
...     inner_len     inner                 (next layer's ciphertext, or the
                                              final payload if next_hop is empty)
```

AEAD: XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`), 24-byte
nonce derived deterministically as `packet_counter` right-aligned into a
zero-padded 24-byte buffer — safe only because `(key_i, packet_counter)`
is never reused (§5).

### 4.3 Relay behavior

On receipt of a `msgTypeCircuitData` body (`Garlic.processCircuitData`,
pure/no I/O — see `docs/garlic-architecture.md` §3.1 for why this is
split from the I/O wrapper):

1. Reject if shorter than `circuitDataMinSize`.
2. Parse the `Envelope`; reject on any parse error or unsupported version.
3. Reject if `Envelope.Expiration` is in the past.
4. Look up (or create, capacity permitting) this circuit ID's relay-side
   `ReplayWindow` (`src/garlic/relaystate.go`); reject if the table is
   full or `PacketCounter` is a replay.
5. Derive `key_i` per §4.1; attempt `DecryptLayer`. Any failure here
   (wrong key because the message wasn't meant for this identity,
   tampered ciphertext, or a malformed plaintext after decryption) is
   treated identically: drop, no error surfaced.
6. If the recovered `NextHop` is empty: deliver `Inner` locally
   (`Garlic.RecvGarlic`).
7. Otherwise (this step describes `EnvelopeVersion1` handling
   specifically; `EnvelopeVersion2` circuits instead forward using the
   decrypted layer's own `NextLocalCircuitID`/`NextLocalCounter`/
   `NextLocalExpiration`, never copying the incoming envelope's values —
   see "Hop-local envelope format" below): rebuild an `Envelope` with the
   same `CircuitID`, `PacketCounter`, and `Expiration`, `Body = Inner`. If
   `Config.PaddingEnabled`, this hop independently re-rolls
   `Envelope.PadToRandomRange(MinPaddedSize, MaxPaddedSize)` before
   marshaling — the outgoing wire size on this hop's outbound link is
   unrelated to the size this hop received on its inbound link, by
   design (§9). Forward
   `msgTypeCircuitData || next_hop_ephemeral || new_envelope` to
   `NextHop`, where `next_hop_ephemeral` is the value this hop just
   decrypted from its own layer's `LayerPlaintext.next_hop_ephemeral`
   (§4.2) — **not** the ephemeral public key this hop itself received.
   A message whose decrypted layer has a non-empty `next_hop` but an
   absent `next_hop_ephemeral` is malformed and dropped rather than
   forwarded.

## Hop-local envelope format (EnvelopeVersion2 / garlic-v3)

`Envelope.Version = 2` marks a hop-local circuit: `CircuitID`,
`PacketCounter`, and `Expiration` are scoped to one hop-to-hop leg, not
the whole circuit. A relay decrypting its own onion layer under this
format finds three additional fields (see `LayerPlaintext` below) telling
it what to write for the *next* leg when it forwards - it never reuses
its own incoming leg's values.

`LayerPlaintext` (hop-local shape, `marshalHopLocal`/
`unmarshalLayerPlaintextHopLocal`, `src/garlic/layer.go`): the existing
`next_hop_len(4) next_hop(N) has_ephemeral(1) [ephemeral(32)]
inner_len(4) inner(M)` prefix, followed by `has_next_local(1)
[next_local_circuit_id(16) next_local_counter(8)
next_local_expiration(8)]` - present for every non-terminal hop, absent
for the circuit's final hop.

Key derivation uses a distinct HKDF label chain
(`LabelCircuitEstablishHopLocal`/`LabelCircuitDataSendHopLocal`,
`src/garlic/crypto.go`) from the legacy `garlic-v2` chain, so a version
mismatch fails at AEAD authentication even if the `Envelope.Version` byte
check were somehow bypassed.

A node advertises support via the `garlic-v3` capability string
(`CapabilityGarlicV3`, `src/garlic/capability.go`) - unrelated to
`msgTypeCircuitDataV3`, the pre-existing auto-pool cover-traffic wire tag.
`Garlic.CreateCircuit` refuses to build a circuit through any hop that
hasn't advertised `garlic-v3`; every circuit this node originates uses
this format once available, never falling back to `EnvelopeVersion1`
intentionally.

## 5. Replay protection

Two independent replay windows exist, both a fixed 2048-bit sliding
bitmap (`src/garlic/replay.go`), bounded regardless of how far or
erratically an attacker drives the counter:

- **Relay-side**, keyed by `CircuitID`, one per circuit a node is
  currently relaying for (`relayCircuitState`, itself capacity-bounded —
  a new circuit ID is refused once the table is full).
- The **originator** never replay-checks its own sends; it is the sole
  source of `PacketCounter` values for a circuit it created, and
  `Circuit.Seal` guarantees they strictly increase per hop, per call.

`CircuitID` is a 128-bit value drawn from `crypto/rand`
(`src/garlic/circuit.go`, `randomCircuitID`) — widened from the original
64 bits purely for collision resistance under random generation (there
is no other bound it needs to satisfy: it carries no integer semantics,
only equality comparison and use as a map key). `CircuitManager` (the
originator's own circuit table) additionally guards against the
vanishingly unlikely case of a locally-generated ID colliding with one
it's already tracking, refusing the insert rather than silently
overwriting the existing circuit's state (`ErrCircuitIDCollision`).

## 6. Identity and GID

`src/garlic/identity.go`, `src/garlic/gid.go`, `src/garlic/descriptor.go`.
A node's long-term Garlic identity now carries two independent
keypairs, neither derived from the other:

- an X25519 keypair (`Identity.PublicKey`/`PrivateKey`) for circuit-hop
  ECDH, unchanged from before, and
- an Ed25519 keypair (`Identity.SigningPublicKey`/`SigningPrivateKey`)
  used only to sign service descriptors.

A Garlic Service ID is now bound to the *signing* key:

```
GID = version_byte(1) || BLAKE2b-256("yggdrasil-garlic-v1-gid" || signing_public_key || service_id)
```

(the GID domain separator string itself is unchanged; only which public
key feeds it changed, from the X25519 identity key to the Ed25519
signing key). 35 bytes total, canonically encoded as unpadded base32.
Computable and verifiable by anyone who knows `signing_public_key` and
`service_id`; never derived from or convertible to the underlying
Yggdrasil IPv6 address.

A published service is a signed `ServiceDescriptor`
(`src/garlic/descriptor.go`), not a bare introduction-point list. What's
signed (`ServiceDescriptor.signedBytes()`) is exactly:

```
offset  size            field
0       1               version
1       32              service_public_key   (ed25519)
33      4               service_id_len        (max 64)
...     service_id_len  service_id
...     4               intro_point_count     (max MaxIntroPoints = 16)
...     ...             per intro point: node_key_len(1) + node_key
...     8                published_at          (unix seconds)
...     8                expires_at             (unix seconds; expires_at -
                                                   published_at capped at
                                                   MaxDescriptorLifetime,
                                                   7 days)
```

followed by a 64-byte Ed25519 `signature` over exactly those bytes — no
field a rendezvous itself might add (receipt timestamps, sequence
numbers, storage hints) is ever part of what's signed.

`Rendezvous.Lookup` returns this descriptor **unverified** — the
rendezvous is untrusted storage/relay, not a co-signer, and can
withhold, reorder, or serve a stale copy. `Garlic.LookupService`
(`src/garlic/manager.go`) is the client-side trust boundary: it
recomputes the GID from the descriptor's own `service_public_key` and
`service_id` (rejecting a mismatch — this is what makes the GID
self-certifying), verifies the Ed25519 signature, and checks
`expires_at` against the local clock, before returning the descriptor's
introduction points to the caller. A malicious or buggy rendezvous
cannot make a client accept an attacker-controlled service as the
legitimate owner of a GID it doesn't hold the signing key for.

## 7. Bundling

`src/garlic/bundle.go`. Wire format:

```
offset  size   field
0       4      message_count   (max 32)
4       ...    per message: len(4) + bytes   (max 65535 bytes each)
```

Wired into the send path via `Garlic.SendGarlicBundled(id, payload,
coverCount)`: it builds the one real `circuitData` entry (§4, same
shape as a standalone message's body — `ephemeral_public_key ||
Envelope`), appends `coverCount` cover entries via
`Bundle.AddCoverMessage` (random bytes, sized to match the real entry),
shuffles the entry order (Fisher-Yates, `shuffleBundleMessages`), and
sends the result as one `msgTypeCircuitDataBundle` message.

On receipt, `Garlic.processCircuitDataBundle` unmarshals the bundle and
runs **every** entry through the exact same `processCircuitData`
pipeline used for a standalone message (§4.3) — no separate code path,
no weaker checks. A cover entry has no valid ephemeral key/ciphertext
relationship, so it fails `DecryptLayer` and is dropped exactly like a
corrupted or misdirected message already is; the real entry (if this
node is a hop for it) is delivered or forwarded normally. Each
non-drop outcome is acted on independently, so a bundle's entries need
not belong to the same circuit or even be addressed through the same
next hop.

This is the actual "garlic" property (as opposed to a single onion
stream): an observer — including a hop that isn't the intended
recipient of any entry in the bundle — cannot decrypt any entry, and
therefore cannot tell which one, if any, is real, or even how many of
the bundle's entries are real versus chaff. See
`docs/garlic-threat-model.md`'s traffic-correlation section for what
this does and does not defend against.

## 8. Discovery / gossip (`msgTypeAnnounce`)

`src/garlic/discovery.go`. Lets a node learn about Garlic-capable peers
it has never directly queried itself, entirely over the
`typeSessionGarlic` channel — a node that doesn't run `src/garlic`
cannot construct, parse, or respond to this message type, so discovery
is only ever visible to other Garlic nodes, by construction (the same
property capability negotiation already has).

Body of a `msgTypeAnnounce` message (`AnnounceMessage`):

```
offset  size  field
0       4     peer_count            (max 32)
4       ...   per peer:
              1     node_key_len    (max 64)
              ...   node_key
              1     garlic_key_len  (max 64)
              ...   garlic_key
```

`Garlic.processAnnounce` records every entry with both keys non-empty
into the local `discoveryRegistry` (bounded, evicts the
least-recently-seen entry once full) — it does **not** treat this as
trust: a gossiped entry is only ever used as a circuit hop after its
own `QueryCapability` round trip succeeds, same as a directly-learned
peer. `Garlic.GossipAnnounce` sends a sample of the local registry
(`Config.GossipSampleSize`) to one peer; a background tick
(`Config.GossipInterval`) calls it for up to `Config.GossipFanout`
peers this node has itself already capability-verified
(`capabilityCache`), never an unverified discovery candidate — so
gossip only propagates outward from nodes this instance has confirmed
are running Garlic.

## 9. Timing and size defenses

Two independent, per-packet randomizations apply to every
`msgTypeCircuitData` send or forward when enabled (both default on,
`Config.PaddingEnabled`/`Config.JitterEnabled`):

- **Size** (§2): `Envelope.PadToRandomRange(MinPaddedSize,
  MaxPaddedSize)`, re-rolled independently by the originator and by
  every relay forwarding the packet — so a packet's size on one
  hop-to-hop link carries no information about its size on the next.
- **Timing**: `Garlic.sendCircuitData` hands every outgoing packet to a
  bounded worker-pool scheduler (`src/garlic/jitter.go`) with a delay
  drawn uniformly from `[MinJitter, MaxJitter]`, independently rolled
  per packet, before it's actually transmitted. The scheduler never
  blocks the caller (a full queue falls back to sending immediately)
  — required because relay forwarding happens synchronously inside
  `core.Core.ReadFrom`'s read loop.

Neither is a general-purpose mixnet: there is no fixed-interval
batching, and a global adversary watching both ends of a circuit
simultaneously can still attempt statistical correlation over enough
samples. See `docs/garlic-threat-model.md`'s "Traffic correlation"
section for what this does and does not raise the cost of.

## 10. Path selection and multipath

Node-local behavior, not a wire message, but it materially changes
what's observable on the wire:

- `Garlic.SelectPath(n)` (`src/garlic/selection.go`) picks `n`
  circuit-hop candidates from this node's discovered/verified Garlic
  peers, preferring topologically distant candidates
  (`core.Core.GetPaths()`'s hop count) and avoiding two candidates that
  share an immediate tree parent (`core.Core.GetTree()`) — a cheap
  signal they might be run by the same operator or sit on the same
  local segment. This is a heuristic, not Sybil resistance (see
  `docs/garlic-threat-model.md`'s Sybil section for what it does not
  solve).
- `SelectPathWithGuardPolicy(pool, n, minHopCount)`
  (`src/garlic/selection.go`) is `AutoCreateCircuit`'s (§11) hop-selection
  policy: every `HopCandidate` now also carries a `SelfVerified` flag
  (mirroring `DiscoveredPeer.SelfVerified` — true only if this node
  itself completed a capability handshake with that peer, never a
  gossip-only mention, and never downgraded back to false by a later
  gossip mention once true). Hop 0 is chosen via `SelectDiversePath`
  restricted to self-verified candidates only, returning
  `ErrNoSelfVerifiedCandidates` if none exist; the remaining hops are
  then chosen via `SelectDiversePath` over the full pool (self-verified
  + gossiped), seeded so hop 1 can't share hop 0's tree parent either —
  one continuous diversity guarantee spanning both stages, not two
  independent ones. Nothing is pinned across calls: the first hop is
  reselected fresh every call, unlike a Tor-style long-lived guard.
- `Garlic.CreateCircuitPool`/`SendGarlicMultipath`
  (`src/garlic/multipath.go`) build several independent circuits and
  round-robin sends across them, so a given circuit's link carries only
  a fraction of one conversation's total traffic — an adversary
  positioned on (or colluding across) only some of the pool's paths
  sees only that fraction.

## 11. Auto-pool circuits: gossip pull and tagged delivery

`src/garlic/manager.go`. Automatic circuit construction, rotation, and
cover traffic (`Garlic.AutoCreateCircuit`, the background `autoPoolLoop`)
are node-local behavior, not wire protocol, same as §10's `SelectPath` —
but they're built on two wire additions that are: a gossip-pull request
type, and a second circuit-data message type carrying a one-byte
real/cover tag past the terminal hop's own layer decryption.

### 11.1 `msgTypeAnnounceRequest` (gossip pull)

Empty body. `Garlic.RequestGossip(peer)` sends it; on receipt,
`Garlic.handleIncoming` immediately calls `g.GossipAnnounce(from)` — the
existing `msgTypeAnnounce` push (§8), triggered on demand instead of
waiting for the sender's own periodic `gossipTick`. This exists because
`gossipTick` only pushes to peers already in this node's own
`capabilityCache` (peers it has itself queried); a freshly bootstrapped
node isn't in anyone *else's* `capabilityCache` yet, so without a pull it
would have to wait for some other node to happen to query it first.

Gated by the same per-peer `RateLimiter` every incoming Garlic message
already goes through (`handleIncoming`'s `g.limiter.Allow(from)` check,
before the type switch) — no additional rate limiting specific to this
type. The `GossipAnnounce` reply it triggers is bounded to
`Config.GossipSampleSize` entries (default 16), itself always well under
`maxAnnouncePeers` (32, `discovery.go`) — the same fixed cap
`AnnounceMessage.Marshal` enforces on any `msgTypeAnnounce` body,
pull-triggered or not.

`Config.BootstrapPeers` (hex-encoded node keys) drives this
automatically: for each configured entry, `Garlic.bootstrap()` (run once,
in its own goroutine, from `New`) retries `QueryCapability` up to
`bootstrapMaxAttempts` (3) times and, on success, calls `RequestGossip` —
the one manual step an operator performs, analogous to Yggdrasil's own
`Peers` config, and what gives a node its first self-verified candidate
(§10's `SelectPathWithGuardPolicy`) to build anything from at all.

Like every other message type, `handleIncoming`'s type switch has no
default case, so a peer running code without this feature simply never
responds — §1's "any other value... is silently dropped" applies
identically here, and no capability check or version negotiation was
needed to add this type.

### 11.2 `msgTypeCircuitDataV3`

Wire-identical to `msgTypeCircuitData` (§4): the same
`ephemeral_public_key || Envelope` body shape, the same per-hop key
derivation (§4.1), the same `LayerPlaintext` layout (§4.2), the same
relay decision logic. `Garlic.processCircuitData` handles both message
types through one shared implementation, taking the inbound type byte as
a `msgType` parameter so it knows which one it's processing — there is
no separate cryptography or parsing path for this type, only a different
outer byte and a different terminal-delivery destination.

The two types exist to keep two circuit-tracking worlds separate without
touching the manual API at all: `msgTypeCircuitData` underlies
`SendGarlic`/`RecvGarlic`/`CreateCircuit`/the `createGarlicCircuit` admin
RPC, unchanged. `msgTypeCircuitDataV3` is what `AutoCreateCircuit`-built
circuits carry instead — both the origin's first send and every
relay-to-relay forward — via `SendGarlicAuto`/`RecvGarlicAuto` and cover
traffic (§11.3).

**Forwarding preserves the inbound type byte.** §4.3's relay step 7 —
rebuild the envelope, forward `msgType || next_hop_ephemeral ||
new_envelope` to the next hop — uses whichever type byte the packet
arrived as, never a hardcoded `msgTypeCircuitData`. A relay forwarding a
`msgTypeCircuitDataV3` packet keeps forwarding it as
`msgTypeCircuitDataV3` all the way to the terminal hop; the type is
otherwise inert to every intermediate hop, which never inspects `Inner`
regardless of which type it's relaying. This is proven directly:
`TestProcessCircuitDataV3ForwardPreservesMessageType` and
`TestProcessCircuitDataPlainForwardStillUsesPlainType`
(`src/garlic/relay_logic_test.go`) each assert the forwarded packet's
leading byte matches the type it arrived as.

**Terminal delivery is where the two types diverge.** When
`processCircuitData` recovers an empty `NextHop` (this node is the
circuit's final hop), the resulting `circuitAction` carries a `tagged`
field set to `msgType == msgTypeCircuitDataV3`. `Garlic.dispatchAction`
routes a tagged delivery to `deliverTagged` instead of the plain
`g.delivered` channel, which reads the delivered `Inner` as:

```
offset  size   field
0       1      kind      (0 = autoPayloadKindReal, 1 = autoPayloadKindCover)
1       ...    payload   (only meaningful when kind == autoPayloadKindReal)
```

- `kind == autoPayloadKindReal` (0): `Inner[1:]` is pushed to
  `g.autoDelivered`, read by `RecvGarlicAuto`/the `recvGarlicAuto` admin
  RPC — never `g.delivered`, so existing `RecvGarlic` callers are
  structurally unaffected by anything in this section.
- `kind == autoPayloadKindCover` (1), or an empty/malformed `Inner`:
  dropped silently — no channel push, no error, no counter distinguishing
  it from a legitimate delivery failure, matching this package's existing
  "a drop is never explained further" convention (§1). Proven by
  `TestProcessCircuitDataV3DeliverIsTagged`/
  `TestProcessCircuitDataPlainDeliverIsNotTagged`.

A `msgTypeCircuitData` (non-V3) delivery is entirely unaffected: `tagged`
is simply `false`, and `dispatchAction` takes the existing `g.delivered`
branch exactly as it did before this section's additions existed.

### 11.3 Cover traffic (auto-pool only)

When `Config.AutoPoolEnabled` and `Config.CoverTrafficEnabled` (default
**on**), the `autoPoolLoop` background loop sends one
`kind == autoPayloadKindCover` packet — `coverPayloadSize` (32) all-zero
plaintext bytes, via `sendCoverTraffic`'s `make([]byte, coverPayloadSize)`
(the AEAD ciphertext this produces is indistinguishable from random
regardless of plaintext content, and per-hop wire size is independently
re-randomized on top of this by `Config.PaddingEnabled` (§9), so an
all-zero plaintext is sufficient — nothing about it is observable past
the AEAD seal) — over every circuit currently in the auto-pool, on
average every `Config.CoverTrafficInterval` (default 75s), jittered
±50% so the interval itself isn't a fixed, fingerprintable period.

Scheduling is per circuit, not per round: when a round comes due,
`sendCoverTraffic` gives each pool circuit its own delay, drawn
independently and uniformly from `[0, Config.CoverTrafficInterval)`
(`coverTrafficStagger`), rather than sending to all of them at once. That
independence is load-bearing — a single shared instant would put
`Config.AutoPoolSize` cover packets on the wire toward
`Config.AutoPoolSize` *different* first hops within one scheduling
window, which is itself a correlation signal binding those otherwise
unrelated circuits to one originator, exactly the "never all at once"
property circuit rotation already preserves (§10). Sent
as ordinary, validly-encrypted `msgTypeCircuitDataV3` traffic, this
travels the *full* circuit depth — indistinguishable in shape from real
auto-pool traffic to every intermediate hop, and to the terminal hop too,
right up until `deliverTagged`'s kind check discards it.

This is a different mechanism from the pre-existing, opt-in-per-call
`SendGarlicBundled` cover entries (§7), and necessarily so: a `Bundle`
cover entry is random bytes with no valid ephemeral-key/ciphertext
relationship, so it fails `DecryptLayer` (and is dropped) at whichever
hop first attempts to decrypt it — always the circuit's first hop, since
`SendGarlicBundled` addresses its bundle to `firstHop` and a forwarded
bundle entry that *does* decrypt is unpacked and relayed onward as an
ordinary single `msgTypeCircuitData` packet, not as a bundle. Bundling's
cover volume therefore only ever appears on the origin→hop-1 link;
links deeper in a circuit see none of it. Continuous auto-pool cover
traffic needed to be real, validly-encrypted onion traffic that actually
reaches the terminal hop and is discarded *there*, which is what
`msgTypeCircuitDataV3`'s tagged delivery (§11.2) provides.

### 11.4 `CapabilityAutoCircuit`

`CapabilityGarlicV2` (§3) gates ordinary Garlic participation.
`CapabilityAutoCircuit` (`capability.go`, value `"garlic-v2-auto"`) is a
second, independent version string in the same
`CapabilityMessage.Versions` list, gating whether a node's code
understands the wire mechanics in §11.1/§11.2 —
`CapabilityMessage.SupportsAutoCircuit()` mirrors the existing
`SupportsGarlicV2()`.

`processCapabilityRequest` (§3) advertises both strings unconditionally,
for every node whose code includes this feature — advertising
`CapabilityAutoCircuit` is **not** gated on `Config.AutoPoolEnabled` or
`Config.CoverTrafficEnabled`. Those two config fields govern only
whether *this* node chooses to originate auto-pool circuits or cover
traffic itself; every Garlic-capable node already relays/forwards for
other nodes' circuits regardless of what it personally originates (there
is no "client-only mode" — see `docs/garlic-threat-model.md`'s
"Intersection attacks" section), and `CapabilityAutoCircuit` states only
that this node's relay/terminal-hop code can correctly handle a
`msgTypeCircuitDataV3` packet if selected into someone else's circuit.

`Garlic.AutoCreateCircuit` checks `SupportsAutoCircuit()` via
`QueryCapability` for **every** selected hop, not only the terminal one —
a candidate missing it fails circuit construction with
`ErrHopMissingAutoCircuitSupport`. Note that `QueryCapability` reuses a
cached result if one already exists for that key (the cache has no TTL);
only a hop this node has no cached answer for costs an actual round trip.
That is the same behavior as the manual `createGarlicCircuit` admin RPC,
and it is deliberate: forcing a fresh `PingCapability` for every hop would
add a full round trip per hop to every auto-built circuit, including for
peers just verified moments earlier. The consequence to be aware of is
that "re-verified per hop" means "checked against what this node has
itself confirmed at some point", not "confirmed live at build time" — a
hop that has since gone away is detected by the circuit failing in use,
not by this check. This is stricter than strictly
necessary for a purely-intermediate position (forwarding never inspects
`Inner`, so even code that predates this feature would happen to forward
a V3 packet correctly by accident) — but a legacy *terminal* hop would
successfully decrypt its own layer, see `Inner` starting with an
unexpected kind byte, and misdeliver or reject it under its own old
code's expectations. Gating every position sidesteps needing to reason
about which specific position is the risky one, and means only nodes
that opted into running this feature's code ever see
`msgTypeCircuitDataV3` traffic at all.

## 12. What this version does not define

- No wire format for circuit teardown/error signaling — a dead or
  uncooperative hop is currently only detected by the originator's own
  `SendGarlic`/timeout logic at the application layer, not a protocol
  message.
- The original `SendGarlic`/`RecvGarlic` API remains one-way. Websites use
  the separate duplex wire types below.

## 13. Websites and distributed directory (`garlic-sites-v1`)

The additive capability gates every hop of a site circuit. Type 8
(`msgTypeDuplexData`) carries the same hop-local forward body as type 3.
After successful decryption, each hop stores its immediate previous/next
node, incoming/child local IDs and an independently derived reply key.
This bounded state expires after three minutes. Existing one-way and
auto-pool traffic do not install return routes or enter the site queues.

Type 9 (`msgTypeCircuitReply`) has `local_id[16] || counter[8] || ciphertext`.
The reverse key is derived through `LabelCircuitEstablishHopLocal`, then
`yggdrasil-garlic-hoplocal-data-reply-v1`. AEAD authenticates the local
ID; each hop adds its own `counter || AEAD(inner)` layer and replaces the
wire ID with its upstream leg's ID. Counters start independently at random
and increment without reuse. The origin accepts only its first hop,
authenticates every layer, then checks per-hop replay windows.

Duplex terminal/reply payloads start with a site operation byte:

| Byte | Operation | Body |
| --- | --- | --- |
| 1 | Register service | JSON signed descriptor and signature over domain separator, GID, relay node key and terminal local circuit ID |
| 2 | Registration acknowledged | Empty |
| 3 | Client packet | GID[33], client flow[16], flow secret[32], opaque QUIC packet |
| 4 | Packet to host | GID[33], relay-chosen server flow[16], opaque QUIC packet |
| 5 | Server packet | GID[33], server flow[16], opaque QUIC packet |
| 6 | Packet to client | Client flow[16], opaque QUIC packet |
| 7 | Directory request | Bounded JSON `directoryMessage` with nonce, GID and optional signed record to store |
| 8 | Directory response | Same nonce/GID, optional signed record, bounded nearest-peer referrals and store acknowledgement |

Operation bytes are internal to duplex payloads, not top-level wire types.
Packets are capped at 8192 bytes; QUIC payloads at 2048 bytes. The relay
checks registration signatures against the exact receiving circuit and
its own key. Client flow secrets permit circuit replacement without
allowing another origin to move a flow by guessing its public flow ID.
Server packets are accepted only on the registered service circuit.
Flows expire after two minutes of inactivity.

QUIC runs over these virtual datagrams with ALPN `yggg-site-v1`. Its TLS
certificate must be signed by the descriptor's Ed25519 service key, be
valid for the hash domain and pass certificate validity checks. A stream
starts with a big-endian virtual port (80 or 443); the host replies 1
after connecting to the configured backend, or 0 on refusal. Remaining
bytes are a reliable full-duplex application stream.

Directory queries are iterative XOR-nearest lookups with bounded fanout,
signed records, up to three replicas, expiry and freshness enforcement.
They use operations 7/8 inside independent circuits; public DNS and the
hosting node's address are not part of resolution. See
[Garlic websites](garlic-sites.md) for limits and lifecycle details.
