# Testing the Garlic Routing Overlay on a real network

This walks through running two `yggdrasil` nodes with Garlic enabled,
peering them, and sending a message end-to-end through a Garlic circuit
via `yggdrasilctl` — the exact sequence below was run against real
built binaries while writing this document, not written from theory.

For a multi-machine / real-Internet deployment, skip straight to
["On a real multi-node network"](#on-a-real-multi-node-network) below —
the two-node walkthrough exists to get you a working local sanity check
first.

## Build

```sh
go build -o ./yggdrasil ./cmd/yggdrasil
go build -o ./yggdrasilctl ./cmd/yggdrasilctl
```

## 1. Generate two configs and enable Garlic

```sh
./yggdrasil -genconf > nodeA.conf
./yggdrasil -genconf > nodeB.conf
```

Edit each file (HJSON, plain text) and change three things — the rest of
the generated config is fine as-is:

```hjson
AdminListen: tcp://localhost:9001    # 9002 for nodeB
Listen: [
  tls://localhost:9101               # 9102 for nodeB - omit if you don't need inbound peers
]
Garlic: {
  Enabled: true
  ...                                 # leave the rest at their defaults
}
```

(`AdminListen` isn't present in the generated file by default on Linux —
it defaults to a fixed Unix socket path, which two nodes on one machine
can't both use, so add the `AdminListen:` line explicitly as shown.)

`IfName: none` is worth setting for this kind of headless test (no TUN
device, no root required) — Garlic doesn't need a TUN interface to work,
since it rides on `core.Core`'s own transport, not on IPv6 packets
through the TUN device. See `docs/garlic-architecture.md` §2 for why.

## 2. Start both nodes

```sh
./yggdrasil -useconffile nodeA.conf -logto nodeA.log &
./yggdrasil -useconffile nodeB.conf -logto nodeB.log &
```

Check `nodeA.log`/`nodeB.log` for a line like:

```
Your Garlic public key is 9434b21a22c8a361b36e341eb7b76b651ce495157936e74010971c10010bce52
```

Onion keys are always ephemeral and rotate (see
[garlic-quickstart.md](garlic-quickstart.md)); only `Garlic.SigningPrivateKey`
is persistent. Relays need `Mode: "relay"`; every originator needs at least
one `Garlic.TrustedPeers` entry, which is always the first hop.

## 3. Peer them

```sh
./yggdrasilctl -endpoint=tcp://localhost:9002 addPeer uri=tls://localhost:9101
./yggdrasilctl -endpoint=tcp://localhost:9001 getPeers   # confirm "Up"
```

Give it a few seconds — DHT convergence isn't instant, and
`garlicQueryCapability`/`createGarlicCircuit` below will fail with a
"capability request timed out" error if you try immediately. This is
the normal, expected timeout for a peer that hasn't been reachable long
enough yet, not a bug — retry after a couple of seconds.

## 4. Exercise the Garlic API via yggdrasilctl

**Important CLI quirk:** `yggdrasilctl`'s plain `key=value` syntax only
ever sends string values — it can't send a JSON array or number. Because
of this, list-valued Garlic arguments (`hops`, `introPoints`) are
**comma-separated strings**, and numeric ones (`timeoutSeconds`,
`ttlSeconds`) are **numeric strings**, not JSON arrays/numbers. All the
examples below already account for this.

```sh
# Get nodeB's Yggdrasil node key (needed as a circuit hop identifier -
# note this is the main Yggdrasil key, not the Garlic public key).
NODEB_KEY=$(./yggdrasilctl -endpoint=tcp://localhost:9002 -json getself | python3 -c "import json,sys; print(json.load(sys.stdin)['key'])")

# Confirm nodeB is Garlic-capable and fetch its Garlic public key.
./yggdrasilctl -endpoint=tcp://localhost:9001 -json garlicQueryCapability key=$NODEB_KEY

# Build a 1-hop circuit through nodeB. For multiple hops, pass
# hops=key1,key2,key3 (comma-separated, ordered).
./yggdrasilctl -endpoint=tcp://localhost:9001 -json createGarlicCircuit hops=$NODEB_KEY
# => {"circuitId": "00112233445566778899aabbccddeeff"}

CIRCUIT_ID=00112233445566778899aabbccddeeff
PAYLOAD_HEX=$(python3 -c "print('hello bob, from alice, via garlic'.encode().hex())")

./yggdrasilctl -endpoint=tcp://localhost:9001 -json sendGarlic circuitId=$CIRCUIT_ID payload=$PAYLOAD_HEX

# On nodeB, receive it (blocks up to timeoutSeconds waiting for delivery):
./yggdrasilctl -endpoint=tcp://localhost:9002 -json recvGarlic timeoutSeconds=5
# => {"circuitId": "00112233445566778899aabbccddeeff", "payload": "68656c6c6f..."}

python3 -c "print(bytes.fromhex('68656c6c6f20626f622c2066726f6d20616c6963652c20766961206761726c6963').decode())"
# => hello bob, from alice, via garlic
```

```sh
# Circuit/relay counts on each side:
./yggdrasilctl -endpoint=tcp://localhost:9001 -json getGarlicStats   # {"originatedCircuits":1,"relayedCircuits":0}
./yggdrasilctl -endpoint=tcp://localhost:9002 -json getGarlicStats   # {"originatedCircuits":0,"relayedCircuits":1}

# Clean up:
./yggdrasilctl -endpoint=tcp://localhost:9001 closeGarlicCircuit circuitId=$CIRCUIT_ID
```

Full handler list (`src/garlic/admin.go`): `getGarlicIdentity`,
`garlicQueryCapability`, `createGarlicCircuit`, `createGarlicCircuitAuto`,
`closeGarlicCircuit`, `sendGarlic`, `sendGarlicBundled`, `recvGarlic`,
`recvGarlicAuto`, `publishGarlicService`, `lookupGarlicService`,
`getGarlicStats`, `getGarlicCircuits`, `getGarlicAutoPool`,
`getGarlicKnownPeers`, `garlicGossip`, `garlicGossipPull`,
`createGarlicCircuitPool`, `closeGarlicCircuitPool`,
`sendGarlicMultipath`.

## 5. Exercise the newer defenses (discovery, diverse selection, multipath, bundling)

Padding (`Config.PaddingEnabled`) and jitter (`Config.JitterEnabled`)
apply automatically to every `sendGarlic` call above — nothing extra to
do to exercise them, they're default on and invisible at the CLI level
(they change wire size/timing, not the API). The rest need deliberate
calls:

```sh
# nodeB learns about any Garlic peers nodeA already knows (itself,
# after the garlicQueryCapability round trip above, plus anything nodeA
# has gossiped from others). Requires nodeA to already be
# capability-verified as seen from nodeB - i.e. run
# garlicQueryCapability from nodeB toward nodeA first if you haven't.
./yggdrasilctl -endpoint=tcp://localhost:9001 -json garlicQueryCapability key=$NODEB_KEY
NODEA_KEY=$(./yggdrasilctl -endpoint=tcp://localhost:9001 -json getself | python3 -c "import json,sys; print(json.load(sys.stdin)['key'])")
./yggdrasilctl -endpoint=tcp://localhost:9002 -json garlicGossip key=$NODEA_KEY
./yggdrasilctl -endpoint=tcp://localhost:9002 -json getGarlicKnownPeers

# Build two independent 1-hop circuits through nodeB as a pool, then
# send a few payloads - each call round-robins to the next circuit in
# the pool, so consecutive sends don't all reuse the same circuit.
./yggdrasilctl -endpoint=tcp://localhost:9001 -json createGarlicCircuitPool paths="$NODEB_KEY;$NODEB_KEY"
# => {"poolId": "..."}
POOL_ID=...
./yggdrasilctl -endpoint=tcp://localhost:9001 -json sendGarlicMultipath poolId=$POOL_ID payload=$PAYLOAD_HEX
./yggdrasilctl -endpoint=tcp://localhost:9002 -json recvGarlic timeoutSeconds=5
./yggdrasilctl -endpoint=tcp://localhost:9001 closeGarlicCircuitPool poolId=$POOL_ID

# Send the real payload alongside 5 cover entries in one bundle - an
# observer who can't decrypt any entry can't tell which one, if any,
# is real. Behaves identically to sendGarlic from the receiving side.
./yggdrasilctl -endpoint=tcp://localhost:9001 -json createGarlicCircuit hops=$NODEB_KEY
CIRCUIT_ID2=...
./yggdrasilctl -endpoint=tcp://localhost:9001 -json sendGarlicBundled circuitId=$CIRCUIT_ID2 payload=$PAYLOAD_HEX coverCount=5
./yggdrasilctl -endpoint=tcp://localhost:9002 -json recvGarlic timeoutSeconds=5
```

`SelectPath`/`SelectDiversePath` (topologically diverse hop selection)
and `HopCount`/`PingCapability` (mesh distance and RTT) are not exposed
as admin handlers — they're Go APIs (`src/garlic/manager.go`,
`src/garlic/selection.go`) intended for a caller building automated hop
selection, not manual CLI use. `TestIntegrationSelectPathAgainstRealTopology`
(`src/garlic/integration_test.go`) exercises `SelectPath` against a real
running mesh if you want to see it in action without writing new code.

## 6. Exercise the auto-pool (auto-built circuits, gossip pull)

Everything above hands the hop keys over by hand. `createGarlicCircuitAuto`
instead picks them itself, out of what this node has discovered — the
first hop restricted to peers it has personally capability-verified, the
rest drawn from the gossiped pool too.

Two config notes before this works on a two-node loopback setup: set
`Garlic.MinHopCount` to `0` (the default `2` rejects a directly-peered
node as "too close", which on a two-node test is every candidate you
have), and `Garlic.PathLength` to `1`. For the background pool and cover
traffic, also set `Garlic.AutoPoolEnabled` to `true` — optionally with
`Garlic.TrustedPeers` listing the other node's key (required: the first
hop is always a trusted peer).

```sh
# nodeA must have verified nodeB itself first - a gossiped-only peer is
# never eligible for the first hop.
./yggdrasilctl -endpoint=tcp://localhost:9001 -json garlicQueryCapability key=$NODEB_KEY

# Let nodeA choose the whole path itself. hopCount is optional and
# defaults to Garlic.PathLength.
./yggdrasilctl -endpoint=tcp://localhost:9001 -json createGarlicCircuitAuto hopCount=1
# => {"circuitId": "..."}
# Fails with "no self-verified candidates" if the query above hasn't
# succeeded yet, or with an insufficient-candidates error if MinHopCount
# filters out everything this node knows.

# See the background pool (only populated when AutoPoolEnabled is true):
./yggdrasilctl -endpoint=tcp://localhost:9001 -json getGarlicAutoPool
# => {"pool": [{"circuitId": "...", "createdAt": "...", "hops": 1}, ...]}

# Ask a verified peer for its known-peer sample right now, instead of
# waiting for the next GossipInterval tick:
./yggdrasilctl -endpoint=tcp://localhost:9002 -json garlicGossipPull key=$NODEA_KEY
./yggdrasilctl -endpoint=tcp://localhost:9002 -json getGarlicKnownPeers
# => each peer carries "selfVerified": true/false - the trust tier used
#    for first-hop selection above.

# Wait for a real payload arriving over an auto-pool circuit terminating
# here. Cover traffic is discarded before this point, so this stays
# blocked until something real arrives:
./yggdrasilctl -endpoint=tcp://localhost:9002 -json recvGarlicAuto timeoutSeconds=5
```

A circuit from `createGarlicCircuitAuto` is an ordinary circuit ID:
`sendGarlic`/`closeGarlicCircuit` work on it exactly as in step 4, and a
payload sent that way is picked up by `recvGarlic`, not `recvGarlicAuto`.
`recvGarlicAuto` is the receiving end of the tagged auto-pool path
(`SendGarlicAuto` in the Go API, and the pool's own cover traffic), which
is deliberately kept separate — see `docs/garlic-protocol.md` §11.2.

## On a real multi-node network

Same procedure, three changes:

1. Set `Listen` to a real reachable address (`tls://0.0.0.0:PORT` or
   similar) and configure `Peers`/exchange connection strings with
   whoever you're testing against, exactly as you would for ordinary
   Yggdrasil peering — Garlic doesn't change how peering works at all.
2. Point `-endpoint=` at each node's actual `AdminListen` address (or run
   `yggdrasilctl` directly on each machine against its local admin
   socket).
3. **You do not need every node on the path to run Garlic.** Per
   `docs/garlic-compatibility.md`, only the nodes you name in `hops=`
   need `Garlic.Enabled: true` — ordinary Yggdrasil nodes between them
   (existing infrastructure, other people's nodes, whatever) carry the
   traffic transparently with zero configuration changes on their part.
   That's the whole point, and it's what
   `TestIntegrationSendGarlicThroughLegacyRelay`
   (`src/garlic/integration_test.go`) proves automatically, in-process,
   without needing real hardware.

## Confirming legacy compatibility yourself

If you want to see the "legacy node doesn't even notice" property
directly rather than take the docs' word for it: query a node that has
`Garlic.Enabled: false` (or is running an older `yggdrasil` build
entirely) with `garlicQueryCapability` — it will time out, identically
to querying an offline node. That timeout, and the total absence of any
error, log line, or state change on the legacy node's side, *is* the
compatibility guarantee.

## Automated tests, if you'd rather not do this by hand

```sh
go test ./src/garlic/...                                    # everything, ~10-70s (mesh convergence timing varies)
go test ./src/garlic/... -run TestIntegrationSendGarlicThroughLegacyRelay -v   # just the 5-node legacy-relay proof
go test ./src/garlic/... -run '^$' -bench . -benchmem        # performance numbers
go test ./src/garlic/... -run '^$' -fuzz=FuzzEnvelopeUnmarshal -fuzztime=60s   # adversarial input, any Fuzz* target
```
