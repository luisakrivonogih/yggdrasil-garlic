# Websites at hash.domains.yggg

Garlic now includes a distributed signed directory, bidirectional onion
circuits, an authenticated QUIC stream transport and a loopback HTTP proxy.
A browser configured to use the proxy can open
`http://<hash>.domains.yggg/` on another node. A website operator runs an
ordinary local HTTP server; Garlic forwards incoming streams to it.

## Start a website

> Operator guide (Russian), including hidden mode, trusted peers and key
> rotation: [garlic-quickstart.md](garlic-quickstart.md).

Generate a configuration with `yggdrasil -genconf`. It contains
`Garlic.SigningPrivateKey`, the Ed25519 seed your domains are derived from;
keep it to retain the domain. Onion (X25519) keys are ephemeral, rotate in
memory and are never stored. Never replace the signing key with the main
Yggdrasil private key.

A site must be hosted by a hidden node (`Mode: "client"`, the default):
relays refuse `Services` unless `AllowServicesOnRelay` is set, because a
publicly listed relay's uptime would be linkable to the site.

Run your HTTP server on, for example, `127.0.0.1:8080`. In the existing
`Garlic` block, preserve its keys and other defaults and set:

```hjson
Enabled: true
Services: [
  {
    ServiceID: ""                 # default service's hash domain
    LocalAddr: "127.0.0.1:8080"    # existing HTTP server
  }
]
```

Add at least one trusted relay (`Garlic.TrustedPeers`, the relay's
Yggdrasil node key) that is reachable over the mesh. It is the first hop of
every circuit and the only node the host contacts directly; all other
relays are learned as signed `RelayInfo` through gossip from it and are
never contacted before a circuit is built through them.

The node logs the domain and then `Garlic website published` when its relay
registration and distributed publication succeed. Inspect it with:

```sh
yggdrasilctl getGarlicDomain
yggdrasilctl getGarlicServices
```

The latter shows publication status and the last publication error, such as
insufficient circuit candidates. Registration and publication retry while
the mesh starts, then refresh automatically. No manual name registration,
IP mapping or descriptor exchange with clients is needed.

For another service, use another hex `ServiceID`, such as `776562` (`web`).
Domains under the same signing identity remain cryptographically linkable;
use separate identities/processes if that separation is required.

## Open it in a browser

On the browsing node, enable `Garlic.Enabled`. The default
`Garlic.Proxy` settings start an HTTP proxy at `127.0.0.1:4444`:

```hjson
Proxy: {
  Enabled: true
  Listen: "127.0.0.1:4444"
}
```

In a browser which supports automatic proxy configuration, set the PAC URL
to **`http://127.0.0.1:4444/proxy.pac`** once. Alternatively, configure
`127.0.0.1:4444` as the browser's HTTP/HTTPS proxy. Then open the site's
**`http://<hash>.domains.yggg/`** address, including `http://` so the browser
does not search for the name or require an HTTPS backend.

The PAC routes the entire `.yggg` namespace to Garlic, including unknown
names, case variations and a final DNS root dot. It contains no direct
fallback for those names. Ordinary Internet sites use the browser's normal
direct connection with this PAC; the Garlic listener itself only accepts
hash domains. DNS settings and the system hosts file do not need edits.

A command-line check using the same browser proxy path is:

```sh
curl --proxy http://127.0.0.1:4444 http://<hash>.domains.yggg/
```

The local browser-to-proxy leg is HTTP on loopback. Website bytes are
encrypted end to end between the browsing and hosting Garlic instances,
including when the website uses an HTTP backend. The relay cannot read
HTTP bodies or headers.

For browser HTTPS, configure `TLSLocalAddr` on the service. CONNECT on
virtual port 443 forwards to that HTTPS backend. The browser independently
validates its certificate; Garlic does not install a browser CA or bypass
browser TLS verification. Only configured virtual ports 80 and 443 can be
reached. The caller never supplies a backend host or arbitrary TCP port.

## Network path

```text
browser -> local HTTP proxy -> client Garlic circuit --+
                                                       relay
HTTP backend <- hosting Garlic <- service Garlic circuit-+

              end-to-end authenticated QUIC/TLS
```

The service builds an outbound circuit to a relay and signs a registration
bound to that circuit's terminal local ID, the relay key and its own GID.
A copied public descriptor is insufficient to register a different circuit.
Its signed directory descriptor lists that relay, never the hosting node.
The client independently builds its own circuit to the relay. The relay
joins opaque QUIC packets between the circuits; the TLS signing key must
match the directory descriptor and hash domain before a stream is opened.

Forward packets use the existing hop-local onion format. Reverse packets
gain an independently keyed AEAD layer, random starting counter and local
ID at each hop. Reverse replay windows are checked after all layers
authenticate. Each direction uses a different HKDF label. QUIC provides
ordered, reliable, flow-controlled streams without buffering whole HTTP
responses in Garlic.

Site circuits rotate at most every 90 seconds (earlier for a shorter
configured lifetime or exhausted budget). Reverse routing state expires
after three minutes. The service re-registers its replacement circuit at
the same relay, preserving the stream's virtual peer address; live QUIC
streams survive circuit rotation. Losing the relay itself requires a new
registration/publication and a client reconnect, not transparent migration
of an established stream to another relay.

Every circuit hop must advertise `garlic-sites-v1`. Site paths keep
`Garlic.PathLength`, `MinHopCount` and the prefix guard/diversity policy;
they never silently fall back to a direct connection. The default path
needs three upgraded hop candidates and adequate mesh diversity. Tiny
isolated development meshes can explicitly use `PathLength: 1` and
`MinHopCount: 0`; this removes the multi-hop privacy separation.

## Distributed directory

The daemon uses `NetworkRendezvous` by default. Explicitly passing
`StaticRendezvous` remains useful for isolated unit tests.

Records are keyed by GID. Nodes rank known node keys by XOR distance between
`SHA256(node_key)` and the GID digest. A lookup iteratively contacts the
closest candidates, in batches of three, accepting at most eight referrals
per honest response and querying at most 24 nodes. Publication replicates
to up to three closest reachable nodes. Both lookup and store RPCs travel
inside Garlic circuits, with replies tied to the request nonce and circuit.
There is no broadcast of GIDs or API for enumerating stored names.

Receivers and clients verify descriptor signatures, GID binding and expiry.
Storage refuses older publications over newer ones and is limited to 4096
records per node. Records expire; the host refreshes its three-minute
descriptor and placement while online. This is an iterative directory
using the existing mesh for transport, not a new ironwood storage API or
a centrally hosted registry. Replication is best effort in small or
partitioned meshes, and directory state is memory-only. Hosts republish
after directory restarts.

## Scope and validation

The HTTP proxy strips forwarding/network identity headers and cross-site
Referer/Origin values, and rewrites HTTP cookies as host-only. It rejects
non-Garlic targets without public DNS/direct fallback. HTTPS CONNECT is
opaque to these HTTP safeguards. An ordinary browser still has its own
fingerprinting, extensions, speculative networking and cookie behavior;
this implementation does not provide Tor Browser's privacy environment.
See the added website section of [the threat model](garlic-threat-model.md).

`TestSiteBrowserAcrossDistributedMesh` publishes a real backend, then adds
a fifth mesh node with an empty directory. Through the HTTP proxy it checks
a roughly 2 MB GET, POST, host-only cookies, rejected external destinations
and unconfigured ports, and a response spanning automatic circuit rotation.
Additional tests cover reply authentication/replay, exact-circuit
registration proofs, descriptor freshness and proxy target restrictions.

```sh
TMPDIR=/private/tmp go test ./src/garlic ./src/garlicproxy
TMPDIR=/private/tmp go test -race ./src/garlic -run '^TestSiteBrowserAcrossDistributedMesh$'
```

`TMPDIR=/private/tmp` avoids macOS's Unix socket path length limit in admin
tests. Mining and human-readable `domain-name.yggg` registrations remain a
separate future stage; `domains.yggg` is reserved for automatic hash names.
