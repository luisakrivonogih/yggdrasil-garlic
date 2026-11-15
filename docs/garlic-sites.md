# Websites at hash.domains.yggg

Garlic now includes a distributed signed directory, bidirectional onion
circuits, an authenticated QUIC stream transport and a loopback proxy
(SOCKS5 and HTTP). A hidden service is named only by its
`<hash>.domains.yggg` address; the port and the protocol are chosen by the
application. A service operator runs ordinary local TCP servers (a web
server, an SSH daemon, anything); Garlic forwards incoming streams to the
ports the operator lists.

## Start a website

> Operator guide (Russian), including hidden mode, trusted peers and key
> rotation: [garlic-quickstart.md](garlic-quickstart.md).

Generate a configuration with `yggdrasil -genconf`. It contains
`Garlic.SigningPrivateKey`, the Ed25519 seed your domains are derived from;
keep it to retain the domain. Onion (X25519) keys are ephemeral, rotate in
memory and are never stored. Never replace the signing key with the main
Yggdrasil private key.

Any node can host sites, several at once. Each `Services` entry with its
own `Name` signs with its own key (HKDF of `SigningPrivateKey` and the
name), so sites of one node cannot be linked to each other or to the node
cryptographically. Hosting on a hidden node (`Mode: "client"`, the default)
is the strongest option: a relay's uptime is publicly observable and can be
compared with the sites' uptime, and the daemon warns about this.

Run your servers on loopback, for example HTTP on `127.0.0.1:8080` and SSH
on `127.0.0.1:22`. In the existing `Garlic` block, preserve its keys and
other defaults and set:

```hjson
Enabled: true
Services: [
  {
    ServiceID: ""                 # default service's hash domain
    Ports: {
      "80": "127.0.0.1:8080"      # virtual port -> local backend
      "22": "127.0.0.1:22"
      "9000": "[::1]:9000"
    }
  }
]
```

`Ports` maps a virtual TCP port (1-65535) to a local `host:port`. Only the
listed ports can be reached; there is no "forward everything" mode, port 0
and duplicate ports are configuration errors, and a caller never supplies a
backend address. The daemon does not know or care which protocol runs over
a port. `LocalAddr` and `TLSLocalAddr` remain as deprecated synonyms of
ports 80 and 443, so old configurations keep working; a synonym that names a
different address than the same port in `Ports` stops the service from
starting.

Add at least one trusted relay (`Garlic.TrustedPeers`, the relay's
Yggdrasil node key) that is reachable over the mesh. It is the first hop of
every circuit and the only node the host contacts directly; all other
relays are learned as signed `RelayInfo` through gossip from it and are
never contacted before a circuit is built through them.

The node logs the domain and then `Garlic service published` when its relay
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

## Reach it from applications

On the client node, enable `Garlic.Enabled`. The default `Garlic.Proxy`
settings start a local proxy at `127.0.0.1:4444` that speaks **SOCKS5 and
HTTP on the same port** (the first byte tells them apart; SOCKS4 is not
supported and the connection is closed):

```hjson
Proxy: {
  Enabled: true
  Listen: "127.0.0.1:4444"
}
```

### SOCKS5 (any TCP application)

The application hands the proxy the *name* and the port; the daemon finds
the service itself. DNS is never used, so always use the variant of your
tool that sends the name to the proxy instead of resolving it:

```sh
curl --socks5-hostname 127.0.0.1:4444 http://<hash>.domains.yggg:8080/
ncat --proxy 127.0.0.1:4444 --proxy-type socks5 <hash>.domains.yggg 7000
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:4444 %h %p' user@<hash>.domains.yggg
```

Rules: only CONNECT with a domain-name address (ATYP 3) for a
`.domains.yggg` name; IP literals and other names are answered `0x02`
(not allowed), BIND and UDP ASSOCIATE `0x07`, and nothing ever leaves for
the ordinary Internet. Authentication methods `0x00` and `0x02` are
accepted; any username/password is accepted and **ignored** (Garlic has no
per-credential circuit isolation yet - reserved for the future). Reply
codes: `0x00` success, `0x05` the port is not offered or its backend
refused, `0x04` service not found, unreachable or timed out, `0x01`
anything else. BND.ADDR is `0.0.0.0:0`. The handshake must finish within
10 seconds.

### HTTP proxy

`CONNECT <hash>.domains.yggg:<any port 1-65535>` opens a tunnel; plain
`http://<hash>.domains.yggg[:port]/` requests (default port 80) are
forwarded with the cleanups described below. Status codes: 403 for a name
outside `.domains.yggg`, 400 for port 0, 502 if the service or port is not
reachable, 504 on timeout.

In a browser which supports automatic proxy configuration, set the PAC URL
to **`http://127.0.0.1:4444/proxy.pac`** once. Alternatively, configure
`127.0.0.1:4444` as the browser's HTTP/HTTPS proxy. Then open the
**`http://<hash>.domains.yggg/`** address, including `http://` so the
browser does not search for the name or require an HTTPS backend.
The PAC deliberately returns `PROXY` (HTTP), not `SOCKS`: the HTTP proxy
always receives the whole name, while some browsers resolve the name with
the system DNS when a PAC returns SOCKS, which would leak it.

The PAC routes the entire `.yggg` namespace to Garlic, including unknown
names, case variations and a final DNS root dot. It contains no direct
fallback for those names. Ordinary Internet sites use the browser's normal
direct connection with this PAC; the Garlic listener itself only accepts
hash domains. DNS settings and the system hosts file do not need edits.

A command-line check using the HTTP path is:

```sh
curl --proxy http://127.0.0.1:4444 http://<hash>.domains.yggg/
```

The local browser-to-proxy leg is HTTP on loopback. Website bytes are
encrypted end to end between the browsing and hosting Garlic instances,
including when the website uses an HTTP backend. The relay cannot read
HTTP bodies or headers.

For HTTPS, list port 443 in `Ports` (or set `TLSLocalAddr`). CONNECT on
that port forwards to the HTTPS backend. The browser independently
validates its certificate; Garlic does not install a browser CA or bypass
TLS verification. Only the ports listed by the service can be reached.

## Limits and future work

- TCP only. The service is served over QUIC streams, so UDP needs a
  separate mechanism (QUIC datagrams plus SOCKS5 UDP ASSOCIATE).
- No transparent mode for applications without proxy support (a local DNS
  that maps `.domains.yggg` to virtual IPv6 addresses plus TUN interception,
  like Tor's AutomapHosts/TransPort).
- SOCKS credentials are accepted but not used for circuit isolation.

## Network path

```text
application -> local proxy -> client Garlic circuit ---+
                                                       relay
TCP backend <- hosting Garlic <- service Garlic circuit-+

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

The local proxy accepts only `.domains.yggg` names. For HTTP requests it strips forwarding/network identity headers and cross-site
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
It also carries a raw binary echo protocol on an arbitrary port through
SOCKS5, and checks the refusal codes for an unoffered port and a dead
backend.
Additional tests cover reply authentication/replay, exact-circuit
registration proofs, descriptor freshness and proxy target restrictions.

```sh
TMPDIR=/private/tmp go test ./src/garlic ./src/garlicproxy
TMPDIR=/private/tmp go test -race ./src/garlic -run '^TestSiteBrowserAcrossDistributedMesh$'
```

`TMPDIR=/private/tmp` avoids macOS's Unix socket path length limit in admin
tests. Mining and human-readable `domain-name.yggg` registrations remain a
separate future stage; `domains.yggg` is reserved for automatic hash names.
