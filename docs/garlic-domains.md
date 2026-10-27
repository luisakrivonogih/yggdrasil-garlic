# Garlic hash domains

Garlic provides automatic service addresses of the form
`<hash>.domains.yggg`. No registration, mining, central name allocator or
IPv6 address is involved in generating an address. The signing key is
randomly generated; the address is deterministic for that key and service ID.

For actual websites, automatic distributed publication and browser setup,
see [Websites at hash.domains.yggg](garlic-sites.md). The commands below
describe the lower-level naming and directory API.

## Address format

```text
digest = BLAKE2b-256("yggdrasil-garlic-v1-gid" || Ed25519_public_key || service_id)
gid    = 0x01 || digest
domain = lowercase(base32_without_padding(gid)) + ".domains.yggg"
```

The first label is 53 ASCII characters (`a-z`, `2-7`), within the DNS
label limit. It retains the complete existing GID, including its version
and all 256 hash bits. Existing uppercase base32 GIDs and signed service
descriptors keep their encoding. A hash domain is another spelling of a
GID, so it inherits the existing signature and descriptor expiry checks.

`GID.Domain()` formats an address. `ParseDomain()` accepts DNS case
variations and one optional final root dot. It rejects extra subdomains,
other suffixes, URLs, ports, whitespace, Unicode, unsupported versions
and base32 encodings with nonzero unused bits. It does not interpret
`name.yggg` as a hash address.

The empty service ID is the identity's default service. Different service
IDs (up to 64 bytes) under the same signing key produce different domains.
Descriptors expose their signing public key, so these services can still
be linked to the same identity; separate domains alone do not provide
identity isolation.

## Operator commands

With `Garlic.Enabled: true`, the node logs its default domain at startup.
It is also included as `domain` in `getGarlicIdentity`. These commands
work through the existing local admin socket:

```sh
yggdrasilctl getGarlicDomain
yggdrasilctl getGarlicDomain serviceId=776562
```

Both return `gid`, `domain` and `serviceId` (hex; `776562` means `web`).
Getting a domain does not publish anything or make a service reachable.

Publish the default service, or a specific service ID, with the existing
publication command. Replace `<hex-node-key>` with an introduction point's
node key:

```sh
yggdrasilctl publishGarlicService introPoints=<hex-node-key> ttlSeconds=3600
yggdrasilctl publishGarlicService serviceId=776562 introPoints=<hex-node-key> ttlSeconds=3600
```

The response now contains both `gid` and `domain`. Resolve that returned
domain with:

```sh
yggdrasilctl resolveGarlicDomain domain=<hash>.domains.yggg
```

The response contains the canonical lowercase `domain`, the original
`gid` and verified `introPoints`. Unknown domains and expired or invalid
descriptors return errors. `lookupGarlicService gid=<base32-gid>` remains
available. In Go, `Garlic.LookupDomain(domain)` uses the same verifying
lookup as `Garlic.LookupService(gid)`.

To retain domains across daemon restarts, configure and preserve both
`Garlic.PrivateKey` (32-byte X25519 secret) and `Garlic.SigningPrivateKey`
(independently generated 32-byte Ed25519 seed), as hex strings. The
signing key determines domains; the X25519 key is used for circuit ECDH.
New `yggdrasil -genconf` output includes both secrets. A configured signing
key alone also keeps domains stable while generating an ephemeral X25519
key. Without a signing key, startup generates an ephemeral one and logs a warning;
an ephemeral signing key produces different domains on restart. Changing
the service ID also changes its domain. Descriptor renewal or changing
introduction points does not change it.

## Current boundary and next stages

The daemon uses the distributed `NetworkRendezvous`. Configured websites
register a relay and automatically publish and refresh their signed records.
The browser proxy resolves them over Garlic circuits and opens an
authenticated stream to the configured backend. The explicit
`StaticRendezvous` implementation remains local and is used by isolated tests.
Neither backend maps a domain to the hosting node's IPv6 address.
See [Garlic websites](garlic-sites.md) for the implemented transport, which
supersedes the earlier inbound-tunnel proposal in the historical
[hidden-services design](superpowers/specs/2026-08-27-garlic-hidden-services-design.md).

Human-readable `domain-name.yggg` registrations through mining are a
future stage. `domains.yggg` is reserved for automatic hash addresses and
must be excluded from that registration namespace. A future registered
name can point to a hash address while the hash address remains available
independently of the registration.

## Validation

```sh
go test ./src/garlic -run 'Test(Domain|ParseDomain|LookupDomain|IdentityResponse)' -count=1
go test ./src/garlic -run '^$' -fuzz '^FuzzParseDomain$' -fuzztime=5s
```

On macOS, a long `TMPDIR` can push test admin socket paths beyond the Unix
socket path limit. Set `TMPDIR=/private/tmp` for the admin integration tests.
