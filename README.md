# Yggdrasil

[![Build status](https://github.com/yggdrasil-network/yggdrasil-go/actions/workflows/ci.yml/badge.svg)](https://github.com/yggdrasil-network/yggdrasil-go/actions/workflows/ci.yml)

## Introduction

Yggdrasil is an early-stage implementation of a fully end-to-end encrypted IPv6
network. It is lightweight, self-arranging, supported on multiple platforms and
allows pretty much any IPv6-capable application to communicate securely with
other Yggdrasil nodes. Yggdrasil does not require you to have IPv6 Internet
connectivity - it also works over IPv4.

## Garlic Routing Overlay (experimental, this branch)

This branch adds an experimental, optional privacy-enhanced routing layer on
top of Yggdrasil: onion/garlic-style circuits, capability negotiation,
per-hop packet-size and timing randomization, gossip-based peer discovery,
topologically diverse hop selection, multipath circuits, and cover-traffic
bundling. It is fully backward compatible - a node with `Garlic.Enabled:
false` (the default) behaves exactly like vanilla Yggdrasil, and ordinary
Yggdrasil nodes transparently carry Garlic traffic without needing to know
it exists or upgrading anything.

Start here:

- [docs/garlic-architecture.md](docs/garlic-architecture.md) - design and integration rationale
- [docs/garlic-protocol.md](docs/garlic-protocol.md) - wire format, what's actually implemented
- [docs/garlic-threat-model.md](docs/garlic-threat-model.md) - what this does and does not protect against (read before relying on it for anything)
- [docs/garlic-security.md](docs/garlic-security.md) - self-review of the implementation
- [docs/garlic-compatibility.md](docs/garlic-compatibility.md) - why old and new nodes keep interoperating
- [docs/garlic-testing.md](docs/garlic-testing.md) - manual walkthrough via `yggdrasilctl`

### Quick install for testing

To build, package, install, and enable Garlic on a Linux server in one
step (auto-detects Debian/Ubuntu-family `apt`/`.deb` vs Fedora/RHEL/CentOS-family
`dnf`/`yum`/`.rpm`):

```sh
curl -fsSL https://raw.githubusercontent.com/luisakrivonogih/yggdrasil-go/develop/install.sh | sudo sh
```

This builds an actual `.deb` or `.rpm` from source, installs it the same
way the official packages install (systemd service,
`/etc/yggdrasil/yggdrasil.conf`), sets `Garlic.Enabled: true` in the
generated config, restarts the service, and prints the resulting Garlic
identity and stats so you can confirm it actually started. See
[install.sh](install.sh) for the environment variables it honors
(`REPO_URL`, `REPO_BRANCH`, `WORKDIR`, `ENABLE_GARLIC`), and
[docs/garlic-testing.md](docs/garlic-testing.md) for how to build a circuit
and send traffic through it once the service is running.

Garlic websites have automatic `<hash>.domains.yggg` addresses, a distributed
signed directory and an HTTP browser proxy at `127.0.0.1:4444`. Configure
the browser with `http://127.0.0.1:4444/proxy.pac`, then open a site's
`http://<hash>.domains.yggg/` URL. See
[Garlic websites](docs/garlic-sites.md) for hosting and browser setup, and
[hash domains](docs/garlic-domains.md) for the naming API.

## Supported Platforms

Yggdrasil works on a number of platforms, including Linux, macOS, Ubiquiti
EdgeRouter, VyOS, Windows, FreeBSD, OpenBSD and OpenWrt.

Please see our [Installation](https://yggdrasil-network.github.io/installation.html)
page for more information. You may also find other platform-specific wrappers, scripts
or tools in the `contrib` folder.

## Building

If you want to build from source, as opposed to installing one of the pre-built
packages:

1. Install [Go](https://golang.org) (requires Go 1.22 or later)
2. Clone this repository
2. Run `./build`

Note that you can cross-compile for other platforms and architectures by
specifying the `GOOS` and `GOARCH` environment variables, e.g. `GOOS=windows
./build` or `GOOS=linux GOARCH=mipsle ./build`.

## Running

### Generate configuration

To generate static configuration, either generate a HJSON file (human-friendly,
complete with comments):

```
./yggdrasil -genconf > /path/to/yggdrasil.conf
```

... or generate a plain JSON file (which is easy to manipulate
programmatically):

```
./yggdrasil -genconf -json > /path/to/yggdrasil.conf
```

You will need to edit the `yggdrasil.conf` file to add or remove peers, modify
other configuration such as listen addresses or multicast addresses, etc.

### Run Yggdrasil

To run with the generated static configuration:

```
./yggdrasil -useconffile /path/to/yggdrasil.conf
```

To run in auto-configuration mode (which will use sane defaults and random keys
at each startup, instead of using a static configuration file):

```
./yggdrasil -autoconf
```

You will likely need to run Yggdrasil as a privileged user or under `sudo`,
unless you have permission to create TUN/TAP adapters. On Linux this can be done
by giving the Yggdrasil binary the `CAP_NET_ADMIN` capability.

## Documentation

Documentation is available [on our website](https://yggdrasil-network.github.io).

- [Installing Yggdrasil](https://yggdrasil-network.github.io/installation.html)
- [Configuring Yggdrasil](https://yggdrasil-network.github.io/configuration.html)
- [Frequently asked questions](https://yggdrasil-network.github.io/faq.html)
- [Version changelog](CHANGELOG.md)

## Communities

A number of IRC communities exist, including the `#yggdrasil` IRC channel on [libera.chat](https://libera.chat) and various others on [Yggdrasil-internal IRC networks](https://yggdrasil-network.github.io/services.html#irc).

## License

This code is released under the terms of the LGPLv3, but with an added exception
that was shamelessly taken from [godeb](https://github.com/niemeyer/godeb).
Under certain circumstances, this exception permits distribution of binaries
that are (statically or dynamically) linked with this code, without requiring
the distribution of Minimal Corresponding Source or Minimal Application Code.
For more details, see: [LICENSE](LICENSE).
