#!/bin/sh

# Convenience installer for the Garlic Routing Overlay branch of Yggdrasil.
#
# macOS: builds from source with Go and installs a launchd service (delegates
# to scripts/setup.sh; honours PEERS and SITE_ADDR). Needs `brew install go`.
# Windows: use scripts\\setup.ps1.
#
# Builds an actual .deb or .rpm from source (autodetecting your package
# manager and CPU architecture), installs it, enables the Garlic Routing
# Overlay in the generated config, restarts the service, and prints a
# quick sanity check so you can confirm Garlic actually started.
#
# Usage (as root, on the server you want to test on):
#   curl -fsSL https://raw.githubusercontent.com/luisakrivonogih/yggdrasil-go/develop/install.sh | sh
# or, from an existing checkout:
#   sudo sh install.sh
#
# Environment overrides:
#   REPO_URL          git URL to build from (default: this fork, develop branch)
#   REPO_BRANCH       branch to build (default: develop)
#   WORKDIR           scratch dir for clone/build/toolchain (default: /opt/yggdrasil-installer)
#   ENABLE_GARLIC     set to 0 to skip enabling Garlic in the config (default: 1)
#   ENABLE_DASHBOARD  1/0/auto: build and enable the local operator dashboard
#                     (default: auto = only on machines with at least 2 GB
#                     RAM; its build needs ~700 MB). It is optional and built
#                     last: a failed dashboard build never stops Yggdrasil or
#                     Garlic from being installed and configured. Needs
#                     Node.js at runtime (not
#                     just to build) - if none is found, a real Node.js
#                     build is installed system-wide under /usr/local
#                     (never touches a distro nodejs package), since the
#                     systemd-managed yggdrasil execs `node` directly and
#                     must find it on PATH.
#   GARLIC_MODE       "relay" or "client" (hidden node, e.g. for a server
#                     that only hosts a site). Default: keep the mode already
#                     set in the config; "relay" on a new install.
#   GARLIC_TRUSTED_PEERS  comma-separated Yggdrasil node keys ("Public key"
#                     from getSelf) of Garlic relays you trust as first hop,
#                     added to Garlic.TrustedPeers.
#   PEERS             comma-separated Yggdrasil peer URIs (tls://host:port),
#                     added to Peers.
#   SITE_ADDR         host:port of a local HTTP server to publish as this
#                     node's .yggg site (e.g. 127.0.0.1:8090). Sites are
#                     hosted by hidden nodes, so this also switches the node
#                     to client mode: it stops being a public relay.
#
# Reinstalling never resets the config: keys, Peers, TrustedPeers and the
# Garlic mode are kept, the lists above are only added to. Peers added at
# runtime with yggdrasilctl addPeer / addGarlicPeer are saved to the config
# by the daemon itself.
#
# Small machines (less than ~1.5-2 GB of RAM + swap) get a temporary swap
# file under WORKDIR for the duration of the build (removed afterwards) and
# a one-package-at-a-time Go build, so the compiler is not OOM-killed.
#
# See docs/garlic-testing.md for how to actually exercise Garlic (build a
# circuit, send/receive a payload) once this has installed and started it -
# or, with the dashboard enabled, watch it happen at http://127.0.0.1:8080
# (loopback-only, tunnel with `ssh -L 8080:127.0.0.1:8080`).

set -e

REPO_URL=${REPO_URL:-https://github.com/luisakrivonogih/yggdrasil-go.git}
REPO_BRANCH=${REPO_BRANCH:-develop}
WORKDIR=${WORKDIR:-/opt/yggdrasil-installer}
ENABLE_GARLIC=${ENABLE_GARLIC:-1}
ENABLE_DASHBOARD=${ENABLE_DASHBOARD:-auto}
GARLIC_MODE=${GARLIC_MODE:-}
PEERS=${PEERS:-}
case "$GARLIC_MODE" in ''|client|relay) ;; *) echo "error: GARLIC_MODE must be client or relay" >&2; exit 1 ;; esac
GARLIC_TRUSTED_PEERS=${GARLIC_TRUSTED_PEERS:-${GARLIC_BOOTSTRAP_PEERS:-}}

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

# Validate list inputs up front: -normaliseconf does not check peer URIs,
# and a malformed one stops the daemon at startup.
for _p in $(echo "$PEERS" | tr ',' ' '); do
  printf '%s' "$_p" | LC_ALL=C grep -Eq '^(tcp|tls|quic|ws|wss|socks|sockstls|unix)://[][A-Za-z0-9.:%_-]+:[0-9]{1,5}([/?][ -~]*)?$' ||
    die "invalid peer URI in PEERS: $_p (example: tls://1.2.3.4:443)"
done
for _k in $(echo "$GARLIC_TRUSTED_PEERS" | tr ',' ' '); do
  printf '%s' "$_k" | grep -Eq '^[0-9a-fA-F]{64}$' ||
    die "invalid key in GARLIC_TRUSTED_PEERS: $_k (need the 64-hex \"Public key\" from yggdrasilctl getSelf)"
done
SITE_ADDR=${SITE_ADDR:-}
if [ -n "$SITE_ADDR" ]; then
  printf '%s' "$SITE_ADDR" | LC_ALL=C grep -Eq '^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$' ||
    die "invalid SITE_ADDR: $SITE_ADDR (example: 127.0.0.1:8090)"
  [ "$GARLIC_MODE" != relay ] ||
    die "sites are hosted by hidden nodes - drop GARLIC_MODE=relay (relays refuse to host sites, see docs/garlic-quickstart.md)"
  GARLIC_MODE=client
fi

# ---- 0. macOS: delegate to scripts/setup.sh (launchd, no deb/rpm) ----
if [ "$(uname -s)" = "Darwin" ]; then
  [ "$(id -u)" = "0" ] || die "this needs root - run: curl -fsSL <url> | sudo -E sh   (or sudo -E sh install.sh)"
  command -v go >/dev/null 2>&1 || die "Go is required on macOS to build: brew install go (https://go.dev/dl/)"
  command -v git >/dev/null 2>&1 || die "git is required (xcode-select --install)"
  SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P) || SCRIPT_DIR=""
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/scripts/setup.sh" ]; then
    MAC_SRC="$SCRIPT_DIR"
    log "macOS: using existing checkout at $MAC_SRC"
  else
    MAC_SRC=$(mktemp -d /tmp/yggdrasil-garlic.XXXXXX)
    log "macOS: cloning $REPO_URL ($REPO_BRANCH) into $MAC_SRC"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$MAC_SRC"
  fi
  cd "$MAC_SRC"
  # PEERS / SITE_ADDR / PREFIX / CONF are passed through the environment.
  exec sh scripts/setup.sh install
fi

[ "$(id -u)" = "0" ] || die "this needs to run as root (e.g. sudo sh install.sh) - it installs a system package and a systemd service"

# ---- 1. Detect package manager ----
if command -v apt-get >/dev/null 2>&1; then
  PKGKIND=deb
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PKGKIND=rpm
else
  die "no supported package manager found (need apt-get, dnf, or yum)"
fi

# ---- 2. Detect architecture ----
case "$(uname -m)" in
  x86_64) PKGARCH=amd64; GOTARBALLARCH=amd64 ;;
  aarch64) PKGARCH=arm64; GOTARBALLARCH=arm64 ;;
  armv7l|armv6l) PKGARCH=armhf; GOTARBALLARCH=armv6l ;;
  i686|i386) PKGARCH=i386; GOTARBALLARCH=386 ;;
  *) die "unsupported architecture: $(uname -m) - build manually, see contrib/deb/generate.sh or contrib/rpm/generate.sh" ;;
esac
log "Detected $PKGKIND packaging, arch $PKGARCH"

# ---- 2b. Memory: small VPS guard ----
# Building is by far the heaviest thing this script does: a Go compile or
# link step peaks at roughly 300-500 MB (one per CPU when run in parallel)
# and the dashboard's Vite build at roughly 700 MB. On a small VPS without
# swap that ends with the OOM killer, or with a machine swapping itself to
# a standstill so the install looks hung. So on small machines: build Go
# one package at a time, add a temporary swap file while building, and
# leave out the optional dashboard unless explicitly asked for.
meminfo_mb() { awk -v k="$1:" '$1 == k { printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null; }
MEM_MB=$(meminfo_mb MemTotal)
SWAP_MB=$(meminfo_mb SwapTotal)
case "$MEM_MB" in ''|*[!0-9]*) MEM_MB=0 ;; esac
case "$SWAP_MB" in ''|*[!0-9]*) SWAP_MB=0 ;; esac
log "Memory: ${MEM_MB} MB RAM, ${SWAP_MB} MB swap"
case "$ENABLE_DASHBOARD" in
  1|0) ;;
  *)
    if [ "$MEM_MB" -ge 1800 ]; then
      ENABLE_DASHBOARD=1
    else
      ENABLE_DASHBOARD=0
      log "Less than 2 GB of RAM - skipping the optional dashboard (its build needs ~700 MB and it keeps a Node.js process running next to yggdrasil); force it with ENABLE_DASHBOARD=1"
    fi
    ;;
esac

BUILD_SWAP="$WORKDIR/build.swap"
remove_build_swap() {
  [ -e "$BUILD_SWAP" ] || return 0
  if grep -q "^$BUILD_SWAP[[:space:]]" /proc/swaps 2>/dev/null; then
    if ! swapoff "$BUILD_SWAP" 2>/dev/null; then
      log "Could not switch off the temporary swap file - remove it later with: swapoff $BUILD_SWAP && rm $BUILD_SWAP"
      return 0
    fi
  fi
  rm -f "$BUILD_SWAP"
}
# add_build_swap WANT_MB: make sure RAM + swap is at least WANT_MB while
# building. Never fatal: containers (OpenVZ, LXC) usually cannot swapon.
add_build_swap() {
  _have=$((MEM_MB + SWAP_MB))
  [ "$_have" -lt "$1" ] || return 0
  _need=$(($1 - _have))
  [ "$_need" -ge 512 ] || _need=512
  if ! command -v mkswap >/dev/null 2>&1 || ! command -v swapon >/dev/null 2>&1; then
    log "Low memory and no mkswap/swapon - building without extra swap"
    return 0
  fi
  mkdir -p "$WORKDIR"
  _free=$(df -Pm "$WORKDIR" 2>/dev/null | awk 'NR == 2 { print $4 }')
  case "$_free" in ''|*[!0-9]*) _free=0 ;; esac
  if [ "$_free" -lt $((_need + 1024)) ]; then
    log "Low memory, but only ${_free} MB free disk in $WORKDIR - building without a temporary swap file"
    return 0
  fi
  remove_build_swap
  log "Low memory: adding a temporary ${_need} MB swap file for the build ($BUILD_SWAP, removed afterwards)"
  if dd if=/dev/zero of="$BUILD_SWAP" bs=1M count="$_need" 2>/dev/null &&
     chmod 600 "$BUILD_SWAP" &&
     mkswap "$BUILD_SWAP" >/dev/null 2>&1 &&
     swapon "$BUILD_SWAP" 2>/dev/null; then
    return 0
  fi
  log "Could not enable a swap file here (a container without swap support?) - building without it"
  rm -f "$BUILD_SWAP"
}
# Also cleans up after an earlier run that was interrupted mid-build.
trap remove_build_swap EXIT
trap 'exit 130' INT TERM HUP
remove_build_swap

# ---- 3. Build prerequisites ----
case "$PKGKIND" in
  deb)
    log "Installing build prerequisites (git, binutils, curl)"
    # A broken third-party repository (e.g. an outdated apt.postgresql.org
    # entry) makes apt-get update fail; the packages below come from the
    # distribution, so carry on and let apt-get install report real problems.
    apt-get update -y || log "apt-get update reported errors (a broken third-party repository?) - continuing"
    apt-get install -y git binutils gzip ca-certificates curl
    ;;
  rpm)
    log "Installing build prerequisites (git, rpm-build, curl)"
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y git rpm-build ca-certificates curl
    else
      yum install -y git rpm-build ca-certificates curl
    fi
    ;;
esac

# ---- 4. Get the source ----
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P) || SCRIPT_DIR=""
if [ -n "$SCRIPT_DIR" ] && grep -q '^module github.com/yggdrasil-network/yggdrasil-go$' "$SCRIPT_DIR/go.mod" 2>/dev/null; then
  SRC_DIR="$SCRIPT_DIR"
  log "Running from an existing checkout at $SRC_DIR"
  if [ "${NO_UPDATE:-0}" != 1 ] && [ -d "$SRC_DIR/.git" ]; then
    log "Checking for newer commits (NO_UPDATE=1 to skip)"
    if [ -n "$SUDO_USER" ]; then _G="sudo -u $SUDO_USER git"; else _G=git; fi
    $_G -C "$SRC_DIR" pull --ff-only -q || log "git pull failed (local changes?), building the current checkout"
  fi
else
  SRC_DIR="$WORKDIR/src"
  log "Cloning $REPO_URL ($REPO_BRANCH branch) into $SRC_DIR"
  mkdir -p "$WORKDIR"
  rm -rf "$SRC_DIR"
  git clone --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR"
  # The script piped in by `curl ... | sh` can be minutes older than the
  # clone (raw.githubusercontent.com caches it for 5 minutes), i.e. an old
  # installer driving new sources. The fresh clone is authoritative: carry
  # on with its own installer.
  if [ -z "$YGG_INSTALLER_REEXEC" ] && [ -f "$SRC_DIR/install.sh" ]; then
    log "Continuing with the installer from the fresh checkout"
    YGG_INSTALLER_REEXEC=1 NO_UPDATE=1
    export YGG_INSTALLER_REEXEC NO_UPDATE
    exec sh "$SRC_DIR/install.sh"
  fi
fi
cd "$SRC_DIR"

# ---- 5. Ensure a Go toolchain new enough to bootstrap go.mod's own ----
# go.mod pins an exact Go version (see `go` directive). Go >=1.21 handles
# this itself: `go build` transparently downloads and uses the pinned
# version (GOTOOLCHAIN=auto, the default) if the local `go` is older. So
# we only need *some* Go >=1.21 present - if there's none at all, fetch a
# private bootstrap copy under $WORKDIR rather than touching any system Go.
#
# go_works GO: the toolchain runs and its standard library is complete. A
# half-extracted copy (an earlier run interrupted mid-download, a full
# disk) otherwise only fails at build time with "package unsafe is not in
# std" - and used to be skipped as "already downloaded" on every rerun.
go_works() { ( cd / && GOTOOLCHAIN=local GOFLAGS= "$1" list unsafe runtime net/http ) >/dev/null 2>&1; }
NEED_BOOTSTRAP=1
if command -v go >/dev/null 2>&1 && ! go_works go; then
  log "System Go at $(command -v go) is broken (incomplete standard library) - using a private bootstrap Go instead"
elif command -v go >/dev/null 2>&1; then
  GOVER=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
  GOMAJOR=$(echo "$GOVER" | cut -d. -f1)
  GOMINOR=$(echo "$GOVER" | cut -d. -f2)
  case "$GOMAJOR" in ''|*[!0-9]*) GOMAJOR=0 ;; esac
  case "$GOMINOR" in ''|*[!0-9]*) GOMINOR=0 ;; esac
  if [ "$GOMAJOR" -gt 1 ] || { [ "$GOMAJOR" -eq 1 ] && [ "$GOMINOR" -ge 21 ]; }; then
    NEED_BOOTSTRAP=0
    log "Found system Go $GOVER (>=1.21, can self-upgrade to what go.mod needs)"
  fi
fi

if [ "$NEED_BOOTSTRAP" = "1" ]; then
  GO_BOOTSTRAP_DIR="$WORKDIR/go-bootstrap"
  if ! go_works "$GO_BOOTSTRAP_DIR/go/bin/go"; then
    if [ -e "$GO_BOOTSTRAP_DIR" ]; then
      log "The bootstrap Go in $GO_BOOTSTRAP_DIR is incomplete or broken - downloading it again"
    else
      log "No suitable Go toolchain found - downloading a bootstrap Go into $GO_BOOTSTRAP_DIR"
    fi
    GOVERSION=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -n1)
    [ -n "$GOVERSION" ] || die "could not determine the latest Go version (network issue?)"
    rm -rf "$GO_BOOTSTRAP_DIR"
    mkdir -p "$GO_BOOTSTRAP_DIR"
    curl -fsSL "https://go.dev/dl/${GOVERSION}.linux-${GOTARBALLARCH}.tar.gz" -o "$GO_BOOTSTRAP_DIR/go.tar.gz"
    tar -C "$GO_BOOTSTRAP_DIR" -xzf "$GO_BOOTSTRAP_DIR/go.tar.gz" || die "could not unpack Go into $GO_BOOTSTRAP_DIR (out of disk space? check: df -h $WORKDIR)"
    rm -f "$GO_BOOTSTRAP_DIR/go.tar.gz"
    go_works "$GO_BOOTSTRAP_DIR/go/bin/go" || die "the downloaded Go in $GO_BOOTSTRAP_DIR does not work (out of disk space? check: df -h $WORKDIR)"
  fi
  PATH="$GO_BOOTSTRAP_DIR/go/bin:$PATH"
  export PATH
  log "Using bootstrap $(go version)"
fi
export GOTOOLCHAIN=auto

# ---- 6. Ensure Node.js is available (dashboard only) ----
# Unlike the Go toolchain (only needed here, to build), the dashboard
# needs `node` present on PATH at *runtime* too - the systemd-managed
# yggdrasil execs it directly (see src/dashboard/dashboard.go). A
# private, only-visible-to-this-script copy (like the Go bootstrap
# above) would not be found by the service, so a suitable Node.js is
# installed system-wide under /usr/local instead - a real upstream
# Node.js release, never a distro nodejs package (whose version varies
# wildly and is often too old for this project's SvelteKit/Vite
# toolchain).
if [ "$ENABLE_DASHBOARD" = "1" ]; then
  NEED_NODE=1
  if command -v node >/dev/null 2>&1; then
    NODEVER=$(node -v | sed 's/^v//')
    NODEMAJOR=$(echo "$NODEVER" | cut -d. -f1)
    case "$NODEMAJOR" in ''|*[!0-9]*) NODEMAJOR=0 ;; esac
    if [ "$NODEMAJOR" -ge 20 ]; then
      NEED_NODE=0
      log "Found system Node.js v$NODEVER (>=20, good enough)"
    fi
  fi
  case "$GOTARBALLARCH" in
    amd64) NODEARCH=x64 ;;
    arm64) NODEARCH=arm64 ;;
    armv6l) NODEARCH=armv7l ;;
    *) NODEARCH="" ;;
  esac
  if [ "$NEED_NODE" = "1" ] && [ -z "$NODEARCH" ]; then
    log "No official Node.js build for this architecture - skipping the dashboard (ENABLE_DASHBOARD=0 to silence this)"
    ENABLE_DASHBOARD=0
  elif [ "$NEED_NODE" = "1" ]; then
    log "No suitable system Node.js (need >=20) - installing one system-wide under /usr/local/lib/nodejs-yggdashboard"
    NODE_INDEX_URL="https://nodejs.org/dist/index.json"
    NODEVERSION=""
    if command -v jq >/dev/null 2>&1; then
      NODEVERSION=$(curl -fsSL "$NODE_INDEX_URL" | jq -r '[.[] | select(.lts != false)][0].version')
    elif command -v python3 >/dev/null 2>&1; then
      NODEVERSION=$(curl -fsSL "$NODE_INDEX_URL" | python3 -c "import json,sys; print(next(d['version'] for d in json.load(sys.stdin) if d['lts']))")
    fi
    [ -n "$NODEVERSION" ] || die "could not determine the latest Node.js LTS version (network issue, or neither jq nor python3 is installed)"
    NODE_INSTALL_DIR=/usr/local/lib/nodejs-yggdashboard
    rm -rf "$NODE_INSTALL_DIR"
    mkdir -p "$NODE_INSTALL_DIR"
    curl -fsSL "https://nodejs.org/dist/${NODEVERSION}/node-${NODEVERSION}-linux-${NODEARCH}.tar.xz" -o "$WORKDIR/node.tar.xz"
    tar -C "$NODE_INSTALL_DIR" --strip-components=1 -xJf "$WORKDIR/node.tar.xz"
    rm -f "$WORKDIR/node.tar.xz"
    for bin in node npm npx; do
      ln -sf "$NODE_INSTALL_DIR/bin/$bin" "/usr/local/bin/$bin"
    done
    PATH="/usr/local/bin:$PATH"
    export PATH
    log "Installed Node.js $NODEVERSION, symlinked into /usr/local/bin (on the systemd service's default PATH)"
  fi
fi

# ---- 7. Build and package ----
if [ "$ENABLE_DASHBOARD" = "1" ]; then add_build_swap 2048; else add_build_swap 1536; fi
if [ $((MEM_MB + SWAP_MB)) -lt 2048 ]; then
  GOFLAGS="${GOFLAGS:+$GOFLAGS }-p=1"
  export GOFLAGS
fi
log "Building and packaging ($PKGKIND, $PKGARCH) - first run also fetches the go.mod-pinned Go toolchain, can take a few minutes"
rm -f ./*.deb ./*.rpm ./yggdrasil ./yggdrasilctl 2>/dev/null || true
BUILD_FAILED="the build failed (see the errors above) - nothing was installed, the existing installation is untouched"
case "$PKGKIND" in
  deb) PKGARCH=$PKGARCH sh contrib/deb/generate.sh || die "$BUILD_FAILED" ;;
  rpm) PKGARCH=$PKGARCH sh contrib/rpm/generate.sh || die "$BUILD_FAILED" ;;
esac
PKGFILE=$(ls -t ./*."$PKGKIND" 2>/dev/null | head -n1)
[ -n "$PKGFILE" ] && [ -f "$PKGFILE" ] || die "package build did not produce a .$PKGKIND file"
# Never install a package without the binaries in it: that replaces a
# working node with a broken service ("yggdrasil: not found").
case "$PKGKIND" in
  deb) PKGLIST=$(dpkg-deb -c "$PKGFILE" 2>/dev/null | awk '{ print $NF }') ;;
  rpm) PKGLIST=$(rpm -qlp "$PKGFILE" 2>/dev/null) ;;
esac
for f in usr/bin/yggdrasil usr/bin/yggdrasilctl; do
  echo "$PKGLIST" | grep -q "$f\$" || die "$PKGFILE has no /$f - $BUILD_FAILED"
done
log "Built $PKGFILE"

# Whether the existing config sets the Garlic mode explicitly - checked
# before the package's postinst normalises it (which writes every field).
HAD_MODE=0
if [ -s /etc/yggdrasil/yggdrasil.conf ] && grep -Eq '^[[:space:]]*"?Mode"?[[:space:]]*:' /etc/yggdrasil/yggdrasil.conf; then
  HAD_MODE=1
fi

# ---- 8. Install ----
# The package name is derived from the current branch (contrib/semver/
# name.sh), same as the build name baked into the binary - so switching
# which branch this installer runs from (e.g. a feature branch to
# develop) produces a differently-NAMED package that still owns the same
# /usr/bin/yggdrasil[ctl] files as whatever was installed before. dpkg
# refuses to let one package overwrite files another package owns; `dpkg
# -i ... || apt-get install -y -f` does not fix that (-f resolves missing
# *dependencies*, not file-ownership conflicts) - left unhandled, that
# failure was silently swallowed here and the script went on to restart
# the untouched old binary while reporting success. Remove any
# differently-named yggdrasil package first, and verify the new one
# actually reports installed afterward rather than assuming it did.
PKGNAME=$(sh contrib/semver/name.sh)
log "Installing $PKGFILE"
case "$PKGKIND" in
  deb)
    OLDPKGS=$(dpkg-query -W -f='${Package}\n' 'yggdrasil*' 2>/dev/null | grep -v "^${PKGNAME}\$" || true)
    if [ -n "$OLDPKGS" ]; then
      log "Removing previously-installed package(s) under a different name: $OLDPKGS"
      dpkg --purge $OLDPKGS || die "failed to remove old package(s): $OLDPKGS"
    fi
    dpkg -i "$PKGFILE" || apt-get install -y -f || die "dpkg/apt-get failed to install $PKGFILE"
    dpkg -s "$PKGNAME" >/dev/null 2>&1 || die "package $PKGNAME does not report as installed after the install step"
    ;;
  rpm)
    OLDPKGS=$(rpm -qa --qf '%{NAME}\n' 'yggdrasil*' 2>/dev/null | grep -v "^${PKGNAME}\$" || true)
    if [ -n "$OLDPKGS" ]; then
      log "Removing previously-installed package(s) under a different name: $OLDPKGS"
      rpm -e $OLDPKGS || die "failed to remove old package(s): $OLDPKGS"
    fi
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y "./$PKGFILE" || die "dnf failed to install $PKGFILE"
    else
      rpm -Uvh "$PKGFILE" || die "rpm failed to install $PKGFILE"
    fi
    rpm -q "$PKGNAME" >/dev/null 2>&1 || die "package $PKGNAME does not report as installed after the install step"
    ;;
esac

# Resolve the installed binaries by absolute path and make sure they run -
# a missing or wrong-architecture binary otherwise only shows up later as
# "yggdrasil: not found" or a systemd 203/EXEC failure.
YGG=$(command -v yggdrasil 2>/dev/null || true)
YGGCTL=$(command -v yggdrasilctl 2>/dev/null || true)
for c in /usr/bin /usr/local/bin /usr/sbin; do
  [ -n "$YGG" ] || { [ -x "$c/yggdrasil" ] && YGG="$c/yggdrasil"; }
  [ -n "$YGGCTL" ] || { [ -x "$c/yggdrasilctl" ] && YGGCTL="$c/yggdrasilctl"; }
done
[ -n "$YGG" ] || die "yggdrasil binary not found after installing $PKGFILE - inspect it with: dpkg -c $PKGFILE (or rpm -qlp $PKGFILE)"
"$YGG" -version >/dev/null 2>&1 || die "$YGG does not run on this machine (wrong architecture?) - check: file $YGG"
log "Installed $("$YGG" -version | tr '\n' ' ')at $YGG"

# The package's postinstall step already generated /etc/yggdrasil/yggdrasil.conf
# (Garlic disabled, the project default) and started the service - see
# contrib/deb/generate.sh's postinst / contrib/rpm/generate.sh's %post.

# ---- 9. Enable Garlic (and, once it is built, the dashboard) ----
# update_config DASH: apply the Garlic settings; DASH=1 also turns the
# dashboard on (DASH=0 leaves Dashboard.Enabled as it is). Safe to run more
# than once: TrustedPeers is merged, not appended twice.
update_config() {
  _dash=$1
  # Mode: what was asked for; otherwise keep the mode the config already
  # sets explicitly; "relay" only for a config that never had one.
  _mode=$GARLIC_MODE
  [ -n "$_mode" ] || [ "$HAD_MODE" = 1 ] || _mode=relay
  log "Updating /etc/yggdrasil/yggdrasil.conf (Garlic=$ENABLE_GARLIC, Mode=${_mode:-unchanged}, Dashboard=$_dash)"
  TMP_JSON="$WORKDIR/yggdrasil.json"
  mkdir -p "$WORKDIR"
  "$YGG" -useconffile /etc/yggdrasil/yggdrasil.conf -normaliseconf -json > "$TMP_JSON"

  EDITED=0
  if command -v jq >/dev/null 2>&1; then
    jq --argjson garlic "$([ "$ENABLE_GARLIC" = "1" ] && echo true || echo false)" \
       --argjson dash "$([ "$_dash" = "1" ] && echo true || echo false)" \
       --arg trusted "$GARLIC_TRUSTED_PEERS" \
       --arg peers "$PEERS" \
       --arg site "$SITE_ADDR" \
       --arg mode "$_mode" \
       'def merge($list; $add): (($list // []) + ($add | split(",") | map(gsub("^ +| +$"; "")) | map(select(. != "")))) as $all
          | reduce $all[] as $x ([]; if index([$x]) then . else . + [$x] end);
        .Garlic.Enabled = (if $garlic then true else .Garlic.Enabled end)
        | .Garlic.Mode = (if $mode != "" then $mode else .Garlic.Mode end)
        | .Dashboard.Enabled = (if $dash then true else .Dashboard.Enabled end)
        | .Garlic.TrustedPeers = merge((.Garlic.TrustedPeers // []) | map(ascii_downcase); $trusted | ascii_downcase)
        | .Peers = merge(.Peers; $peers)
        | .Garlic.Services = (if $site == "" then .Garlic.Services
            else ((.Garlic.Services // []) as $s
              | if any($s[]; .ServiceID == "") then $s | map(if .ServiceID == "" then .LocalAddr = $site else . end)
                else $s + [{ServiceID: "", LocalAddr: $site}] end) end)' \
       "$TMP_JSON" > "$TMP_JSON.new" && EDITED=1
  elif command -v python3 >/dev/null 2>&1; then
    ENABLE_GARLIC="$ENABLE_GARLIC" ENABLE_DASHBOARD="$_dash" GARLIC_TRUSTED_PEERS="$GARLIC_TRUSTED_PEERS" PEERS="$PEERS" SITE_ADDR="$SITE_ADDR" GARLIC_MODE="$_mode" python3 - "$TMP_JSON" > "$TMP_JSON.new" <<'PY' && EDITED=1
import json, os, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
def merge(old, add):
    out = list(old or [])
    for x in (s.strip() for s in add.split(",")):
        if x and x not in out:
            out.append(x)
    return out
if os.environ.get("ENABLE_GARLIC") == "1":
    cfg.setdefault("Garlic", {})["Enabled"] = True
if os.environ.get("ENABLE_DASHBOARD") == "1":
    cfg.setdefault("Dashboard", {})["Enabled"] = True
garlic = cfg.setdefault("Garlic", {})
if os.environ.get("GARLIC_MODE"):
    garlic["Mode"] = os.environ["GARLIC_MODE"]
garlic["TrustedPeers"] = merge([k.lower() for k in garlic.get("TrustedPeers") or []], os.environ.get("GARLIC_TRUSTED_PEERS", "").lower())
cfg["Peers"] = merge(cfg.get("Peers"), os.environ.get("PEERS", ""))
site = os.environ.get("SITE_ADDR", "")
if site:
    services = garlic.get("Services") or []
    for s in services:
        if not s.get("ServiceID"):
            s["LocalAddr"] = site
            break
    else:
        services.append({"ServiceID": "", "LocalAddr": site})
    garlic["Services"] = services
json.dump(cfg, sys.stdout, indent=2)
PY
  fi

  if [ "$EDITED" = "1" ] && [ -s "$TMP_JSON.new" ]; then
    # Write a new file and swap it in only when it is complete: a failed
    # write must never leave an empty config (= new keys, no peers).
    if ! "$YGG" -useconffile "$TMP_JSON.new" -normaliseconf > /etc/yggdrasil/yggdrasil.conf.new || [ ! -s /etc/yggdrasil/yggdrasil.conf.new ]; then
      rm -f /etc/yggdrasil/yggdrasil.conf.new
      die "could not write the updated config (invalid PEERS entry?) - /etc/yggdrasil/yggdrasil.conf left unchanged"
    fi
    chown root:yggdrasil /etc/yggdrasil/yggdrasil.conf.new
    chmod 640 /etc/yggdrasil/yggdrasil.conf.new
    mv /etc/yggdrasil/yggdrasil.conf.new /etc/yggdrasil/yggdrasil.conf
    rm -f "$TMP_JSON" "$TMP_JSON.new"
    systemctl restart yggdrasil
    log "Config updated, yggdrasil restarted"
  else
    log "Neither jq nor python3 found - enable manually: set \"Garlic\": { \"Enabled\": true } and/or \"Dashboard\": { \"Enabled\": true } (and \"Mode\": \"relay\", \"TrustedPeers\": [...]) in /etc/yggdrasil/yggdrasil.conf, then run 'systemctl restart yggdrasil'"
  fi
}
if [ "$ENABLE_GARLIC" = "1" ] || [ -n "$GARLIC_TRUSTED_PEERS" ] || [ -n "$PEERS" ] || [ -n "$GARLIC_MODE" ] || [ -n "$SITE_ADDR" ]; then
  update_config 0
fi

# ---- 10. Build and install the dashboard (optional, last) ----
# Built only after Yggdrasil and Garlic are installed, configured and
# running, and never fatal: a small server that cannot build it still ends
# up with a working node.
if [ "$ENABLE_DASHBOARD" = "1" ]; then
  log "Building the optional dashboard (npm install && npm run build) - can take a few minutes on a small server"
  TIMEOUT=""
  if command -v timeout >/dev/null 2>&1; then TIMEOUT="timeout 1800"; fi
  if ( cd "$SRC_DIR/yggdashboard" && $TIMEOUT npm install --no-audit --no-fund && $TIMEOUT npm run build ); then
    DASHBOARD_INSTALL_DIR=/usr/lib/yggdrasil/dashboard
    rm -rf "$DASHBOARD_INSTALL_DIR"
    mkdir -p "$DASHBOARD_INSTALL_DIR"
    cp -r "$SRC_DIR/yggdashboard/build/." "$DASHBOARD_INSTALL_DIR/"
    chown -R root:yggdrasil "$DASHBOARD_INSTALL_DIR"
    chmod -R go-w "$DASHBOARD_INSTALL_DIR"
    log "Dashboard built assets installed to $DASHBOARD_INSTALL_DIR (yggdrasil's default search path, no Dashboard.Path config needed)"
    update_config 1
  else
    log "WARNING: the dashboard build failed or timed out (out of memory? check: free -m; dmesg | grep -i -e oom -e killed)."
    log "Yggdrasil and Garlic are installed and running without it. Retry with more RAM/swap, or skip it with ENABLE_DASHBOARD=0."
    ENABLE_DASHBOARD=0
  fi
fi
remove_build_swap

# ---- 11. Verify ----
sleep 2
log "Verifying"
if systemctl is-active --quiet yggdrasil; then
  log "yggdrasil.service is active"
else
  log "yggdrasil.service is NOT active - check: journalctl -u yggdrasil -n 50 --no-pager"
fi

echo
echo "--- Yggdrasil node ---"
"$YGGCTL" getself || true
echo
echo "--- Garlic identity (present only if Garlic started successfully) ---"
"$YGGCTL" getGarlicIdentity || true
echo
echo "--- Garlic peers ---"
"$YGGCTL" getGarlicPeers || true
if [ -n "$SITE_ADDR" ]; then
  echo
  echo "--- Site ---"
  SITE_DOMAIN=$("$YGGCTL" getGarlicDomain 2>/dev/null | sed -n 's/.*"domain": *"\([^"]*\)".*/\1/p')
  echo "address:      http://$SITE_DOMAIN/"
  if curl -s -o /dev/null --max-time 3 "http://$SITE_ADDR/"; then
    echo "local server: $SITE_ADDR answers"
  else
    echo "local server: nothing answers at $SITE_ADDR yet - start your web server there (e.g. python3 -m http.server ${SITE_ADDR##*:} --bind ${SITE_ADDR%:*})"
  fi
  echo "This node now runs in client (hidden) mode: it hosts the site and is no longer a public relay."
  echo "Nodes that had it as their only trusted peer need another one (addGarlicPeer)."
  printf "publishing (up to 60 s)"
  for _i in $(seq 1 30); do
    if "$YGGCTL" getGarlicServices 2>/dev/null | grep -q '"published": *true'; then break; fi
    printf "."
    sleep 2
  done
  echo
  "$YGGCTL" getGarlicServices || true
  echo "Open it from another Garlic node through its browser proxy 127.0.0.1:4444:"
  echo "  curl --proxy http://127.0.0.1:4444 http://$SITE_DOMAIN/"
fi
if [ "$ENABLE_DASHBOARD" = "1" ]; then
  echo
  echo "--- Dashboard ---"
  if journalctl -u yggdrasil -n 30 --no-pager 2>/dev/null | grep -q "Dashboard started"; then
    echo "started - loopback-only at http://127.0.0.1:8080"
    echo "view it remotely with: ssh -L 8080:127.0.0.1:8080 <this-server>"
  else
    echo "did not report starting - check: journalctl -u yggdrasil -n 50 --no-pager | grep -i dashboard"
  fi
fi
echo
echo "Done. To actually exercise Garlic (build a circuit through a peer, send/receive"
echo "a payload, try the newer padding/jitter/discovery/multipath/bundling defenses),"
echo "see $SRC_DIR/docs/garlic-testing.md - you'll need at least one more Garlic-enabled"
echo "peer (run this installer there too, or peer with an existing Yggdrasil node - only"
echo "the nodes you explicitly build a circuit through need Garlic enabled). The dashboard"
echo "(if enabled) shows those circuits live under /circuits and /garlic once you peer."
