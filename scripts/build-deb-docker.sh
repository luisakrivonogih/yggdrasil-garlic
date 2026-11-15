#!/usr/bin/env bash
#
# Build a yggdrasil-go .deb package inside a Docker container.
#
# No Go toolchain is required on the host: the build runs in a golang image
# and reuses contrib/deb/generate.sh. The resulting package can be copied to
# any Debian/Ubuntu server and installed with dpkg/apt.
#
# Usage:
#   scripts/build-deb-docker.sh [-a ARCH] [-i IMAGE] [-o DIR]
#
# Examples:
#   scripts/build-deb-docker.sh                     # amd64 (default)
#   scripts/build-deb-docker.sh -a arm64
#   scripts/build-deb-docker.sh -a armhf -o /tmp/debs
#   GO_IMAGE=golang:1.26-bookworm scripts/build-deb-docker.sh
#
# Supported architectures (Go cross-compiles, so one container fits all):
#   amd64, i386, mips, mipsel, armhf, arm64, armel

set -euo pipefail

GO_IMAGE="${GO_IMAGE:-docker.io/golang:latest}"
PKGARCH="${PKGARCH:-amd64}"
OUTDIR="${OUTDIR:-bin}"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts "a:i:o:h" opt; do
  case "$opt" in
    a) PKGARCH="$OPTARG" ;;
    i) GO_IMAGE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

case "$PKGARCH" in
  amd64|i386|mips|mipsel|armhf|arm64|armel) ;;
  *)
    echo "ERROR: unsupported architecture '$PKGARCH'" >&2
    echo "Supported: amd64, i386, mips, mipsel, armhf, arm64, armel" >&2
    exit 1
    ;;
esac

command -v docker >/dev/null 2>&1 || {
  echo "ERROR: docker is not installed or not running" >&2
  exit 1
}

# contrib/deb/generate.sh must run from the top level of the git repo.
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: run this script from inside the yggdrasil-go git repository" >&2
  exit 1
}
cd "$REPO_ROOT"

# Determine package name/version on the host (git describe needs the local
# .git); fall back gracefully if there are no tags.
PKGNAME="${PKGNAME:-$(sh contrib/semver/name.sh 2>/dev/null || echo yggdrasil)}"
PKGVERSION="${PKGVERSION:-$(sh contrib/semver/version.sh --bare 2>/dev/null || true)}"
if [ -z "$PKGVERSION" ]; then
  PKGVERSION="0.0.0-git$(git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)"
fi

echo "==> Package:    $PKGNAME $PKGVERSION ($PKGARCH)"
echo "==> Build image: $GO_IMAGE"
echo "==> Output dir:  $OUTDIR"

mkdir -p "$OUTDIR"

# Run as the host user so the produced files are not owned by root,
# keep all Go caches inside the container (nothing pollutes the repo).
docker run --rm \
  -v "$PWD":/src \
  -w /src \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GOCACHE=/tmp/go-build-cache \
  -e GOMODCACHE=/tmp/go-mod-cache \
  -e GOPATH=/tmp/gopath \
  -e CGO_ENABLED=0 \
  -e PKGARCH="$PKGARCH" \
  -e PKGNAME="$PKGNAME" \
  -e PKGVERSION="$PKGVERSION" \
  "$GO_IMAGE" \
  bash -ec '
    git config --global --add safe.directory /src
    sh contrib/deb/generate.sh
  '

# generate.sh drops the .deb in the repo root; move it to the output dir.
built="$(ls -t "$PKGNAME"-*-"$PKGARCH".deb 2>/dev/null | head -n 1 || true)"
if [ -z "$built" ]; then
  echo "ERROR: no .deb package was produced" >&2
  exit 1
fi
mv -f "$built" "$OUTDIR/"
DEB_PATH="$OUTDIR/$built"

# The binaries are already packed into the .deb; keep the repo root clean.
rm -f yggdrasil yggdrasilctl

echo
echo "==> Package ready: $DEB_PATH"
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$DEB_PATH"
else
  sha256sum "$DEB_PATH"
fi

cat <<EOF

Transfer to a server and install:

  scp "$DEB_PATH" user@your-server:/tmp/
  ssh user@your-server
  sudo dpkg -i /tmp/$(basename "$DEB_PATH")
  # or: sudo apt install /tmp/$(basename "$DEB_PATH")

The package installs /usr/bin/yggdrasil and /usr/bin/yggdrasilctl,
registers systemd units, and generates /etc/yggdrasil/yggdrasil.conf
on first install (existing config is backed up in /var/backups/).
EOF
