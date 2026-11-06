#!/bin/sh

# This is a lazy script to create an .rpm for Fedora/RHEL/CentOS and other
# rpm-based distributions. It installs yggdrasil and enables it in systemd.
# Mirrors contrib/deb/generate.sh - same build, same /etc/yggdrasil layout,
# same systemd units - just packaged as an rpm instead of a deb. You can
# give it the PKGARCH= argument, using the same values as the deb script,
# i.e. PKGARCH=arm64 sh contrib/rpm/generate.sh
#
# Requires rpmbuild (the "rpm-build" package on Fedora/RHEL/CentOS).

if [ `pwd` != `git rev-parse --show-toplevel` ]
then
  echo "You should run this script from the top-level directory of the git repo"
  exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild not found - install it first, e.g.:"
  echo "  dnf install -y rpm-build   (Fedora/RHEL/CentOS)"
  echo "  zypper install -y rpm-build   (openSUSE)"
  exit 1
fi

PKGNAME=${PKGNAME:-$(sh contrib/semver/name.sh)}
PKGVERSION=${PKGVERSION:-$(sh contrib/semver/version.sh --bare)}
PKGARCH=${PKGARCH-amd64}

# RPM's Version/Release fields can't contain "-". git describe --bare gives
# e.g. "0.5.14-29-g36c42ec" for a dev build (29 commits past tag v0.5.14) or
# just "0.5.14" on an exact tag - split that into a valid Version+Release.
RPMVERSION=$(echo "$PKGVERSION" | cut -d- -f1)
RPMRELEASE=$(echo "$PKGVERSION" | sed "s/^$RPMVERSION-\{0,1\}//" | sed 's/-/./g')
if [ -z "$RPMRELEASE" ]; then RPMRELEASE=1; fi

GOLDFLAGS="-X github.com/yggdrasil-network/yggdrasil-go/src/config.defaultConfig=/etc/yggdrasil/yggdrasil.conf"
GOLDFLAGS="${GOLDFLAGS} -X github.com/yggdrasil-network/yggdrasil-go/src/config.defaultAdminListen=unix:///var/run/yggdrasil/yggdrasil.sock"

# Same PKGARCH vocabulary as contrib/deb/generate.sh; translated to the
# native rpm arch name for the package metadata/filename below.
if [ $PKGARCH = "amd64" ]; then GOARCH=amd64 GOOS=linux ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=x86_64
elif [ $PKGARCH = "i386" ]; then GOARCH=386 GOOS=linux ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=i686
elif [ $PKGARCH = "mipsel" ]; then GOARCH=mipsle GOOS=linux ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=mipsel
elif [ $PKGARCH = "mips" ]; then GOARCH=mips64 GOOS=linux ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=mips64
elif [ $PKGARCH = "armhf" ]; then GOARCH=arm GOOS=linux GOARM=6 ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=armv6hl
elif [ $PKGARCH = "arm64" ]; then GOARCH=arm64 GOOS=linux ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=aarch64
elif [ $PKGARCH = "armel" ]; then GOARCH=arm GOOS=linux GOARM=5 ./build -l "${GOLDFLAGS}" || exit 1; RPMARCH=armv5tel
else
  echo "Specify PKGARCH=amd64,i386,mips,mipsel,armhf,arm64,armel"
  exit 1
fi

PKGFILE=$PKGNAME-$RPMVERSION-$RPMRELEASE.$RPMARCH.rpm
echo "Building $PKGFILE"

TOPDIR=/tmp/$PKGNAME-rpmbuild
rm -rf $TOPDIR
mkdir -p $TOPDIR/BUILD $TOPDIR/RPMS $TOPDIR/SOURCES $TOPDIR/SPECS $TOPDIR/SRPMS $TOPDIR/BUILDROOT

# Binaries and units already built above - this spec only packages them, it
# does not compile anything itself (rpmbuild has no Go toolchain dependency
# this way, same philosophy as the deb script's hand-rolled data.tar.gz).
cat > $TOPDIR/SPECS/$PKGNAME.spec << EOF
Name: $PKGNAME
Version: $RPMVERSION
Release: $RPMRELEASE
Summary: Yggdrasil Network
License: LGPLv3
URL: https://github.com/yggdrasil-network/yggdrasil-go/
Requires: systemd
# Statically-linked-ish Go binary - rpm's automatic dependency scanner has
# nothing useful to add here and can misfire on Go's ELF metadata.
AutoReqProv: no

%description
Yggdrasil is an early-stage implementation of a fully end-to-end encrypted IPv6
network. It is lightweight, self-arranging, supported on multiple platforms and
allows pretty much any IPv6-capable application to communicate securely with
other Yggdrasil nodes.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
install -m 0755 $PWD/yggdrasil %{buildroot}/usr/bin/yggdrasil
install -m 0755 $PWD/yggdrasilctl %{buildroot}/usr/bin/yggdrasilctl
install -m 0644 $PWD/contrib/systemd/yggdrasil.service.debian %{buildroot}/usr/lib/systemd/system/yggdrasil.service
install -m 0644 $PWD/contrib/systemd/yggdrasil-default-config.service.debian %{buildroot}/usr/lib/systemd/system/yggdrasil-default-config.service

%files
/usr/bin/yggdrasil
/usr/bin/yggdrasilctl
/usr/lib/systemd/system/yggdrasil.service
/usr/lib/systemd/system/yggdrasil-default-config.service

%pre
getent group yggdrasil >/dev/null || groupadd --system yggdrasil || true
exit 0

%post
systemctl daemon-reload >/dev/null 2>&1 || true

if [ ! -d /etc/yggdrasil ]; then
    mkdir -p /etc/yggdrasil
    chown root:yggdrasil /etc/yggdrasil
    chmod 750 /etc/yggdrasil
fi

if [ -s /etc/yggdrasil/yggdrasil.conf ]; then
  mkdir -p /var/backups
  backup_path=/var/backups/yggdrasil.conf.\`date +%Y%m%d-%H%M%S\`
  echo "Backing up configuration file to \$backup_path"
  cp /etc/yggdrasil/yggdrasil.conf "\$backup_path"
  chmod 640 "\$backup_path"

  # Never truncate the config (see contrib/deb/generate.sh).
  echo "Normalising and updating /etc/yggdrasil/yggdrasil.conf"
  if /usr/bin/yggdrasil -useconf -normaliseconf < "\$backup_path" > /etc/yggdrasil/yggdrasil.conf.new && [ -s /etc/yggdrasil/yggdrasil.conf.new ]; then
    mv /etc/yggdrasil/yggdrasil.conf.new /etc/yggdrasil/yggdrasil.conf
  else
    rm -f /etc/yggdrasil/yggdrasil.conf.new
    echo "Could not normalise the configuration - keeping it unchanged"
  fi

  chown root:yggdrasil /etc/yggdrasil/yggdrasil.conf
  chmod 640 /etc/yggdrasil/yggdrasil.conf
else
  if ls /var/backups/yggdrasil.conf.* >/dev/null 2>&1; then
    echo "NOTE: /etc/yggdrasil/yggdrasil.conf is missing or empty; earlier configs (keys, peers) are in /var/backups/yggdrasil.conf.*"
  fi
  echo "Generating initial configuration file /etc/yggdrasil/yggdrasil.conf"
  (umask 037 && /usr/bin/yggdrasil -genconf > /etc/yggdrasil/yggdrasil.conf)

  chown root:yggdrasil /etc/yggdrasil/yggdrasil.conf
  chmod 640 /etc/yggdrasil/yggdrasil.conf
fi

systemctl enable yggdrasil >/dev/null 2>&1 || true
systemctl restart yggdrasil >/dev/null 2>&1 || true
exit 0

%preun
if [ "\$1" = "0" ]; then
  if command -v systemctl >/dev/null; then
    systemctl stop yggdrasil >/dev/null 2>&1 || true
    systemctl disable yggdrasil >/dev/null 2>&1 || true
  fi
fi
exit 0

%changelog
* $(date "+%a %b %d %Y") Yggdrasil <noreply@yggdrasil-network.github.io> - $RPMVERSION-$RPMRELEASE
- See https://github.com/yggdrasil-network/yggdrasil-go/blob/develop/CHANGELOG.md
EOF

rpmbuild --define "_topdir $TOPDIR" --target "$RPMARCH" -bb "$TOPDIR/SPECS/$PKGNAME.spec"

find $TOPDIR/RPMS -name '*.rpm' -exec cp {} "./$PKGFILE" \;
rm -rf $TOPDIR

echo "Built $PKGFILE"
