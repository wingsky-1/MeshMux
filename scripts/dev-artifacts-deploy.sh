#!/usr/bin/env bash
# Install a development artifact drop for the #12e dev lane.
#
# Run only on a disposable, isolated host (a VM or a fixture container). This is
# NOT a release installer and it does not touch an installed Hub: it only
# publishes the two executor artifacts and their checksum document where the dev
# pin reads them, so the Hub self-upgrade chain can be exercised end to end.
#
#   sudo scripts/dev-artifacts-deploy.sh dist/dev
#
# The drop is root-owned on purpose. The unprivileged Web process reads the
# checksum document to build the served manifest, so it must not be able to
# rewrite it: a Web-writable checksum file would let any local writer re-point
# the pin.
set -Eeuo pipefail

DEST=/var/lib/meshmux-dev
ARCHES=(amd64 arm64)

die() { echo "dev-artifacts-deploy: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (the drop is root-owned by design)"
[ "$#" -eq 1 ] || die "usage: $0 <artifact-dir>"
SRC=$1
[ -d "$SRC" ] || die "artifact directory not found: $SRC"
[ -f "$SRC/SHA256SUMS" ] || die "no SHA256SUMS in $SRC (run 'make dev-artifacts')"

# The document must be exactly a sha256sum list of the two fixed names, so a
# hand-edited or partial directory cannot become a trust anchor.
expected=$(printf '%s\n' "${ARCHES[@]/#/meshmuxd-linux-}" | sort)
listed=$(awk '{print $2}' "$SRC/SHA256SUMS" | sed 's/^\*//' | sort)
[ "$listed" = "$expected" ] || die "SHA256SUMS does not name exactly: $(echo $expected)"

for arch in "${ARCHES[@]}"; do
  name="meshmuxd-linux-$arch"
  [ -f "$SRC/$name" ] || die "missing artifact $name"
  # Verify the bytes against the document before installing anything: the whole
  # point of the drop is that the pin names bytes someone checked.
  ( cd "$SRC" && printf '%s  %s\n' \
      "$(awk -v n="$name" '$2 == n || $2 == "*" n {print $1}' SHA256SUMS)" "$name" | sha256sum -c - ) \
    || die "$name does not match SHA256SUMS"
done

install -d -m 0755 -o root -g root "$DEST"
for arch in "${ARCHES[@]}"; do
  name="meshmuxd-linux-$arch"
  install -m 0755 -o root -g root "$SRC/$name" "$DEST/$name"
done
install -m 0644 -o root -g root "$SRC/SHA256SUMS" "$DEST/SHA256SUMS"

# Read back: the drop is only usable when the installed bytes still match the
# installed document.
( cd "$DEST" && sha256sum -c SHA256SUMS ) || die "installed drop does not verify"

# The drop is the running release's catalog, not an upgrade target. If a Hub is
# already installed, its runtime binary must be the drop's artifact for this
# architecture: the pin pairs this host's own digest with the drop's source
# path, so a mismatched pair would advertise bytes nobody runs. The target drop
# for an upgrade is separate; see scripts/dev-root-manifest.sh.
if [ -f /usr/local/libexec/meshmuxd ]; then
  hostarch=$(dpkg --print-architecture 2>/dev/null || uname -m)
  case "$hostarch" in
    x86_64) hostarch=amd64 ;;
    aarch64) hostarch=arm64 ;;
  esac
  running=$(sha256sum /usr/local/libexec/meshmuxd | awk '{print $1}')
  dropped=$(awk -v n="meshmuxd-linux-$hostarch" '$2 == n || $2 == "*" n {print $1}' "$DEST/SHA256SUMS")
  [ -n "$dropped" ] || die "SHA256SUMS has no line for $hostarch"
  [ "$running" = "$dropped" ] \
    || die "the running executor ($running) is not the drop's $hostarch artifact ($dropped); deploy the build that is actually running, and use scripts/dev-root-manifest.sh for an upgrade target"
fi

echo "dev drop installed in $DEST:"
sed 's/^/  /' "$DEST/SHA256SUMS"
echo
echo "The running executor is checked against the drop's artifact for this host."
echo "An upgrade target belongs in /var/lib/meshmux-dev-target, not in this drop."

