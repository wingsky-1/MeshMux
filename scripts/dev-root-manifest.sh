#!/usr/bin/env bash
# Generate and install one root-preset target manifest for the #12e dev lane.
#
#   sudo scripts/dev-root-manifest.sh <target-version> <artifact-dir> [arch]
#
# <artifact-dir> is a directory produced by `make dev-artifacts`: it holds
# meshmuxd-linux-<arch> and its `sha256sum`-format SHA256SUMS. <arch> defaults
# to this host's Debian architecture; only the fixed amd64/arm64 matrix is
# accepted.
#
# The target artifact is a *different* build from the running Hub. It is
# published to its own root-owned drop, /var/lib/meshmux-dev-target, so the
# running Hub's SHA256SUMS drop (/var/lib/meshmux-dev) keeps naming the build
# that is actually running. The manifest is written to
# /var/lib/meshmux-installer/upgrade/manifest-<target>.json, the one directory
# the unprivileged Web may read and only root may write.
#
# This is not a release channel: it only makes the Hub self-upgrade chain
# testable on a disposable host. The production table comes from the 12e
# release pipeline (GitHub release assets), not from this script.
set -Eeuo pipefail

TARGET_DIR=/var/lib/meshmux-dev-target
MANIFEST_DIR=/var/lib/meshmux-installer/upgrade

die() { echo "dev-root-manifest: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (the manifest and the drop are root-owned)"
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || die "usage: $0 <target-version> <artifact-dir> [arch]"
TARGET=$1
SRC=$2
ARCH=${3:-$(dpkg --print-architecture 2>/dev/null || true)}

# The target is a SemVer pre-release of the dev lane, never a release. Keeping
# the `-dev.` part mandatory is what lets the manifest gate accept it as a dev
# component and refuses a hand-written "1.0.1" that no built artifact backs.
case "$TARGET" in
  [0-9]*.[0-9]*.[0-9]*-dev.*) ;;
  *) die "target '$TARGET' is not a X.Y.Z-dev.N pre-release" ;;
esac
printf '%s' "$TARGET" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+-dev\.[0-9A-Za-z.-]+$' \
  || die "target '$TARGET' is not a valid SemVer dev pre-release"

[ -d "$SRC" ] || die "artifact directory not found: $SRC"
[ -f "$SRC/SHA256SUMS" ] || die "no SHA256SUMS in $SRC (run 'make dev-artifacts')"
case "$ARCH" in
  amd64|arm64) ;;
  *) die "architecture '$ARCH' is outside the fixed amd64/arm64 matrix" ;;
esac

name="meshmuxd-linux-$ARCH"
artifact="$SRC/$name"
[ -f "$artifact" ] || die "missing artifact $artifact"

# The document is the only digest source. Verify the artifact against it before
# anything is published: the manifest repeats that digest as the trust anchor,
# so a stale or hand-edited pair would authorize bytes nobody checked.
listed=$(awk -v n="$name" '$2 == n || $2 == "*" n {print $1}' "$SRC/SHA256SUMS")
[ -n "$listed" ] || die "SHA256SUMS does not name $name"
actual=$(sha256sum "$artifact" | awk '{print $1}')
[ "$actual" = "$listed" ] || die "$name does not match SHA256SUMS"

# ELF magic catches a truncated download or an accidental text file before the
# digest is signed into a manifest.
[ "$(head -c 4 "$artifact" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] \
  || die "$artifact is not an ELF binary"

# On the host architecture the build can answer its own identity. That proves
# the artifact was built with -ldflags -X ...Version=<target>, which the root
# executor later re-checks as a version binding.
if [ "$ARCH" = "$(dpkg --print-architecture 2>/dev/null || uname -m)" ] || \
   { [ "$ARCH" = amd64 ] && [ "$(uname -m)" = x86_64 ]; } || \
   { [ "$ARCH" = arm64 ] && [ "$(uname -m)" = aarch64 ]; }; then
  reported=$("$artifact" __internal-agent-version 2>/dev/null || true)
  [ "$reported" = "$TARGET" ] \
    || die "$artifact reports '${reported:-<none>}', want the target version $TARGET"
fi

# Publish the target artifact where the unprivileged Web can read it. A
# group/world-writable drop would let a local writer swap the bytes after root
# anchored them, so both the directory and the file stay root-owned.
install -d -m 0755 -o root -g root "$TARGET_DIR"
install -m 0755 -o root -g root "$artifact" "$TARGET_DIR/$name"

# The manifest directory is created by the installer as 0755 root; re-assert it
# here so a pre-created loose directory cannot slip past the gate.
install -d -m 0755 -o root -g root "$MANIFEST_DIR"

tmp=$(mktemp "$MANIFEST_DIR/.manifest-$TARGET.XXXXXX")
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT INT TERM

# Only the meshmuxd component is described. The Hub self-upgrade moves the
# executor and restarts the Web unit; the other fixed components keep their
# existing release pins and are not touched by this lane.
cat >"$tmp" <<JSON
{
  "schema": "meshmux-release/v1",
  "version": "$TARGET",
  "architecture": "$ARCH",
  "policy_schema": 8,
  "components": [
    {
      "Name": "meshmuxd",
      "Version": "$TARGET",
      "Architecture": "$ARCH",
      "Source": "file://$TARGET_DIR/$name",
      "SHA256": "$listed",
      "Format": "elf",
      "Dev": true
    }
  ],
  "database_migration": "additive"
}
JSON

install -m 0644 -o root -g root "$tmp" "$MANIFEST_DIR/manifest-$TARGET.json"

# Read back the installed facts. The strict gate still runs in the Hub on
# backup; this only rules out an obvious operator mistake before one is made.
installed_manifest="$MANIFEST_DIR/manifest-$TARGET.json"
[ "$(stat -c '%U %a' "$installed_manifest")" = "root 644" ] \
  || die "installed manifest is not root 0644"
[ "$(stat -c '%U %a' "$MANIFEST_DIR")" = "root 755" ] \
  || die "$MANIFEST_DIR is not root 0755"
[ "$(stat -c '%U %a' "$TARGET_DIR")" = "root 755" ] \
  || die "$TARGET_DIR is not root 0755; the unprivileged Web could not read the target"
[ "$(stat -c '%U %a' "$TARGET_DIR/$name")" = "root 755" ] \
  || die "installed artifact is not root 0755"
[ "$(sha256sum "$TARGET_DIR/$name" | awk '{print $1}')" = "$listed" ] \
  || die "installed artifact no longer matches the manifest digest"
grep -q "\"Source\": \"file://$TARGET_DIR/$name\"" "$installed_manifest" \
  || die "installed manifest does not name the published artifact"
rm -f "$tmp"
trap - EXIT INT TERM

echo "root manifest installed: $installed_manifest"
echo "  target:     $TARGET"
echo "  arch:       $ARCH"
echo "  artifact:   $TARGET_DIR/$name"
echo "  sha256:     $listed"
echo
echo "The target must be strictly newer than the running Hub version (the gate"
echo "refuses otherwise). In /tasks: back up to this target_version, then apply"
echo "the returned operation_id. The root dispatcher performs the swap; the"
echo "startup reconcile confirms version and digest after the restart."
