#!/usr/bin/env bash
# L2 Node component self-check for Issue #6 PR-B. Run only inside the
# disposable Debian 13 container started by .github/workflows/hub-components.yml.
# Never run this on a real host: it installs packages and writes unit files
# inside the container filesystem.
set -Eeuo pipefail

if ! grep -q '^VERSION_ID="13"' /etc/os-release; then
  echo 'Expected Debian 13 (trixie) container' >&2
  exit 1
fi

arch="$(dpkg --print-architecture)"
echo "L2 container architecture: $arch"
case "$arch" in
  amd64|arm64) ;;
  *)
    echo "Unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

INSTALL_TEST="${INSTALL_TEST:-/workspace/.ci/bin/install.test}"
if [[ ! -x "$INSTALL_TEST" ]]; then
  echo "install.test not found at $INSTALL_TEST" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  ca-certificates curl tar systemd fail2ban nftables jq systemd-sysv

# --- Node fixtures ------------------------------------------------------
fx="$(mktemp -d /tmp/node-l2-fx.XXXXXX)"
trap 'rm -rf "$fx"' EXIT
echo '--- Render Node fixtures ---'
MESHMUX_NODE_FIXTURE_DIR="$fx" "$INSTALL_TEST" \
  -test.run '^TestWriteNodeComponentFixtures$' -test.v

echo '--- Fixture manifest ---'
test -f "$fx/releases.tsv" || { echo 'releases.tsv missing' >&2; exit 1; }
cat "$fx/releases.tsv"
for role in edge out; do
  d="$fx/$role"
  test -d "$d" || { echo "role dir missing: $d" >&2; exit 1; }
  ls -1 "$d"
done

echo '--- Verify Node fixture bytes match the pinned code-base release ---'
echo "code-pinned (internal/install/artifacts.go):"
grep -E '"1\.14\.3"' /workspace/internal/install/artifacts.go | head -2 || true
echo "fixture-pinned (releases.tsv):"
cat "$fx/releases.tsv"

# Confirm both architectures are pinned to exactly 1.14.3 with the official
# SagerNet URL prefix and 64-hex digests. Fail closed on mismatch.
awk -F'\t' 'NR>1 && ($2!="1.14.3" || $1!~/^(amd64|arm64)$/ || length($4)!=64 || length($5)!=64 || index($3,"https://github.com/SagerNet/sing-box/releases/download/v")!=1) { bad=1 } END{exit bad} ' "$fx/releases.tsv" \
  || { echo 'releases.tsv disagrees with the in-tree pin' >&2; exit 1; }

# Confirm amd64 + arm64 both rows are present (otherwise CI on a single arch
# would silently accept a one-arch pin).
for want in amd64 arm64; do
  awk -F'\t' 'NR>1 {print $1}' "$fx/releases.tsv" | sort -u | grep -q "^${want}$" \
    || { echo "$want row missing from releases.tsv" >&2; exit 1; }
done
echo 'amd64 + arm64: both rows present and pinned to 1.14.3'

echo '--- systemd-analyze verify Node units (offline) ---'
for role in edge out; do
  for unit in "$fx/$role"/*.service; do
    install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
  done
done
units=( /etc/systemd/system/meshmux-agent.service
        /etc/systemd/system/meshmux-sing-box.service )
if [[ -f /etc/systemd/system/meshmux-out-acl.service ]]; then
  units+=( /etc/systemd/system/meshmux-out-acl.service )
fi
if ! systemd-analyze verify "${units[@]}" 2>&1 | tee /tmp/node-l2-verify.log; then
  echo 'systemd-analyze verify failed' >&2
  cat /tmp/node-l2-verify.log >&2
  exit 1
fi
echo "verified units: ${units[*]}"

echo '--- nft -c -f Out ACL dry-run ---'
# Dry-run check only; no kernel transactions are applied.
acls=()
for f in "$fx"/*/acl.nft "$fx"/*/out.nft; do
  [[ -f "$f" ]] || continue
  acls+=("$f")
done
if (( ${#acls[@]} == 0 )); then
  echo 'no ACL fixtures produced' >&2
  exit 1
fi
for acl in "${acls[@]}"; do
  if ! grep -q 'tcp dport 8443 drop' "$acl" || ! grep -q 'udp dport 8443 drop' "$acl"; then
    echo "ACL missing VLESS drop rules in $acl" >&2
    cat "$acl" >&2
    exit 1
  fi
  echo "ACL: $acl"
  cat "$acl"
  nft -c -f "$acl"
done

echo '--- fail2ban client -t (with MeshMux-only jail) ---'
mkdir -p /etc/fail2ban/jail.d
for j in "$fx"/*/meshmux-node-ssh.local; do
  [[ -f "$j" ]] || continue
  install -m 0644 "$j" /etc/fail2ban/jail.d/meshmux-node-ssh.local
done
fail2ban-client -t

echo '--- jq validate candidate.json per role ---'
for role in edge out; do
  c="$fx/$role/candidate.json"
  [[ -f "$c" ]] || continue
  jq -r '.inbounds[0].type' "$c"
  jq -r '.inbounds[0].listen_port' "$c"
  jq -r '.outbounds[0].type' "$c"
done

echo "Debian 13 $arch: Node L2 component validation PASS"
