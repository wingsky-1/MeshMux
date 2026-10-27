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
echo "code-pinned (internal/cli/install/artifacts.go):"
grep -E '"1\.14\.3"' /workspace/internal/cli/install/artifacts.go | head -2 || true
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
# systemd-analyze verify resolves ExecStart binaries. The real binaries are
# produced by the installer transaction (hash-verified in L3), so offline
# unit validation uses empty executable stubs; this checks unit syntax and
# dependencies, not binary contents.
mkdir -p /usr/local/libexec
: > /usr/local/libexec/meshmuxd
: > /usr/local/libexec/meshmux-sing-box
chmod 0755 /usr/local/libexec/meshmuxd /usr/local/libexec/meshmux-sing-box
if ! systemd-analyze verify "${units[@]}" 2>&1 | tee /tmp/node-l2-verify.log; then
  echo 'systemd-analyze verify failed' >&2
  cat /tmp/node-l2-verify.log >&2
  exit 1
fi
echo "verified units: ${units[*]}"

echo '--- nft -c -f Out ACL dry-run + apply/readback ---'
# The -c pass never touches the kernel. The apply/readback below is a real
# nft transaction and therefore runs only when this container has
# CAP_NET_ADMIN (the CI container is started with --privileged). Without it
# the step reports an explicit SKIP and is not counted as applied evidence.
# Only acl.nft carries the rendered table: out.nft is the empty dynamic
# placeholder that installNodeDynamic fills from the validated candidate
# (nodeManagedFiles marks it Static:false with no Body), so it is expected
# to be empty here and is not syntax-checked.
acls=()
for f in "$fx"/*/acl.nft; do
  [[ -f "$f" ]] || continue
  acls+=("$f")
done
if (( ${#acls[@]} == 0 )); then
  echo 'no ACL fixtures produced' >&2
  exit 1
fi
can_apply=0
if nft list tables >/dev/null 2>&1; then
  can_apply=1
else
  echo 'SKIP nft apply/readback: nft list tables denied (no CAP_NET_ADMIN); dry-run only, not counted as applied evidence'
fi
for acl in "${acls[@]}"; do
  if ! grep -q 'table inet meshmux_out' "$acl" ||
     ! grep -q 'type filter hook input priority -10; policy accept;' "$acl" ||
     grep -qE ' (saddr|dport) | drop' "$acl"; then
    echo "ACL is not the retired, rule-free Out table in $acl" >&2
    cat "$acl" >&2
    exit 1
  fi
  echo "ACL: $acl"
  cat "$acl"
  nft -c -f "$acl"
  if (( can_apply )); then
    nft -f "$acl"
    nft_log=/tmp/node-l2-nft-out-apply.log
    nft list table inet meshmux_out | tee "$nft_log"
    rules="$(nft -j list table inet meshmux_out | jq '[.nftables[] | select(has("rule"))] | length')"
    echo "nft readback: ${rules} rule(s) in inet meshmux_out (log: $nft_log)"
    if (( rules != 0 )); then
      echo "expected zero rules in the retired Out table after nft -f, got ${rules}" >&2
      exit 1
    fi
    if ! grep -q 'table inet meshmux_out' "$nft_log"; then
      echo 'live nft readback is missing the retired Out table' >&2
      cat "$nft_log" >&2
      exit 1
    fi
    nft delete table inet meshmux_out
    echo 'nft apply/readback PASS; removed inet meshmux_out after readback'
  fi
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
