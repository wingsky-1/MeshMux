#!/usr/bin/env bash
# Run Node L3 acceptance only on a disposable GitHub Actions runner. The
# VM-only test binaries, fixture service and credentials never touch a host.
set -Eeuo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_TEMP:-}" == "" ]]; then
  echo 'Refusing to launch privileged Node VM outside GitHub Actions' >&2
  exit 2
fi

role="${1:-}"
case "$role" in
  edge|out) ;;
  *)
    echo "Usage: $0 edge|out" >&2
    exit 2
    ;;
esac

work="${RUNNER_TEMP}/meshmux-${role}-vm"
mkdir -p "$work"
chmod 700 "$work"
image="$work/debian13.qcow2"
disk="$work/disk.qcow2"
key="$work/id_ed25519"
seed="$work/seed.iso"
serial="$work/serial.log"
redacted_serial="$work/serial.redacted.log"
node_status="$work/node-fixture.status"
fixture_dir="$work/hub-fixture"
pid=''
fixture_pid=''
redact_serial() {
  if [[ ! -f "$serial" ]]; then
    return 0
  fi
  awk '
    /-----BEGIN [^-]+-----/ { in_key=1; print "<redacted private key>"; next }
    in_key && /-----END [^-]+-----/ { in_key=0; next }
    in_key { next }
    { print }
  ' "$serial" |
    sed -E \
      -e '/(database|sqlite|identity|credential|pairing|token|secret|password|private|code)/I s#.*#<redacted sensitive diagnostic line>#' \
      -e 's#(pairing[_-]?code|token|secret|password|private[_-]?key|code)([=: ]+)[^[:space:]]+#\1\2<redacted>#Ig' \
      -e 's#[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}#<redacted-uuid>#Ig' \
      -e 's#[A-Za-z0-9_+/-]{24,}#<redacted>#g' \
      -e 's#https?://[^[:space:]]+#<redacted-url>#Ig' |
    tail -200 >"$redacted_serial"
  chmod 600 "$redacted_serial"
}
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [[ -n "${fixture_pid:-}" ]]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  redact_serial || true
}
trap cleanup EXIT
trap 'redact_serial || true; echo "Node VM test failed; redacted serial console tail follows:"; tail -100 "$redacted_serial" 2>/dev/null || true' ERR

require_test() {
  local binary="$1"
  local test_name="$2"
  local tests
  if [[ ! -f "$binary" ]]; then
    echo "Required test binary is missing: $binary" >&2
    return 1
  fi
  tests="$("$binary" -test.list "^${test_name}$")" || {
    echo "Could not list tests in $binary" >&2
    return 1
  }
  if ! grep -Fxq "$test_name" <<<"$tests"; then
    echo "Required $test_name is absent from $binary; refusing a no-match pass" >&2
    return 1
  fi
  echo "$binary lists $test_name"
}

require_test .ci/bin/install.test TestNodeSystemVM
require_test .ci/bin/web.test TestNodeHubFixture

echo 'Downloading official pinned Debian 13 cloud image'
curl -fL --retry 3 --connect-timeout 15 --max-time 320 \
  'https://cloud.debian.org/cdimage/cloud/trixie/20261001-2618/debian-13-genericcloud-amd64-20261001-2618.qcow2' -o "$image"
expected='9G8GcablvexSkauJcrri8Q5UCML2SnQHjxHvwvBqQ2qdAxPtUOBHJULuq/eA6ffHkqwKMUxsIFB/zZ/YG0aMPQ'
actual="$(openssl dgst -sha512 -binary "$image" | base64 -w0 | tr -d '=')"
[[ "$actual" == "$expected" ]] || { echo 'Debian image SHA-512 mismatch' >&2; exit 1; }

qemu-img create -f qcow2 -F qcow2 -b "$image" "$disk" 15G
ssh-keygen -q -t ed25519 -N '' -f "$key"
cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: runner
    shell: /bin/bash
    groups: [sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$key.pub")
ssh_pwauth: false
disable_root: true
package_update: false
EOF
cat >"$work/meta-data" <<EOF
instance-id: meshmux-node-${role}-issue6-ci
local-hostname: meshmux-node-${role}-ci
EOF
cloud-localds "$seed" "$work/user-data" "$work/meta-data"

ssh_port=22223
if [[ "$role" == "out" ]]; then
  ssh_port=22224
fi
accel='tcg,thread=multi'
if [[ -c /dev/kvm && -w /dev/kvm ]]; then
  accel='kvm'
fi
echo "QEMU accelerator: $accel"
qemu-system-x86_64 \
  -machine q35 -accel "$accel" \
  -cpu max -m 3072 -smp 2 -nographic \
  -drive file="$disk",if=virtio,format=qcow2 \
  -drive file="$seed",if=virtio,format=raw \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22 \
  -device virtio-net-pci,netdev=n0 \
  -serial file:"$serial" -monitor none \
  </dev/null >/dev/null 2>&1 &
pid=$!

ssh_vm() {
  ssh -p "$ssh_port" -i "$key" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=5 runner@127.0.0.1 "$@"
}
scp_vm() {
  scp -P "$ssh_port" -i "$key" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$1" "runner@127.0.0.1:$2"
}
wait_ssh() {
  for _ in $(seq 1 180); do
    if ssh_vm 'echo vm-ready' >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 2
  done
  echo 'Debian 13 SSH boot timeout' >&2
  return 1
}
copy_test_binaries() {
  scp_vm .ci/bin/meshmux /tmp/meshmux
  scp_vm .ci/bin/install.test /tmp/install.test
  scp_vm .ci/bin/web.test /tmp/web.test
  ssh_vm 'sudo chmod 755 /tmp/meshmux /tmp/install.test /tmp/web.test'
}
start_node_fixture() {
  # Launch the real Hub fixture (persistent SQLite + private TLS CA) on the
  # runner loopback. The guest reaches it through the QEMU slirp gateway
  # 10.0.2.2; nothing here listens on a runner-external address.
  mkdir -p "$fixture_dir"
  chmod 700 "$fixture_dir"
  if [[ -z "${fixture_pid:-}" ]] || ! kill -0 "$fixture_pid" 2>/dev/null || [[ ! -f "$fixture_dir/fixture-ready" ]]; then
    rm -f "$fixture_dir/fixture-ready"
    # The guest reaches the runner loopback fixture through the QEMU slirp
    # gateway, so the fixture must advertise Origin https://10.0.2.2:19443;
    # otherwise the Hub Host check rejects pairing with HOST_REJECTED (403).
    MESHMUX_NODE_HUB_FIXTURE_DIR="$fixture_dir" MESHMUX_NODE_HUB_FIXTURE_ROLE="$role" MESHMUX_NODE_HUB_FIXTURE_SSH_PORT=22 MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST=10.0.2.2 \
      ./.ci/bin/web.test -test.run '^TestNodeHubFixture$' -test.v >"$work/fixture.log" 2>&1 &
    fixture_pid=$!
  fi
  for _ in $(seq 1 120); do
    if [[ -f "$fixture_dir/fixture-ready" ]] && kill -0 "$fixture_pid" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then
      echo 'Hub fixture exited early; log follows:' >&2
      tail -50 "$work/fixture.log" >&2
      return 1
    fi
    sleep 1
  done
  if [[ ! -f "$fixture_dir/fixture-ready" ]]; then
    echo 'Hub fixture not ready' >&2
    tail -50 "$work/fixture.log" >&2
    return 1
  fi
  # Translate the runner-loopback Hub URL to the guest route and stage the
  # VM status plus the fixture CA the VM test installs into system roots.
  # The fixture advertises Origin https://10.0.2.2:19443 for the guest path
  # (MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST). The staged status must already
  # carry that guest route; fail closed instead of silently rewriting it.
  if ! grep -qE '"hub_url": *"https://10\.0\.2\.2:[0-9]+' "$fixture_dir/node-fixture.json"; then
    echo 'fixture hub_url is not the guest route; check MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST' >&2
    tail -50 "$work/fixture.log" >&2
    return 1
  fi
  cp "$fixture_dir/node-fixture.json" "$node_status"
  chmod 600 "$node_status"
  scp_vm "$node_status" /tmp/node-fixture.status
  scp_vm "$fixture_dir/ca.crt" /tmp/node-fixture-ca.crt
  ssh_vm 'sudo chmod 600 /tmp/node-fixture.status /tmp/node-fixture-ca.crt'
  for _ in $(seq 1 60); do
    if ssh_vm 'timeout 5 bash -c "</dev/tcp/10.0.2.2/19443"' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo 'guest cannot reach fixture Hub at 10.0.2.2:19443' >&2
  return 1
}

wait_ssh
ssh_vm 'cloud-init status --wait; cat /etc/os-release | grep VERSION_ID; systemctl --version | head -1'
copy_test_binaries
start_node_fixture
ssh_vm "sudo env MESHMUX_NODE_SYSTEM_VM=1 MESHMUX_NODE_ROLE=${role} MESHMUX_NODE_PHASE=install MESHMUX_NODE_FIXTURE_STATUS=/tmp/node-fixture.status MESHMUX_NODE_FIXTURE_CA=/tmp/node-fixture-ca.crt /tmp/install.test -test.run '^TestNodeSystemVM$' -test.timeout=25m -test.v"
boot_before="$(ssh_vm 'cat /proc/sys/kernel/random/boot_id')"
ssh_vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 8
wait_ssh
boot_after="$(ssh_vm 'cat /proc/sys/kernel/random/boot_id')"
if [[ "$boot_before" == "$boot_after" ]]; then
  echo 'VM did not actually reboot; refusing to count persistence as verified' >&2
  exit 1
fi
# Debian may mount /tmp as tmpfs, so restore the ephemeral binaries and status.
copy_test_binaries
start_node_fixture
ssh_vm "sudo env MESHMUX_NODE_SYSTEM_VM=1 MESHMUX_NODE_ROLE=${role} MESHMUX_NODE_PHASE=post-reboot MESHMUX_NODE_FIXTURE_STATUS=/tmp/node-fixture.status MESHMUX_NODE_FIXTURE_CA=/tmp/node-fixture-ca.crt /tmp/install.test -test.run '^TestNodeSystemVM$' -test.timeout=10m -test.v"
echo "Node $role Debian 13 first-install/reboot acceptance PASS"
