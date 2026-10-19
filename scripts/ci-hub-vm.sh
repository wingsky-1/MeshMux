#!/usr/bin/env bash
# Full-system acceptance. This script is allowed ONLY on disposable GitHub
# Actions runners; the VM uses internal test certificates and fake example.org
# names. It never operates on a real user's server or cloud security group.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_TEMP:-}" == "" ]]; then
  echo 'Refusing to launch privileged Hub VM outside GitHub Actions' >&2
  exit 2
fi

work="${RUNNER_TEMP}/meshmux-hub-vm"
mkdir -p "$work"
chmod 700 "$work"
image="$work/debian13.qcow2"
disk="$work/disk.qcow2"
key="$work/id_ed25519"
seed="$work/seed.iso"
serial="$work/serial.log"
pid=''
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'echo "VM test failed; serial console tail follows:"; tail -100 "$serial" || true' ERR

echo 'Downloading official pinned Debian 13 cloud image'
curl -fL --retry 3 --connect-timeout 15 --max-time 320 \
  'https://cloud.debian.org/cdimage/cloud/trixie/20261001-2618/debian-13-genericcloud-amd64-20261001-2618.qcow2' -o "$image"
expected='9G8GcablvexSkauJcrri8Q5UCML2SnQHjxHvwvBqQ2qdAxPtUOBHJULuq/eA6ffHkqwKMUxsIFB/zZ/YG0aMPQ'
actual="$(openssl dgst -sha512 -binary "$image" | base64 -w0)"
[[ "$actual" == "$expected" ]] || { echo 'Debian image SHA-512 mismatch' >&2; exit 1; }

qemu-img create -f qcow2 -F qcow2 -b "$image" "$disk" 15G
ssh-keygen -q -t ed25519 -N '' -f "$key"
cat > "$work/user-data" <<EOF
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
cat > "$work/meta-data" <<EOF
instance-id: meshmux-hub-issue5-ci
local-hostname: meshmux-ci
EOF
cloud-localds "$seed" "$work/user-data" "$work/meta-data"

accel='tcg,thread=multi'
if [[ -c /dev/kvm && -w /dev/kvm ]]; then
  accel='kvm'
fi
echo "QEMU accelerator: $accel"
qemu-system-x86_64 \
  -machine q35,accel="$accel" \
  -cpu max -m 2048 -smp 2 -nographic -no-reboot \
  -drive file="$disk",if=virtio,format=qcow2 \
  -drive file="$seed",if=virtio,format=raw \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:22222-:22 \
  -device virtio-net-pci,netdev=n0 \
  -serial file:"$serial" -monitor none \
  </dev/null >/dev/null 2>&1 &
pid=$!

ssh_vm() {
  ssh -p 22222 -i "$key" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=5 runner@127.0.0.1 "$@"
}
scp_vm() {
  scp -P 22222 -i "$key" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$1" "runner@127.0.0.1:$2"
}
wait_ssh() {
  for i in $(seq 1 180); do
    if ssh_vm 'echo vm-ready' >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 2
  done
  echo 'Debian 13 SSH boot timeout' >&2
  return 1
}
wait_ssh
ssh_vm 'cloud-init status --wait; cat /etc/os-release | grep VERSION_ID; systemctl --version | head -1'
scp_vm .ci/bin/meshmux /tmp/meshmux
scp_vm .ci/bin/install.test /tmp/install.test
ssh_vm 'sudo chmod 755 /tmp/meshmux /tmp/install.test; sudo env MESHMUX_HUB_SYSTEM_VM=1 MESHMUX_HUB_SYSTEM_PHASE=install /tmp/install.test -test.run "^TestHubSystemVM$" -test.timeout=25m -test.v'
ssh_vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 8
wait_ssh
ssh_vm 'sudo env MESHMUX_HUB_SYSTEM_VM=1 MESHMUX_HUB_SYSTEM_PHASE=post-reboot /tmp/install.test -test.run "^TestHubSystemVM$" -test.timeout=10m -test.v'
echo 'Hub Debian 13 full-system installation/restart/recovery acceptance PASS'
