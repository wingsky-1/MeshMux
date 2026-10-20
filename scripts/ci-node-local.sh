#!/usr/bin/env bash
# Local behavioral validation for Issue #6 PR-B (Node install/enroll/repair).
#
# Runs the REAL InstallNode transaction with Root=/ INSIDE a disposable
# privileged Debian 13 container that boots systemd as PID 1. This is the
# closest local approximation of the QEMU L3 guest: real service
# supervision, real fail2ban/nft behavior, real file ownership, reboot
# persistence via container restart.
#
# The host is never touched: no volume mounts, everything enters via
# `docker cp`, and the container is removed on exit (success or failure).
# Needs: docker, Go toolchain (host builds the test binaries), outbound
# HTTPS through PROXY_HOST:PROXY_PORT (default 172.17.0.1:7890).
#
# Usage: scripts/ci-node-local.sh <edge|out>
# What it does NOT cover (still QEMU-only): cloud-init boot, slirp
# networking (loopback is used instead; the 10.0.2.2 translation path stays
# L3-only), TCG emulation slowness (mitigated by design: the installer polls
# instead of assuming instant startup).
set -Eeuo pipefail

role="${1:?usage: ci-node-local.sh <edge|out>}"
if [[ "$role" != edge && "$role" != out ]]; then
  echo "role must be edge or out" >&2
  exit 2
fi

IMAGE="${MESHMUX_LOCAL_IMAGE:-meshmux/node-l3local:13}"
BASE_IMAGE="${MESHMUX_LOCAL_BASE:-debian:13}"
PROXY_HOST="${PROXY_HOST:-172.17.0.1}"
PROXY_PORT="${PROXY_PORT:-7890}"
CONTAINER="meshmux-l3local-${role}-$$"
BINDIR=/opt/meshmux-l3
FIXTURE_DIR=/opt/meshmux-l3/fixture
WORK="$(mktemp -d /tmp/meshmux-l3local.XXXXXX)"

cleanup() {
  if [[ "${KEEP_CONTAINER:-0}" != 1 ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  else
    echo "KEEP_CONTAINER=1: leaving $CONTAINER running for inspection" >&2
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

dc() { docker exec -e http_proxy="http://$PROXY_HOST:$PROXY_PORT" -e https_proxy="http://$PROXY_HOST:$PROXY_PORT" -e HTTP_PROXY="http://$PROXY_HOST:$PROXY_PORT" -e HTTPS_PROXY="http://$PROXY_HOST:$PROXY_PORT" "$CONTAINER" "$@"; }

echo "--- build host test binaries"
mkdir -p "$WORK/bin"
( cd "$(dirname "$0")/.." && go test -c -o "$WORK/bin/install.test" ./internal/install )
( cd "$(dirname "$0")/.." && go test -c -o "$WORK/bin/web.test" ./internal/web )
( cd "$(dirname "$0")/.." && CGO_ENABLED=0 go build -o "$WORK/bin/meshmux" ./cmd/meshmux )

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "--- provision local systemd image $IMAGE (one-time)"
  prov="meshmux-l3prov-$$"
  docker run -d --rm --name "$prov" --platform linux/amd64 "$BASE_IMAGE" sleep infinity >/dev/null
  trap 'docker rm -f "$prov" >/dev/null 2>&1 || true; docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
  docker exec "$prov" bash -lc "printf '%s\n' 'Acquire::http::Proxy \"http://$PROXY_HOST:$PROXY_PORT/\";' 'Acquire::https::Proxy \"http://$PROXY_HOST:$PROXY_PORT/\";' > /etc/apt/apt.conf.d/99-local-proxy"
  docker exec "$prov" bash -lc "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd-sysv openssh-server iproute2 dbus"
  docker exec "$prov" systemctl enable ssh >/dev/null
  docker commit "$prov" "$IMAGE" >/dev/null
  docker rm -f "$prov" >/dev/null
  trap cleanup EXIT
  docker image inspect "$IMAGE" >/dev/null
fi

echo "--- start disposable systemd container $CONTAINER"
docker run -d --rm --name "$CONTAINER" --platform linux/amd64 \
  --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$IMAGE" /sbin/init >/dev/null
# getty@tty1 and systemd-modules-load fail in containers (no TTY, no
# module loading); "degraded" is the healthy state here. sshd must be up.
wait_systemd() {
  local state
  for _ in $(seq 1 45); do
    state="$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
    if [[ "$state" == running || "$state" == degraded ]] && [[ "$(docker exec "$CONTAINER" systemctl is-active ssh 2>/dev/null || true)" == active ]]; then
      return 0
    fi
    sleep 2
  done
  echo "container systemd/sshd never became ready (state=$state)" >&2
  return 1
}
wait_systemd

echo "--- copy test binaries into the container"
dc mkdir -p "$BINDIR" "$FIXTURE_DIR"
dc chmod 700 "$FIXTURE_DIR"
docker cp "$WORK/bin/install.test" "$CONTAINER:$BINDIR/install.test"
docker cp "$WORK/bin/web.test" "$CONTAINER:$BINDIR/web.test"
docker cp "$WORK/bin/meshmux" "$CONTAINER:$BINDIR/meshmux"
dc chmod 755 "$BINDIR/install.test" "$BINDIR/web.test" "$BINDIR/meshmux"

# The Hub fixture dies with the container on restart while its ready file
# survives, so every boot removes the stale marker and (re)starts it.
start_fixture() {
  dc rm -f "$FIXTURE_DIR/fixture-ready"
  dc bash -lc "MESHMUX_NODE_HUB_FIXTURE_DIR=$FIXTURE_DIR MESHMUX_NODE_HUB_FIXTURE_ROLE=$role MESHMUX_NODE_HUB_FIXTURE_SSH_PORT=22 $BINDIR/web.test -test.run '^TestNodeHubFixture\$' -test.v > $BINDIR/fixture.log 2>&1 &"
  for _ in $(seq 1 60); do
    if dc test -f "$FIXTURE_DIR/fixture-ready" >/dev/null 2>&1; then break; fi
    sleep 2
  done
  dc test -f "$FIXTURE_DIR/fixture-ready"
}

echo "--- start Hub fixture inside the container (loopback)"
start_fixture

echo "--- install phase (first install, repair, fault injection)"
dc env "MESHMUX_NODE_SYSTEM_VM=1" "MESHMUX_NODE_ROLE=$role" MESHMUX_NODE_PHASE=install "MESHMUX_NODE_FIXTURE_STATUS=$FIXTURE_DIR/node-fixture.json" "MESHMUX_NODE_FIXTURE_CA=$FIXTURE_DIR/ca.crt" "MESHMUX_NODE_MESHMUX_BIN=$BINDIR/meshmux" $BINDIR/install.test -test.run '^TestNodeSystemVM$' -test.v -test.timeout 20m

echo "--- reboot (container restart keeps the filesystem)"
docker restart -t 30 "$CONTAINER" >/dev/null
wait_systemd
echo "--- restart Hub fixture (it does not survive reboot)"
start_fixture

echo "--- post-reboot phase (repair persistence)"
dc env "MESHMUX_NODE_SYSTEM_VM=1" "MESHMUX_NODE_ROLE=$role" MESHMUX_NODE_PHASE=post-reboot "MESHMUX_NODE_FIXTURE_STATUS=$FIXTURE_DIR/node-fixture.json" "MESHMUX_NODE_FIXTURE_CA=$FIXTURE_DIR/ca.crt" "MESHMUX_NODE_MESHMUX_BIN=$BINDIR/meshmux" $BINDIR/install.test -test.run '^TestNodeSystemVM$' -test.v -test.timeout 8m

echo "LOCAL L3 $role: PASS"
