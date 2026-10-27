#!/usr/bin/env bash
# Run only in the disposable Debian 13 Docker container created by
# .github/workflows/hub-components.yml. Never run this on a VPS.
set -Eeuo pipefail

if ! grep -q '^VERSION_ID="\?13"\?$' /etc/os-release; then
  echo 'Expected Debian 13 (trixie) container' >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  ca-certificates curl tar systemd fail2ban nftables openssh-server

arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64)
    caddy_hash="727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b"
    headscale_hash="e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980"
    ;;
  arm64)
    caddy_hash="d8fc6d179a5d283028a472a5618564f6ad8a86fed513e64f032b3b0b7cc45e42"
    headscale_hash="3afddd207b89ac22cfad4235cc163c6e538cc59ada139e7c0bf47640c5d9e945"
    ;;
  *)
    echo "Unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fL --retry 3 --connect-timeout 10 --max-time 150 \
  "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_${arch}.tar.gz" \
  -o "$tmp/caddy.tar.gz"
curl -fL --retry 3 --connect-timeout 10 --max-time 150 \
  "https://github.com/juanfont/headscale/releases/download/v0.29.5/headscale_0.29.5_linux_${arch}" \
  -o "$tmp/headscale"
printf '%s  %s\n' "$caddy_hash" "$tmp/caddy.tar.gz" "$headscale_hash" "$tmp/headscale" | sha256sum -c -

mkdir -p "$tmp/extracted" /usr/local/libexec /tmp/meshmux-headscale-ci
tar -xzf "$tmp/caddy.tar.gz" -C "$tmp/extracted"
test -f "$tmp/extracted/caddy"
install -m 0755 "$tmp/extracted/caddy" /usr/local/libexec/meshmux-caddy
install -m 0755 "$tmp/headscale" /usr/local/libexec/meshmux-headscale
install -m 0755 /workspace/.ci/bin/meshmux-web /usr/local/libexec/meshmux-web
install -m 0755 /workspace/.ci/bin/meshmux /usr/local/libexec/meshmuxd

fixture=/workspace/.ci/hub-fixture
MESHMUX_HUB_FIXTURE_DIR="$fixture" /workspace/.ci/bin/install.test \
  -test.run '^TestWriteComponentFixtures$' -test.v

/usr/local/libexec/meshmux-caddy version
/usr/local/libexec/meshmux-headscale version
/usr/local/libexec/meshmux-caddy validate --config "$fixture/Caddyfile" --adapter caddyfile
/usr/local/libexec/meshmux-headscale --config "$fixture/headscale.yaml" configtest

for file in "$fixture"/meshmux-*.service "$fixture"/meshmux-*.path; do
  install -m 0644 "$file" "/etc/systemd/system/${file##*/}"
done
install -m 0644 "$fixture/meshmux.conf" /etc/tmpfiles.d/meshmux.conf
systemd-analyze verify /etc/systemd/system/meshmux-web.service \
  /etc/systemd/system/meshmux-headscale.service \
  /etc/systemd/system/meshmux-caddy.service \
  /etc/systemd/system/meshmux-hub-dispatch.service \
  /etc/systemd/system/meshmux-hub-dispatch.path

# The journald drop-in is not a unit, so it is validated by content and by the
# real journald.conf.d lookup: the three quota keys only exist in
# /etc/systemd/journald.conf.d/99-meshmux.conf, so systemd-analyze cat-config
# proving the merged journald config contains them proves discovery too. Nothing
# else (storage, forwarding, rate limits) is taken over.
install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$fixture/99-meshmux.conf" /etc/systemd/journald.conf.d/99-meshmux.conf
journald_config="$(systemd-analyze cat-config systemd/journald.conf)"
grep -qx 'SystemMaxUse=1G' <<<"$journald_config"
grep -qx 'RuntimeMaxUse=512M' <<<"$journald_config"
grep -qx 'MaxFileSec=30day' <<<"$journald_config"

# The dispatch substrate depends on the exact tmpfiles modes: the Web must be
# able to write requests and read results, while the ledger tree stays 0600 and
# the request.done tree stays root-only. staging/ is the unwatched sibling the
# Web completes a request in, so it needs the same Web-writable mode.
grep -qx 'd /run/meshmux-hub/requests 0730 root meshmux' /etc/tmpfiles.d/meshmux.conf
grep -qx 'd /run/meshmux-hub/staging 0730 root meshmux' /etc/tmpfiles.d/meshmux.conf
grep -qx 'd /run/meshmux-hub/requests.done 0700 root root' /etc/tmpfiles.d/meshmux.conf
grep -qx 'd /var/lib/meshmux-installer 0711 root root' /etc/tmpfiles.d/meshmux.conf
grep -qx 'd /var/lib/meshmux-installer/hub-upgrade/results 0750 root meshmux' /etc/tmpfiles.d/meshmux.conf
grep -q 'ReadWritePaths=/run/meshmux-hub/requests /run/meshmux-hub/staging' /etc/systemd/system/meshmux-web.service

install -m 0644 "$fixture/meshmux-ssh.local" /etc/fail2ban/jail.d/meshmux-ssh.local
fail2ban-client -t
echo "Debian 13 $arch: all Hub component validations passed"
