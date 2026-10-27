package install

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/core/mesh"
)

// CandidateFiles returns deterministic, UNAPPLIED configurations for Phase B.
// All interpolation comes from Config.Validate(), never remote user input.
func CandidateFiles(c Config, ssh []int) (map[string]string, error) {
	return candidateFiles(c, ssh, false)
}

// candidateFiles permits internal TLS only to the isolated systemd integration
// test; no public CLI option can enable it.
func candidateFiles(c Config, ssh []int, internalTLS bool) (map[string]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if len(ssh) == 0 {
		return nil, fmt.Errorf("SSH_LISTENER_UNKNOWN")
	}
	var ports []string
	for _, p := range ssh {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("SSH_LISTENER_MISMATCH")
		}
		ports = append(ports, strconv.Itoa(p))
	}
	tlsLine := ""
	if internalTLS {
		tlsLine = "\ttls internal\n"
	}
	caddy := fmt.Sprintf(`{
	admin off
}
%s {
%s	header {
		Strict-Transport-Security "max-age=31536000"
		-Server
	}
	@health path /healthz
	respond @health 404
	reverse_proxy %s {
		header_up X-MeshMux-Client-IP {http.request.remote.host}
	}
}
%s {
%s	route {
		@subscription path /subscription/*
		reverse_proxy @subscription %s {
			header_up -X-MeshMux-Client-IP
		}
		respond 404
	}
}
%s {
%s	@private path /api/* /swagger* /metrics* /debug/*
	respond @private 404
	reverse_proxy %s
}
`, c.ManagementDomain, tlsLine, versions.WebListenAddress(), c.SubscriptionDomain, tlsLine, versions.WebListenAddress(),
		c.HeadscaleDomain, tlsLine, versions.WebHost+":"+strconv.Itoa(HeadscalePort))

	headscale := fmt.Sprintf(`# Headscale %s, aligned to the tagged official config-example.yaml.
server_url: https://%s
listen_addr: %s
metrics_listen_addr: ""
grpc_listen_addr: %s
grpc_allow_insecure: false
trusted_proxies: []
noise:
  private_key_path: /var/lib/meshmux-headscale/noise_private.key
prefixes:
  v4: %s
  v6: %s
  allocation: sequential
database:
  type: sqlite
  sqlite:
    path: /var/lib/meshmux-headscale/db.sqlite
    write_ahead_log: true
derp:
  server:
    enabled: true
    region_id: 999
    region_code: meshmux
    region_name: MeshMux embedded DERP
    verify_clients: true
    stun_listen_addr: "0.0.0.0:%d"
    private_key_path: /var/lib/meshmux-headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
log:
  level: info
  format: text
policy:
  mode: file
  path: ""
dns:
  magic_dns: false
  base_domain: "tail.%s"
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []
unix_socket: /run/meshmux-headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
auto_update:
  enabled: false
`, HeadscaleVersion, c.HeadscaleDomain, versions.WebHost+":"+strconv.Itoa(HeadscalePort),
		versions.WebHost+":"+strconv.Itoa(HeadscaleGRPCPort), mesh.TailnetIPv4Prefix, mesh.TailnetIPv6Prefix,
		STUNPort, c.HeadscaleDomain)

	webUnit := fmt.Sprintf(`[Unit]
Description=MeshMux Hub Web
After=network-online.target
Wants=network-online.target
# A Web that dies before /healthz becomes healthy is restarted only a bounded
# number of times; the process-level boot guard writes the same fact to /run so
# an operator sees HUB_UPGRADE_BOOT_CRASH_LOOP instead of an endless restart.
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User=meshmux
Group=meshmux
# WatchdogSec is liveness, not identity: the heartbeat stops when the database
# no longer answers SELECT 1. NotifyAccess=main accepts WATCHDOG=1 only from the
# Web process itself.
WatchdogSec=120
NotifyAccess=main
# Supplementary membership of the Headscale service group lets the Web process
# connect to the 0770 local unix socket (unix_socket_permission "0770"). It
# grants no filesystem access to /var/lib/meshmux-headscale, which stays 0700 and
# owned by meshmux-headscale: the group only covers the socket directory.
SupplementaryGroups=meshmux-headscale
StateDirectory=meshmux
StateDirectoryMode=0700
ExecStart=%s __internal-web --listen %s --origin https://%s --subscription-origin https://%s --headscale-origin https://%s --data-dir /var/lib/meshmux%s
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=%s/requests %s/staging
ReadWritePaths=%s/boot
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, versions.RuntimeBinaryPath, versions.WebListenAddress(), c.ManagementDomain, c.SubscriptionDomain,
		c.HeadscaleDomain, directCaddyArg(c), versions.HubRunDir, versions.HubRunDir, versions.HubRunDir)

	headscaleUnit := fmt.Sprintf(`[Unit]
Description=MeshMux Headscale coordination and embedded DERP/STUN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meshmux-headscale
Group=meshmux-headscale
StateDirectory=meshmux-headscale
StateDirectoryMode=0700
RuntimeDirectory=meshmux-headscale
RuntimeDirectoryMode=0750
ExecStart=%s --config /etc/meshmux/headscale.yaml serve
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, headscaleBinaryPath)

	caddyUnit := fmt.Sprintf(`[Unit]
Description=MeshMux dedicated Caddy TLS proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meshmux-caddy
Group=meshmux-caddy
StateDirectory=meshmux-caddy
StateDirectoryMode=0700
Environment=XDG_DATA_HOME=/var/lib/meshmux-caddy
ExecStart=%s run --config /etc/meshmux/Caddyfile --adapter caddyfile
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, caddyBinaryPath)
	// SSH jail is for verified effective listeners; it does not alter sshd.
	sshJail := fmt.Sprintf(`# MeshMux-owned SSH jail. It does not alter sshd or the host nftables ruleset.
[meshmux-sshd]
enabled = true
filter = sshd
backend = systemd
port = %s
protocol = tcp
banaction = nftables-multiport
maxretry = 5
findtime = 10m
bantime = 15m
usedns = no
`, strings.Join(ports, ","))
	// Web jail is disabled by default: banning an unverified proxy/CDN client
	// IP would lock out innocent users behind shared egress addresses.
	webJail := fmt.Sprintf(`[meshmux-web]
enabled = %t
filter = meshmux-web
backend = systemd
port = http,https
protocol = tcp
banaction = nftables-multiport
maxretry = 5
findtime = 10m
bantime = 10m
usedns = no
`, c.DirectCaddy)
	// The filter body is a literal (it contains fail2ban's own % directives),
	// so only the journal unit is interpolated.
	webFilter := webFilterBody + "\njournalmatch = _SYSTEMD_UNIT=" + versions.WebUnitName + "\n"
	files := map[string]string{
		caddyConfigPath:                         caddy,
		headscaleConfigPath:                     headscale,
		versions.WebUnitPath:                    webUnit,
		headscaleUnitPath:                       headscaleUnit,
		caddyUnitPath:                           caddyUnit,
		fail2banJailDir + "/" + sshJailFileName: sshJail,
		fail2banJailDir + "/meshmux-web.local":  webJail,
		fail2banFilterDir + "/" + webFilterName: webFilter,
	}
	for path, body := range hubDispatchFiles() {
		files[path] = body
	}
	return files, nil
}

// webFilterBody is the fail2ban filter shared by the rendered file and the
// deployed reference in deploy/fail2ban/meshmux-web.conf.
const webFilterBody = `[Definition]
failregex = ^\{"time":"[^"]*","level":"WARN","msg":"authentication_failed","operation_id":"[A-Za-z0-9_-]{22}","stage":"auth","error_code":"AUTH_FAILED","ban_candidate":true,"client_ip":"<ADDR>"\}$
ignoreregex =
datepattern = {UNB}(?<="time":")%%Y-%%m-%%dT%%H:%%M:%%S(?:\.\d{1,9})?%%z
`

func directCaddyArg(c Config) string {
	if c.DirectCaddy {
		return " --direct-caddy"
	}
	return ""
}
