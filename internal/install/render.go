package install

import (
	"fmt"
	"strconv"
	"strings"
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
		tlsLine = "\\ttls internal\\n"
	}
	caddy := fmt.Sprintf(`{
	admin off
}
%s {
%s\theader {
		Strict-Transport-Security "max-age=31536000"
		-Server
	}
	@health path /healthz
	respond @health 404
	reverse_proxy 127.0.0.1:9080 {
		header_up X-MeshMux-Client-IP {http.request.remote.host}
	}
}
%s {
%s\trespond "Subscription service is not yet installed" 404
}
%s {
%s\t@private path /api/* /swagger* /metrics* /debug/*
	respond @private 404
	reverse_proxy 127.0.0.1:8080
}
`, c.ManagementDomain, tlsLine, c.SubscriptionDomain, tlsLine, c.HeadscaleDomain, tlsLine)

	headscale := fmt.Sprintf(`# Headscale 0.29.5, aligned to the tagged official config-example.yaml.
server_url: https://%s
listen_addr: 127.0.0.1:8080
metrics_listen_addr: ""
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
trusted_proxies: []
noise:
  private_key_path: /var/lib/meshmux-headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
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
    stun_listen_addr: "0.0.0.0:3478"
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
`, c.HeadscaleDomain, c.HeadscaleDomain)

	webUnit := fmt.Sprintf(`[Unit]
Description=MeshMux Hub Web
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meshmux
Group=meshmux
StateDirectory=meshmux
StateDirectoryMode=0700
ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:9080 --origin https://%s --data-dir /var/lib/meshmux%s
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
`, c.ManagementDomain, directCaddyArg(c))

	headscaleUnit := `[Unit]
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
ExecStart=/usr/local/libexec/meshmux-headscale --config /etc/meshmux/headscale.yaml serve
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
`

	caddyUnit := `[Unit]
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
ExecStart=/usr/local/libexec/meshmux-caddy run --config /etc/meshmux/Caddyfile --adapter caddyfile
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
`
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
	webJail := "[meshmux-web]\\nenabled = false\\nfilter = meshmux-web\\nbackend = systemd\\nport = http,https\\nprotocol = tcp\\nbanaction = nftables-multiport\\nmaxretry = 5\\nfindtime = 10m\\nbantime = 10m\\nusedns = no\\n"
	if c.DirectCaddy {
		webJail = strings.Replace(webJail, "enabled = false", "enabled = true", 1)
	}
	webFilter := `[Definition]
failregex = ^\\{"time":"[^"]*","level":"WARN","msg":"authentication_failed","operation_id":"[A-Za-z0-9_-]{22}","stage":"auth","error_code":"AUTH_FAILED","ban_candidate":true,"client_ip":"<ADDR>"\\}$
ignoreregex =
datepattern = {UNB}(?<="time":")%%Y-%%m-%%dT%%H:%%M:%%S(?:\\.%%f)?%%z
journalmatch = _SYSTEMD_UNIT=meshmux-web.service
`
	return map[string]string{
		"/etc/meshmux/Caddyfile":                        caddy,
		"/etc/meshmux/headscale.yaml":                   headscale,
		"/etc/systemd/system/meshmux-web.service":       webUnit,
		"/etc/systemd/system/meshmux-headscale.service": headscaleUnit,
		"/etc/systemd/system/meshmux-caddy.service":     caddyUnit,
		"/etc/fail2ban/jail.d/meshmux-ssh.local":        sshJail,
		"/etc/fail2ban/jail.d/meshmux-web.local":        webJail,
		"/etc/fail2ban/filter.d/meshmux-web.conf":       webFilter,
	}, nil
}

func directCaddyArg(c Config) string {
	if c.DirectCaddy {
		return " --direct-caddy"
	}
	return ""
}
