package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/node"
)

type nodeManagedFile struct {
	Path   string
	Body   string
	Mode   uint32
	Owner  string
	Static bool
}

func nodeManagedFiles(cfg node.Config, ssh []int, identity node.Identity) (map[string]nodeManagedFile, error) {
	return nodeManagedFilesForLayout(cfg, ssh, identity, standaloneNodeLayout())
}

// nodeManagedFilesForLayout renders the fixed managed file set of a Node
// operation. A co-located Line reuses the Hub's Fail2ban SSH jail instead of
// installing a second jail for the same SSH listeners, so it never writes
// the jail file the Hub owns.
func nodeManagedFilesForLayout(cfg node.Config, ssh []int, identity node.Identity, layout nodeLayout) (map[string]nodeManagedFile, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return nil, err
	}
	if len(ssh) == 0 || !containsPort(ssh, cfg.SSHPort) {
		return nil, errors.New("SSH_LISTENER_MISMATCH")
	}
	for _, port := range ssh {
		if port == cfg.VLESSPort {
			return nil, errors.New("PORT_CONFLICT")
		}
	}
	agentConfig, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, errors.New("CONFIG_RENDER_FAILED")
	}
	agentConfig = append(agentConfig, '\n')
	identityBody, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return nil, errors.New("IDENTITY_RENDER_FAILED")
	}
	identityBody = append(identityBody, '\n')

	files := map[string]nodeManagedFile{
		node.AgentConfigPath: {
			Path: node.AgentConfigPath, Body: string(agentConfig), Mode: 0600, Owner: "root:root", Static: true,
		},
		node.IdentityPath: {
			Path: node.IdentityPath, Body: string(identityBody), Mode: 0600, Owner: "root:root", Static: false,
		},
		"/etc/systemd/system/" + node.AgentUnit: {
			Path: "/etc/systemd/system/" + node.AgentUnit, Body: nodeAgentUnit(), Mode: 0644, Owner: "root:root", Static: true,
		},
		"/etc/systemd/system/" + node.SingBoxUnit: {
			Path: "/etc/systemd/system/" + node.SingBoxUnit, Body: nodeSingBoxUnitFor(cfg.Role == node.RoleOut), Mode: 0644, Owner: "root:root", Static: true,
		},
	}
	if !layout.ReuseHubSSHJail {
		files[nodeSSHJailPath] = nodeManagedFile{
			Path: nodeSSHJailPath, Body: nodeSSHJail(ssh), Mode: 0644, Owner: "root:root", Static: true,
		}
	}
	if cfg.Role == node.RoleOut {
		// The path is owned by the installer but the bytes are dynamic and are
		// written only by installNodeDynamic from the validated candidate.
		files[node.ACLPath] = nodeManagedFile{
			Path: node.ACLPath, Mode: 0600, Owner: "root:root", Static: false,
		}
		files["/etc/systemd/system/"+node.ACLUnit] = nodeManagedFile{
			Path: "/etc/systemd/system/" + node.ACLUnit, Body: nodeACLUnit(), Mode: 0644, Owner: "root:root", Static: true,
		}
	}
	return files, nil
}

func nodeAgentUnit() string {
	return `[Unit]
Description=MeshMux node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/libexec/meshmuxd __internal-agent
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
ReadWritePaths=/var/lib/meshmux-agent /var/lib/meshmux-singbox
ReadOnlyPaths=/etc/meshmux/agent.json /usr/local/libexec/meshmuxd /usr/local/libexec/meshmux-sing-box
# ss -p must resolve the non-root sing-box PID via /proc/PID/fd, which needs
# DAC_READ_SEARCH; exe/cmdline also needs SYS_PTRACE. No DAC_OVERRIDE.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_CHOWN CAP_SYS_PTRACE
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_CHOWN CAP_SYS_PTRACE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`
}

func nodeSingBoxUnitFor(out bool) string {
	aclDependency := ""
	if out {
		aclDependency = "Requires=meshmux-out-acl.service\nAfter=meshmux-out-acl.service\n"
	}
	return fmt.Sprintf(`[Unit]
Description=MeshMux native sing-box kernel
After=network-online.target
Wants=network-online.target
%s
[Service]
Type=simple
User=meshmux-singbox
Group=meshmux-singbox
ExecStart=/usr/local/libexec/meshmux-sing-box run -c /var/lib/meshmux-singbox/config.json
Restart=on-failure
RestartSec=5s
UMask=0027
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadOnlyPaths=/var/lib/meshmux-singbox/config.json
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
# AF_NETLINK stays allowed: sing-box enumerates interfaces and routes at
# startup, and denying it kills the kernel under this unit (seen as a
# crashloop with no stable MainPID on slow hosts).
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, aclDependency)
}

func nodeACLUnit() string {
	return `[Unit]
Description=MeshMux Out default-deny ACL
Before=meshmux-sing-box.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /var/lib/meshmux-agent/out.nft
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
`
}

func nodeSSHJail(ssh []int) string {
	ports := sortedInts(ssh)
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	return fmt.Sprintf(`# MeshMux-owned SSH jail; it does not alter sshd or the host ruleset.
[meshmux-node-sshd]
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
`, strings.Join(values, ","))
}
