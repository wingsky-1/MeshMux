package core

import "github.com/wingsky-1/MeshMux/internal/cli/versions"

// The installer's own path/unit vocabulary. Everything below is private to this
// package: no other layer renders these files, so the constants live next to the
// renderer instead of in the shared versions leaf. Anything a second package
// needs (installer root, ledger, runtime binary, web unit, ports, architecture)
// comes from internal/cli/versions.
//
// agent.json is not declared here: internal/node owns its one path constant
// (node.AgentConfigPath), because the Agent and the Hub upgrade producer both
// address that file.

const (
	// CaddyConfigPath and HeadscaleConfigPath are the two rendered service
	// configs. The Hub channel's hub_stage.go validates them before any file
	// is replaced.
	CaddyConfigPath     = "/etc/meshmux/Caddyfile"
	HeadscaleConfigPath = "/etc/meshmux/headscale.yaml"

	// unitDir is the systemd unit directory; node units are named by the node
	// domain and appended to it.
	unitDir = "/etc/systemd/system"

	// fail2banJailDir and fail2banFilterDir hold MeshMux's jails and filter.
	Fail2banJailDir   = "/etc/fail2ban/jail.d"
	Fail2banFilterDir = "/etc/fail2ban/filter.d"
	SSHJailFileName   = "meshmux-ssh.local"
	WebFilterName     = "meshmux-web.conf"

	// JournaldDropInPath is the one host-level journald drop-in MeshMux owns.
	// The "99-" prefix sorts last inside journald.conf.d, so the quota wins over
	// distribution drop-ins while the main journald.conf is never rewritten. The
	// file is host-level, not per-role: the Hub always writes it, a standalone
	// Line writes it, and a co-located Line reuses the Hub's copy so exactly one
	// ledger owns the path.
	JournaldDropInPath = "/etc/systemd/journald.conf.d/99-meshmux.conf"

	// NodeUpgradeClaimPath records an in-flight Node upgrade claim. It is
	// shared with the generic rollback, which clears it after a restore.
	NodeUpgradeClaimPath = versions.AgentRoot + "/upgrade-claim.json"

	// hubDispatchPathUnit is the armed path unit of the Hub self-upgrade
	// (#11d). The generic rollback disables it before restoring files, so its
	// identity is shared with the Hub renderer instead of living there alone.
	HubDispatchPathUnit = "meshmux-hub-dispatch.path"
	HubDispatchPathPath = unitDir + "/" + HubDispatchPathUnit
)

// unitPath returns the installed unit file of one unit name.
func UnitPath(name string) string { return unitDir + "/" + name }
