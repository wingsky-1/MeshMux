package install

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
	// caddyConfigPath and headscaleConfigPath are the two rendered service
	// configs. hub_stage.go validates them before any file is replaced.
	caddyConfigPath     = "/etc/meshmux/Caddyfile"
	headscaleConfigPath = "/etc/meshmux/headscale.yaml"

	// unitDir is the systemd unit directory; node units are named by the node
	// domain and appended to it.
	unitDir = "/etc/systemd/system"

	// fail2banJailDir and fail2banFilterDir hold MeshMux's jails and filter.
	fail2banJailDir   = "/etc/fail2ban/jail.d"
	fail2banFilterDir = "/etc/fail2ban/filter.d"
	sshJailFileName   = "meshmux-ssh.local"
	webFilterName     = "meshmux-web.conf"
)

// unitPath returns the installed unit file of one unit name.
func unitPath(name string) string { return unitDir + "/" + name }
