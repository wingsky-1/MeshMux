package versions

import "strconv"

// This file owns every fixed deployment-contract value that more than one
// MeshMux layer has to agree on. It lives in this leaf on purpose: internal/
// versions imports no other internal package, so the cli, core and control
// layers can all read the value without pulling a domain (or each other) into
// their dependency graph.
//
// Ownership and direction:
//   - layer: core leaf (the bottom of the internal DAG);
//   - consumers: internal/cli/install, internal/cli/update,
//     internal/cli/hubupgrade, internal/cli/hubupgrade/rootexec,
//     internal/cli/webcmd, internal/cli/upgrade, internal/core/meshnet;
//   - imports: standard library only. Never add an internal edge here.
//
// A literal that appears in more than one of those packages belongs here, not
// in a per-package copy. Values that are private to one package (for example a
// unit file only the installer renders) stay next to that package.

// Installer roots. The installer tree is root-owned; the Agent tree belongs
// to the meshmux service account. Both are absolute and non-configurable: no
// caller, remote request or manifest may choose another path.
const (
	// InstallerRoot is the private installer state root. It is 0711 so the
	// unprivileged Web can traverse to the root manifest/result files without
	// being able to list it.
	InstallerRoot = "/var/lib/meshmux-installer"
	// InstallerStatePath is the strict Hub/Line installer ledger.
	InstallerStatePath = InstallerRoot + "/state.json"
	// LocalLineStatePath is the ledger of a Line co-located with a Hub.
	LocalLineStatePath = InstallerRoot + "/local-line/state.json"
	// InstallerUpgradeDir holds root manifests and the root-only exec copies.
	InstallerUpgradeDir = InstallerRoot + "/upgrade"
	// HubUpgradeResultsDir is the Web-readable result directory.
	HubUpgradeResultsDir = InstallerRoot + "/hub-upgrade/results"

	// AgentRoot is the private Agent state root owned by the meshmux account.
	AgentRoot = "/var/lib/meshmux-agent"
	// AgentUpdateDir is the staged-package/work directory of the handoff.
	AgentUpdateDir = AgentRoot + "/update"
	// AgentUpgradeBackupsDir is the Node rollback store.
	AgentUpgradeBackupsDir = AgentRoot + "/upgrade-backups"

	// RuntimeBinaryPath is the installed MeshMux runtime binary (Hub/Agent).
	RuntimeBinaryPath = "/usr/local/libexec/meshmuxd"
)

// Fixed network contract. The Web always listens on loopback; the public
// ingress is the dedicated Caddy process.
const (
	// WebHost is the only accepted Web listener host.
	WebHost = "127.0.0.1"
	// WebPort is the fixed loopback Web port. Caddy, the systemd unit, the
	// launcher and the restore health probe all read it here.
	WebPort = 9080
	// HeadscalePort is the Headscale HTTP/gRPC listener port.
	HeadscalePort = 8080
	// HeadscaleGRPCPort is the Headscale gRPC listener port.
	HeadscaleGRPCPort = 50443
	// STUNPort is the embedded Headscale DERP STUN port.
	STUNPort = 3478
)

// WebListenAddress is the one accepted Web listener address. It is derived
// from WebHost and WebPort so a port change cannot leave a stale literal in
// the launcher, the rendered unit or the restore health probe.
func WebListenAddress() string {
	return WebHost + ":" + strconv.Itoa(WebPort)
}

// Hub runtime contract. /run/meshmux-hub is tmpfs-backed and survives neither
// a reboot nor a --data-dir flip, which is exactly what the fixed dispatcher
// and the boot guard need.
const (
	// HubRunDir is the fixed runtime root of the Hub upgrade mechanism.
	HubRunDir = "/run/meshmux-hub"
	// WebUnitName is the systemd unit that runs the Web launcher.
	WebUnitName = "meshmux-web.service"
	// WebUnitPath is the installed unit file path.
	WebUnitPath = "/etc/systemd/system/" + WebUnitName
)

// Architecture AMD64 and Architecture ARM64 are the only Debian architectures
// this release ships. Both the installer artifact tables and the release
// manifest set must cover exactly this matrix.
const (
	ArchitectureAMD64 = "amd64"
	ArchitectureARM64 = "arm64"
)

// SupportedArchitectures returns a fresh copy of the fixed architecture
// matrix. A caller cannot mutate the package contract through the result.
func SupportedArchitectures() []string {
	return []string{ArchitectureAMD64, ArchitectureARM64}
}

// IsSupportedArchitecture reports whether architecture is in the fixed matrix.
func IsSupportedArchitecture(architecture string) bool {
	switch architecture {
	case ArchitectureAMD64, ArchitectureARM64:
		return true
	default:
		return false
	}
}
