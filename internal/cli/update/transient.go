package update

// The transient unit (#11c-2, spec §4.2/§4.4/§4.5/§6). The update process no
// longer runs the install inside the Agent's cgroup: it launches one transient
// systemd unit whose ExecStart is the verified new binary, and the unit — not
// the Agent — performs install, Agent restart and result write. That is the
// whole point: a child of the Agent is killed by the restart it performs
// (KillMode=control-group), while a unit owned by PID 1 is not.
//
// Two fixed argv leave this package: systemd-run to start the unit, and
// systemctl show to read its liveness. There is no shell, no D-Bus client and
// no caller-chosen property or executable.

import (
	"context"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	// transientUnitPrefix names the one-shot unit of one approved operation.
	// The operation ID is 32 lowercase hex, so the unit name needs no encoding.
	transientUnitPrefix = "meshmux-update-"
	// transientRWPaths is the complete write set of the unit (spec §6): the
	// binaries, agent.json, the private Agent directory, the unit file, the
	// installer state and cache, the sing-box config, the fail2ban jail and the
	// install lock. Every entry is required — a missing one is EROFS at install
	// time — so the list is pinned by test, never assembled per call.
	transientRWPaths = "/usr/local/libexec /etc/meshmux /var/lib/meshmux-agent " +
		"/etc/systemd/system /var/lib/meshmux-installer /var/cache/meshmux-installer " +
		"/var/lib/meshmux-singbox /etc/fail2ban /run/lock"
	// transientCaps is the capability bounding set of the unit, audited against
	// the install code paths rather than guessed (spec §6, amended 2026-10-24):
	//
	//	CAP_CHOWN          os.Chown on every managed file (install/apply_shared.go:restoreFileSnapshots,
	//	                   shared by install/node_apply.go + install/apply.go rollback) and the chown(1) calls that set the
	//	                   Agent data directory to root:meshmux-agent
	//	                   (install/node_apply.go:731, :1140).
	//	CAP_NET_ADMIN      every nft call: install/node_stage.go:144 (`nft -c`),
	//	                   install/node_apply.go:796 (`nft -j list`),
	//	                   install/node_plan.go:597 (`nft list table`).
	//	CAP_DAC_READ_SEARCH + CAP_SYS_PTRACE
	//	                   the install's own readback (pollNodeReadback →
	//	                   node.ReadbackLocal) runs inside the unit and must
	//	                   attribute the non-root sing-box listener: `ss -p`
	//	                   reads /proc/<pid>/fd (install/node_plan.go:321, :441)
	//	                   and the ownership hash reads /proc/<pid>/exe
	//	                   (install/node_plan.go:20, :31). Both are declared
	//	                   together because they are the exact pair the Agent
	//	                   unit already proves in production for this same
	//	                   readback (install/node_render.go:113-116); without
	//	                   them ss omits pid= and the install fails closed with
	//	                   PORT_OWNER_UNVERIFIED on a real host.
	//
	// Deliberately absent: DAC_OVERRIDE (the write set is enumerated and every
	// target is root-owned), SETUID/SETGID, SYS_ADMIN, SYS_MODULE, MKNOD. The
	// two install steps that would need them — apt-get for a missing package
	// (install/apply_shared.go:22-30) and useradd for a missing account
	// (install/node_apply.go:717) — cannot run on a host MeshMux installed,
	// because both are already satisfied there; if one ever is not, the unit
	// fails closed instead of widening its own privileges.
	transientCaps = "CAP_CHOWN CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"
	// transientAddressFamilies is the socket-family allowlist: AF_UNIX for
	// systemctl/fail2ban-client, AF_INET/AF_INET6 for the bind probes and
	// outbound HTTPS, AF_NETLINK because ss (SOCK_DIAG) and nft speak netlink.
	transientAddressFamilies = "AF_UNIX AF_INET AF_INET6 AF_NETLINK"
)

// ActiveState is one systemd unit state as reported by `systemctl show`. It is
// a process signal only: D5 decides success from the chain's readback, never
// from this value.
type ActiveState string

// The states systemd reports for ActiveState. A value outside this set means
// the reply was not a systemd answer and is refused.
const (
	ActiveStateActive       ActiveState = "active"
	ActiveStateReloading    ActiveState = "reloading"
	ActiveStateInactive     ActiveState = "inactive"
	ActiveStateFailed       ActiveState = "failed"
	ActiveStateActivating   ActiveState = "activating"
	ActiveStateDeactivating ActiveState = "deactivating"
	ActiveStateMaintenance  ActiveState = "maintenance"
)

var activeStates = map[ActiveState]bool{
	ActiveStateActive: true, ActiveStateReloading: true, ActiveStateInactive: true,
	ActiveStateFailed: true, ActiveStateActivating: true, ActiveStateDeactivating: true,
	ActiveStateMaintenance: true,
}

// ExecMainStatus is the unit's main process exit status as systemd records it
// (0 for a unit that never ran, 128+signal for a signalled process).
type ExecMainStatus int

// BuildTransientArgv builds the one fixed `systemd-run` command line that
// starts the approved install as a transient unit (spec §6). Every value is
// checked first and every property is a constant: the only caller-influenced
// inputs are the SemVer target, the two pinned digests and the operation ID,
// and each is either an enum or fixed-width hex. The ExecStart is the staged
// package of this build's own architecture under the staging directory.
//
// PackageSHA256 is the verified package digest the unit re-checks before it
// installs anything; Run fills it from the manifest component it verified, so
// the unit and the Agent trust the same bytes.
func BuildTransientArgv(op Config) ([]string, error) {
	return buildTransientArgv(op, runtime.GOARCH)
}

// buildTransientArgv is BuildTransientArgv with the architecture explicit. The
// exported entry always passes runtime.GOARCH; the parameter exists so the
// architecture gate is testable without cross-compiling a fixture.
func buildTransientArgv(op Config, arch string) ([]string, error) {
	switch {
	case !targetRE.MatchString(op.Target):
		return nil, fail(backup.CodeTargetInvalid, "target is not a SemVer release")
	case !digestRE.MatchString(op.ManifestSHA256):
		return nil, fail(backup.CodeDigestInvalid, "manifest SHA-256 is not 64 lowercase hex")
	case !digestRE.MatchString(op.PackageSHA256):
		return nil, fail(backup.CodeDigestInvalid, "package SHA-256 is not 64 lowercase hex")
	case op.OperationID == "":
		return nil, fail("OPERATION_REQUIRED", "an operation ID is required")
	case !opIDRE.MatchString(op.OperationID):
		return nil, fail(backup.CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	dir, err := transientWorkDir(op.WorkDir)
	if err != nil {
		return nil, err
	}
	binary, err := transientStagedPath(dir, op.Target, arch)
	if err != nil {
		return nil, err
	}
	return []string{
		systemdRunPath,
		"--unit=" + transientUnitPrefix + op.OperationID,
		"--collect",
		"--property=Type=oneshot",
		"--property=Restart=no",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=" + transientRWPaths,
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=RestrictAddressFamilies=" + transientAddressFamilies,
		"--property=CapabilityBoundingSet=" + transientCaps,
		binary,
		"__internal-update-install",
		"--target", op.Target,
		"--manifest-sha256", op.ManifestSHA256,
		"--expected-sha256", op.PackageSHA256,
		"--operation-id", op.OperationID,
		"--from-recorded-state",
	}, nil
}

// transientWorkDir checks the staging directory before it becomes an argv
// element. The production value is DefaultWorkDir; tests pass a temporary
// directory. It must be an already-clean absolute path with no control
// characters, so no line break or relative path can reach the unit.
func transientWorkDir(dir string) (string, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		strings.ContainsAny(dir, "\n\r\x00") {
		return "", fail("UPDATE_STAGE_FAILED", "the staging directory is not a clean absolute path")
	}
	return dir, nil
}

// transientStagedPath is the staged package name shared by the fetch and the
// unit: exactly one file per target and architecture. The architecture is
// checked against upgrade's fixed matrix — the same set the manifest set
// serves — so an unsupported build never names a unit.
func transientStagedPath(dir, target, arch string) (string, error) {
	if _, err := upgrade.ForArch(arch); err != nil {
		return "", fail("MANIFEST_ARCH_INVALID", "the transient unit targets an unsupported architecture")
	}
	return filepath.Join(dir, "meshmuxd-"+target+"-"+arch), nil
}

// UnitActiveState reads the unit's liveness through one fixed `systemctl show`
// of exactly ActiveState and ExecMainStatus (spec §6). It reports the process
// signal only: a non-zero ExecMainStatus or a failed unit is not by itself a
// verdict on the upgrade, and an unobservable unit is not a failure — the
// caller combines the state with the marker's age (D5).
func UnitActiveState(ctx context.Context, runner node.CommandRunner, operationID string) (ActiveState, ExecMainStatus, error) {
	if operationID == "" {
		return "", 0, fail("OPERATION_REQUIRED", "an operation ID is required")
	}
	if !opIDRE.MatchString(operationID) {
		return "", 0, fail(backup.CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	out, err := runner.Run(ctx, systemctlPath, "show", "-p", "ActiveState", "-p", "ExecMainStatus",
		transientUnitPrefix+operationID)
	if err != nil {
		return "", 0, fail("UPDATE_UNIT_QUERY_FAILED", "the transient unit state could not be read")
	}
	var state ActiveState
	var status ExecMainStatus
	var haveState, haveStatus bool
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			if haveState {
				return "", 0, fail("UPDATE_UNIT_STATE_INVALID", "the unit state was reported twice")
			}
			state, haveState = ActiveState(value), true
		case "ExecMainStatus":
			if haveStatus {
				return "", 0, fail("UPDATE_UNIT_STATE_INVALID", "the unit exit status was reported twice")
			}
			n, convErr := strconv.Atoi(value)
			if convErr != nil || n < 0 {
				return "", 0, fail("UPDATE_UNIT_STATE_INVALID", "the unit exit status is not a number")
			}
			status, haveStatus = ExecMainStatus(n), true
		}
	}
	if !haveState || !haveStatus || !activeStates[state] {
		return "", 0, fail("UPDATE_UNIT_STATE_INVALID", "the reply does not carry a systemd unit state")
	}
	return state, status, nil
}
