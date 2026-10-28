package node

// The recorded-state repair entry (#11c-2, spec §4.10/§4.11).
//
// The transient unit has no terminal, no caller-supplied configuration and no
// secret on stdin, so the new package must be able to repair a Node from what
// the host itself recorded. `--from-recorded-state` is that mode: it is only
// reachable inside the hidden `__internal-update*` family, never from the
// public `install` surface, and it never becomes a second install mode.
//
// Two rules make the derivation trustworthy:
//
//   - the effective Node ledger supplies every configuration value, and the
//     positional edge/out role must agree with it (a role is the one input the
//     unit can still name);
//   - the ledger's recorded release identity (AgentVersion + AgentSHA256) must
//     agree with agent.json, the file the running Agent actually reads. If a
//     completed installation records one build and agent.json names another,
//     the host is not in the state the ledger claims, so the handoff refuses
//     with CONFIG_CONFLICT before any mutation instead of guessing which build
//     it is repairing from.
//
// A ledger that is not yet `installed` (a first attempt that failed before the
// apply) is exempt from the second rule: nothing has been applied, agent.json
// may legitimately be absent, and completing that operation is exactly what a
// repair is for.

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// recordedNodeConfig derives the full Node configuration of this host from its
// effective ledger. It never reads argv, environment or remote input.
func recordedNodeConfig(root string, role corenode.Role) (corenode.Config, *core.InstallError) {
	state, exists, err := core.ReadNodeState(root)
	if err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) && ie.Code != "" {
			return corenode.Config{}, ie
		}
		return corenode.Config{}, &core.InstallError{Stage: "preflight", Code: core.CodeInstallStateInvalid,
			Recovery: "Inspect the recorded installer state; do not delete Agent identity or kernel data."}
	}
	if !exists || state.Node == nil {
		return corenode.Config{}, &core.InstallError{Stage: "preflight", Code: core.CodeRepairStateMissing,
			Recovery: "A recorded-state handoff needs a Node ledger created by MeshMux; enroll the node first."}
	}
	if state.Node.Role != role {
		return corenode.Config{}, &core.InstallError{Stage: "preflight", Code: core.CodeConfigConflict,
			Recovery: "The recorded node role differs from this handoff; a recorded-state repair never changes the role."}
	}
	recorded := *state.Node
	if state.Status == "installed" {
		// A completed installation must record the release identity it
		// applied; without it the I8 comparison has no left side, which is a
		// broken ledger rather than an unattended upgrade.
		if !core.ValidDigest.MatchString(recorded.AgentSHA256) || recorded.AgentVersion == "" {
			return corenode.Config{}, &core.InstallError{Stage: "preflight", Code: core.CodeConfigConflict,
				Recovery: "The ledger records no verified Agent release identity; run one interactive repair to re-record it."}
		}
		if conflict := checkRecordedAgentConfig(root, recorded); conflict != nil {
			return corenode.Config{}, conflict
		}
	}
	return recorded, nil
}

// checkRecordedAgentConfig proves that agent.json still names the release the
// ledger recorded. This is the I8 comparison: ledger AgentVersion/AgentSHA256
// against the same fields of the file the Agent boots from. A missing or unsafe
// file on a completed installation also fails closed: the handoff cannot prove
// which build is running, and guessing is exactly what an unattended upgrade
// must never do.
func checkRecordedAgentConfig(root string, recorded corenode.Config) *core.InstallError {
	conflict := &core.InstallError{Stage: "preflight", Code: core.CodeConfigConflict,
		Recovery: "The Node ledger and /etc/meshmux/agent.json disagree about the installed build. Inspect both and run one interactive repair before retrying the handoff."}
	path := core.Rooted(root, corenode.AgentConfigPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return conflict
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return conflict
	}
	var onDisk corenode.Config
	if json.Unmarshal(data, &onDisk) != nil {
		return conflict
	}
	if onDisk.AgentVersion != recorded.AgentVersion || onDisk.AgentSHA256 != recorded.AgentSHA256 {
		return conflict
	}
	return nil
}

// recordSameOperationRedo notes on the journal that this operation is being
// re-entered. Ruling I13: a re-entry of the same operation is an idempotent
// redo, not a conflict — the ledger and the journal are the audit trail, the
// apply itself is written to be repeatable (every step is a verified atomic
// replace of recorded files).
func recordSameOperationRedo(record func(string, string, string) error) error {
	return record("stage", "idempotent_redo", "")
}

// installLockWaitFor selects the bounded install-lock window. Only an
// unattended handoff retries: an interactive run has an operator who can decide
// when to retry, and keeps the immediate INSTALL_BUSY refusal. A test may set a
// short bound.
func installLockWaitFor(opts core.NodeApplyOptions) time.Duration {
	if opts.LockWait > 0 {
		return opts.LockWait
	}
	if opts.NonInteractive {
		return core.InstallLockWait
	}
	return 0
}

// recordedStateIdentityErrors is the recorded-state override of the identity
// phase codes. Without an operator, a lost or revoked identity is terminal:
// UPDATE_REENROLL_REQUIRED ends the chain instead of asking for a code that no
// one is present to type (spec §4.11 / Q-D3). A code the operator did place on
// the host is still tried, and a rejected one remains PAIRING_FAILED.
func recordedStateIdentityErrors(failures nodeIdentityErrors) nodeIdentityErrors {
	reenroll := &core.InstallError{Stage: "stage", Code: "UPDATE_REENROLL_REQUIRED",
		Recovery: "The recorded Node identity can no longer be used. Re-enroll the node in Hub Web; an unattended upgrade never prompts for a code."}
	failures.identityInvalid = reenroll
	failures.identityMissing = reenroll
	failures.pairingRequired = reenroll
	return failures
}
