package update

// The outside-sandbox convergence unit (#11c-2, spec §4.2 amended / §4.8).
//
// The Agent's unit keeps /etc read-only, so after an in-memory crash-window
// adoption the Agent cannot rewrite agent.json itself. It keeps the claim and
// asks the writer wired as RuntimeOptions.HandoffConvergence. That writer runs
// inside the Agent process, while the Agent holds the shared runtime lock, so it
// must never wait: it starts ONE transient oneshot unit (`--no-block`) that
// runs the new binary's hidden `__internal-update-converge`, and returns. The
// unit does the /etc write; the Agent's pair readback remains the only thing
// that may clear the claim.
//
// Two fixed argv leave this package here: systemd-run to start the unit and the
// unit's own ExecStart. Every value is an operation ID or a digest; there is no
// shell, no caller-chosen executable and no caller-chosen path.

import (
	"context"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/versions"
)

const (
	// convergeUnitPrefix names the one-shot unit of one convergence request.
	// It is distinct from the updater's unit so a hung updater can never be
	// mistaken for a convergence request and vice versa.
	convergeUnitPrefix = "meshmux-converge-"
	// convergeRWPaths is the complete write set: agent.json and the private
	// Agent directory that holds the claim record (read only, but keeping the
	// directory visible keeps the unit's view identical to the installer's).
	convergeRWPaths = "/etc/meshmux " + versions.AgentRoot
	// convergeHiddenCommand is the unit's only subcommand.
	convergeHiddenCommand = "__internal-update-converge"
)

// BuildConvergeArgv builds the fixed `systemd-run` command line of one
// convergence unit. The properties are constants: the unit needs to replace one
// root-owned 0600 file inside an otherwise read-only filesystem, and nothing
// else. `--no-block` is what lets the Agent hold its runtime lock and return:
// without it systemd-run would wait for the oneshot to finish, which is exactly
// the lock-taking repair the carry forbids.
func BuildConvergeArgv(operationID, expectedSHA256 string) ([]string, error) {
	switch {
	case operationID == "":
		return nil, fail("OPERATION_REQUIRED", "an operation ID is required")
	case !opIDRE.MatchString(operationID):
		return nil, fail(backup.CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	case !digestRE.MatchString(expectedSHA256):
		return nil, fail(backup.CodeDigestInvalid, "the claimed digest is not 64 lowercase hex")
	}
	return []string{
		systemdRunPath,
		"--unit=" + convergeUnitPrefix + operationID,
		"--collect",
		"--no-block",
		"--property=Type=oneshot",
		"--property=Restart=no",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=" + convergeRWPaths,
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=CapabilityBoundingSet=",
		// The fixed ExecStart: the installed Agent binary (the build the claim
		// just proved) and one narrow subcommand. Root owns agent.json, so no
		// capability is needed to replace it.
		node.AgentBinaryPath,
		convergeHiddenCommand,
		"--operation-id", operationID,
		"--expected-sha256", expectedSHA256,
	}, nil
}

// ConvergenceWriter implements node.HandoffConvergenceWriter. It SPAWNS the
// transient convergence unit and returns immediately: the Agent keeps the
// claim until its own pair readback proves the write, so a queued unit that
// never got to run is a deferred convergence, never a failed boot.
//
// It uses node.Spawner, not node.CommandRunner, because the caller holds the
// shared runtime lock: waiting for the helper (or the unit) would serialize the
// Agent's poll cycle behind a lock-taking repair, which is exactly what the
// Task-4 carry forbids.
//
// The spawn context is deliberately detached from the caller's. The Agent wraps
// this call in a bounded context and cancels it on return
// (runtime_handoff.requestHandoffConvergence), and Spawn is
// exec.CommandContext + Start: handing the caller's context to it would SIGKILL
// the systemd-run helper at that cancel, before it submitted the job, with no
// error to log — convergence would silently never happen. The helper's lifetime
// is the unit's own, not this call's, exactly as the updater's spawn is
// detached in internal/node/runtime.go.
type ConvergenceWriter struct {
	// Spawner is the Agent's start-only process boundary. Production passes
	// node.ExecRunner; tests pass a fixture that records the argv.
	Spawner node.Spawner
}

// NewConvergenceWriter wires the production writer.
func NewConvergenceWriter() *ConvergenceWriter {
	return &ConvergenceWriter{Spawner: node.ExecRunner{}}
}

// ConvergeHandoffConfig validates the claim again (the Agent validated it
// before asking) and enqueues exactly one unit. A refusal here is returned to
// the Agent, which logs it and keeps the claim; it never fails startup.
//
// The spawn runs on a context detached from the caller's cancellation: the call
// returns, the caller's `defer cancel()` fires, and the systemd-run helper must
// still be alive to submit its job. Nothing after the spawn waits on ctx, so no
// cancellation bound is lost by detaching — the helper is short-lived (it
// submits one transient unit) and systemd owns the unit's lifetime.
func (w *ConvergenceWriter) ConvergeHandoffConfig(ctx context.Context, claim node.HandoffClaim) error {
	if w == nil || w.Spawner == nil {
		return errors.New("HANDOFF_CONVERGE_UNAVAILABLE")
	}
	argv, err := BuildConvergeArgv(claim.OperationID, claim.NewSHA256)
	if err != nil {
		return err
	}
	return w.spawn(ctx, argv)
}

// spawn starts the fixed argv on a context detached from the caller's
// cancellation. It is the one place the detach lives, so the rule is testable
// with the real process boundary (see TestConvergeSpawnOutlivesCallerCancel):
// a fake spawner cannot observe a SIGKILL that only exec.CommandContext
// performs.
func (w *ConvergenceWriter) spawn(ctx context.Context, argv []string) error {
	if len(argv) < 1 {
		return fail("HANDOFF_CONVERGE_START_FAILED", "the convergence argv is empty")
	}
	if _, err := w.Spawner.Spawn(context.WithoutCancel(ctx), argv[0], argv[1:]...); err != nil {
		return fail("HANDOFF_CONVERGE_START_FAILED", "systemd did not accept the convergence unit; the claim is kept for the next repair")
	}
	return nil
}

// The production writer must keep the node-side contract.
var _ node.HandoffConvergenceWriter = (*ConvergenceWriter)(nil)
