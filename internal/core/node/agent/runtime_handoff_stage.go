package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// stageOrHandOff runs the config.stage step of one task chain. A row stamped
// with an upgrade target that differs from the running version is not a local
// stage at all: the Agent starts the local update with the fixed argv and
// reports a non-terminal handoff receipt at once. Every other row keeps the
// existing stage path.
//
// The child is never waited for. The poll interval is 1s, so blocking here
// would stop the heartbeat and make a live node look offline for the length of
// an install. The handoff is recorded in the persisted marker before the child
// exists, and the stage row stays "applying" until the marker resolves, so the
// Hub keeps the whole chain open: apply and readback are gated (see
// handoffGate) and TASKS_IN_PROGRESS refuses a second approval.
//
// The update writes its verified rollback record to
// upgrade-backups/<operation_id>/record.json before it mutates anything
// (TestHandoffBacksUpBeforeMutating), so the rollback source exists regardless
// of how the handoff ends. The Agent never reads the child's Result; the
// separate <operation_id>.revert.json is the revert outcome it reads.
func (r *Runtime) stageOrHandOff(ctx context.Context, task protocol.Task, revision int64) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	handoff, pending, err := r.pendingUpgradeHandoff()
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if pending {
		// Advance the Agent-owned phase from the updater's result file and
		// apply the local 30-minute orphan rule before deciding who owns the
		// node. A marker that is already failed is never advanced again.
		handoff, err = r.reconcileHandoff(handoff)
		if err != nil {
			return failedResult(result, errorCode(err)), err
		}
	}
	if pending && handoff.OperationID == task.OperationID {
		if handoff.State == handoffFailed {
			return r.handoffFailureReceipt(ctx, task.OperationID, handoff)
		}
		if r.handoffInFlight(handoff) {
			// Redelivery while the install still runs: replay the same
			// non-terminal receipt and never start a second update.
			return upgradeQueuedReceipt(task.OperationID, handoff.TargetVersion), nil
		}
		// The owner chain is gone and the running release is still not the
		// target: the update did not install. Record the failure so the
		// remaining steps of this chain fail honestly, and fail this step.
		if err = r.failUpgradeHandoff(handoff); err != nil {
			return failedResult(result, errorCode(err)), err
		}
		return r.handoffFailureReceipt(ctx, task.OperationID, handoff)
	}
	if pending && handoff.State == handoffFailed {
		// A previous chain's upgrade failed. This new chain owns the node now:
		// drop the stale marker so its steps may run. The previous chain's own
		// rows are already terminal.
		if err = r.clearUpgradeHandoff(); err != nil {
			return failedResult(result, errorCode(err)), err
		}
		if err = r.clearUpgradeClaim(); err != nil {
			return failedResult(result, errorCode(err)), err
		}
	} else if pending {
		// A different chain is being installed. The Hub serializes chains, so
		// this is a contract violation; staging this row would let two installs
		// race. Refuse without touching anything.
		return failedResult(result, "UPDATE_HANDOFF_IN_PROGRESS"),
			errors.New("UPDATE_HANDOFF_IN_PROGRESS: another upgrade handoff owns this node")
	}
	target, stamped, err := r.stampedStageTarget(ctx, task)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if !stamped {
		return r.stage(ctx, revision)
	}
	spawner, ok := r.runner.(Spawner)
	if !ok {
		return failedResult(result, "UPDATE_SPAWN_UNAVAILABLE"), errors.New("UPDATE_SPAWN_UNAVAILABLE")
	}
	// The executable is the fixed installed Agent, never a caller-named path.
	// On a real root its digest is the configured one, so a swapped binary is
	// refused instead of started.
	binary, err := fixedBinary(r.root, AgentBinaryPath, r.cfg)
	if err != nil {
		return failedResult(result, errorCodeOr(err, "UPDATE_SPAWN_FAILED")), err
	}
	// The marker is written before the child exists, so a crash between the two
	// can never lose the gate that keeps apply off the data plane.
	record := upgradeHandoff{
		Schema:         upgradeHandoffSchema,
		State:          handoffRunning,
		Phase:          handoffPhaseStaged,
		OperationID:    task.OperationID,
		TargetVersion:  target.Version,
		ManifestSHA256: target.ManifestSHA256,
		Revision:       revision,
		StartedAt:      r.now().Unix(),
	}
	if err = r.writeUpgradeHandoff(record); err != nil {
		return failedResult(result, errorCode(err)), err
	}
	// The child outlives this poll cycle: a cancelled cycle (Agent shutdown,
	// task timeout) must not kill an update that is already installing. Its
	// lifetime is the update's own, not the poll's.
	pid, err := spawner.Spawn(context.WithoutCancel(ctx), binary,
		"__internal-update",
		"--target", target.Version,
		"--manifest-sha256", target.ManifestSHA256,
		"--operation-id", task.OperationID,
		"--confirm-target")
	if err != nil {
		// The update never started, so no install can be in flight: drop the
		// gate and fail the step. The node is not wedged.
		_ = r.clearUpgradeHandoff()
		return failedResult(result, "UPDATE_SPAWN_FAILED"), err
	}
	record.ChildPID = pid
	if err = r.writeUpgradeHandoff(record); err != nil {
		// The child is already running. The marker without its PID still gates
		// (by age), so keep going and log; refusing here would let apply run
		// against a version that is being replaced.
		r.logger.ErrorContext(ctx, "handoff marker pid not recorded",
			"operation_id", task.OperationID, "error_code", errorCode(err))
	}
	return upgradeQueuedReceipt(task.OperationID, target.Version), nil
}

// stampedStageTarget reports the upgrade target stamped onto this stage row and
// whether it is an upgrade at all. No source means the pre-upgrade behaviour: a
// plain config stage. A stamped target equal to the running version is the same
// chain's redelivery after the update installed it, so it is a plain stage too;
// treating it as a second upgrade would loop.
func (r *Runtime) stampedStageTarget(ctx context.Context, task protocol.Task) (StageTarget, bool, error) {
	if r.stageTargets == nil {
		return StageTarget{}, false, nil
	}
	target, ok, err := r.stageTargets.StageTarget(ctx, task.OperationID)
	if err != nil {
		return StageTarget{}, false, fmt.Errorf("STAGE_TARGET_UNAVAILABLE: %w", err)
	}
	if !ok {
		return StageTarget{}, false, nil
	}
	if !protocol.ValidSemVer(target.Version) || !protocol.ValidSHA256(target.ManifestSHA256) {
		return StageTarget{}, false, errors.New("STAGE_TARGET_INVALID: target must be a pinned SemVer release")
	}
	if target.Version == r.cfg.AgentVersion {
		return StageTarget{}, false, nil
	}
	return target, true, nil
}
