package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// reconcileHandoff advances a running marker from the updater's result file
// (the Agent is the marker's only writer) and applies D2's ownerless rule. The
// result file's exit code and phase are process signals only: they are recorded
// by the phase transition, never interpreted as "applied".
func (r *Runtime) reconcileHandoff(handoff upgradeHandoff) (upgradeHandoff, error) {
	if handoff.State != handoffRunning {
		return handoff, nil
	}
	result, ok, err := r.readHandoffResult(handoff.OperationID)
	if err != nil {
		// A result the updater wrote but the Agent cannot validate is a local
		// failure, not a reason to leave the node wedged in "running". The
		// failed marker still blocks this chain and is clearable by a new one.
		handoff.State = handoffFailed
		handoff.ErrorCode = errorCodeOr(err, "UPDATE_RESULT_INVALID")
		handoff.ChildPID = 0
		if writeErr := r.writeUpgradeHandoff(handoff); writeErr != nil {
			return handoff, writeErr
		}
		return handoff, err
	}
	if ok {
		if result.Target != handoff.TargetVersion {
			handoff.State = handoffFailed
			handoff.ErrorCode = "UPDATE_RESULT_MISMATCH"
			handoff.ChildPID = 0
			if writeErr := r.writeUpgradeHandoff(handoff); writeErr != nil {
				return handoff, writeErr
			}
			return handoff, errors.New("UPDATE_RESULT_MISMATCH")
		}
		if next, _ := handoffPhaseRank(result.Phase); next > phaseRank(handoff.Phase) {
			handoff.Phase = result.Phase
			if err := r.writeUpgradeHandoff(handoff); err != nil {
				return handoff, err
			}
		}
	}
	if r.handoffOrphaned(handoff) {
		handoff.State = handoffFailed
		handoff.ErrorCode = handoffOrphanedErrorCode
		handoff.ChildPID = 0
		if err := r.writeUpgradeHandoff(handoff); err != nil {
			return handoff, err
		}
	}
	return handoff, nil
}

func phaseRank(phase string) int {
	rank, _ := handoffPhaseRank(phase)
	return rank
}

// handoffOrphaned is the local 30-minute rule (D2): no Hub query, no guessing
// about a chain that has disappeared. The age bound alone is not enough while
// the unit is still running; an active unit is the live owner of the attempt.
func (r *Runtime) handoffOrphaned(handoff upgradeHandoff) bool {
	if r.now().Sub(time.Unix(handoff.StartedAt, 0)) <= upgradeHandoffMaxAge {
		return false
	}
	state, _, err := r.handoffUnitState(handoff.OperationID)
	if err != nil {
		// Unobservable and over age: the owner cannot be proven alive.
		return true
	}
	return !handoffUnitRunning(state)
}

// handoffInFlight reports whether the marker still describes a running update.
// The updater helper's PID is no longer load-bearing: the transient unit and
// its result file are. Intent for the age bound is explicit: a unit that is
// still active owns the attempt and keeps it in flight even past 30 minutes
// (reconcileHandoff only fails an ownerless attempt); the age bound decides only
// when the unit cannot be observed or has not appeared yet (the updater helper
// may still be fetching). A finished unit with a result record is over — the
// caller fails the chain because the old release is still running.
func (r *Runtime) handoffInFlight(handoff upgradeHandoff) bool {
	if handoff.State != handoffRunning {
		return false
	}
	state, _, err := r.handoffUnitState(handoff.OperationID)
	overAge := r.now().Sub(time.Unix(handoff.StartedAt, 0)) > upgradeHandoffMaxAge
	if err != nil {
		// Unobservable: the local age bound is the only safe verdict.
		return !overAge
	}
	if handoffUnitRunning(state) {
		return true
	}
	if overAge {
		// Defensive: reconcileHandoff has already turned this ownerless
		// attempt into the failed/UPGRADE_HANDOFF_ORPHANED state.
		return false
	}
	if _, ok, err := r.readHandoffResult(handoff.OperationID); err == nil && ok {
		return false
	}
	return true
}

// pendingUpgradeHandoff returns the marker that still governs this node, or
// (zero, false, nil) when none does. A marker whose target is already the
// running release means the install reached the running build: the handoff no
// longer gates the chain, and this is never an applied claim (readback remains
// the anchor). The marker itself is cleared only after the on-disk pair
// readback passes; an in-memory adoption (old agent.json, new binary) keeps the
// marker and claim for the outside convergence writer / next repair while
// still letting apply and readback run against the running target.
func (r *Runtime) pendingUpgradeHandoff() (upgradeHandoff, bool, error) {
	handoff, ok, err := r.readUpgradeHandoff()
	if err != nil || !ok {
		return upgradeHandoff{}, false, err
	}
	if handoff.TargetVersion == r.cfg.AgentVersion {
		if r.handoffPairConverged() {
			if err := r.clearUpgradeHandoff(); err != nil {
				return upgradeHandoff{}, false, err
			}
			if err := r.clearUpgradeClaim(); err != nil {
				return upgradeHandoff{}, false, err
			}
		}
		return upgradeHandoff{}, false, nil
	}
	return handoff, true, nil
}

// reconcileHandoffOnBoot is the startup half of the recovery rules (spec §4.2
// amended, §4.6), called by NewRuntime before journal recovery. It never claims
// the upgrade applied: when the running release is the target it only releases
// the gate so the chain's readback step can prove the result. A corrupt marker
// is a terminal refusal. An in-memory claim adoption never fails startup and
// never clears the claim: convergence happens outside this sandbox.
func (r *Runtime) reconcileHandoffOnBoot() error {
	handoff, ok, err := r.readUpgradeHandoff()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if !ok {
		// A claim can outlive its marker (a completed or repaired handoff).
		// Settle it only by the on-disk pair readback; never invent a marker.
		r.settleHandoffClaim(ctx)
		return nil
	}
	if handoff.State == handoffRunning && handoff.TargetVersion == r.cfg.AgentVersion {
		if r.handoffPairConverged() {
			if err := r.clearUpgradeHandoff(); err != nil {
				return err
			}
			r.settleHandoffClaim(ctx)
			return nil
		}
		// The target is running but agent.json still names the old binary:
		// this is the in-memory adoption branch. Ask an outside-sandbox
		// writer once, if one is wired, then re-read the pair. A missing
		// writer keeps both records for the next install --repair.
		r.settleHandoffClaim(ctx)
		if r.handoffPairConverged() {
			if err := r.clearUpgradeHandoff(); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := r.reconcileHandoff(handoff); err != nil {
		// A corrupt updater result must not prevent the Agent from starting;
		// the marker has already been moved to failed where possible, and the
		// chain gate reports the stable code.
		r.logger.ErrorContext(ctx, "upgrade handoff result rejected on boot",
			"operation_id", handoff.OperationID, "error_code", errorCode(err))
		return nil
	}
	// A failed marker is intentionally left in place: only a later chain's
	// stage step may clear it (D2), and this Agent has just started with no
	// chain to resolve it.
	return nil
}

// upgradeQueuedReceipt is the stage step's non-terminal receipt: a legal
// "applying" result that says the handoff is queued, never that it was applied.
// The detail is stable across polls, so the Hub's in-place result check treats
// a redelivery as the same receipt.
func upgradeQueuedReceipt(operationID, target string) protocol.TaskResult {
	data, err := json.Marshal(struct {
		State  string `json:"state"`
		Target string `json:"target"`
	}{State: "queued", Target: target})
	if err != nil {
		data = []byte(`{"state":"queued"}`)
	}
	return protocol.TaskResult{OperationID: operationID, Status: "applying", Detail: string(data)}
}

// handoffGate is the apply/readback gate. It returns (receipt, true, nil) while
// an update is in flight: the caller must report that receipt (a legal
// non-terminal "applying", no detail) and must not touch the data plane. A
// marker that already failed returns its recorded terminal code, so the rest of
// that chain ends honestly instead of applying the old release.
// (receipt, false, nil) means no handoff governs this node and the step may run
// normally.
func (r *Runtime) handoffGate(ctx context.Context, operationID string) (protocol.TaskResult, bool, error) {
	result := protocol.TaskResult{OperationID: operationID, Status: "failed"}
	handoff, pending, err := r.pendingUpgradeHandoff()
	if err != nil {
		return failedResult(result, errorCode(err)), true, err
	}
	if !pending {
		return protocol.TaskResult{}, false, nil
	}
	handoff, err = r.reconcileHandoff(handoff)
	if err != nil {
		return failedResult(result, errorCode(err)), true, err
	}
	if r.handoffInFlight(handoff) {
		// "applying" is the only legal non-terminal result for a config step
		// that is waiting on the update. The detail stays empty: a step that has
		// not run must not name a target or a result, and the cycle pre-reports
		// the apply step with an empty detail too.
		return protocol.TaskResult{OperationID: operationID, Status: "applying"}, true, nil
	}
	if err := r.failUpgradeHandoff(handoff); err != nil {
		return failedResult(result, errorCode(err)), true, err
	}
	receipt, receiptErr := r.handoffFailureReceipt(ctx, operationID, handoff)
	return receipt, true, receiptErr
}

func handoffFailureCode(handoff upgradeHandoff) string {
	if handoff.ErrorCode != "" {
		return handoff.ErrorCode
	}
	return handoffIncompleteCode
}

// failUpgradeHandoff records that the owner chain is gone without installing
// the target. The marker stays in the failed state until a later chain's stage
// step claims the node, so the remaining steps of this chain fail with the same
// stable code instead of applying the old release. The phase is frozen at the
// endpoint the attempt reached.
func (r *Runtime) failUpgradeHandoff(handoff upgradeHandoff) error {
	if handoff.State == handoffFailed {
		return nil
	}
	handoff.State = handoffFailed
	handoff.ErrorCode = handoffIncompleteCode
	handoff.ChildPID = 0
	return r.writeUpgradeHandoff(handoff)
}

// preLockHandoffGate answers the upgrade gate without the runtime lock. Only a
// non-terminal answer (the install is in flight) takes this early path; a
// terminal gate answer falls through to the locked path so it is cached and
// replayed like every other final result. The cheap preconditions are the same
// ones the locked path would check first, so a malformed, stale or already
// answered task still gets its ordinary result.
func (r *Runtime) preLockHandoffGate(ctx context.Context, task protocol.Task) (protocol.TaskResult, bool) {
	if task.Kind != protocol.KindConfigApply && task.Kind != protocol.KindConfigReadback {
		return protocol.TaskResult{}, false
	}
	if err := protocol.ValidateTask(task); err != nil || task.NodeID != r.cfg.NodeID {
		return protocol.TaskResult{}, false
	}
	revision, err := taskRevision(task)
	if err != nil {
		return protocol.TaskResult{}, false
	}
	state, err := r.loadStateForExecution()
	if err != nil || revision <= state.LastTaskRevision {
		return protocol.TaskResult{}, false
	}
	if _, ok := state.Idempotency[task.IdempotencyKey]; ok {
		return protocol.TaskResult{}, false
	}
	for _, item := range state.Idempotency {
		if item.OperationID == task.OperationID {
			return protocol.TaskResult{}, false
		}
	}
	if task.Kind == protocol.KindConfigApply && state.Journal != nil {
		return protocol.TaskResult{}, false
	}
	result, stop, _ := r.handoffGate(ctx, task.OperationID)
	if !stop || terminalTaskResult(result.Status) {
		return protocol.TaskResult{}, false
	}
	return result, true
}
