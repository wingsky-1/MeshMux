package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// UpgradeConfirmer is the rollback-store half of the health-gated finalize
// (spec §4.6). Implementations live where the store lives: the updater owns
// upgrade-backups/<op>/record.json and update.GCBackups, while this package
// cannot import it (the updater imports node). The Agent passes the exact
// anchors its accepted readback proved.
//
// # Contract (11c-3 review ruling, binding for Task 4)
//
//  1. Idempotent: confirming an already-confirmed record is a no-op, and the
//     N-1 GC (update.GCBackups(root, backupKeepConfirmed)) runs after the
//     confirm write, never before it.
//  2. It MUST refuse a record already marked failed. A failed upgrade that was
//     reverted is not confirmed by a later readback of the release it was
//     reverted to; confirming it would release the very pointer the revert
//     depends on.
//  3. It MUST verify the running binary against the record: agentSHA256 (the
//     digest the accepted readback proved) must equal record.PackageSHA256,
//     together with record.TargetVersion == targetVersion and
//     record.State == staged. A mismatch is a refusal, never a rewrite.
//  4. After a successful revert the implementation MUST clear the operation's
//     stale <operation_id>.result.json, because that file is the Agent's
//     confirmation anchor (upgradeConfirmationCandidate) and would otherwise
//     outlive the attempt it describes.
//
// Task 4 MAY touch internal/node narrowly for the revert trigger call only; it
// must not reshape the marker, the frozen 11c-2 result schema or this contract.
type UpgradeConfirmer interface {
	ConfirmVersion(ctx context.Context, operationID, targetVersion, agentSHA256 string) error
}

// WithUpgradeConfirmation wires the rollback-store confirmer. Nil keeps the
// readback side effect unavailable: nothing is confirmed and no pointer is
// released to GC, and the Agent logs UPDATE_CONFIRM_UNAVAILABLE on each
// accepted readback instead of pretending the finalize happened.
func WithUpgradeConfirmation(confirmer UpgradeConfirmer) RunOption {
	return func(opts *RuntimeOptions) { opts.UpgradeConfirmation = confirmer }
}

// UpgradeReverter is the transient revert executor of a failed upgrade (spec
// §4.7/§4.17, Task 4). The updater owns the fixed argv and the store, so the
// Agent only awaits this contract:
//
//   - done=true means the revert has a finished verdict (or there is nothing
//     to revert). The caller then reads <operation_id>.revert.json, exactly as
//     Task 3 froze it.
//   - done=false means the unit is still running. The caller MUST return a
//     non-terminal receipt and must never cache a failed verdict: Execute
//     replays the first terminal result, so an asynchronous revert could never
//     be reported and the chain would end with a half-restored change set.
type UpgradeReverter interface {
	RevertOperation(ctx context.Context, operationID string) (done bool, err error)
}

// WithUpgradeRevert wires the transient revert executor. Nil keeps Task 3's
// behaviour: the failed attempt reports the honest handoff failure and no
// revert is attempted.
func WithUpgradeRevert(reverter UpgradeReverter) RunOption {
	return func(opts *RuntimeOptions) { opts.UpgradeRevert = reverter }
}

// finalizeUpgradeReadback is the ONLY finalize side effect (spec §4.6). It is
// not a parallel verdict: the healthy readback above is the verdict, and this
// runs only after it was accepted. Two jobs, in order:
//
//  1. finish the marker this chain left behind: `verifying` is this step's
//     frozen phase (spec §4.16), and the marker is cleared only when the
//     on-disk binary/config pair is proven — 11c-2 still owns that condition.
//     A marker whose pair is not converged is retained at `verifying` for the
//     next repair;
//  2. ask the rollback store to confirm the operation's record and release
//     older generations to GC (keep N-1).
//
// Confirmation is best effort: the upgrade is already applied, so a store
// failure is logged and retried by the next accepted readback instead of
// flipping an applied upgrade to failed.
func (r *Runtime) finalizeUpgradeReadback(ctx context.Context, readback Readback) {
	if readback.AgentVersion != r.cfg.AgentVersion || readback.AgentSHA256 != r.cfg.AgentSHA256 {
		return
	}
	r.advanceVerifiedHandoff(ctx, readback.AgentVersion)
	candidate, ok := r.upgradeConfirmationCandidate(readback)
	if !ok {
		return
	}
	if r.upgradeConfirmation == nil {
		r.logger.WarnContext(ctx, "upgrade confirmation unavailable",
			"operation_id", candidate.OperationID, "error_code", upgradeConfirmUnavailableCode)
		return
	}
	if err := r.upgradeConfirmation.ConfirmVersion(ctx, candidate.OperationID, candidate.Target, candidate.Digest); err != nil {
		r.logger.WarnContext(ctx, "upgrade confirmation failed",
			"operation_id", candidate.OperationID, "error_code", errorCodeOr(err, upgradeConfirmFailedCode))
		return
	}
	r.logger.InfoContext(ctx, "upgrade confirmed",
		"operation_id", candidate.OperationID, "target_version", candidate.Target)
}

// advanceVerifiedHandoff moves a marker that this accepted readback governs to
// the readback step's frozen phase, and finishes it once the pair is proven.
// The Agent is the marker's only writer, and a failed marker never advances.
// Everything here is progress bookkeeping: an unreadable or unwritable marker is
// logged by the caller and never fails accepted evidence. The claim has its own
// single owner (settleHandoffClaim, called immediately before this).
func (r *Runtime) advanceVerifiedHandoff(ctx context.Context, runningVersion string) {
	handoff, ok, err := r.readUpgradeHandoff()
	if err != nil || !ok || handoff.State != handoffRunning || handoff.TargetVersion != runningVersion {
		return
	}
	if r.handoffPairConverged() {
		if clearErr := r.clearUpgradeHandoff(); clearErr != nil {
			r.logger.WarnContext(ctx, "completed upgrade marker could not be cleared",
				"operation_id", handoff.OperationID, "error_code", errorCode(clearErr))
		}
		return
	}
	if phaseRank(handoff.Phase) >= phaseRank(handoffPhaseVerifying) {
		return
	}
	handoff.Phase = handoffPhaseVerifying
	if writeErr := r.writeUpgradeHandoff(handoff); writeErr != nil {
		r.logger.WarnContext(ctx, "upgrade marker phase not advanced",
			"operation_id", handoff.OperationID, "error_code", errorCode(writeErr))
	}
}

// upgradeConfirmationCandidate resolves the upgrade operation this readback
// proves. Two sources, most precise first:
//
//  1. a surviving marker whose target is the running release names the
//     operation exactly;
//  2. otherwise the 11c-2 <operation_id>.result.json is the durable link: the
//     marker is cleared as soon as the target runs, while the updater's record
//     stays next to the staged package.
//
// Either way the record must match all three anchors the readback proved —
// target release, approved package digest and a successful install — so a
// hand-edited version string can never release a rollback pointer (spec §4.6
// "binary/config/version 对上"). When scanning, the newest matching record wins
// and equal timestamps break on the operation ID, so the choice is
// deterministic.
func (r *Runtime) upgradeConfirmationCandidate(readback Readback) (handoffResult, bool) {
	if readback.AgentVersion != r.cfg.AgentVersion || readback.AgentSHA256 != r.cfg.AgentSHA256 {
		return handoffResult{}, false
	}
	if handoff, ok, err := r.readUpgradeHandoff(); err == nil && ok &&
		handoff.TargetVersion == readback.AgentVersion {
		if result, ok, err := r.readHandoffResult(handoff.OperationID); err == nil && ok &&
			confirmationAnchorsMatch(result, readback) {
			return result, true
		}
	}
	entries, err := os.ReadDir(rooted(r.root, upgradeHandoffResultDir))
	if err != nil {
		return handoffResult{}, false
	}
	var best handoffResult
	found := false
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, upgradeHandoffResultSuffix) ||
			len(name) != 32+len(upgradeHandoffResultSuffix) {
			continue
		}
		operationID := strings.TrimSuffix(name, upgradeHandoffResultSuffix)
		if !protocol.ValidID(operationID) {
			continue
		}
		if scanned++; scanned > upgradeResultScanMax {
			break
		}
		result, ok, readErr := r.readHandoffResult(operationID)
		if readErr != nil || !ok || !confirmationAnchorsMatch(result, readback) {
			continue
		}
		if !found || result.Timestamp > best.Timestamp ||
			result.Timestamp == best.Timestamp && result.OperationID < best.OperationID {
			best, found = result, true
		}
	}
	return best, found
}

// confirmationAnchorsMatch is the evidence test of the finalize side effect:
// the record must name the release the readback proved, the exact package digest
// the running binary hashes to, and a completed install. A staged or installing
// record proves nothing about what runs.
func confirmationAnchorsMatch(result handoffResult, readback Readback) bool {
	return result.Target == readback.AgentVersion &&
		result.Digest == readback.AgentSHA256 &&
		result.Phase == handoffPhaseInstalledAwaitingRestart &&
		result.ExitCode == 0
}

// handoffFailureReceipt reports what actually happened to one ended attempt.
// When the transient revert executor recorded an outcome for this operation
// (Task 4), the receipt says so: a restored change set keeps the attempt's
// stable code and carries the restored release in its detail, and a failed
// revert is terminal with the revert's own stable code plus the manual-action
// guidance — it is never retried. A missing or invalid revert record never
// invents a verdict; the honest handoff failure stands.
//
// The status stays "failed" even after a successful revert. The Hub's frozen
// result machine only accepts rolled_back from "applying", and a gated
// apply/readback row (or a stage row whose queued receipt never reached the Hub)
// is still "pending"; reporting rolled_back there is refused with
// TASK_STATE_INVALID, which the Agent cannot resolve and would retry forever.
// The revert outcome therefore travels in the detail, and the Hub keeps its
// one-way state machine.
//
// # Ordering ruling for the Task 4 trigger (11c-3 review, binding)
//
// Task 4 may add the revert trigger here (a narrow internal/node touch is
// allowed for that call only), but the revert must FINISH before this receipt is
// returned: Execute caches and replays the first terminal result, so a revert
// that lands asynchronously can never be reported. The trigger is therefore
// spawn-and-await over a fixed argv (the transient revert unit), and only its
// finished outcome — the <operation_id>.revert.json read below — decides the
// receipt. A still-running revert is not a verdict: it must not be cached as
// failed, or the chain would end while the change set is half restored.
func (r *Runtime) handoffFailureReceipt(ctx context.Context, operationID string, handoff upgradeHandoff) (protocol.TaskResult, error) {
	code := handoffFailureCode(handoff)
	failed := protocol.TaskResult{OperationID: operationID, Status: "failed"}
	// The revert must FINISH before this receipt is built: Execute caches and
	// replays the first terminal result, so a revert that lands asynchronously
	// could never be reported. A still-running unit is not a verdict — return
	// the legal non-terminal receipt and let the next poll read the outcome.
	if r.upgradeRevert != nil {
		done, revertErr := r.upgradeRevert.RevertOperation(ctx, handoff.OperationID)
		if revertErr != nil {
			r.logger.WarnContext(ctx, "upgrade revert unavailable",
				"operation_id", handoff.OperationID, "error_code", errorCodeOr(revertErr, upgradeRevertUnavailableCode))
		}
		if !done {
			return protocol.TaskResult{OperationID: operationID, Status: "applying"}, nil
		}
	}
	revert, ok, err := r.readUpgradeRevert(handoff.OperationID)
	if err == nil && ok {
		switch revert.Outcome {
		case upgradeRevertRolledBack:
			result := failedResult(failed, code)
			result.Detail = revertDetail(upgradeRevertRolledBack, revert.FromVersion, "", "")
			return result, fmt.Errorf("%s: the update failed and the change set was restored to %s", code, revert.FromVersion)
		case upgradeRevertFailed:
			result := failedResult(failed, revert.ErrorCode)
			result.Detail = revertDetail(upgradeRevertFailed, "", code, upgradeRevertManualAction)
			return result, fmt.Errorf("%s: the revert did not restore the change set; manual action is required", revert.ErrorCode)
		}
	} else if err != nil {
		r.logger.Warn("revert result rejected",
			"operation_id", handoff.OperationID, "error_code", errorCode(err))
	}
	return failedResult(failed, code),
		fmt.Errorf("%s: the update unit finished without installing the target", code)
}

// revertDetail is the bounded, stable detail of a terminal upgrade receipt that
// has a recorded revert outcome. It is metadata only: no path, no secret and no
// claim of success. cause carries the attempt's stable code when the revert
// itself failed, so the receipt names both the original failure and the failure
// to undo it. action is a fixed-vocabulary operator hint: Execute discards the
// returned error once a stable code is set, so the hint must live in the receipt
// or it evaporates.
func revertDetail(outcome, restoredVersion, cause, action string) string {
	detail := struct {
		Revert   string `json:"revert"`
		Restored string `json:"restored,omitempty"`
		Cause    string `json:"cause,omitempty"`
		Action   string `json:"action,omitempty"`
	}{Revert: outcome, Restored: restoredVersion, Cause: cause, Action: action}
	data, err := json.Marshal(detail)
	if err != nil {
		return ""
	}
	return boundedDetail(data)
}

// upgradeRevertResult is the SEPARATE <operation_id>.revert.json schema
// (spec §4.16 choice): the 11c-2 install result is frozen at its three phases
// and its writer is the install unit, while a revert is a different verdict
// written by a different transient executor (Task 4). Keeping it in its own
// versioned file leaves the frozen schema byte-identical and lets the Agent
// read both outcomes from the same fixed private directory.
type upgradeRevertResult struct {
	Schema        string `json:"schema"`
	OperationID   string `json:"operation_id"`
	TargetVersion string `json:"target_version"`
	FromVersion   string `json:"from_version"`
	Outcome       string `json:"outcome"`
	ExitCode      int    `json:"exit_code"`
	ErrorCode     string `json:"error_code,omitempty"`
	Timestamp     int64  `json:"ts"`
}

// readUpgradeRevert reads one revert outcome under the same strict, private
// rules as every other Agent-side record: the name must derive from the
// operation, the mode/owner must be 0600/euid, unknown fields and trailing data
// are corruption, and the outcome must be one of the two frozen verdicts. A
// rolled_back outcome carries no error code of its own (the attempt's failure
// code is reported); a failed outcome must name its stable reason.
func (r *Runtime) readUpgradeRevert(operationID string) (upgradeRevertResult, bool, error) {
	if !protocol.ValidID(operationID) {
		return upgradeRevertResult{}, false, errors.New("OPERATION_ID_INVALID")
	}
	path := rooted(r.root, filepath.Join(upgradeHandoffResultDir, operationID+upgradeRevertSuffix))
	data, _, err := readPrivateFileLimited(path, upgradeRevertMaxBytes)
	if os.IsNotExist(err) {
		return upgradeRevertResult{}, false, nil
	}
	if err != nil {
		return upgradeRevertResult{}, false, errors.New("UPDATE_REVERT_RESULT_INVALID")
	}
	var result upgradeRevertResult
	if decodeStrictJSON(data, &result) != nil ||
		result.Schema != upgradeRevertSchema || result.OperationID != operationID ||
		!protocol.ValidSemVer(result.TargetVersion) ||
		!protocol.ValidSemVer(result.FromVersion) ||
		result.ExitCode < 0 || result.ExitCode > 255 || result.Timestamp < 1 {
		return upgradeRevertResult{}, false, errors.New("UPDATE_REVERT_RESULT_INVALID")
	}
	switch result.Outcome {
	case upgradeRevertRolledBack:
		if result.ErrorCode != "" {
			return upgradeRevertResult{}, false, errors.New("UPDATE_REVERT_RESULT_INVALID")
		}
	case upgradeRevertFailed:
		if !protocol.ValidErrorCode(result.ErrorCode) {
			return upgradeRevertResult{}, false, errors.New("UPDATE_REVERT_RESULT_INVALID")
		}
	default:
		return upgradeRevertResult{}, false, errors.New("UPDATE_REVERT_RESULT_INVALID")
	}
	return result, true, nil
}
