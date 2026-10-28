package agent

import (
	"context"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/client"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// Run heartbeats and drains tasks. Control-plane failures are logged and
// retried without touching an active data plane.
func (r *Runtime) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	r.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.cycle(ctx)
		}
	}
}

func (r *Runtime) cycle(ctx context.Context) {
	heartbeat := protocol.HeartbeatRequest{AgentVersion: r.cfg.AgentVersion, KernelVersion: KernelVersion}
	if err := heartbeat.Validate(); err != nil {
		r.logger.ErrorContext(ctx, "heartbeat invalid", "error_code", errorCode(err))
		return
	}
	if err := r.controller.Heartbeat(ctx, heartbeat); err != nil {
		r.logger.WarnContext(ctx, "heartbeat unavailable", "error_code", "CONTROL_PLANE_UNAVAILABLE")
	}
	// A journal left by a degraded startup or a failed in-process restore is
	// retried here, with the shared lock, before any task can reach the data
	// plane. A settled recovery is saved and its receipt joins the outbox that
	// replayResults drains below.
	r.retryJournalRecovery(ctx)
	if err := r.replayResults(ctx); err != nil {
		r.logger.WarnContext(ctx, "result replay unavailable", "error_code", errorCode(err))
		return
	}
	tasks, err := r.controller.Tasks(ctx)
	if err != nil {
		r.logger.WarnContext(ctx, "task poll unavailable", "error_code", "CONTROL_PLANE_UNAVAILABLE")
		return
	}
	for _, task := range tasks {
		if ctx.Err() != nil {
			return
		}
		var result protocol.TaskResult
		if task.Kind == protocol.KindConfigApply {
			if cached, ok := r.cachedTaskResult(task); ok {
				if reportErr := r.controller.Report(ctx, cached); reportErr != nil {
					if isAlreadyFinal(reportErr) {
						_ = r.removeOutbox(task.OperationID)
						continue
					}
					return
				}
				_ = r.removeOutbox(task.OperationID)
				continue
			}
			// While an upgrade handoff is in flight the apply step must not even
			// announce progress: the "applying" pre-report implies the data plane
			// is being changed. Execute still runs because it owns the gate
			// receipt and persists a terminal gate failure.
			if _, stop, _ := r.handoffGate(ctx, task.OperationID); stop {
				result = r.Execute(withApplyAcknowledged(ctx), task)
			} else {
				if reportErr := r.controller.Report(ctx, protocol.TaskResult{
					OperationID: task.OperationID, Status: "applying",
				}); reportErr != nil {
					if isAlreadyFinal(reportErr) {
						_ = r.removeOutbox(task.OperationID)
					}
					return
				}
				result = r.Execute(withApplyAcknowledged(ctx), task)
			}
		} else {
			result = r.Execute(ctx, task)
		}
		if result.ErrorCode == "RUNTIME_BUSY" {
			// The shared lock belongs to an install/repair. Reporting a failure
			// would end the chain over a transient condition, so skip this
			// cycle: the task is redelivered on the next poll, and this
			// cycle's heartbeat already went out above (spec §4.9).
			r.logger.WarnContext(ctx, "runtime busy; retry next poll",
				"operation_id", task.OperationID, "error_code", "RUNTIME_BUSY")
			return
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			result = failedResult(result, "RESULT_INVALID")
		}
		if err := r.controller.Report(ctx, result); err != nil {
			r.logger.WarnContext(ctx, "task report deferred",
				"operation_id", task.OperationID, "error_code", "RESULT_REPORT_UNAVAILABLE")
			if isAlreadyFinal(err) {
				_ = r.removeOutbox(task.OperationID)
				continue
			}
			return
		}
		if terminalTaskResult(result.Status) {
			_ = r.removeOutbox(task.OperationID)
		}
	}
}

// retryJournalRecovery is the poll-cycle half of the degraded startup. While
// the journal survives, check/stage/apply keep answering RECOVERY_REQUIRED (the
// existing guard); this retries the restore with the shared lock so the node can
// leave that state without a restart. A settled recovery is persisted before
// replayResults runs, so its rolled_back receipt is drained in the same cycle.
// The retry is bounded: once the startup-transient budget is spent, the journal
// is retired with the partial receipt the failed attempt already recorded, and
// the next chain can repair the node instead of being refused forever.
func (r *Runtime) retryJournalRecovery(ctx context.Context) {
	state, err := r.loadStateForExecution()
	if err != nil || state.Journal == nil {
		return
	}
	operationID := state.Journal.OperationID
	if operationID != r.journalRecoveryOperation {
		r.journalRecoveryOperation = operationID
		r.journalRecoveryAttempts = 0
	}
	if r.journalRecoveryAttempts >= journalRecoveryRetryLimit {
		state.Journal = nil
		if err := r.saveState(&state); err != nil {
			r.logger.WarnContext(ctx, "journal recovery convergence not persisted",
				"operation_id", operationID, "error_code", statePersistCode(err))
			return
		}
		r.logger.ErrorContext(ctx, "journal recovery converged without a proved restore",
			"operation_id", operationID, "error_code", "RECOVERY_REQUIRED")
		return
	}
	lock, err := acquireRuntimeLock(ctx, r.root, true, r.lockTimeout)
	if err != nil {
		if ctx.Err() == nil {
			r.logger.WarnContext(ctx, "journal recovery deferred",
				"operation_id", operationID, "error_code", errorCode(err))
		}
		return
	}
	defer lock.Close()
	// The state may have changed while waiting for the lock; only the journal
	// this retry budget belongs to is processed.
	state, err = r.loadStateForExecution()
	if err != nil || state.Journal == nil {
		return
	}
	if state.Journal.OperationID != operationID {
		r.journalRecoveryOperation = state.Journal.OperationID
		r.journalRecoveryAttempts = 0
		return
	}
	r.journalRecoveryAttempts++
	recoveryCtx, cancel := context.WithTimeout(ctx, journalRecoveryTimeout)
	retryable, recoveryErr := r.recoverJournal(recoveryCtx, &state)
	cancel()
	if ctx.Err() != nil {
		// The process is stopping mid-attempt. The disk still carries the
		// journal, so the next start settles it; nothing this attempt concluded
		// is persisted or reported.
		return
	}
	if recoveryErr != nil {
		r.logger.WarnContext(ctx, "journal recovery retry failed",
			"operation_id", operationID, "error_code", errorCode(recoveryErr),
			"recovery_required", retryable)
	}
	if err := r.saveState(&state); err != nil {
		r.logger.WarnContext(ctx, "journal recovery state not persisted",
			"operation_id", operationID, "error_code", statePersistCode(err))
		return
	}
	if recoveryErr == nil {
		r.journalRecoveryAttempts = 0
		r.logger.InfoContext(ctx, "journal recovery settled", "operation_id", operationID)
	}
}

func (r *Runtime) replayResults(ctx context.Context) error {
	state, err := r.loadStateForExecution()
	if err != nil {
		return err
	}
	for operationID, result := range state.FinalResults {
		if err = r.controller.Report(ctx, result); err != nil {
			if isAlreadyFinal(err) {
				r.logger.WarnContext(ctx, "report result already final",
					"operation_id", operationID, "error_code", "TASK_ALREADY_FINAL")
				delete(state.FinalResults, operationID)
				if err = r.saveState(&state); err != nil {
					return err
				}
				continue
			}
			return err
		}
		delete(state.FinalResults, operationID)
		if err = r.saveState(&state); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) removeOutbox(operationID string) error {
	state, err := r.loadStateForExecution()
	if err != nil {
		return err
	}
	delete(state.FinalResults, operationID)
	return r.saveState(&state)
}

func isAlreadyFinal(err error) bool {
	var clientErr *client.ClientError
	return errors.As(err, &clientErr) && clientErr.Code == "TASK_ALREADY_FINAL"
}
