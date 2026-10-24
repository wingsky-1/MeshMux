package node

// Revert trigger ordering (#11c-3 Task 4, binding review carry).
//
// The failed attempt's terminal receipt is cached and replayed by Execute, so a
// revert that lands asynchronously can never be reported. The Agent therefore
// asks the injected reverter to finish the revert BEFORE handoffFailureReceipt
// builds its verdict: RevertOperation returns done=false only while the unit is
// still running, and that case must stay non-terminal (never cached as failed).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

// revertRecorder is the node-side half of the revert seam. The production
// implementation lives in the updater.
type revertRecorder struct {
	done     []bool
	calls    []string
	onCall   func(call int)
	doneFlag bool
	err      error
}

func (r *revertRecorder) RevertOperation(_ context.Context, operationID string) (bool, error) {
	r.calls = append(r.calls, operationID)
	if r.onCall != nil {
		r.onCall(len(r.calls))
	}
	if len(r.done) > 0 {
		done := r.done[0]
		r.done = r.done[1:]
		return done, r.err
	}
	return r.doneFlag, r.err
}

func newRevertRuntime(t *testing.T, reverter UpgradeReverter) *Runtime {
	t.Helper()
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: &runtimeTestController{candidate: testCandidate(7)},
		UpgradeRevert: reverter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

// TestRevertTriggerFinishesBeforeTerminalReceipt is the core ordering ruling: a
// still-running revert is not a verdict. The first poll reports applying and is
// not cached; the next poll, after the revert finished and wrote its outcome,
// reports the terminal receipt that carries the restored release.
func TestRevertTriggerFinishesBeforeTerminalReceipt(t *testing.T) {
	recorder := &revertRecorder{done: []bool{false, true}, doneFlag: true}
	runtime := newRevertRuntime(t, recorder)
	operationID := strings.Repeat("c", 32)
	failedHandoffFixture(t, runtime.root, runtime, operationID, "1.0.1")
	stage := task(protocol.KindConfigStage, operationID, strings.Repeat("e", 32), 11, 10)

	first := runtime.Execute(context.Background(), stage)
	if first.Status != "applying" {
		t.Fatalf("first receipt = %+v, want the non-terminal applying receipt", first)
	}
	if err := protocol.ValidateTaskResult(first); err != nil {
		t.Fatalf("non-terminal receipt is not a legal result: %v", err)
	}
	// The still-running revert must not be cached: the state file would replay
	// it and the chain would end with a half-restored change set.
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if _, cached := state.FinalResults[operationID]; cached {
		t.Fatal("a still-running revert was cached as a final result")
	}

	// The reverter writes the verdict as the unit finishes; the second call
	// returns done and the receipt carries it.
	recorder.onCall = func(call int) {
		if call == 2 {
			writeRevertResultFile(t, runtime.root, operationID, "1.0.1",
				runtime.cfg.AgentVersion, "rolled_back", "", 0)
		}
	}
	second := runtime.Execute(context.Background(), stage)
	if second.Status != "failed" || second.ErrorCode != handoffIncompleteCode {
		t.Fatalf("second receipt = %+v, want the attempt's stable failure", second)
	}
	if !strings.Contains(second.Detail, `"revert":"rolled_back"`) {
		t.Fatalf("second detail = %q, want the restored outcome", second.Detail)
	}
	if len(recorder.calls) < 2 {
		t.Fatalf("reverter calls = %+v, want the still-running attempt and the finishing attempt", recorder.calls)
	}
	for _, call := range recorder.calls {
		if call != operationID {
			t.Fatalf("reverter calls = %+v, want every call for %s", recorder.calls, operationID)
		}
	}
}

// TestRevertTriggerFinishesInsideTheCall pins the spawn-and-await shape: when
// the reverter returns done=true it has already written the outcome, so the
// very first terminal receipt reports it instead of an invented failure.
func TestRevertTriggerFinishesInsideTheCall(t *testing.T) {
	operationID := strings.Repeat("c", 32)
	recorder := &revertRecorder{done: []bool{true}, doneFlag: true}
	runtime := newRevertRuntime(t, recorder)
	recorder.onCall = func(int) {
		writeRevertResultFile(t, runtime.root, operationID, "1.0.1",
			runtime.cfg.AgentVersion, "failed", "UPDATE_REVERT_RESTORE_FAILED", 1)
	}
	failedHandoffFixture(t, runtime.root, runtime, operationID, "1.0.1")
	apply := task(protocol.KindConfigApply, strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "failed" || result.ErrorCode != "UPDATE_REVERT_RESTORE_FAILED" {
		t.Fatalf("receipt = %+v, want the revert's stable failure", result)
	}
	if !strings.Contains(result.Detail, `"action":"`+upgradeRevertManualAction+`"`) {
		t.Fatalf("detail = %q, want the manual action hint", result.Detail)
	}
	// The pre-lock and locked gates both ask; the reverter is idempotent and
	// the verdict is what makes the receipt terminal, not the call count.
	if len(recorder.calls) < 1 {
		t.Fatalf("reverter was never asked: %+v", recorder.calls)
	}
}

// TestRevertTriggerErrorKeepsHonestFailure shows that a reverter that cannot
// say "finished" never blocks the receipt forever: an error with done=true
// leaves the honest handoff failure (the unit's verdict is read separately).
func TestRevertTriggerErrorKeepsHonestFailure(t *testing.T) {
	recorder := &revertRecorder{done: []bool{true}, doneFlag: true, err: errors.New("UPDATE_REVERT_UNAVAILABLE")}
	runtime := newRevertRuntime(t, recorder)
	operationID := strings.Repeat("c", 32)
	failedHandoffFixture(t, runtime.root, runtime, operationID, "1.0.1")
	apply := task(protocol.KindConfigApply, strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "failed" || result.ErrorCode != handoffIncompleteCode {
		t.Fatalf("receipt = %+v, want the honest handoff failure", result)
	}
	if strings.Contains(result.Detail, "revert") {
		t.Fatalf("detail invented a revert verdict: %q", result.Detail)
	}
}

// TestRevertTriggerNilKeepsLegacyReceipt is the compatibility property: an
// unwired Agent behaves exactly as 11c-3 Task 3 left it.
func TestRevertTriggerNilKeepsLegacyReceipt(t *testing.T) {
	runtime := newRevertRuntime(t, nil)
	operationID := strings.Repeat("c", 32)
	failedHandoffFixture(t, runtime.root, runtime, operationID, "1.0.1")
	apply := task(protocol.KindConfigApply, strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "failed" || result.ErrorCode != handoffIncompleteCode {
		t.Fatalf("receipt = %+v, want the handoff failure", result)
	}
}
