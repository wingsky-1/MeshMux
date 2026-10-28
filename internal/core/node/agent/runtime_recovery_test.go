package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// seedInterruptedApply writes the journal a crash between the journal write and
// the "applying" report would leave behind: the interrupted task, a valid
// revision-9 transaction and an LKG of the bootstrapped revision 7.
func seedInterruptedApply(t *testing.T, runtime *Runtime, reported bool) (protocol.Task, *applyJournal) {
	t.Helper()
	journalTask := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 22, 9)
	payload, err := json.Marshal(journalTask)
	if err != nil {
		t.Fatal(err)
	}
	config, err := CompileCandidate(testCandidate(9).Candidate())
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	state.Journal = &applyJournal{
		Schema:       journalTXNSchema,
		OperationID:  journalTask.OperationID,
		Idempotency:  journalTask.IdempotencyKey,
		Payload:      sha256Hex(payload),
		TaskRevision: journalTask.Revision,
		Revision:     9,
		Digest:       sha256Hex(config),
		Config:       config,
		Reported:     reported,
	}
	state.LastTaskRevision = journalTask.Revision
	if err := runtime.persistState(&state); err != nil {
		t.Fatal(err)
	}
	return journalTask, state.Journal
}

func reportedResult(t *testing.T, controller *runtimeTestController, operationID string) (protocol.TaskResult, bool) {
	t.Helper()
	for _, report := range controller.reports {
		if report.OperationID == operationID {
			return report, true
		}
	}
	return protocol.TaskResult{}, false
}

// TestJournalRecoveryFailureStartsDegradedConvergesAndReportsPartial is the
// crash-loop fix: a restore that cannot succeed at boot must not make the Agent
// exit (systemd would restart it into the same failure forever). The node starts,
// the terminal partial receipt is persisted for the Hub, and the deterministic
// failure retires the journal so the next chain can repair the node.
func TestJournalRecoveryFailureStartsDegradedConvergesAndReportsPartial(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	boot := newTestRuntime(t, root, cfg, identity, runner, controller)
	_, journal := seedInterruptedApply(t, boot, true)
	// The deterministic host drift: the staged candidate of the LKG revision is
	// gone, so no later attempt can restore it.
	if err := os.Remove(stagedCandidatePath(root, 7)); err != nil {
		t.Fatal(err)
	}

	agent, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
	})
	if err != nil {
		t.Fatalf("journal recovery failure refused startup, so systemd would loop: %v", err)
	}
	state, err := agent.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Journal != nil {
		t.Fatal("a deterministic restore failure left the journal in place forever")
	}
	receipt, ok := state.FinalResults[journal.OperationID]
	if !ok {
		t.Fatal("the recovery failure was not queued for the Hub")
	}
	if receipt.Status != "partial" || receipt.ErrorCode != "LKG_CANDIDATE_RESTORE_FAILED" {
		t.Fatalf("recovery receipt = %+v", receipt)
	}
	if item, ok := state.Idempotency[journal.Idempotency]; !ok || item.Result.Status != "partial" {
		t.Fatalf("redelivery receipt = %+v", item)
	}

	// The outbox is what makes the startup failure reportable instead of silent.
	if err := agent.replayResults(context.Background()); err != nil {
		t.Fatal(err)
	}
	report, ok := reportedResult(t, controller, journal.OperationID)
	if !ok || report.Status != "partial" || report.ErrorCode != "LKG_CANDIDATE_RESTORE_FAILED" {
		t.Fatalf("reported recovery result = %+v (found=%v)", report, ok)
	}

	// A converged journal no longer refuses the next chain.
	check := task(protocol.KindConfigCheck, strings.Repeat("3", 32), strings.Repeat("4", 32), 23, 7)
	if result := agent.Execute(context.Background(), check); result.Status != "healthy" {
		t.Fatalf("check after convergence = %+v", result)
	}
}

// ssFailureRunner emulates a kernel whose listener query is not ready yet: the
// only journal-recovery failure the boot path may retry.
type ssFailureRunner struct {
	*runtimeTestRunner
	fail bool
}

func (r *ssFailureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == ssPath && r.fail {
		return nil, errors.New("ss unavailable")
	}
	return r.runtimeTestRunner.Run(ctx, name, args...)
}

// TestJournalRecoveryKeepsTheJournalForAStartingKernel pins the degraded half:
// a startup-transient failure still starts the Agent and reports partial, but
// keeps the journal, so check/stage/apply answer RECOVERY_REQUIRED instead of
// touching a data plane whose LKG was not proved. The next poll settles it.
func TestJournalRecoveryKeepsTheJournalForAStartingKernel(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	boot := newTestRuntime(t, root, cfg, identity, base, controller)
	_, journal := seedInterruptedApply(t, boot, true)
	runner := &ssFailureRunner{runtimeTestRunner: base, fail: true}

	agent, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
	})
	if err != nil {
		t.Fatalf("a starting kernel refused startup: %v", err)
	}
	state, err := agent.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Journal == nil {
		t.Fatal("a retryable failure dropped the journal before the LKG was proved")
	}
	receipt := state.FinalResults[journal.OperationID]
	if receipt.Status != "partial" || receipt.ErrorCode != "LKG_READBACK_FAILED" {
		t.Fatalf("degraded startup receipt = %+v", receipt)
	}
	check := task(protocol.KindConfigCheck, strings.Repeat("3", 32), strings.Repeat("4", 32), 23, 7)
	if result := agent.Execute(context.Background(), check); result.ErrorCode != "RECOVERY_REQUIRED" {
		t.Fatalf("degraded node accepted dynamic work: %+v", result)
	}

	runner.fail = false
	agent.cycle(context.Background())
	state, err = agent.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Journal != nil {
		t.Fatal("the poll retry did not settle the journal")
	}
	if report, ok := reportedResult(t, controller, journal.OperationID); !ok || report.Status != "rolled_back" {
		t.Fatalf("settled recovery report = %+v (found=%v)", report, ok)
	}
}

// TestJournalRecoveryRetryIsBounded proves the degraded state converges even
// when the host never settles: after the bounded retry the journal is retired
// with the partial receipt already recorded, so config work can repair the node
// instead of being refused forever.
func TestJournalRecoveryRetryIsBounded(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	boot := newTestRuntime(t, root, cfg, identity, base, controller)
	_, journal := seedInterruptedApply(t, boot, true)
	runner := &ssFailureRunner{runtimeTestRunner: base, fail: true}

	agent, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
	})
	if err != nil {
		t.Fatalf("a starting kernel refused startup: %v", err)
	}
	for range journalRecoveryRetryLimit {
		agent.cycle(context.Background())
	}
	state, err := agent.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Journal != nil {
		t.Fatalf("journal survived %d degraded retries; every config task would stay RECOVERY_REQUIRED", journalRecoveryRetryLimit)
	}
	if report, ok := reportedResult(t, controller, journal.OperationID); !ok || report.Status != "partial" {
		t.Fatalf("bounded recovery report = %+v (found=%v)", report, ok)
	}
	check := task(protocol.KindConfigCheck, strings.Repeat("3", 32), strings.Repeat("4", 32), 23, 7)
	if result := agent.Execute(context.Background(), check); result.Status != "healthy" {
		t.Fatalf("check after convergence = %+v", result)
	}
}

// TestJournalRecoveryWithoutAReportedApplyUsesThePendingSafeReceipt covers the
// crash window before the Hub saw "applying": the row is still pending, where
// the Hub's frozen state machine refuses rolled_back. The restore is proved, but
// the receipt must be partial so a redelivery can actually be delivered.
func TestJournalRecoveryWithoutAReportedApplyUsesThePendingSafeReceipt(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	boot := newTestRuntime(t, root, cfg, identity, runner, controller)
	journalTask, journal := seedInterruptedApply(t, boot, false)

	agent, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := agent.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Journal != nil {
		t.Fatal("a proved restore did not settle the journal")
	}
	if _, queued := state.FinalResults[journal.OperationID]; queued {
		t.Fatal("an operation the Hub never saw was queued for the outbox")
	}
	got := agent.Execute(context.Background(), journalTask)
	if got.Status != "partial" || got.ErrorCode != "RECOVERED_AFTER_CRASH" {
		t.Fatalf("pending-safe recovery replay = %+v", got)
	}
}

// TestJournalInvalidRestoresBestEffortAndConverges pins the corrupt-journal
// branch: an unprovable transaction is never guessed at, the LKG is still put
// back when possible, the partial receipt names the invalid journal, and startup
// proceeds.
func TestJournalInvalidRestoresBestEffortAndConverges(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	boot := newTestRuntime(t, root, cfg, identity, runner, controller)
	_, journal := seedInterruptedApply(t, boot, true)
	state, err := boot.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	state.Journal.Digest = strings.Repeat("0", 64)
	if err := boot.persistState(&state); err != nil {
		t.Fatal(err)
	}

	agent, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
	})
	if err != nil {
		t.Fatalf("an invalid journal refused startup: %v", err)
	}
	state, err = agent.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Journal != nil {
		t.Fatal("an invalid journal was kept instead of converged")
	}
	receipt := state.FinalResults[journal.OperationID]
	if receipt.Status != "partial" || receipt.ErrorCode != "JOURNAL_INVALID" {
		t.Fatalf("invalid journal receipt = %+v", receipt)
	}
}
