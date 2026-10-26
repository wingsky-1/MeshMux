package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node/protocol"
)

const stageHandoffTarget = "1.0.1"

// stageTargetFixture is the Hub read that reports the stamped upgrade target of
// one config.stage row. It records the operation ids it was asked about, so the
// test can prove the Agent asked for this exact task.
type stageTargetFixture struct {
	target  StageTarget
	stamped bool
	err     error
	asked   []string
}

func (f *stageTargetFixture) StageTarget(_ context.Context, operationID string) (StageTarget, bool, error) {
	f.asked = append(f.asked, operationID)
	return f.target, f.stamped, f.err
}

// handoffRunner is a start-only runner. Spawn returns as soon as the child
// exists, exactly like ExecRunner.Spawn; the simulated child keeps running on
// its own goroutine until the test closes child. A test that sees finished
// closed before it ends proves the stage branch waited for the child.
type handoffRunner struct {
	*runtimeTestRunner
	spawnErr error
	// childPID is the PID the fake child reports. It defaults to the test's own
	// PID, which the fixture proc root already materializes, so the marker sees
	// a live child without any extra file.
	childPID int
	child    chan struct{}
	finished chan struct{}
	spawns   [][]string
	// unitState is the ActiveState the fixture systemd reports for the
	// transient update unit. Empty means "active": the owner chain is alive,
	// which is the default while a handoff is expected to be in flight.
	unitState  string
	unitStatus int
	unitErr    error
}

// Run answers the transient-unit liveness query with the fixture state and
// delegates everything else to the shared runtime runner.
func (r *handoffRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == systemctlPath && len(args) > 1 && args[0] == "show" &&
		strings.HasPrefix(args[len(args)-1], "meshmux-update-") {
		if r.unitErr != nil {
			return nil, r.unitErr
		}
		state := r.unitState
		if state == "" {
			state = "active"
		}
		return []byte("ActiveState=" + state + "\nExecMainStatus=" +
			strconv.Itoa(r.unitStatus) + "\n"), nil
	}
	return r.runtimeTestRunner.Run(ctx, name, args...)
}

func (r *handoffRunner) Spawn(_ context.Context, name string, args ...string) (int, error) {
	r.spawns = append(r.spawns, append([]string{name}, args...))
	if r.spawnErr != nil {
		return 0, r.spawnErr
	}
	if r.child != nil {
		go func() {
			<-r.child
			close(r.finished)
		}()
	}
	pid := r.childPID
	if pid == 0 {
		pid = os.Getpid()
	}
	return pid, nil
}

// waitOnlyRunner is a CommandRunner without the start-only half: a handoff
// cannot be reported honestly because the Agent cannot know the child started.
type waitOnlyRunner struct {
	*runtimeTestRunner
}

func newUpgradeRuntime(t *testing.T, root string, cfg Config, identity Identity, runner CommandRunner,
	controller Controller, source StageTargetSource) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller, StageTargets: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func stageHandoffTargetFixture() *stageTargetFixture {
	return &stageTargetFixture{
		stamped: true,
		target:  StageTarget{Version: stageHandoffTarget, ManifestSHA256: strings.Repeat("d", 64)},
	}
}

// assertQueuedApplying pins the handoff receipt: a legal non-terminal result, so
// the chain stays open at the Hub and no healthy/staged evidence is recorded.
func assertQueuedApplying(t *testing.T, result protocol.TaskResult, operationID, target string) {
	t.Helper()
	if result.Status != "applying" || result.ErrorCode != "" {
		t.Fatalf("handoff receipt = %+v, want non-terminal applying", result)
	}
	if !strings.Contains(result.Detail, `"state":"queued"`) || !strings.Contains(result.Detail, target) {
		t.Fatalf("handoff detail = %q", result.Detail)
	}
	if result.OperationID != operationID {
		t.Fatalf("handoff operation = %s, want %s", result.OperationID, operationID)
	}
	if err := protocol.ValidateTaskResult(result); err != nil {
		t.Fatalf("handoff receipt is not a legal result: %v", err)
	}
}

// TestStageHandsOffToUpdate is the stamped-target property: a stage row that
// names a release other than the running one is not staged locally, it starts the
// local update with the exact fixed argv and reports a non-terminal handoff at
// once. The child is still running when Execute returns, so the poll loop never
// blocks, and the row stays unfinished so the rest of the chain cannot proceed.
func TestStageHandsOffToUpdate(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	source := stageHandoffTargetFixture()
	runner := &handoffRunner{runtimeTestRunner: base, child: make(chan struct{}), finished: make(chan struct{})}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, source)

	operationID := strings.Repeat("5", 32)
	stage := task(protocol.KindConfigStage, operationID, strings.Repeat("6", 32), 11, 10)
	started := time.Now()
	result := runtime.Execute(context.Background(), stage)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stage handoff blocked for %s", elapsed)
	}
	assertQueuedApplying(t, result, operationID, stageHandoffTarget)
	if len(source.asked) != 1 || source.asked[0] != operationID {
		t.Fatalf("target source asked %v, want [%s]", source.asked, operationID)
	}
	want := []string{
		rooted(root, AgentBinaryPath),
		"__internal-update",
		"--target", stageHandoffTarget,
		"--manifest-sha256", strings.Repeat("d", 64),
		"--operation-id", operationID,
		"--confirm-target",
	}
	if len(runner.spawns) != 1 || !slices.Equal(runner.spawns[0], want) {
		t.Fatalf("spawn argv = %q, want %q", runner.spawns, want)
	}
	select {
	case <-runner.finished:
		t.Fatal("stage handoff waited for the child")
	default:
	}
	// A handoff is not a local stage: the Agent never fetches or writes the
	// candidate, so a later apply cannot mistake it for validated evidence.
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("handoff staged the config locally: %v", err)
	}
	// The row is not final, so the marker is on disk and the receipt is not in
	// the idempotency cache: the chain stays open and the node stays busy.
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); err != nil {
		t.Fatalf("handoff marker missing: %v", err)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if _, cached := state.Idempotency[stage.IdempotencyKey]; cached {
		t.Fatal("non-terminal handoff was cached as a final result")
	}
	if state.LastTaskRevision >= stage.Revision {
		t.Fatalf("handoff advanced LastTaskRevision to %d", state.LastTaskRevision)
	}
	// A redelivered stage replays the same receipt and starts no second update.
	replay := runtime.Execute(context.Background(), stage)
	assertQueuedApplying(t, replay, operationID, stageHandoffTarget)
	if len(runner.spawns) != 1 {
		t.Fatalf("replay spawned again: %q", runner.spawns)
	}
	close(runner.child)
}

// TestStageHandoffGatesApplyAndReadback pins the chain property: while the
// update is in flight, apply and readback report a non-terminal state and touch
// nothing — no staged config, no restart, no readback — so the old release keeps
// serving and TASKS_IN_PROGRESS still sees an unfinished chain.
func TestStageHandoffGatesApplyAndReadback(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, child: make(chan struct{}), finished: make(chan struct{})}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, stageHandoffTargetFixture())

	stage := task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 10)
	assertQueuedApplying(t, runtime.Execute(context.Background(), stage), stage.OperationID, stageHandoffTarget)

	apply := task(protocol.KindConfigApply, strings.Repeat("7", 32), strings.Repeat("8", 32), 12, 10)
	gated := runtime.Execute(context.Background(), apply)
	if gated.Status != "applying" || gated.ErrorCode != "" || gated.Detail != "" {
		t.Fatalf("gated apply = %+v, want non-terminal applying", gated)
	}
	if runner.restartCount != 0 {
		t.Fatalf("gated apply restarted the kernel %d times", runner.restartCount)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("gated apply staged a config: %v", err)
	}
	readback := task(protocol.KindConfigReadback, strings.Repeat("9", 32), strings.Repeat("a", 32), 13, 10)
	gated = runtime.Execute(context.Background(), readback)
	if gated.Status != "applying" || gated.ErrorCode != "" {
		t.Fatalf("gated readback = %+v, want non-terminal applying", gated)
	}
	// Neither gated step may be cached: they have not run, so a later poll must
	// execute them for real once the handoff resolves.
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []protocol.Task{apply, readback} {
		if _, cached := state.Idempotency[step.IdempotencyKey]; cached {
			t.Fatalf("gated step %s was cached", step.Kind)
		}
	}
	close(runner.child)
}

// TestStageHandoffChildGoneFailsChain pins the failure path: the spawned helper
// is only diagnostic now (the transient unit owns the install), so liveness
// comes from the unit state and the updater result file. A unit that is gone,
// whose result says it never got past install or whose restart never produced
// the target, ends the chain with a stable code; the remaining steps of that
// chain fail the same way instead of applying the old release. A later chain
// may still take the node.
func TestStageHandoffChildGoneFailsChain(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	// The transient unit is gone and the result file says the install reached
	// installed-awaiting-restart with exit 0 — yet this Agent still runs the old
	// release, so the restart is not proven and the chain must fail.
	runner := &handoffRunner{runtimeTestRunner: base, childPID: 1, unitState: "inactive"}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, stageHandoffTargetFixture())

	stage := task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 10)
	assertQueuedApplying(t, runtime.Execute(context.Background(), stage), stage.OperationID, stageHandoffTarget)
	writeHandoffResultFile(t, root, stage.OperationID, stageHandoffTarget, handoffPhaseInstalledAwaitingRestart, 0)
	// Same step redelivered after the unit is gone.
	result := runtime.Execute(context.Background(), stage)
	if result.Status != "failed" || result.ErrorCode != "UPDATE_HANDOFF_INCOMPLETE" {
		t.Fatalf("stage after child exit = %+v", result)
	}
	apply := task(protocol.KindConfigApply, strings.Repeat("7", 32), strings.Repeat("8", 32), 12, 10)
	if got := runtime.Execute(context.Background(), apply); got.ErrorCode != "UPDATE_HANDOFF_INCOMPLETE" {
		t.Fatalf("apply after failed handoff = %+v", got)
	}
	if runner.restartCount != 0 {
		t.Fatalf("failed chain restarted the kernel %d times", runner.restartCount)
	}
	handoff, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok || handoff.State != handoffFailed {
		t.Fatalf("failed marker = %+v, %v, %v", handoff, ok, err)
	}
	// A new chain owns the node from here: its stage step drops the stale
	// failed marker and stages normally (its target equals the running build).
	source := &stageTargetFixture{stamped: true, target: StageTarget{Version: cfg.AgentVersion, ManifestSHA256: strings.Repeat("d", 64)}}
	next := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, source)
	nextStage := task(protocol.KindConfigStage, strings.Repeat("b", 32), strings.Repeat("c", 32), 14, 9)
	if got := next.Execute(context.Background(), nextStage); got.Status != "healthy" {
		t.Fatalf("next chain stage = %+v", got)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("stale failed marker survived a new chain: %v", err)
	}
}

// TestStageHandoffBlocksSecondChain pins the serialization property: while one
// chain's install is in flight, another chain's stage step is refused instead of
// starting a second update.
func TestStageHandoffBlocksSecondChain(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, child: make(chan struct{}), finished: make(chan struct{})}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, stageHandoffTargetFixture())

	stage := task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 10)
	assertQueuedApplying(t, runtime.Execute(context.Background(), stage), stage.OperationID, stageHandoffTarget)
	second := task(protocol.KindConfigStage, strings.Repeat("d", 32), strings.Repeat("e", 32), 12, 10)
	if got := runtime.Execute(context.Background(), second); got.ErrorCode != "UPDATE_HANDOFF_IN_PROGRESS" {
		t.Fatalf("second chain = %+v", got)
	}
	if len(runner.spawns) != 1 {
		t.Fatalf("second chain spawned %q", runner.spawns)
	}
	close(runner.child)
}

// TestStageHandoffCompletesWhenTargetIsRunning pins the completion path: once
// the running release is the target (the update installed and the Agent
// restarted on it), the leftover marker is cleared and the redelivered stage row
// becomes an ordinary local stage instead of starting a second upgrade.
func TestStageHandoffCompletesWhenTargetIsRunning(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, childPID: 1}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, stageHandoffTargetFixture())
	stage := task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 10)
	assertQueuedApplying(t, runtime.Execute(context.Background(), stage), stage.OperationID, stageHandoffTarget)

	// The update installed the release this fixture build represents, so the
	// leftover marker names the running version and the stamped target does too.
	// That is the state the restarted Agent finds; no second upgrade may start.
	handoff, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok {
		t.Fatalf("marker before restart = %+v, %v, %v", handoff, ok, err)
	}
	handoff.TargetVersion = cfg.AgentVersion
	handoff.State = handoffRunning
	handoff.ChildPID = 0
	if err = runtime.writeUpgradeHandoff(handoff); err != nil {
		t.Fatal(err)
	}
	// The restarted Agent finds a whole on-disk pair: the config names the
	// binary that is running. Only then is the completed marker cleared.
	writeAgentConfigFile(t, root, cfg)
	installed := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, &stageTargetFixture{
			stamped: true,
			target:  StageTarget{Version: cfg.AgentVersion, ManifestSHA256: strings.Repeat("d", 64)},
		})
	if got := installed.Execute(context.Background(), stage); got.Status != "healthy" || got.Detail != "" {
		t.Fatalf("stage after install = %+v", got)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("completed marker survived: %v", err)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 10)); err != nil {
		t.Fatalf("completed handoff did not stage: %v", err)
	}
	if len(runner.spawns) != 1 {
		t.Fatalf("completed handoff started another update: %q", runner.spawns)
	}
}

// TestHandoffCycleKeepsChainOpenViaPollLoop pins the behaviour through the real
// poll loop: the Hub hands the whole four-task chain at once, and while the
// update is in flight the chain must stay open with every step non-terminal —
// no apply, no kernel restart, no readback — so a second approval is still
// refused by the Hub's TASKS_IN_PROGRESS guard.
func TestHandoffCycleKeepsChainOpenViaPollLoop(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, child: make(chan struct{}), finished: make(chan struct{})}
	controller := &runtimeTestController{candidate: testCandidate(10)}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner, controller, stageHandoffTargetFixture())
	controller.tasks = []protocol.Task{
		task(protocol.KindConfigCheck, strings.Repeat("1", 32), strings.Repeat("a", 32), 10, 10),
		task(protocol.KindConfigStage, strings.Repeat("2", 32), strings.Repeat("b", 32), 11, 10),
		task(protocol.KindConfigApply, strings.Repeat("3", 32), strings.Repeat("c", 32), 12, 10),
		task(protocol.KindConfigReadback, strings.Repeat("4", 32), strings.Repeat("d", 32), 13, 10),
	}
	runtime.cycle(context.Background())

	statuses := map[string]string{}
	checkID := strings.Repeat("1", 32)
	for _, report := range controller.reports {
		statuses[report.OperationID] = report.Status
		if report.Status == "healthy" && report.OperationID != checkID {
			// Only the read-only check may succeed; stage, apply and readback
			// must not claim anything while the install runs.
			t.Fatalf("handoff cycle reported healthy: %+v", report)
		}
	}
	for _, want := range []struct{ id, status string }{
		{strings.Repeat("1", 32), "healthy"}, // check is read-only and may run
		{strings.Repeat("2", 32), "applying"},
		{strings.Repeat("3", 32), "applying"},
	} {
		if got, ok := statuses[want.id]; ok && got != want.status {
			t.Fatalf("operation %s status = %s, want %s", want.id, got, want.status)
		}
	}
	if retried, ok := statuses[strings.Repeat("3", 32)]; !ok || retried != "applying" {
		t.Fatalf("apply was not gated: %q", retried)
	}
	if runner.restartCount != 0 {
		t.Fatalf("cycle restarted the kernel %d times during handoff", runner.restartCount)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("cycle staged/applied under the handoff: %v", err)
	}
	close(runner.child)
}

// TestStageNilTargetSourceKeepsOldPath pins the wiring contract: with no
// StageTargetSource configured (the production default until #11c-1 Task 6 wires
// GET /api/agent/upgrade-target + Client.StageTarget) every stage row keeps the
// pre-upgrade behaviour and no marker is ever written.
func TestStageNilTargetSourceKeepsOldPath(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, nil)

	result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9))
	if result.Status != "healthy" || result.Detail != "" {
		t.Fatalf("nil-source stage receipt = %+v", result)
	}
	if len(runner.spawns) != 0 {
		t.Fatalf("nil-source stage started %q", runner.spawns)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("nil source wrote a handoff marker: %v", err)
	}
}

// TestStageWithoutTargetUnchanged pins that a plain config.stage row still takes
// the local stage path: it writes the staged candidate and config and starts
// nothing.
func TestStageWithoutTargetUnchanged(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	source := &stageTargetFixture{}
	runner := &handoffRunner{runtimeTestRunner: base}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, source)

	result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9))
	if result.Status != "healthy" || result.Detail != "" {
		t.Fatalf("plain stage receipt = %+v", result)
	}
	if len(runner.spawns) != 0 {
		t.Fatalf("plain stage started %q", runner.spawns)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 9)); err != nil {
		t.Fatalf("plain stage wrote no staged config: %v", err)
	}
}

// TestStageTargetEqualToRunningVersionStagesNormally pins the "differing from
// the running version" rule: after the upgrade installed the target, the same
// chain's stage row is redelivered and must become an ordinary local stage, not
// a second upgrade.
func TestStageTargetEqualToRunningVersionStagesNormally(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	source := &stageTargetFixture{
		stamped: true,
		target:  StageTarget{Version: cfg.AgentVersion, ManifestSHA256: strings.Repeat("d", 64)},
	}
	runner := &handoffRunner{runtimeTestRunner: base}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, source)

	result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9))
	if result.Status != "healthy" || result.Detail != "" {
		t.Fatalf("running-target stage receipt = %+v", result)
	}
	if len(runner.spawns) != 0 {
		t.Fatalf("running-target stage started %q", runner.spawns)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 9)); err != nil {
		t.Fatalf("running-target stage wrote no staged config: %v", err)
	}
}

// TestStageHandoffSpawnFailure pins the failure receipt: an update that cannot be
// started fails the stage step with a stable code, leaves no marker behind and
// does not fall back to staging.
func TestStageHandoffSpawnFailure(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	source := stageHandoffTargetFixture()
	runner := &handoffRunner{runtimeTestRunner: base, spawnErr: errors.New("exec: file does not exist")}
	// Revision 10 is a real candidate, so the absence of staged files below
	// proves the failed handoff did not fall back to a local stage.
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(10)}, source)

	result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 10))
	if result.Status != "failed" || result.ErrorCode != "UPDATE_SPAWN_FAILED" {
		t.Fatalf("spawn failure receipt = %+v", result)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("failed handoff fell back to staging: %v", err)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("failed spawn left a marker: %v", err)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if _, pending := state.FinalResults[result.OperationID]; !pending {
		t.Fatal("failed handoff left no terminal result")
	}
}

// TestStageHandoffRequiresSpawner pins that the Agent never claims "queued" for a
// child it could not start: a runner with only the waiting Run half is refused.
func TestStageHandoffRequiresSpawner(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	source := stageHandoffTargetFixture()
	runner := &waitOnlyRunner{runtimeTestRunner: base}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, source)

	result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9))
	if result.Status != "failed" || result.ErrorCode != "UPDATE_SPAWN_UNAVAILABLE" {
		t.Fatalf("runner without spawn = %+v", result)
	}
}

// TestStageTargetSourceError pins that an unreadable stamped target fails the
// stage step instead of staging a candidate that was meant for an upgrade.
func TestStageTargetSourceError(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	source := &stageTargetFixture{err: &ClientError{Code: "CONTROL_PLANE_UNAVAILABLE"}}
	runner := &handoffRunner{runtimeTestRunner: base}
	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, source)

	result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9))
	if result.Status != "failed" || result.ErrorCode != "STAGE_TARGET_UNAVAILABLE" {
		t.Fatalf("target source failure receipt = %+v", result)
	}
	if len(runner.spawns) != 0 {
		t.Fatalf("unavailable target still started %q", runner.spawns)
	}
}

// TestStageRejectsUnpinnedTarget pins that only a pinned SemVer release may
// reach the fixed argv. A floating version or digest is refused before anything
// starts.
func TestStageRejectsUnpinnedTarget(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	for _, target := range []StageTarget{
		{Version: "latest", ManifestSHA256: strings.Repeat("d", 64)},
		{Version: stageHandoffTarget, ManifestSHA256: "deadbeef"},
		{Version: "", ManifestSHA256: strings.Repeat("d", 64)},
	} {
		source := &stageTargetFixture{stamped: true, target: target}
		runner := &handoffRunner{runtimeTestRunner: base}
		runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(9)}, source)
		result := runtime.Execute(context.Background(), task(protocol.KindConfigStage, strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9))
		if result.Status != "failed" || result.ErrorCode != "STAGE_TARGET_INVALID" {
			t.Fatalf("target %+v receipt = %+v", target, result)
		}
		if len(runner.spawns) != 0 {
			t.Fatalf("unpinned target %+v started %q", target, runner.spawns)
		}
	}
}

// TestExecRunnerSpawnDoesNotWait pins the production boundary: a real child that
// blocks still lets Spawn return at once, and a missing executable is reported as
// a start failure rather than a silent handoff. The child is killed through the
// returned PID, so the assertion never depends on a race with its own exit.
func TestExecRunnerSpawnDoesNotWait(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep on this host")
	}
	started := time.Now()
	pid, err := (ExecRunner{}).Spawn(context.Background(), "/bin/sleep", "30")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if process, findErr := os.FindProcess(pid); findErr == nil {
			_ = process.Kill()
		}
	}()
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Spawn blocked for %s", elapsed)
	}
	if pid < 1 {
		t.Fatalf("Spawn returned pid %d", pid)
	}
	if _, err := os.Lstat(filepath.Join("/proc", strconv.Itoa(pid))); err != nil {
		t.Fatalf("child %d is not running: %v", pid, err)
	}
	if _, err := (ExecRunner{}).Spawn(context.Background(), "/nonexistent/meshmux-update"); err == nil {
		t.Fatal("missing executable reported as started")
	}
}

// TestUnknownKindRejected pins that the stage branch did not widen the frozen
// allowlist: an unknown kind is TASK_KIND_REJECTED and a reserved upgrade kind is
// still refused before any execution.
func TestUnknownKindRejected(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runtime := newUpgradeRuntime(t, root, cfg, identity, &handoffRunner{runtimeTestRunner: base},
		&runtimeTestController{candidate: testCandidate(9)}, &stageTargetFixture{})

	unknown := task("config.reconcile", strings.Repeat("5", 32), strings.Repeat("6", 32), 11, 9)
	if result := runtime.Execute(context.Background(), unknown); result.ErrorCode != "TASK_KIND_REJECTED" {
		t.Fatalf("unknown kind = %+v, want TASK_KIND_REJECTED", result)
	}
	reserved := task("upgrade.agent", strings.Repeat("7", 32), strings.Repeat("8", 32), 11, 9)
	if result := runtime.Execute(context.Background(), reserved); result.ErrorCode != "UPGRADE_NOT_IMPLEMENTED" {
		t.Fatalf("reserved kind = %+v, want UPGRADE_NOT_IMPLEMENTED", result)
	}
}
