package node

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
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
	child    chan struct{}
	finished chan struct{}
	spawns   [][]string
}

func (r *handoffRunner) Spawn(_ context.Context, name string, args ...string) error {
	r.spawns = append(r.spawns, append([]string{name}, args...))
	if r.spawnErr != nil {
		return r.spawnErr
	}
	if r.child != nil {
		go func() {
			<-r.child
			close(r.finished)
		}()
	}
	return nil
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

// TestStageHandsOffToUpdate is the stamped-target property: a stage row that
// names a release other than the running one is not staged locally, it starts the
// local update with the exact fixed argv and reports the handoff at once. The
// child is still running when Execute returns, so the poll loop never blocks.
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
	if result.Status != "healthy" || !strings.Contains(result.Detail, `"state":"queued"`) ||
		!strings.Contains(result.Detail, stageHandoffTarget) {
		t.Fatalf("handoff receipt = %+v", result)
	}
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
	// candidate (revision 10 is not even the fixture's candidate), so a later
	// apply cannot mistake it for validated evidence.
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("handoff staged the config locally: %v", err)
	}
	// The receipt is terminal and persisted, so a redelivered stage task replays
	// it instead of starting a second update.
	replay := runtime.Execute(context.Background(), stage)
	if replay != result {
		t.Fatalf("replayed receipt = %+v, want %+v", replay, result)
	}
	if len(runner.spawns) != 1 {
		t.Fatalf("replay spawned again: %q", runner.spawns)
	}
	close(runner.child)
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
// started fails the stage step with a stable code, and the node is not wedged
// because the failure is terminal.
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
// blocks for longer than the test's patience still lets Spawn return at once, and
// a missing executable is reported as a start failure rather than a silent
// handoff.
func TestExecRunnerSpawnDoesNotWait(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep on this host")
	}
	started := time.Now()
	if err := (ExecRunner{}).Spawn(context.Background(), "/bin/sleep", "1"); err != nil {
		t.Fatal(err)
	}
	// The child lives for a second, so an implementation that waited would take
	// at least that long. (The package run itself still waits for the child's
	// inherited stderr pipe to close; that is a `go test` artifact, not the
	// Agent waiting.)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Spawn blocked for %s", elapsed)
	}
	if err := (ExecRunner{}).Spawn(context.Background(), "/nonexistent/meshmux-update"); err == nil {
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
