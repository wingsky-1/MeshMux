package node

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// writeInFlightHandoff stores the marker of one running install. ChildPID is
// this test process, which the fixture proc root already materializes, so the
// marker reads as a live child without another fixture file.
func writeInFlightHandoff(t *testing.T, runtime *Runtime, operationID, target string) {
	t.Helper()
	handoff := upgradeHandoff{
		Schema:         upgradeHandoffSchema,
		State:          handoffRunning,
		Phase:          handoffPhaseStaged,
		OperationID:    operationID,
		TargetVersion:  target,
		ManifestSHA256: strings.Repeat("d", 64),
		Revision:       10,
		StartedAt:      runtime.now().Unix(),
		ChildPID:       os.Getpid(),
	}
	if err := runtime.writeUpgradeHandoff(handoff); err != nil {
		t.Fatal(err)
	}
}

// TestGatedApplySkipsLock is the lock-order property of spec §4.9: a gated
// apply returns its non-terminal receipt without waiting for the shared runtime
// lock, even while an installer owns that lock. The gate must be answered
// before the lock, or the poll cycle would block for the length of an install
// and the next heartbeat would slip.
func TestGatedApplySkipsLock(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runtime := newUpgradeRuntime(t, root, cfg, identity, &handoffRunner{runtimeTestRunner: base},
		&runtimeTestController{candidate: testCandidate(10)}, nil)

	stageOperation := strings.Repeat("5", 32)
	writeInFlightHandoff(t, runtime, stageOperation, "1.0.1")

	// The installer may hold the runtime lock for the whole install. A gated
	// apply must not wait for it, so the test holds it for the entire call.
	held, err := AcquireRuntimeLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	apply := task(protocol.KindConfigApply, strings.Repeat("7", 32), strings.Repeat("8", 32), 11, 10)
	started := time.Now()
	result := runtime.Execute(context.Background(), apply)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("gated apply waited %s for the runtime lock", elapsed)
	}
	if result.Status != "applying" || result.ErrorCode != "" || result.Detail != "" ||
		result.OperationID != apply.OperationID {
		t.Fatalf("gated apply = %+v, want non-terminal applying", result)
	}
	if err := protocol.ValidateTaskResult(result); err != nil {
		t.Fatalf("gated receipt is not a legal result: %v", err)
	}
	// The gate is not a licence to touch the data plane either: nothing was
	// staged and the kernel was never restarted.
	if base.restartCount != 0 {
		t.Fatalf("gated apply restarted the kernel %d times", base.restartCount)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("gated apply staged a config: %v", err)
	}
	// The foreign lock is untouched: another writer still cannot take it, so
	// Execute neither acquired nor released the lock on the gated path.
	contended, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := AcquireRuntimeLock(contended, root); err == nil {
		t.Fatal("gated apply released or replaced the runtime lock")
	}
}

// countingHeartbeatController records heartbeats so a test can prove the poll
// loop kept its liveness signal while the shared lock was busy.
type countingHeartbeatController struct {
	*runtimeTestController
	heartbeats int
}

func (c *countingHeartbeatController) Heartbeat(context.Context, protocol.HeartbeatRequest) error {
	c.heartbeats++
	return nil
}

// TestAgentLockTimeout is the Agent-side lock bound: a contended runtime lock
// makes one cycle return in well under the poll interval, the heartbeat of that
// cycle still goes out, and the busy task is not reported as a terminal
// failure — it is simply redelivered on the next poll (spec §4.9).
func TestAgentLockTimeout(t *testing.T) {
	if agentLockTimeout != 5*time.Second {
		t.Fatalf("agent lock timeout = %s, want 5s", agentLockTimeout)
	}
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	controller := &countingHeartbeatController{
		runtimeTestController: &runtimeTestController{candidate: testCandidate(9)},
	}
	// The production bound is exercised above through its constant; the
	// mechanism runs with a short bound so the suite does not idle for 5s.
	runtime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root: root, Runner: base, Controller: controller,
		LockTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	held, err := AcquireRuntimeLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	controller.tasks = []protocol.Task{
		task(protocol.KindConfigReadback, strings.Repeat("9", 32), strings.Repeat("a", 32), 10, 9),
	}
	started := time.Now()
	runtime.cycle(context.Background())
	elapsed := time.Since(started)
	if elapsed >= 2*time.Second {
		t.Fatalf("busy cycle blocked for %s", elapsed)
	}
	if elapsed < 25*time.Millisecond {
		t.Fatalf("busy cycle returned in %s, without waiting for the lock bound", elapsed)
	}
	if controller.heartbeats != 1 {
		t.Fatalf("heartbeats = %d, want 1: the heartbeat must not wait on the lock", controller.heartbeats)
	}
	if len(controller.reports) != 0 {
		t.Fatalf("busy cycle reported %+v, want the cycle skipped until the next poll", controller.reports)
	}
}
