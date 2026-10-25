package node

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// delayedRelease releases the shared runtime lock after delay, proving that
// startup does wait for a lock held by an ordinary install and that the wait is
// what the startup bound applies to.
func delayedRelease(t *testing.T, lock io.Closer, delay time.Duration) {
	t.Helper()
	go func() {
		time.Sleep(delay)
		_ = lock.Close()
	}()
}

// TestStartupLockBound pins the startup side of spec §4.9: a lock that stays
// held past the startup window refuses startup with RUNTIME_LOCK_TIMEOUT instead
// of waiting forever, and the bound is the installer's own unattended window.
func TestStartupLockBound(t *testing.T) {
	if runtimeStartupLockTimeout != 60*time.Second {
		t.Fatalf("startup lock timeout = %s, want 60s", runtimeStartupLockTimeout)
	}
	if agentLockTimeout >= runtimeStartupLockTimeout {
		t.Fatalf("startup bound %s must exceed the per-cycle bound %s", runtimeStartupLockTimeout, agentLockTimeout)
	}

	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	held, err := AcquireRuntimeLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	// The production bound is exercised above through its constant; the
	// mechanism runs with a short bound so the suite does not idle for a minute.
	started := time.Now()
	_, err = NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: base, Controller: &runtimeTestController{candidate: testCandidate(9)},
		StartupLockTimeout: 50 * time.Millisecond,
	})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("startup took the shared lock another writer holds")
	}
	if errorCode(err) != "RUNTIME_LOCK_TIMEOUT" {
		t.Fatalf("startup lock refusal = %v, want RUNTIME_LOCK_TIMEOUT", err)
	}
	if !errors.Is(err, stableError("RUNTIME_LOCK_TIMEOUT")) {
		t.Fatalf("refusal is not the stable code the exit line names: %v", err)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("startup waited %s past its 50ms bound", elapsed)
	}
}

// TestStartupLockWaitsForAnOrdinaryInstall proves the bound is a ceiling, not an
// immediate refusal: startup still waits for a lock that is released inside the
// window, exactly like the installer's own 60s unattended wait.
func TestStartupLockWaitsForAnOrdinaryInstall(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	held, err := AcquireRuntimeLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	delayedRelease(t, held, 100*time.Millisecond)

	started := time.Now()
	runtime, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: base, Controller: &runtimeTestController{candidate: testCandidate(9)},
		StartupLockTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("startup did not wait for a lock released inside the window: %v", err)
	}
	if runtime == nil {
		t.Fatal("startup returned no runtime")
	}
	if elapsed := time.Since(started); elapsed < 50*time.Millisecond {
		t.Fatalf("startup returned in %s, before the lock was released", elapsed)
	}
}

// countingStartRunner reports a kernel that is not ready for the first
// transients calls of `systemctl show`, then delegates to the healthy fixture.
type countingStartRunner struct {
	*runtimeTestRunner
	transients int32
	shows      int32
}

func (r *countingStartRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == systemctlPath && len(args) > 1 && args[0] == "show" && args[1] == SingBoxUnit &&
		hasSystemdProperty(args, "--property=MainPID") {
		atomic.AddInt32(&r.shows, 1)
		if atomic.AddInt32(&r.transients, -1) >= 0 {
			return []byte("ActiveState=activating\nSubState=start\nMainPID=0\n"), nil
		}
	}
	return r.runtimeTestRunner.Run(ctx, name, args...)
}

func hasSystemdProperty(args []string, property string) bool {
	for _, arg := range args {
		if arg == property {
			return true
		}
	}
	return false
}

// TestBootstrapReadbackRetriesInsideTheLockBudget pins the other half of the
// startup fix: the readback retry is bounded by the same agentLockTimeout budget
// a contended poll cycle gets, not by a fixed 58s sleep, so a kernel that never
// becomes ready fails startup quickly and releases the lock.
func TestBootstrapReadbackRetriesInsideTheLockBudget(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &countingStartRunner{runtimeTestRunner: base, transients: 1 << 20}

	started := time.Now()
	_, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: &runtimeTestController{candidate: testCandidate(9)},
		BootstrapReadbackTimeout: 700 * time.Millisecond,
	})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("bootstrap accepted a kernel that never became ready")
	}
	if errorCode(err) != "SINGBOX_NOT_RUNNING" {
		t.Fatalf("bootstrap failure = %v, want the transient kernel code", err)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("bootstrap retried for %s; the old 58s sleep is back", elapsed)
	}
	if attempts := atomic.LoadInt32(&runner.shows); attempts < 2 {
		t.Fatalf("bootstrap attempts = %d, want the bounded retry to try again", attempts)
	}
	// Failure must not leave the startup lock held: the next systemd start has
	// to be able to retry.
	lockCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	lock, lockErr := AcquireRuntimeLock(lockCtx, root)
	if lockErr != nil {
		t.Fatalf("failed startup left the runtime lock held: %v", lockErr)
	}
	_ = lock.Close()
}

// TestBootstrapReadbackRecoversWhenKernelStarts proves the bounded retry is not
// a shorter first attempt: a kernel that appears inside the budget still boots.
func TestBootstrapReadbackRecoversWhenKernelStarts(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &countingStartRunner{runtimeTestRunner: base, transients: 2}

	runtime, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: &runtimeTestController{candidate: testCandidate(9)},
		BootstrapReadbackTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("bootstrap gave up before the kernel started: %v", err)
	}
	if runtime == nil {
		t.Fatal("bootstrap returned no runtime")
	}
	if atomic.LoadInt32(&runner.shows) < 3 {
		t.Fatalf("kernel shows = %d, want the readback to have retried", runner.shows)
	}
}

// TestBootstrapReadbackStopsOnCancellation proves the retry is cancellable: a
// stop request ends startup immediately instead of sleeping out the budget.
func TestBootstrapReadbackStopsOnCancellation(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &countingStartRunner{runtimeTestRunner: base, transients: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := NewRuntimeContext(ctx, cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: &runtimeTestController{candidate: testCandidate(9)},
		BootstrapReadbackTimeout: 30 * time.Second,
	})
	elapsed := time.Since(started)
	if errorCode(err) != "REQUEST_CANCELLED" {
		t.Fatalf("cancelled startup = %v, want REQUEST_CANCELLED", err)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("cancelled startup took %s; the retry did not observe cancellation", elapsed)
	}
}

// TestBootstrapReadbackFailsFastOnDeterministicErrors keeps the rule the old
// loop had: only startup-transient signals are retried, never config bytes or
// ownership.
func TestBootstrapReadbackFailsFastOnDeterministicErrors(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	// The kernel is already running; its binary digest is the deterministic
	// mismatch. A retry there would be treating a broken data plane as slow.
	runner := &countingStartRunner{runtimeTestRunner: base}
	cfg.KernelSHA256 = strings.Repeat("a", 64)

	started := time.Now()
	_, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: &runtimeTestController{candidate: testCandidate(9)},
		BootstrapReadbackTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("bootstrap accepted a mismatched running kernel")
	}
	if errorCode(err) != codeSingboxRunningBinaryMismatch {
		t.Fatalf("bootstrap failure = %v, want %s", err, codeSingboxRunningBinaryMismatch)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("deterministic failure was retried for %s", elapsed)
	}
	if atomic.LoadInt32(&runner.shows) != 1 {
		t.Fatalf("deterministic failure produced %d readbacks, want 1", runner.shows)
	}
}

// TestBootstrapReadbackBudgetDefaultsToAgentLockTimeout pins the reuse of the
// per-cycle lock budget (`agentLockTimeout`) for the startup retry, so startup
// holds the shared lock no longer than one contended poll cycle.
func TestBootstrapReadbackBudgetDefaultsToAgentLockTimeout(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: base, Controller: controller,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.bootstrapTimeout != agentLockTimeout {
		t.Fatalf("bootstrap budget = %s, want agentLockTimeout %s", runtime.bootstrapTimeout, agentLockTimeout)
	}
	if runtime.lockTimeout != agentLockTimeout {
		t.Fatalf("cycle lock budget = %s, want agentLockTimeout %s", runtime.lockTimeout, agentLockTimeout)
	}
}

// TestStartupReliesOnTheSharedRuntimeLock is a smoke check that the fixture
// revision is what the bounded retry bootstrapped, so the tests above exercise
// the real startup path and not an early refusal.
func TestStartupReliesOnTheSharedRuntimeLock(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime, err := NewRuntimeContext(context.Background(), cfg, identity, RuntimeOptions{
		Root: root, Runner: base, Controller: controller,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 9 {
		t.Fatalf("bootstrapped revision = %d, want 9", state.Revision)
	}
}
