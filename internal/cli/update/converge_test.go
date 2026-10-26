package update

// The convergence writer (#11c-2 Task 5, binding carry from Task 4).
//
// The Agent holds the shared runtime lock when it asks for convergence, so the
// writer must SPAWN one transient unit and return — never run the /etc write
// inside the Agent's process and never wait for a repair that would take the
// same lock. The spawn itself is detached from the caller's cancellation: the
// Agent's bounded context is cancelled as soon as the call returns, and the
// systemd-run helper must outlive that to submit its job. These tests pin the
// fixed argv, the detach and the return-without-waiting rule.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// convergeSpawner records the one argv the writer starts and can block, so a
// writer that waited for the unit would hang the test.
func convergeSpawner(calls *[][]string, release <-chan struct{}) node.Spawner {
	return spawnerFunc(func(ctx context.Context, name string, args ...string) (int, error) {
		*calls = append(*calls, append([]string{name}, args...))
		if release != nil {
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		return 4242, nil
	})
}

type spawnerFunc func(context.Context, string, ...string) (int, error)

func (f spawnerFunc) Spawn(ctx context.Context, name string, args ...string) (int, error) {
	return f(ctx, name, args...)
}

// TestConvergeArgvPinned pins the whole transient convergence unit: one fixed
// systemd-run, the enumerated properties, `--no-block` (the Agent never waits)
// and the installed binary's single hidden subcommand.
func TestConvergeArgvPinned(t *testing.T) {
	operationID := strings.Repeat("a", 32)
	digest := strings.Repeat("b", 64)
	argv, err := BuildConvergeArgv(operationID, digest)
	if err != nil {
		t.Fatalf("BuildConvergeArgv: %v", err)
	}
	want := []string{
		"/usr/bin/systemd-run",
		"--unit=meshmux-converge-" + operationID,
		"--collect",
		"--no-block",
		"--property=Type=oneshot",
		"--property=Restart=no",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=/etc/meshmux /var/lib/meshmux-agent",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=CapabilityBoundingSet=",
		node.AgentBinaryPath,
		"__internal-update-converge",
		"--operation-id", operationID,
		"--expected-sha256", digest,
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv = %q\nwant    %q", argv, want)
	}
}

// TestConvergeArgvRejectsUnvalidatedInput refuses anything that is not an
// operation ID and a digest before a unit is named.
func TestConvergeArgvRejectsUnvalidatedInput(t *testing.T) {
	for _, tc := range []struct{ name, op, digest string }{
		{"empty operation", "", strings.Repeat("b", 64)},
		{"path operation", "../../etc", strings.Repeat("b", 64)},
		{"short operation", "abc", strings.Repeat("b", 64)},
		{"bad digest", strings.Repeat("a", 32), "not-a-digest"},
		{"short digest", strings.Repeat("a", 32), strings.Repeat("b", 63)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if argv, err := BuildConvergeArgv(tc.op, tc.digest); err == nil || argv != nil {
				t.Fatalf("argv = %q, err = %v, want a refusal", argv, err)
			}
		})
	}
}

// TestConvergeWriterSpawnsWithoutWaiting is the Task-4 carry: the writer uses
// the start-only boundary and returns while the unit runs. The struct has no
// command-runner field at all, so it cannot wait for the /etc write; the argv
// it spawns carries --no-block for the same reason at the systemd level.
func TestConvergeWriterSpawnsWithoutWaiting(t *testing.T) {
	var calls [][]string
	writer := &ConvergenceWriter{Spawner: convergeSpawner(&calls, nil)}
	claim := node.HandoffClaim{OperationID: strings.Repeat("c", 32), NewSHA256: strings.Repeat("d", 64)}
	if err := writer.ConvergeHandoffConfig(context.Background(), claim); err != nil {
		t.Fatalf("ConvergeHandoffConfig: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %q, want exactly one", calls)
	}
	if calls[0][0] != "/usr/bin/systemd-run" || !slices.Contains(calls[0], "--no-block") {
		t.Fatalf("call = %q, want the fixed --no-block systemd-run", calls[0])
	}
}

// TestConvergeHandoffConfigDetachesThroughThePublicEntry closes the coverage
// seam: the real-process test calls spawn() directly, so a refactor that made
// ConvergeHandoffConfig bypass spawn() and pass its own ctx to the Spawner would
// still leave that test green. This one goes through the public entry and asserts
// the context the spawner RECEIVED is not Done after the parent cancels — the
// observable half of the detach, which a fake can see even though it cannot see
// the SIGKILL.
func TestConvergeHandoffConfigDetachesThroughThePublicEntry(t *testing.T) {
	var got context.Context
	var calls int
	writer := &ConvergenceWriter{Spawner: spawnerFunc(
		func(ctx context.Context, _ string, _ ...string) (int, error) {
			calls++
			got = ctx
			return 4242, nil
		})}
	claim := node.HandoffClaim{OperationID: strings.Repeat("a", 32), NewSHA256: strings.Repeat("b", 64)}

	parent, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := writer.ConvergeHandoffConfig(parent, claim); err != nil {
		cancel()
		t.Fatalf("ConvergeHandoffConfig: %v", err)
	}
	cancel()

	if calls != 1 || got == nil {
		t.Fatalf("spawner calls = %d, ctx nil = %v, want exactly one spawn", calls, got == nil)
	}
	// The caller's cancellation is what killed the pre-fix helper; the context
	// the spawner saw must be unaffected by it.
	select {
	case <-got.Done():
		t.Fatalf("the spawner received the caller's cancellable context (%v); ConvergeHandoffConfig bypassed the detach", got.Err())
	case <-time.After(50 * time.Millisecond):
	}
	if parent.Err() == nil {
		t.Fatal("the parent context was never cancelled; the test proves nothing")
	}
}

// TestConvergeWriterReportsStartFailure keeps the failure honest: a unit systemd
// did not accept is reported to the Agent, which logs it and keeps the claim. It
// is never reported as a converged config.
func TestConvergeWriterReportsStartFailure(t *testing.T) {
	writer := &ConvergenceWriter{Spawner: spawnerFunc(
		func(context.Context, string, ...string) (int, error) { return 0, errors.New("no systemd") })}
	err := writer.ConvergeHandoffConfig(context.Background(),
		node.HandoffClaim{OperationID: strings.Repeat("e", 32), NewSHA256: strings.Repeat("f", 64)})
	if err == nil || codeOf(err) != "HANDOFF_CONVERGE_START_FAILED" {
		t.Fatalf("err = %v, want HANDOFF_CONVERGE_START_FAILED", err)
	}
}

// TestConvergeWriterWithoutRunner proves the nil seam is a refusal, not a panic:
// an unwired writer must never look like a successful convergence.
func TestConvergeWriterWithoutRunner(t *testing.T) {
	var writer *ConvergenceWriter
	if err := writer.ConvergeHandoffConfig(context.Background(), node.HandoffClaim{}); err == nil {
		t.Fatal("a nil writer reported success")
	}
	if err := (&ConvergenceWriter{}).ConvergeHandoffConfig(context.Background(), node.HandoffClaim{}); err == nil {
		t.Fatal("a writer without a spawner reported success")
	}
}

// The real-process proof that the spawn outlives the caller's cancellation.
//
// The Agent calls the writer from a bounded context and cancels it as soon as
// the call returns (`defer cancel()` in runtime_handoff.requestHandoffConvergence).
// Spawn is exec.CommandContext + Start, so a writer that handed that context
// down would SIGKILL the systemd-run helper at the cancel — after Start
// succeeded, so Spawn returns nil, nothing is logged, and convergence silently
// never happens. A fake spawner cannot observe that: only the real
// exec.CommandContext performs the kill.
//
// The helper below is the test binary itself, told to write a marker file after
// a delay. The test asserts the marker appears after the caller cancelled. The
// control case spawns the same helper through the same ctx WITHOUT the detach
// and asserts the marker does not appear, so the test is proven to have teeth.

const (
	convergeHelperEnv    = "MESHMUX_CONVERGE_HELPER"
	convergeHelperMarker = "MESHMUX_CONVERGE_MARKER"
	// convergeHelperDelay is long enough that the cancel in the control case
	// always lands while the helper is still alive (it is issued microseconds
	// after Start returns), and short enough to keep the suite quick.
	convergeHelperDelay = 500 * time.Millisecond
)

// TestConvergeHelperProcess is the fixture child. Without the environment
// marker it is skipped, so it never runs as an ordinary test.
func TestConvergeHelperProcess(t *testing.T) {
	if os.Getenv(convergeHelperEnv) != "1" {
		t.Skip("fixture child process")
	}
	marker := os.Getenv(convergeHelperMarker)
	if marker == "" {
		t.Fatal("fixture child has no marker path")
	}
	time.Sleep(convergeHelperDelay)
	if err := os.WriteFile(marker, []byte("submitted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The real helper would have submitted its unit and exited; exiting is
	// part of the contract (nothing waits for it).
}

func convergeHelperArgv(marker string) []string {
	return []string{os.Args[0], "-test.run=^TestConvergeHelperProcess$", "-test.timeout=60s"}
}

// TestConvergeSpawnOutlivesCallerCancel is the High-defect regression: after the
// caller cancels, the already-started helper still runs to completion.
func TestConvergeSpawnOutlivesCallerCancel(t *testing.T) {
	if os.Getenv(convergeHelperEnv) == "1" {
		t.Skip("fixture child process")
	}
	marker := filepath.Join(t.TempDir(), "converged")
	t.Setenv(convergeHelperMarker, marker)
	t.Setenv(convergeHelperEnv, "1") // inherited by the child

	// Mirror the Agent exactly: a bounded context, one call, then cancel.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	w := &ConvergenceWriter{Spawner: node.ExecRunner{}}
	if err := w.spawn(ctx, convergeHelperArgv(marker)); err != nil {
		cancel()
		t.Fatalf("spawn: %v", err)
	}
	cancel() // the caller's defer cancel(), immediately after the return

	waitForFile(t, marker, 10*time.Second, true, "the helper was killed by the caller's cancel")
}

// TestConvergeSpawnCancelControlKillsChild is the control that proves the
// previous test detects the defect: the same helper, through the same real
// boundary, but spawned on the caller's cancellable context (the pre-fix
// behaviour). The child dies at cancel and never writes its marker.
func TestConvergeSpawnCancelControlKillsChild(t *testing.T) {
	if os.Getenv(convergeHelperEnv) == "1" {
		t.Skip("fixture child process")
	}
	marker := filepath.Join(t.TempDir(), "converged")
	t.Setenv(convergeHelperMarker, marker)
	t.Setenv(convergeHelperEnv, "1")

	ctx, cancel := context.WithCancel(context.Background())
	runner := node.ExecRunner{}
	if _, err := runner.Spawn(ctx, convergeHelperArgv(marker)[0], convergeHelperArgv(marker)[1:]...); err != nil {
		cancel()
		t.Fatalf("spawn: %v", err)
	}
	cancel()
	waitForFile(t, marker, convergeHelperDelay+2*time.Second, false, "the undetached spawn survived its caller's cancel")
}

// waitForFile polls for a marker file. When want is true it fails if the file
// never appears; when false it fails if the file appears within the window.
func waitForFile(t *testing.T, path string, window time.Duration, want bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(window)
	for {
		_, err := os.Stat(path)
		if err == nil {
			if !want {
				t.Fatalf("%s: %s", failure, path)
			}
			return
		}
		if time.Now().After(deadline) {
			if want {
				t.Fatalf("%s: %v", failure, err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
