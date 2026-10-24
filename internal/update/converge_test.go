package update

// The convergence writer (#11c-2 Task 5, binding carry from Task 4).
//
// The Agent holds the shared runtime lock when it asks for convergence, so the
// writer must SPAWN one transient unit and return — never run the /etc write
// inside the Agent's process and never wait for a repair that would take the
// same lock. The 15s context the Agent wraps around the call is the only guard.
// These tests pin the fixed argv and prove the call returns without waiting.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
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
