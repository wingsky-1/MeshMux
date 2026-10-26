package install

// Task 5 of 11c-2: the nine contracts of an unattended repair.
//
// The transient unit runs the new package as
//
//	install <role> --repair --non-interactive --from-recorded-state --operation-id <op32hex>
//
// with no terminal and no stdin. A repair must therefore be complete without
// an operator: the recorded ledger supplies the configuration, the recorded
// identity is reused or the run ends terminally, a fresh code may only come
// from an operator-placed file, drift is refused before any mutation, a held
// lock is retried for a bounded window, a co-located Line keeps its refusal,
// failures map to four coarse exit buckets, and re-entering the same operation
// is an idempotent redo recorded in the journal.
//
// Every test is fixture-rooted: no host file, unit or lock is touched.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

func nonInteractiveRepair(t *testing.T, f *nodeFixture, operationID string, opts NodeApplyOptions) (InstallResult, error) {
	t.Helper()
	opts.NonInteractive = true
	opts.FromRecordedState = true
	return InstallNode(context.Background(), f.cfg, operationID, true, "", opts)
}

// fixtureReadback returns the readback the fixture kernel would report for the
// active candidate: the compiled config digest is what the LKG readback
// compares against, so a repair after a completed install must answer it.
func fixtureReadback(t *testing.T, f *nodeFixture) func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
	t.Helper()
	compiled, err := node.CompileCandidate(f.candidate.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	digest := sumBytes(compiled)
	return func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
		return node.Readback{
			Architecture: "amd64", AgentVersion: node.CurrentAgentVersion(),
			AgentSHA256: strings.Repeat("b", 64), KernelVersion: node.KernelVersion,
			KernelSHA256: strings.Repeat("c", 64), ActiveRevision: f.candidate.Revision,
			ConfigSHA256: digest, LocalActive: true,
			OutDefaultDeny: f.cfg.Role == node.RoleOut,
		}, nil
	}
}

// TestNonInteractive2RecordedStateNeedsNoOperator is contract 1: a recorded
// installation repairs itself from the ledger with no prompt, no pairing code
// and no stdin, and the recorded identity is reused instead of replaced.
func TestNonInteractive2RecordedStateNeedsNoOperator(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install: %v", err)
	}
	pairs := 0
	opts := f.opts
	opts.Pair = func(context.Context, node.Config, string) (node.Identity, error) {
		pairs++
		return node.Identity{}, errors.New("an unattended repair must not pair")
	}
	opts.Readback = fixtureReadback(t, f)
	result, err := nonInteractiveRepair(t, f, strings.Repeat("b", 32), opts)
	if err != nil || result.Status != "installed" {
		t.Fatalf("recorded-state repair = %+v, %v", result, err)
	}
	if pairs != 0 {
		t.Fatalf("unattended repair paired %d times", pairs)
	}
	state, _, _ := ReadState(f.root)
	if state.OperationID != strings.Repeat("b", 32) || state.Status != "installed" {
		t.Fatalf("ledger after repair = %+v", state)
	}
}

// TestNonInteractive2OperationIDMandatory is contract 2: every mutation carries
// a valid operation ID, and an invalid one is refused before any host read.
func TestNonInteractive2OperationIDMandatory(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	for _, operationID := range []string{"", "not-an-operation", strings.Repeat("A", 32)} {
		result, err := nonInteractiveRepair(t, f, operationID, f.opts)
		var ie *InstallError
		if !errors.As(err, &ie) || ie.Code != "OPERATION_ID_INVALID" {
			t.Fatalf("operation %q = %+v, %v, want OPERATION_ID_INVALID", operationID, result, err)
		}
		if len(f.runner.calls) != 0 {
			t.Fatalf("invalid operation ID reached the host: %v", f.runner.calls)
		}
	}
}

// TestNonInteractive2IdentityIsTerminal is contract 3: a revoked (401), missing
// or invalid recorded identity ends the unattended run with the terminal
// UPDATE_REENROLL_REQUIRED. It never falls back to a prompt and never asks for
// a fresh code by itself.
func TestNonInteractive2IdentityIsTerminal(t *testing.T) {
	t.Run("revoked identity", func(t *testing.T) {
		f := makeNodeFixture(t, node.RoleEdge)
		if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
			t.Fatal(err)
		}
		f.opts.Metadata = func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
			return node.Metadata{}, &node.ClientError{Code: "UNAUTHORIZED", StatusCode: 401}
		}
		result, err := nonInteractiveRepair(t, f, strings.Repeat("c", 32), f.opts)
		ie, ok := err.(*InstallError)
		if !ok || ie.Code != "UPDATE_REENROLL_REQUIRED" {
			t.Fatalf("revoked identity = %+v, %v, want UPDATE_REENROLL_REQUIRED", result, err)
		}
		if result.Status == "installed" {
			t.Fatalf("the terminal identity refusal claimed installed: %+v", result)
		}
	})
	t.Run("missing identity", func(t *testing.T) {
		f := makeNodeFixture(t, node.RoleEdge)
		if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(rooted(f.root, node.IdentityPath)); err != nil {
			t.Fatal(err)
		}
		_, err := nonInteractiveRepair(t, f, strings.Repeat("d", 32), f.opts)
		var ie *InstallError
		if !errors.As(err, &ie) || ie.Code != "UPDATE_REENROLL_REQUIRED" {
			t.Fatalf("missing identity = %v, want UPDATE_REENROLL_REQUIRED", err)
		}
	})
	t.Run("invalid identity", func(t *testing.T) {
		f := makeNodeFixture(t, node.RoleEdge)
		if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rooted(f.root, node.IdentityPath), []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := nonInteractiveRepair(t, f, strings.Repeat("e", 32), f.opts)
		var ie *InstallError
		if !errors.As(err, &ie) || ie.Code != "UPDATE_REENROLL_REQUIRED" {
			t.Fatalf("invalid identity = %v, want UPDATE_REENROLL_REQUIRED", err)
		}
	})
}

// TestNonInteractive2PairingCodeOnlyFromOperatorFile is contract 4: when the
// operator has placed a fresh code, the hidden family passes it in and the run
// replaces the revoked identity; without that file the identity is lost and the
// run is terminal. There is no automatic fetch and no pairing-code prompt.
func TestNonInteractive2PairingCodeOnlyFromOperatorFile(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	fresh := strings.Repeat("B", 43)
	pairs := 0
	f.opts.Pair = func(_ context.Context, _ node.Config, code string) (node.Identity, error) {
		pairs++
		if code != fresh {
			t.Fatalf("pairing code = %q, want the operator file's", code)
		}
		return f.identity, nil
	}
	opts := f.opts
	opts.NonInteractive, opts.FromRecordedState = true, true
	opts.Readback = fixtureReadback(t, f)
	result, err := InstallNode(context.Background(), f.cfg, strings.Repeat("f", 32), true, fresh, opts)
	if err != nil || result.Status != "installed" {
		t.Fatalf("operator-code repair = %+v, %v", result, err)
	}
	if pairs != 1 {
		t.Fatalf("pair calls = %d, want exactly one", pairs)
	}
}

// TestNonInteractive2LedgerAndAgentConfigMustAgree pins the I8 comparison: the
// ledger's AgentVersion/AgentSHA256 and agent.json's same fields must name one
// build. Any disagreement is CONFIG_CONFLICT before the apply, because the
// handoff cannot prove which build it is repairing from.
func TestNonInteractive2LedgerAndAgentConfigMustAgree(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*node.Config)
	}{
		{"other digest", func(cfg *node.Config) { cfg.AgentSHA256 = strings.Repeat("9", 64) }},
		{"other version", func(cfg *node.Config) { cfg.AgentVersion = "0.0.1" }},
		{"missing digest", func(cfg *node.Config) { cfg.AgentSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeNodeFixture(t, node.RoleEdge)
			if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
				t.Fatal(err)
			}
			onDisk := f.cfg
			onDisk.AgentSHA256 = sumBytes([]byte("fixture MeshMux Agent executable"))
			tc.mutate(&onDisk)
			body, err := json.MarshalIndent(onDisk, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(rooted(f.root, node.AgentConfigPath), append(body, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			callsBefore := len(f.runner.calls)
			result, err := nonInteractiveRepair(t, f, strings.Repeat("6", 32), f.opts)
			var ie *InstallError
			if !errors.As(err, &ie) || ie.Code != "CONFIG_CONFLICT" {
				t.Fatalf("mismatched pair = %+v, %v, want CONFIG_CONFLICT", result, err)
			}
			if result.Status != "failed" || result.Stage != "preflight" {
				t.Fatalf("mismatch result = %+v", result)
			}
			if len(f.runner.calls) != callsBefore {
				t.Fatalf("the mismatch refusal ran host commands: %v", f.runner.calls[callsBefore:])
			}
		})
	}
}

// TestNonInteractive2DriftIsRefusedBeforeApply is contract 5: a recorded file
// that changed outside the installer is MANAGED_FILE_DRIFT, refused before any
// file is replaced, so the unattended run cannot overwrite an operator's edit.
func TestNonInteractive2DriftIsRefusedBeforeApply(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	drifted := rooted(f.root, "/etc/systemd/system/"+node.AgentUnit)
	if err := os.WriteFile(drifted, []byte("# operator edit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before, exists, err := ReadState(f.root)
	if err != nil || !exists {
		t.Fatal(err)
	}
	callsBefore := len(f.runner.calls)
	result, err := nonInteractiveRepair(t, f, strings.Repeat("1", 32), f.opts)
	var ie *InstallError
	if !errors.As(err, &ie) || ie.Code != "MANAGED_FILE_DRIFT" {
		t.Fatalf("drift = %+v, %v, want MANAGED_FILE_DRIFT", result, err)
	}
	if result.Status != "failed" || result.Stage != "preflight" {
		t.Fatalf("drift result = %+v", result)
	}
	after, _ := os.ReadFile(drifted)
	if string(after) != "# operator edit\n" {
		t.Fatalf("the drift refusal rewrote the file: %q", after)
	}
	current, _, _ := ReadState(f.root)
	if current.Status != before.Status || !current.UpdatedAt.Equal(before.UpdatedAt) ||
		current.OperationID != before.OperationID {
		t.Fatalf("the drift refusal mutated the ledger: was %+v, now %+v", before, current)
	}
	for _, call := range f.runner.calls[callsBefore:] {
		if strings.Contains(call, "systemctl start") || strings.Contains(call, "systemctl restart") ||
			strings.Contains(call, "systemctl enable") || strings.Contains(call, "daemon-reload") {
			t.Fatalf("drift refusal reached a mutating command: %v", f.runner.calls[callsBefore:])
		}
	}
}

// TestNonInteractive2LockRetryExhausted is contract 6: the unattended path waits
// for the bounded install lock window (60s in production) and then reports
// UPDATE_RETRY_EXHAUSTED without touching the ledger. INTERACTIVE runs keep the
// immediate INSTALL_BUSY refusal.
func TestNonInteractive2LockRetryExhausted(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(rooted(f.root, installerStatePath))
	if err != nil {
		t.Fatal(err)
	}
	held, lockErr := acquireInstallLock(f.root, testLockRecovery)
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	defer held.Close()
	if installLockWait != 60*time.Second {
		t.Fatalf("production lock wait = %v, want the 60s bound (D7)", installLockWait)
	}
	opts := f.opts
	opts.NonInteractive, opts.FromRecordedState = true, true
	opts.LockWait = 50 * time.Millisecond
	started := time.Now()
	result, err := InstallNode(context.Background(), f.cfg, strings.Repeat("2", 32), true, "", opts)
	var ie *InstallError
	if !errors.As(err, &ie) || ie.Code != "UPDATE_RETRY_EXHAUSTED" {
		t.Fatalf("held lock = %+v, %v, want UPDATE_RETRY_EXHAUSTED", result, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("lock retry took %v, want the configured bound", elapsed)
	}
	after, err := os.ReadFile(rooted(f.root, installerStatePath))
	if err != nil || string(after) != string(before) {
		t.Fatalf("lock exhaustion mutated the ledger: %v", err)
	}
	// The interactive path is unchanged: it still fails at once with
	// INSTALL_BUSY instead of waiting.
	if _, err := InstallNode(context.Background(), f.cfg, strings.Repeat("3", 32), true, "", f.opts); err == nil {
		t.Fatal("an interactive run accepted a held install lock")
	} else if ie, ok := err.(*InstallError); !ok || ie.Code != "INSTALL_BUSY" {
		t.Fatalf("interactive held lock = %v, want INSTALL_BUSY", err)
	}
}

// TestNonInteractive2CoLocatedRefusalKept is contract 7: a co-located Line still
// refuses a shared runtime that no longer matches its pin, even in the
// unattended recorded-state mode. It never replaces the Hub-owned binary.
func TestNonInteractive2CoLocatedRefusalKept(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("co-located install: %v", err)
	}
	shared := rooted(f.root, runtimeBinaryPath)
	if err := os.WriteFile(shared, []byte("operator replaced the shared runtime"), 0755); err != nil {
		t.Fatal(err)
	}
	opts := f.opts
	opts.NonInteractive, opts.FromRecordedState = true, true
	result, err := InstallNode(context.Background(), f.cfg, strings.Repeat("4", 32), true, "", opts)
	var ie *InstallError
	if !errors.As(err, &ie) || ie.Code != "SHARED_BINARY_MISMATCH" {
		t.Fatalf("co-located mismatch = %+v, %v, want SHARED_BINARY_MISMATCH", result, err)
	}
	after, readErr := os.ReadFile(shared)
	if readErr != nil || string(after) != "operator replaced the shared runtime" {
		t.Fatalf("the Line rewrote the Hub-owned runtime: %q, %v", after, readErr)
	}
}

// TestNonInteractive2SameOperationRedo is contract 9: the same operation
// re-entered after a partial attempt is an idempotent redo. It is not a
// conflict; the journal records the redo for audit and the ledger ends
// installed under the same operation ID.
func TestNonInteractive2SameOperationRedo(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	operationID := strings.Repeat("5", 32)
	f.opts.Metadata = func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
		return node.Metadata{}, errors.New("hub unavailable")
	}
	first, err := InstallNode(context.Background(), f.cfg, operationID, false, strings.Repeat("A", 43), f.opts)
	if err == nil || first.Status != "partial" {
		t.Fatalf("first attempt = %+v, %v, want partial", first, err)
	}
	f.opts.Metadata = func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
		return f.cfg.Metadata(), nil
	}
	opts := f.opts
	opts.NonInteractive, opts.FromRecordedState = true, true
	second, err := InstallNode(context.Background(), f.cfg, operationID, true, "", opts)
	if err != nil || second.Status != "installed" {
		t.Fatalf("same-operation redo = %+v, %v", second, err)
	}
	state, _, readErr := ReadState(f.root)
	if readErr != nil || state.Status != "installed" || state.OperationID != operationID {
		t.Fatalf("ledger after redo = %+v, %v", state, readErr)
	}
	journalPath := filepath.Join(f.root, "var/lib/meshmux-installer/operations", operationID, "events.jsonl")
	data, readErr := os.ReadFile(journalPath)
	if readErr != nil {
		t.Fatalf("redo journal: %v", readErr)
	}
	events := 0
	started := 0
	redo := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var event operationEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		if event.OperationID != operationID {
			t.Fatalf("journal event names another operation: %+v", event)
		}
		events++
		if event.Stage == "stage" && event.Status == "started" {
			started++
		}
		if event.Stage == "stage" && event.Status == "idempotent_redo" {
			redo = true
		}
	}
	if events < 2 || started < 2 || !redo {
		t.Fatalf("journal events = %d, started = %d, redo marker = %v: %s", events, started, redo, data)
	}
}
