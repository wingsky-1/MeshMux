package main

// Task 5 of 11c-2: the recorded-state repair contract at the CLI boundary.
//
// The transient unit invokes the new package as
//
//	meshmux install <role> --repair --non-interactive --from-recorded-state --operation-id <op32hex>
//
// The public `install` surface does not gain a flag: both hidden inputs are
// consumed only by that fixed argv, they are refused outside it, and the
// recorded ledger (not argv) supplies the configuration. The exit code is a
// coarse bucket; the JSON result's error_code is the contract.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

func recordedNodeState(t *testing.T, role node.Role) (install.InstallState, string) {
	t.Helper()
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: role, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: node.CurrentAgentVersion(), AgentSHA256: strings.Repeat("b", 64),
		KernelSHA256: strings.Repeat("c", 64),
	}
	operationID := strings.Repeat("1", 32)
	return install.InstallState{
		Schema: 1, OperationID: operationID, LastOperation: operationID,
		Status: "installed", Node: &cfg, ManagedFiles: map[string]string{},
	}, operationID
}

func recordedStateArgs(role string, operationID string, extra ...string) []string {
	args := []string{
		"install", role,
		"--repair", "--non-interactive", "--from-recorded-state",
		"--operation-id", operationID,
	}
	return append(args, extra...)
}

// TestRecordedStateCLIDerivesConfigFromLedger pins contract 1: the handoff
// carries no Hub URL, node ID or ports, so the ledger supplies them. The
// positional role is kept (spec §6 omits it) and cross-checked against the
// ledger, because a role is the one input the transient unit can still name.
func TestRecordedStateCLIDerivesConfigFromLedger(t *testing.T) {
	state, operationID := recordedNodeState(t, node.RoleEdge)
	runner := &fakeNodeRunner{state: state, hasState: true,
		checks: []install.Check{{Name: "os", Status: "pass"}}}
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(recordedStateArgs("edge", operationID),
		strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 1 {
		t.Fatalf("installs = %+v", runner.installs)
	}
	call := runner.installs[0]
	if !call.repair || !call.nonInteractive || !call.fromRecordedState {
		t.Fatalf("call = %+v, want a recorded-state non-interactive repair", call)
	}
	if call.operationID != operationID {
		t.Fatalf("operation id = %q, want %q", call.operationID, operationID)
	}
	if call.cfg.HubURL != state.Node.HubURL || call.cfg.NodeID != state.Node.NodeID ||
		call.cfg.Role != state.Node.Role || call.cfg.VLESSPort != state.Node.VLESSPort ||
		call.cfg.SSHPort != state.Node.SSHPort {
		t.Fatalf("derived config = %+v, want the recorded %+v", call.cfg, *state.Node)
	}
	if call.code != "" {
		t.Fatalf("recorded-state run consumed a pairing code: %q", call.code)
	}
}

// TestRecordedStateCLIRejectsRoleMismatch keeps the co-located/role refusal:
// the positional role must be the recorded role, and a mismatched invocation
// never reaches preflight or apply.
func TestRecordedStateCLIRejectsRoleMismatch(t *testing.T) {
	state, operationID := recordedNodeState(t, node.RoleEdge)
	runner := &fakeNodeRunner{state: state, hasState: true}
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(recordedStateArgs("out", operationID),
		strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 5 {
		t.Fatalf("exit = %d, want 5; stderr=%q", got, stderr.String())
	}
	if !strings.HasPrefix(stderr.String(), "CONFIG_CONFLICT") {
		t.Fatalf("stderr = %q, want CONFIG_CONFLICT", stderr.String())
	}
	if runner.preflights != 0 || len(runner.installs) != 0 {
		t.Fatal("a mismatched recorded role reached preflight or apply")
	}
}

// TestRecordedStateCLIRequiresRecordedLedgerAndOperation pins contracts 1 and
// 2: the mode needs an operation ID and a recorded Node ledger, and both are
// refused before any host read.
func TestRecordedStateCLIRequiresRecordedLedgerAndOperation(t *testing.T) {
	t.Run("missing operation", func(t *testing.T) {
		runner := &fakeNodeRunner{}
		var stdout, stderr bytes.Buffer
		args := []string{"install", "edge", "--repair", "--non-interactive", "--from-recorded-state"}
		// A missing mandatory input is a precondition failure (5), never the
		// interaction/state bucket.
		if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 5 {
			t.Fatalf("exit = %d, want 5; stderr=%q", got, stderr.String())
		}
		if !strings.HasPrefix(stderr.String(), "OPERATION_REQUIRED") {
			t.Fatalf("stderr = %q, want OPERATION_REQUIRED", stderr.String())
		}
		if runner.reads != 0 || runner.preflights != 0 || len(runner.installs) != 0 {
			t.Fatal("a missing operation ID reached installer dependencies")
		}
	})
	t.Run("missing ledger", func(t *testing.T) {
		runner := &fakeNodeRunner{}
		var stdout, stderr bytes.Buffer
		// A missing recorded ledger is the state bucket (3).
		if got := runWithDependencies(recordedStateArgs("edge", strings.Repeat("2", 32)),
			strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
			t.Fatalf("exit = %d, want 3; stderr=%q", got, stderr.String())
		}
		if !strings.HasPrefix(stderr.String(), "REPAIR_STATE_MISSING") {
			t.Fatalf("stderr = %q, want REPAIR_STATE_MISSING", stderr.String())
		}
		if runner.preflights != 0 || len(runner.installs) != 0 {
			t.Fatal("a missing ledger reached preflight or apply")
		}
	})
	t.Run("without repair", func(t *testing.T) {
		runner := &fakeNodeRunner{}
		var stdout, stderr bytes.Buffer
		args := []string{"install", "edge", "--non-interactive", "--from-recorded-state",
			"--operation-id", strings.Repeat("3", 32)}
		if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
			t.Fatalf("exit = %d, want 3; stderr=%q", got, stderr.String())
		}
		if !strings.HasPrefix(stderr.String(), "UPDATE_INTERACTIVE_REFUSED") {
			t.Fatalf("stderr = %q, want UPDATE_INTERACTIVE_REFUSED", stderr.String())
		}
	})
}

// TestRecordedStateCLIPairingCodeOnlyFromOperatorFile pins contract 4: the only
// acceptable fresh identity input is an operator-placed 0600 file, read once and
// never auto-discovered. A missing or unsafe file is a terminal refusal, and no
// stdin is ever consumed on this path.
func TestRecordedStateCLIPairingCodeOnlyFromOperatorFile(t *testing.T) {
	code := strings.Repeat("A", 43)
	state, operationID := recordedNodeState(t, node.RoleEdge)
	t.Run("operator file is passed through", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pairing-code")
		if err := os.WriteFile(path, []byte(code+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		runner := &fakeNodeRunner{state: state, hasState: true,
			checks: []install.Check{{Name: "os", Status: "pass"}}}
		var stdout, stderr bytes.Buffer
		args := recordedStateArgs("edge", operationID, "--pairing-code-file", path)
		if got := runWithDependencies(args, strings.NewReader(strings.Repeat("Z", 43)),
			&stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
			t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
		}
		if len(runner.installs) != 1 || runner.installs[0].code != code {
			t.Fatalf("installs = %+v, want the operator file's code", runner.installs)
		}
	})
	t.Run("unsafe file is refused", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			setup func(string) error
		}{
			{"missing", func(string) error { return nil }},
			{"public mode", func(path string) error { return os.WriteFile(path, []byte(code), 0644) }},
			{"not a code", func(path string) error { return os.WriteFile(path, []byte("short"), 0600) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "pairing-code")
				if err := tc.setup(path); err != nil {
					t.Fatal(err)
				}
				runner := &fakeNodeRunner{state: state, hasState: true}
				var stdout, stderr bytes.Buffer
				args := recordedStateArgs("edge", operationID, "--pairing-code-file", path)
				if got := runWithDependencies(args, strings.NewReader(""),
					&stdout, &stderr, runner, &fakeAgentService{}); got != 5 {
					t.Fatalf("exit = %d, want 5; stderr=%q", got, stderr.String())
				}
				if !strings.HasPrefix(stderr.String(), "PAIRING_CODE_INVALID") {
					t.Fatalf("stderr = %q, want PAIRING_CODE_INVALID", stderr.String())
				}
				if len(runner.installs) != 0 {
					t.Fatal("an unsafe pairing file reached the installer")
				}
			})
		}
	})
	t.Run("file flag outside the hidden family", func(t *testing.T) {
		runner := &fakeNodeRunner{state: state, hasState: true}
		var stdout, stderr bytes.Buffer
		args := append(validNodeArgs("edge"), "--repair", "--yes", "--pairing-code-file", "/tmp/x")
		if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 2 {
			t.Fatalf("exit = %d, want 2; stderr=%q", got, stderr.String())
		}
		if len(runner.installs) != 0 {
			t.Fatal("the hidden pairing flag reached the public install path")
		}
	})
}

// TestRecordedStateCLIExitMap pins contract 8: 0 installed only, 3 for the
// interactive/state bucket, 4 for UPDATE_REENROLL_REQUIRED, 5 for a
// precondition failure and 6 for lock retry exhaustion. In every case the JSON
// error_code is the stable code, never the exit bucket.
func TestRecordedStateCLIExitMap(t *testing.T) {
	state, operationID := recordedNodeState(t, node.RoleEdge)
	for _, tc := range []struct {
		name   string
		err    error
		result install.InstallResult
		want   int
		code   string
	}{
		{"installed", nil, install.InstallResult{Status: "installed"}, 0, ""},
		{"interactive", &install.InstallError{Stage: "preflight", Code: "UPDATE_INTERACTIVE_REFUSED"},
			install.InstallResult{Status: "failed"}, 3, "UPDATE_INTERACTIVE_REFUSED"},
		{"reenroll", &install.InstallError{Stage: "stage", Code: "UPDATE_REENROLL_REQUIRED"},
			install.InstallResult{Status: "failed"}, 4, "UPDATE_REENROLL_REQUIRED"},
		{"drift", &install.InstallError{Stage: "preflight", Code: "MANAGED_FILE_DRIFT"},
			install.InstallResult{Status: "failed"}, 5, "MANAGED_FILE_DRIFT"},
		{"exhausted", &install.InstallError{Stage: "preflight", Code: "UPDATE_RETRY_EXHAUSTED"},
			install.InstallResult{Status: "failed"}, 6, "UPDATE_RETRY_EXHAUSTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{state: state, hasState: true,
				checks:      []install.Check{{Name: "os", Status: "pass"}},
				installErrs: []error{tc.err},
				results:     []install.InstallResult{tc.result}}
			var stdout, stderr bytes.Buffer
			got := runWithDependencies(recordedStateArgs("edge", operationID),
				strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{})
			if got != tc.want {
				t.Fatalf("exit = %d, want %d; stderr=%q", got, tc.want, stderr.String())
			}
			if tc.code == "" {
				if strings.Contains(stdout.String(), `"status": "failed"`) {
					t.Fatalf("installed result reported failed: %s", stdout.String())
				}
				return
			}
			if !strings.Contains(stdout.String(), `"error_code": "`+tc.code+`"`) {
				t.Fatalf("JSON error_code is not authoritative: %s", stdout.String())
			}
		})
	}
}

// TestRecordedStateCLIStructuredRefusals pins that a recorded-state run which
// stops before the plan still leaves one JSON result with the stable code: the
// transient unit's result file records only the coarse exit code, so the code
// must be on stdout too.
func TestRecordedStateCLIStructuredRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*fakeNodeRunner)
		args   []string
		code   string
		exit   int
		opSeen bool
	}{
		{"missing ledger", func(*fakeNodeRunner) {}, recordedStateArgs("edge", strings.Repeat("7", 32)),
			"REPAIR_STATE_MISSING", 3, true},
		{"ledger read failure", func(r *fakeNodeRunner) {
			r.stateErr = &install.InstallError{Stage: "preflight", Code: "INSTALL_STATE_INVALID"}
		}, recordedStateArgs("edge", strings.Repeat("8", 32)), "INSTALL_STATE_INVALID", 5, true},
		{"role mismatch", func(r *fakeNodeRunner) {
			state, _ := recordedNodeState(t, node.RoleEdge)
			r.state, r.hasState = state, true
		}, recordedStateArgs("out", strings.Repeat("9", 32)), "CONFIG_CONFLICT", 5, true},
		{"invalid operation id", func(r *fakeNodeRunner) {
			state, _ := recordedNodeState(t, node.RoleEdge)
			r.state, r.hasState = state, true
		}, recordedStateArgs("edge", "../../etc"), "OPERATION_ID_INVALID", 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{}
			tc.setup(runner)
			var stdout, stderr bytes.Buffer
			if got := runWithDependencies(tc.args, strings.NewReader(""), &stdout, &stderr,
				runner, &fakeAgentService{}); got != tc.exit {
				t.Fatalf("exit = %d, want %d; stderr=%q", got, tc.exit, stderr.String())
			}
			var result install.InstallResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("stdout is not one JSON result: %v (%q)", err, stdout.String())
			}
			if result.ErrorCode != tc.code || result.Status != "failed" {
				t.Fatalf("structured refusal = %+v, want failed/%s", result, tc.code)
			}
			if tc.opSeen && result.OperationID == "" {
				t.Fatalf("a valid operation ID was dropped from the refusal: %+v", result)
			}
			if !tc.opSeen && result.OperationID != "" {
				t.Fatalf("a rejected operation ID was echoed: %+v", result)
			}
			if len(runner.installs) != 0 {
				t.Fatal("a pre-plan refusal reached the installer")
			}
		})
	}
}

// TestRecordedStateCLIAcceptsTheTransientArgv is the cross-task gate: the exact
// argv Task 3's runInternalUpdateInstall builds
//
//	install <role> --repair --non-interactive --from-recorded-state --operation-id <op>
//
// carries no --yes, no Hub URL, no node ID and no ports, and must still reach
// the installer. Every earlier gate in runNodeInstall (unknown flag, --yes
// requirement, config validation, SameNodeConfig, confirmation prompt) has to
// keep its behaviour for the public surface while this fixed shape passes.
func TestRecordedStateCLIAcceptsTheTransientArgv(t *testing.T) {
	state, _ := recordedNodeState(t, node.RoleOut)
	operationID := strings.Repeat("d", 32)
	runner := &fakeNodeRunner{state: state, hasState: true,
		checks: []install.Check{{Name: "os", Status: "pass"}}}
	var stdout, stderr bytes.Buffer
	argv := []string{"install", "out", "--repair", "--non-interactive",
		"--from-recorded-state", "--operation-id", operationID}
	if got := runWithDependencies(argv, strings.NewReader(""), &stdout, &stderr,
		runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 1 {
		t.Fatalf("installs = %+v", runner.installs)
	}
	if runner.installs[0].cfg.Role != node.RoleOut || runner.installs[0].operationID != operationID {
		t.Fatalf("call = %+v", runner.installs[0])
	}
	if stdout.Len() == 0 || !strings.Contains(stdout.String(), `"status": "installed"`) {
		t.Fatalf("the transient argv produced no installed result: %s", stdout.String())
	}
}

// panicReader fails the test if anything reads stdin on the handoff path.
type panicReader struct{ t *testing.T }

func (r panicReader) Read([]byte) (int, error) {
	r.t.Fatal("the recorded-state handoff read stdin")
	return 0, nil
}

// TestRecordedStateCLINeverReadsStdin pins "no stdin ever": not for the plan
// confirmation, not for a pairing code, and not on any refusal path. The
// transient unit has no terminal, so a read would block or steal EOF.
func TestRecordedStateCLINeverReadsStdin(t *testing.T) {
	state, _ := recordedNodeState(t, node.RoleEdge)
	operationID := strings.Repeat("e", 32)
	for _, tc := range []struct {
		name  string
		state install.InstallState
		has   bool
		args  []string
	}{
		{"installed", state, true, recordedStateArgs("edge", operationID)},
		{"missing ledger", install.InstallState{}, false, recordedStateArgs("edge", operationID)},
		{"blocked preflight", state, true, recordedStateArgs("edge", operationID)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{state: tc.state, hasState: tc.has,
				checks: []install.Check{{Name: "os", Status: "pass"}}}
			if tc.name == "blocked preflight" {
				runner.checks = []install.Check{{Name: "os", Status: "fail", Code: "OS_UNSUPPORTED"}}
			}
			var stdout, stderr bytes.Buffer
			runWithDependencies(tc.args, panicReader{t: t}, &stdout, &stderr,
				runner, &fakeAgentService{})
			if len(runner.installs) > 1 || (len(runner.installs) == 1 && runner.installs[0].code != "") {
				t.Fatalf("a pairing code was passed on the handoff path: %+v", runner.installs)
			}
		})
	}
}

// TestPublicInstallUsageOmitsHiddenHandoffInputs pins "zero public surface":
// the recorded-state inputs are parsed only for the fixed hidden argv and never
// documented as public install options.
func TestPublicInstallUsageOmitsHiddenHandoffInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(nil, strings.NewReader(""), &stdout, &stderr,
		&fakeNodeRunner{}, &fakeAgentService{}); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	usage := stdout.String() + stderr.String()
	for _, hidden := range []string{"from-recorded-state", "pairing-code-file", "operation-id", "non-interactive"} {
		if strings.Contains(usage, hidden) {
			t.Fatalf("public usage documents the hidden handoff input %q: %s", hidden, usage)
		}
	}
}
