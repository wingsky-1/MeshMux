package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

type fakeNodeRunner struct {
	state       install.InstallState
	hasState    bool
	stateErr    error
	checks      []install.Check
	ssh         []int
	plan        install.NodePlan
	installErrs []error
	results     []install.InstallResult
	installs    []nodeInstallCall
	preflights  int
	reads       int
}

type nodeInstallCall struct {
	cfg               node.Config
	operationID       string
	repair            bool
	code              string
	nonInteractive    bool
	fromRecordedState bool
}

func (f *fakeNodeRunner) PreflightNode(context.Context, node.Config, bool) ([]install.Check, []int) {
	f.preflights++
	return f.checks, f.ssh
}

func (f *fakeNodeRunner) BuildNodePlanForRoot(_, _ string, cfg node.Config, _ string, checks []install.Check, ssh []int) install.NodePlan {
	if f.plan.Status == "" {
		status := "preflight_passed"
		applyAvailable := true
		for _, check := range checks {
			if check.Status == "fail" {
				status = "preflight_blocked"
				applyAvailable = false
				break
			}
		}
		return install.NodePlan{
			OperationID:    "plan-id",
			Stage:          "plan",
			Status:         status,
			Config:         cfg,
			Checks:         checks,
			SSHPPorts:      ssh,
			ApplyAvailable: applyAvailable,
		}
	}
	return f.plan
}

func (f *fakeNodeRunner) InstallNode(_ context.Context, cfg node.Config, operationID string, repair bool, code string, opts install.NodeApplyOptions) (install.InstallResult, error) {
	f.installs = append(f.installs, nodeInstallCall{cfg: cfg, operationID: operationID, repair: repair, code: code,
		nonInteractive: opts.NonInteractive, fromRecordedState: opts.FromRecordedState})
	var err error
	if len(f.installErrs) >= len(f.installs) {
		err = f.installErrs[len(f.installs)-1]
	}
	if len(f.results) >= len(f.installs) {
		return f.results[len(f.installs)-1], err
	}
	return install.InstallResult{OperationID: operationID, Stage: "apply", Status: "installed"}, err
}

func (f *fakeNodeRunner) ReadNodeState(string) (install.InstallState, bool, error) {
	f.reads++
	return f.state, f.hasState, f.stateErr
}

func validNodeArgs(role string) []string {
	return []string{
		"install", role,
		"--hub", "https://hub.example.invalid",
		"--node", strings.Repeat("a", 32),
		"--vless-port", "8443",
		"--ssh-port", "2222",
	}
}

func TestNodeCLIRejectsUnknownPairingFlagWithoutEcho(t *testing.T) {
	secret := "A43CharacterSecretThatMustNeverAppearInOutput123"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"pairing flag", []string{"--pairing-code", secret}},
		{"pairing equals", []string{"--pairing-code=" + secret}},
		{"token flag", []string{"--token", secret}},
		{"pairing before valid flags", append([]string{"--pairing-code", secret}, validNodeArgs("edge")[2:]...)},
		{"positional", []string{secret}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{checks: []install.Check{{Name: "os", Status: "pass"}}}
			var stdout, stderr bytes.Buffer
			args := validNodeArgs("edge")
			if !strings.Contains(tc.name, "before valid") {
				args = append(args, tc.args...)
			} else {
				args = append(args[:2], tc.args...)
			}
			if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 2 {
				t.Fatalf("exit = %d, want 2", got)
			}
			if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
				t.Fatal("CLI output echoed a rejected secret")
			}
			if runner.reads != 0 || runner.preflights != 0 || len(runner.installs) != 0 {
				t.Fatal("rejected arguments reached installer dependencies")
			}
		})
	}
}

func TestNodeCLIRejectsPlanWithMutatingFlags(t *testing.T) {
	for _, extra := range [][]string{{"--plan", "--yes"}, {"--plan", "--repair"}} {
		runner := &fakeNodeRunner{}
		var stdout, stderr bytes.Buffer
		args := append(validNodeArgs("edge"), extra...)
		if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 2 {
			t.Fatalf("exit = %d, want 2", got)
		}
		if runner.reads != 0 || runner.preflights != 0 || len(runner.installs) != 0 {
			t.Fatal("invalid plan mode reached installer dependencies")
		}
	}
}

func TestNodeCLIInvalidConfigAndPortsHaveNoSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing node", []string{"install", "edge", "--hub", "https://hub.example.invalid", "--vless-port", "8443", "--ssh-port", "2222"}},
		{"role conflict", []string{"install", "edge", "--hub", "https://hub.example.invalid", "--node", strings.Repeat("a", 32), "--vless-port", "8443", "--ssh-port", "2222", "out"}},
		{"zero port", []string{"install", "edge", "--hub", "https://hub.example.invalid", "--node", strings.Repeat("a", 32), "--vless-port", "0", "--ssh-port", "2222"}},
		{"same ports", []string{"install", "edge", "--hub", "https://hub.example.invalid", "--node", strings.Repeat("a", 32), "--vless-port", "2222", "--ssh-port", "2222"}},
		{"injected origin", []string{"install", "out", "--hub", "https://hub.example.invalid\nX", "--node", strings.Repeat("a", 32), "--vless-port", "8443", "--ssh-port", "2222"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{}
			var stdout, stderr bytes.Buffer
			if got := runWithDependencies(tc.args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr=%q", got, stderr.String())
			}
			if runner.reads != 0 || runner.preflights != 0 || len(runner.installs) != 0 {
				t.Fatal("invalid config reached installer dependencies")
			}
		})
	}
}

func TestNodeCLIPlanDoesNotConsumePairingCode(t *testing.T) {
	secret := strings.Repeat("A", pairingCodeLimit)
	runner := &fakeNodeRunner{checks: []install.Check{{Name: "os", Status: "pass"}}}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("edge"), "--plan")
	if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 0 {
		t.Fatal("--plan reached InstallNode")
	}
	if strings.Contains(stdout.String(), secret) {
		t.Fatal("--plan output contained stdin")
	}
}

func TestNodeCLIUnconfirmedOrBlockedDoesNotInstall(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdin  string
		checks []install.Check
		yes    bool
	}{
		{"unconfirmed", "", []install.Check{{Name: "os", Status: "pass"}}, false},
		{"wrong confirmation", "install out\n" + strings.Repeat("A", pairingCodeLimit) + "\n", []install.Check{{Name: "os", Status: "pass"}}, false},
		{"blocked with yes", strings.Repeat("A", pairingCodeLimit) + "\n", []install.Check{{Name: "os", Status: "fail"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{checks: tc.checks}
			var stdout, stderr bytes.Buffer
			args := validNodeArgs("edge")
			if tc.yes {
				args = append(args, "--yes")
			}
			if got := runWithDependencies(args, strings.NewReader(tc.stdin), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
				t.Fatalf("exit = %d, want 3", got)
			}
			if len(runner.installs) != 0 {
				t.Fatal("unconfirmed or blocked plan reached InstallNode")
			}
			if strings.Contains(stdout.String(), strings.Repeat("A", pairingCodeLimit)) {
				t.Fatal("stdin secret appeared in output")
			}
		})
	}
}

func TestNodeCLIStdinCodePassedOnlyToInstallNode(t *testing.T) {
	secret := strings.Repeat("A", pairingCodeLimit)
	runner := &fakeNodeRunner{checks: []install.Check{{Name: "os", Status: "pass"}}}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("out"), "--yes")
	if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 1 || runner.installs[0].code != secret {
		t.Fatal("pairing code was not passed once to InstallNode")
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("pairing code appeared in CLI output")
	}
	if strings.Contains(stdout.String(), "pairing_code") {
		t.Fatal("pairing code appeared in structured output")
	}
}

func TestNodeCLIReadsConfirmationAndCodeFromOneBufferedReader(t *testing.T) {
	secret := strings.Repeat("B", pairingCodeLimit)
	runner := &fakeNodeRunner{checks: []install.Check{{Name: "os", Status: "pass"}}}
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(validNodeArgs("edge"), strings.NewReader("install edge\n"+secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 1 || runner.installs[0].code != secret {
		t.Fatal("confirmation consumed or lost the following pairing code")
	}
}

func TestNodeCLIRepairReusesIdentityWithoutCode(t *testing.T) {
	cfg := node.Config{
		HubURL:    "https://hub.example.invalid",
		NodeID:    strings.Repeat("a", 32),
		Role:      node.RoleEdge,
		VLESSPort: 8443,
		SSHPort:   2222,
	}
	runner := &fakeNodeRunner{
		state:    install.InstallState{Node: &cfg},
		hasState: true,
		checks:   []install.Check{{Name: "os", Status: "pass"}},
	}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("edge"), "--repair", "--yes")
	if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 1 || runner.installs[0].code != "" || !runner.installs[0].repair {
		t.Fatal("repair did not make exactly one empty-code attempt")
	}
}

func TestNodeCLIRepairRequiresRecordedNodeState(t *testing.T) {
	hubConfig := install.Config{ManagementDomain: "hub.example.invalid"}
	for _, tc := range []struct {
		name     string
		state    install.InstallState
		hasState bool
	}{
		{"missing state", install.InstallState{}, false},
		{"hub state", install.InstallState{Config: hubConfig}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{state: tc.state, hasState: tc.hasState}
			var stdout, stderr bytes.Buffer
			args := append(validNodeArgs("edge"), "--repair", "--yes")
			if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
				t.Fatalf("exit = %d, want 3", got)
			}
			if runner.preflights != 0 || len(runner.installs) != 0 {
				t.Fatal("invalid repair state reached preflight or apply")
			}
		})
	}
}

func TestNodeCLIRepairPromptsOnlyWhenInstallerRequiresCode(t *testing.T) {
	cfg := node.Config{
		HubURL:    "https://hub.example.invalid",
		NodeID:    strings.Repeat("a", 32),
		Role:      node.RoleOut,
		VLESSPort: 8443,
		SSHPort:   2222,
	}
	secret := strings.Repeat("C", pairingCodeLimit)
	runner := &fakeNodeRunner{
		state:       install.InstallState{Node: &cfg},
		hasState:    true,
		checks:      []install.Check{{Name: "os", Status: "pass"}},
		installErrs: []error{&install.InstallError{Stage: "preflight", Code: "PAIRING_CODE_REQUIRED"}, nil},
	}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("out"), "--repair", "--yes")
	if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 2 || runner.installs[0].code != "" || runner.installs[1].code != secret {
		t.Fatal("repair retry did not receive the stdin pairing code")
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("repair pairing code appeared in output")
	}
}

func TestNodeCLIRejectsOversizedPairingCode(t *testing.T) {
	secret := strings.Repeat("D", pairingCodeLimit+1)
	runner := &fakeNodeRunner{checks: []install.Check{{Name: "os", Status: "pass"}}}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("edge"), "--yes")
	if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	if len(runner.installs) != 0 {
		t.Fatal("oversized pairing code reached InstallNode")
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("oversized pairing code appeared in output")
	}
}

func TestNodeCLIStructuredResultAndPartialExit(t *testing.T) {
	secret := strings.Repeat("F", pairingCodeLimit)
	runner := &fakeNodeRunner{
		checks: []install.Check{{Name: "os", Status: "pass"}},
		results: []install.InstallResult{{
			OperationID: "different-operation-id",
			Stage:       "verify",
			Status:      "partial",
			ErrorCode:   "READBACK_FAILED",
			Recovery:    "Inspect the data plane before retrying.",
		}},
	}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("edge"), "--yes")
	if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 1 {
		t.Fatalf("exit = %d, want 1", got)
	}
	output := stdout.String()
	for _, want := range []string{`"operation_id": "different-operation-id"`, `"stage": "verify"`, `"status": "partial"`, `"error_code": "READBACK_FAILED"`, `"next_action": "Inspect the data plane before retrying."`} {
		if !strings.Contains(output, want) {
			t.Fatalf("structured result missing %s: %s", want, output)
		}
	}
	if strings.Contains(output, secret) {
		t.Fatal("pairing code appeared in structured result")
	}
}

func TestNodeCLIInstallErrorOverridesStructuredFailure(t *testing.T) {
	secret := strings.Repeat("G", pairingCodeLimit)
	runner := &fakeNodeRunner{
		checks:      []install.Check{{Name: "os", Status: "pass"}},
		installErrs: []error{&install.InstallError{Stage: "apply", Code: "FILE_APPLY_FAILED", Recovery: "Inspect the journal and retry."}},
		results:     []install.InstallResult{{OperationID: "runner-id", Stage: "apply", Status: "failed", ErrorCode: "WRONG_CODE", Recovery: "wrong recovery"}},
	}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("out"), "--yes")
	if got := runWithDependencies(args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 1 {
		t.Fatalf("exit = %d, want 1", got)
	}
	for _, want := range []string{`"error_code": "FILE_APPLY_FAILED"`, `"stage": "apply"`, `"next_action": "Inspect the journal and retry."`} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("structured error missing %s: %s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "WRONG_CODE") || strings.Contains(stdout.String(), secret) {
		t.Fatal("CLI did not replace failure fields with the stable error")
	}
}

func TestNodeCLIRejectsCodeViaFlagButAcceptsItViaStdin(t *testing.T) {
	secret := strings.Repeat("E", pairingCodeLimit)
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"flag", append(validNodeArgs("edge"), "--yes", "--pairing-code", secret), 2},
		{"stdin", append(validNodeArgs("edge"), "--yes"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{checks: []install.Check{{Name: "os", Status: "pass"}}}
			var stdout, stderr bytes.Buffer
			if got := runWithDependencies(tc.args, strings.NewReader(secret+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != tc.want {
				t.Fatalf("exit = %d, want %d; stderr=%q", got, tc.want, stderr.String())
			}
			if tc.want == 2 && len(runner.installs) != 0 {
				t.Fatal("flag-provided pairing code reached InstallNode")
			}
			if tc.want == 0 && (len(runner.installs) != 1 || runner.installs[0].code != secret) {
				t.Fatal("stdin pairing code was not passed to InstallNode")
			}
			if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
				t.Fatal("pairing code appeared in output")
			}
		})
	}
}

func TestNodeCLIStateConflictDoesNotRunPreflight(t *testing.T) {
	cfg := node.Config{
		HubURL:    "https://hub.example.invalid",
		NodeID:    strings.Repeat("b", 32),
		Role:      node.RoleEdge,
		VLESSPort: 8443,
		SSHPort:   2222,
	}
	runner := &fakeNodeRunner{state: install.InstallState{Node: &cfg}, hasState: true}
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(validNodeArgs("edge"), strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
		t.Fatalf("exit = %d, want 3", got)
	}
	if runner.preflights != 0 || len(runner.installs) != 0 {
		t.Fatal("state conflict reached preflight or apply")
	}
}

type fakeAgentService struct {
	args   []string
	stderr io.Writer
	code   int
}

func (f *fakeAgentService) RunCommand(args []string, stderr io.Writer) int {
	f.args = append([]string(nil), args...)
	f.stderr = stderr
	return f.code
}

func TestInternalAgentDispatchIsExact(t *testing.T) {
	agent := &fakeAgentService{code: 17}
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies([]string{"__internal-agent", "--fixed-arg"}, strings.NewReader(""), &stdout, &stderr, &fakeNodeRunner{}, agent); got != 17 {
		t.Fatalf("exit = %d, want 17", got)
	}
	if len(agent.args) != 1 || agent.args[0] != "--fixed-arg" || agent.stderr != &stderr {
		t.Fatal("internal Agent arguments or stderr were not forwarded exactly")
	}
}

func TestInternalAgentVersionIsExactPrivateZeroArgOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies([]string{"__internal-agent-version"}, strings.NewReader(""), &stdout, &stderr, &fakeNodeRunner{}, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
	}
	if stdout.String() != node.CurrentAgentVersion()+"\n" {
		t.Fatalf("stdout = %q, want exact pinned version", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestInternalAgentVersionRejectsArgumentsWithoutEcho(t *testing.T) {
	secret := "must-not-be-echoed"
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies([]string{"__internal-agent-version", secret}, strings.NewReader(""), &stdout, &stderr, &fakeNodeRunner{}, &fakeAgentService{}); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if strings.Contains(stderr.String(), secret) {
		t.Fatal("internal version argument was echoed")
	}
}

func TestPairingRequiredOnlyAcceptsStableCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("PAIRING_CODE_REQUIRED"), false},
		{&install.InstallError{Code: "PAIRING_CODE_REQUIRED"}, true},
		{&install.InstallError{Code: "PAIRING_REQUIRED"}, true},
		{&install.InstallError{Code: "PAIRING_INVALID"}, false},
	} {
		if got := pairingRequired(tc.err); got != tc.want {
			t.Fatalf("pairingRequired(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
