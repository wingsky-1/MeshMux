package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install"
)

func fail2banBaselineFailure() install.Check {
	return install.Check{
		Name: "fail2ban_baseline", Status: "fail", Code: install.CodeFail2banBaselineInvalid,
		Detail:   "fail2ban-client -t rejected the packaged configuration",
		Recovery: "Install rsyslog so /var/log/auth.log exists and re-run the install.",
	}
}

// TestNodeCLIFail2banBaselineRepairRequiresConfirmation pins the interactive
// contract: the operator sees the broken baseline before the pairing code is
// consumed, picks one repair explicitly, and the install continues only after
// that repair is re-verified by preflight.
func TestNodeCLIFail2banBaselineRepairRequiresConfirmation(t *testing.T) {
	code := strings.Repeat("A", 43)
	runner := &fakeNodeRunner{
		checks:            []install.Check{fail2banBaselineFailure(), {Name: "os", Status: "pass"}},
		ssh:               []int{2222},
		checksAfterRepair: []install.Check{{Name: "os", Status: "pass"}},
	}
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("1\ninstall edge\n" + code + "\n")
	if got := runWithDependencies(validNodeArgs("edge"), stdin, &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
	}
	if len(runner.repairs) != 1 || runner.repairs[0] != install.Fail2banRepairRsyslog {
		t.Fatalf("confirmed repairs = %v, want one rsyslog repair", runner.repairs)
	}
	if runner.preflights != 2 {
		t.Fatalf("preflights = %d, want 2 (before and after the repair)", runner.preflights)
	}
	if len(runner.installs) != 1 || runner.installs[0].code != code {
		t.Fatalf("installs = %+v, want one with the same code", runner.installs)
	}
	if !strings.Contains(stdout.String(), "Repair [1/2, empty=stop]") {
		t.Fatalf("stdout does not explain the repair choice: %s", stdout.String())
	}
}

// TestNodeCLIFail2banBaselineNeverRepairsWithoutConfirmation pins the refusal
// paths: --yes and an empty interactive answer both stop before any repair or
// install, and both carry the check's next_action.
func TestNodeCLIFail2banBaselineNeverRepairsWithoutConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{"--yes", append(validNodeArgs("edge"), "--yes"), ""},
		{"interactive stop", validNodeArgs("edge"), "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{
				checks: []install.Check{fail2banBaselineFailure(), {Name: "os", Status: "pass"}},
				ssh:    []int{2222},
			}
			var stdout, stderr bytes.Buffer
			if got := runWithDependencies(tc.args, strings.NewReader(tc.stdin), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
				t.Fatalf("exit = %d, want 3; stderr=%q", got, stderr.String())
			}
			if len(runner.repairs) != 0 || len(runner.installs) != 0 {
				t.Fatalf("an unconfirmed baseline changed the host: repairs=%v installs=%+v", runner.repairs, runner.installs)
			}
			if !strings.Contains(stderr.String(), install.CodeFail2banBaselineInvalid) ||
				!strings.Contains(stderr.String(), "rsyslog") {
				t.Fatalf("stderr does not carry the stable code and next_action: %q", stderr.String())
			}
		})
	}
}

// TestNodeCLIFail2banBaselineStageGateRepair covers the fresh host whose
// fail2ban was only installed during stage: the gate fails after the fixed
// packages, before pairing, and the same unconsumed code is reused after a
// confirmed repair.
func TestNodeCLIFail2banBaselineStageGateRepair(t *testing.T) {
	code := strings.Repeat("A", 43)
	baselineErr := &install.InstallError{
		Stage: "preflight", Code: install.CodeFail2banBaselineInvalid,
		Recovery: "Install rsyslog so /var/log/auth.log exists and re-run the install.",
	}
	runner := &fakeNodeRunner{
		checks:      []install.Check{{Name: "os", Status: "pass"}},
		ssh:         []int{2222},
		installErrs: []error{baselineErr},
		results:     []install.InstallResult{{Status: "failed"}, {Status: "installed"}},
	}
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("install edge\n" + code + "\n2\n")
	if got := runWithDependencies(validNodeArgs("edge"), stdin, &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
	}
	if len(runner.repairs) != 1 || runner.repairs[0] != install.Fail2banRepairSystemdBackend {
		t.Fatalf("confirmed repairs = %v, want one backend override", runner.repairs)
	}
	if len(runner.installs) != 2 {
		t.Fatalf("installs = %+v, want a retry after the repair", runner.installs)
	}
	for _, call := range runner.installs {
		if call.code != code {
			t.Fatalf("retry did not reuse the unconsumed code: %+v", runner.installs)
		}
	}
}

// TestNodeCLIFail2banBaselineStageGateRefusesWithYes keeps the Web/--yes
// contract: a stage-gate baseline failure is reported with its stable code and
// never becomes a prompt.
func TestNodeCLIFail2banBaselineStageGateRefusesWithYes(t *testing.T) {
	baselineErr := &install.InstallError{
		Stage: "preflight", Code: install.CodeFail2banBaselineInvalid,
		Recovery: "Install rsyslog so /var/log/auth.log exists and re-run the install.",
	}
	runner := &fakeNodeRunner{
		checks:      []install.Check{{Name: "os", Status: "pass"}},
		ssh:         []int{2222},
		installErrs: []error{baselineErr},
	}
	var stdout, stderr bytes.Buffer
	args := append(validNodeArgs("edge"), "--yes")
	if got := runWithDependencies(args, strings.NewReader(strings.Repeat("A", 43)+"\n"), &stdout, &stderr, runner, &fakeAgentService{}); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", got, stderr.String())
	}
	if len(runner.repairs) != 0 || len(runner.installs) != 1 {
		t.Fatalf("--yes prompted or repaired: repairs=%v installs=%+v", runner.repairs, runner.installs)
	}
	if !strings.Contains(stderr.String(), install.CodeFail2banBaselineInvalid) {
		t.Fatalf("stderr = %q, want the stable code", stderr.String())
	}
}
