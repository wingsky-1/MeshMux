package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

// TestInstallNonInteractiveRequiresConfirmAndRepair is the CLI half of the
// handoff contract: the flag exists only so the Web-driven handoff can pass it,
// and it is refused unless the run is a confirmed repair. It never becomes a
// second install mode and never prompts.
func TestInstallNonInteractiveRequiresConfirmAndRepair(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"without --yes", append(validNodeArgs("edge"), "--non-interactive")},
		{"without --repair", append(validNodeArgs("edge"), "--yes", "--non-interactive")},
		{"hub without --repair", []string{"install", "hub", "--management-domain", "console.example.org",
			"--subscription-domain", "sub.example.org", "--headscale-domain", "mesh.example.org",
			"--yes", "--non-interactive"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeNodeRunner{}
			var stdout, stderr bytes.Buffer
			if got := runWithDependencies(tc.args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 3 {
				t.Fatalf("exit = %d, want 3; stderr=%q", got, stderr.String())
			}
			if !strings.HasPrefix(stderr.String(), "UPDATE_INTERACTIVE_REFUSED") {
				t.Fatalf("stderr = %q, want UPDATE_INTERACTIVE_REFUSED", stderr.String())
			}
			if len(runner.installs) != 0 {
				t.Fatalf("refused run reached the installer: %+v", runner.installs)
			}
		})
	}
}

// TestInstallNonInteractivePassesThrough is the positive half: a confirmed
// repair carries the option (and the chain's operation ID) into the installer,
// and no pairing code is read.
func TestInstallNonInteractivePassesThrough(t *testing.T) {
	cfg := node.Config{HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222}
	runner := &fakeNodeRunner{state: install.InstallState{Node: &cfg}, hasState: true,
		checks: []install.Check{{Name: "os", Status: "pass"}}}
	operationID := strings.Repeat("c", 32)
	args := append(validNodeArgs("edge"), "--yes", "--repair", "--non-interactive", "--operation-id", operationID)
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", got, stderr.String())
	}
	if len(runner.installs) != 1 {
		t.Fatalf("installs = %+v", runner.installs)
	}
	if call := runner.installs[0]; !call.repair || call.code != "" || !call.nonInteractive || call.operationID != operationID {
		t.Fatalf("call = %+v, want a non-interactive repair carrying the chain operation ID", call)
	}
}

// TestInstallOperationIDIsValidated pins the carried ID rule: a malformed chain
// ID is refused before any state or journal path is derived from it.
func TestInstallOperationIDIsValidated(t *testing.T) {
	runner := &fakeNodeRunner{}
	args := append(validNodeArgs("edge"), "--yes", "--repair", "--operation-id", "../../etc")
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(args, strings.NewReader(""), &stdout, &stderr, runner, &fakeAgentService{}); got != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%q", got, stderr.String())
	}
	if runner.reads != 0 || len(runner.installs) != 0 {
		t.Fatal("a malformed operation ID reached installer dependencies")
	}
	if strings.Contains(stderr.String(), "../../etc") {
		t.Fatal("the rejected operation ID was echoed")
	}
}
