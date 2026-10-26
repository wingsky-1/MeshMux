package rootexec

// The Line half is optional: a standalone Hub has no co-located Line ledger,
// so only the Hub ledger pins move. The test also proves agent.json is not
// touched when there is no Line to re-pin.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

func TestLineRepinWithoutLine(t *testing.T) {
	f := newUpdateFixture(t)
	agentBefore, err := os.ReadFile(f.agentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.lineLedgerPath); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{lineActive: true}
	if err := RunUpdate(context.Background(), f.config(), runner); err != nil {
		t.Fatal(err)
	}
	hub, _, err := install.ReadState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if got := hub.SharedBinaries[sharedAgentKey].SHA256; got != f.newSHA {
		t.Fatalf("Hub shared pin = %q", got)
	}
	if got := hub.ManagedFiles[node.AgentBinaryPath]; got != f.newSHA {
		t.Fatalf("Hub managed pin = %q", got)
	}
	agentAfter, err := os.ReadFile(f.agentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(agentAfter) != string(agentBefore) {
		t.Fatal("agent.json changed without a co-located Line")
	}
	if runner.restarted(lineUnit) {
		t.Fatalf("restarted a nonexistent Line: %v", runner.calls)
	}
}

// TestWritePinsRenameFailureRestoresExactBytes is the direct all-or-nothing
// proof: the Hub and Line ledgers are renamed before the failure, and the
// captured old bytes (including Line updated_at) come back unchanged.
func TestWritePinsRenameFailureRestoresExactBytes(t *testing.T) {
	f := newUpdateFixture(t)
	oldPins, err := readPins(f.root, os.Geteuid(), f.from, f.oldSHA)
	if err != nil {
		t.Fatal(err)
	}
	next, err := advancePins(f.root, oldPins, f.target, f.newSHA)
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshotPins(t)
	failPinRenameAt(t, 3)
	err = writePins(f.root, next, oldPins)
	if err == nil {
		t.Fatal("rename failure was swallowed")
	}
	var repinned *repinError
	if !errors.As(err, &repinned) || repinned.mutated {
		t.Fatalf("writePins error = %v, want a complete restore", err)
	}
	f.requirePinsUnchanged(t, before)
}
