package rootexec

// The Line half is optional: a standalone Hub has no co-located Line ledger,
// so only the Hub ledger pins move. The test also proves agent.json is not
// touched when there is no Line to re-pin.

import (
	"context"
	"os"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
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
