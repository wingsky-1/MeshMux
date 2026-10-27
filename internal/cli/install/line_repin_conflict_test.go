package install

// Regression test for the fourth Line pin of #11d Task 6 (spec §5.6 step 6③).
//
// Re-pinning only the Hub ledger, the Line ledger's shared_binaries and
// agent.json looks complete on disk, but the next fixed-argv
// `--from-recorded-state` handoff reads the Line ledger's state.Node pair
// through checkRecordedAgentConfig. If that pair still names the old release,
// the handoff refuses with CONFIG_CONFLICT and the upgrade chain is dead. This
// test pins that exact failure so the four-pin writer cannot regress to three.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

func TestLineRepinFourthPinNeeded(t *testing.T) {
	root := t.TempDir()
	oldSHA := strings.Repeat("a", 64)
	newSHA := strings.Repeat("b", 64)
	oldVersion, newVersion := "1.0.0-dev", "1.0.1"

	hub := InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed",
		Config: Config{
			ManagementDomain:   "hub.example.invalid",
			SubscriptionDomain: "sub.example.invalid",
			HeadscaleDomain:    "mesh.example.invalid",
		},
		ManagedFiles: map[string]string{node.AgentBinaryPath: newSHA},
		SharedBinaries: map[string]SharedBinary{
			sharedAgentKey: {Path: node.AgentBinaryPath, SHA256: newSHA},
		},
	}
	if err := writeStateAt(root, installerStatePath, hub); err != nil {
		t.Fatal(err)
	}
	nodeCfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("c", 32),
		Role: node.RoleEdge, VLESSPort: 443, SSHPort: 2222,
		AgentVersion: newVersion, AgentSHA256: newSHA,
	}
	line := InstallState{
		Schema: 1, OperationID: strings.Repeat("2", 32), Status: "installed",
		Node: &nodeCfg,
		ManagedFiles: map[string]string{
			node.AgentConfigPath: strings.Repeat("d", 64),
		},
		SharedBinaries: map[string]SharedBinary{
			sharedAgentKey: {Path: node.AgentBinaryPath, SHA256: newSHA},
		},
	}

	t.Run("agent.json and state.Node agree", func(t *testing.T) {
		if err := writeStateAt(root, localLineStatePath, line); err != nil {
			t.Fatal(err)
		}
		writeAgentConfig(t, root, nodeCfg)
		if _, conflict := recordedNodeConfig(root, node.RoleEdge); conflict != nil {
			t.Fatalf("a complete four-pin set was refused: %+v", conflict)
		}
	})

	t.Run("state.Node left at the old release", func(t *testing.T) {
		stale := line
		staleCfg := *line.Node
		staleCfg.AgentVersion, staleCfg.AgentSHA256 = oldVersion, oldSHA
		stale.Node = &staleCfg
		if err := writeStateAt(root, localLineStatePath, stale); err != nil {
			t.Fatal(err)
		}
		writeAgentConfig(t, root, nodeCfg)
		if _, conflict := recordedNodeConfig(root, node.RoleEdge); conflict == nil || conflict.Code != "CONFIG_CONFLICT" {
			t.Fatalf("recorded-state handoff conflict = %+v, want CONFIG_CONFLICT", conflict)
		}
	})
}

func writeAgentConfig(t *testing.T, root string, cfg node.Config) {
	t.Helper()
	body, err := RenderNodeAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := rooted(root, node.AgentConfigPath)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}
