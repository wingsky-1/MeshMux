package install

// The convergence write (#11c-2 Task 5, spec §4.2 amended).
//
// After an in-memory crash-window adoption the Agent cannot write agent.json:
// its unit keeps /etc read-only. A one-shot transient unit runs the hidden
// convergence command instead. These tests pin what that command may and may
// not publish, entirely on a fixture root.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
)

const convergeOperationID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type convergeFixture struct {
	root        string
	operationID string
	newSHA256   string
	cfg         node.Config
}

func makeConvergeFixture(t *testing.T) *convergeFixture {
	t.Helper()
	root := t.TempDir()
	binary := []byte("new agent binary")
	if err := os.MkdirAll(filepath.Dir(rooted(root, node.AgentBinaryPath)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(root, node.AgentBinaryPath), binary, 0755); err != nil {
		t.Fatal(err)
	}
	newSHA256 := sumBytes(binary)
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: "0.9.9", AgentSHA256: strings.Repeat("0", 64),
		KernelSHA256: strings.Repeat("c", 64),
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(rooted(root, node.AgentConfigPath)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(root, node.AgentConfigPath), append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeNodeUpgradeClaim(root, convergeOperationID, newSHA256); err != nil {
		t.Fatal(err)
	}
	return &convergeFixture{root: root, operationID: convergeOperationID, newSHA256: newSHA256, cfg: cfg}
}

// TestConvergeHandoffConfigPublishesClaimedPair is the positive path: the
// claimed digest is written into agent.json and the pair reads back consistent.
// The claim itself is NOT removed here — only the Agent's pair readback may.
func TestConvergeHandoffConfigPublishesClaimedPair(t *testing.T) {
	f := makeConvergeFixture(t)
	if err := ConvergeHandoffConfig(f.root, f.operationID, f.newSHA256); err != nil {
		t.Fatalf("ConvergeHandoffConfig: %v", err)
	}
	written, err := readAgentConfig(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if written.AgentSHA256 != f.newSHA256 || written.AgentVersion != node.CurrentAgentVersion() {
		t.Fatalf("written pair = %q/%q, want %q/%q", written.AgentVersion, written.AgentSHA256,
			node.CurrentAgentVersion(), f.newSHA256)
	}
	if written.HubURL != f.cfg.HubURL || written.NodeID != f.cfg.NodeID || written.Role != f.cfg.Role ||
		written.VLESSPort != f.cfg.VLESSPort || written.SSHPort != f.cfg.SSHPort ||
		written.KernelSHA256 != f.cfg.KernelSHA256 {
		t.Fatalf("convergence changed another configuration field: %+v", written)
	}
	if info, statErr := os.Lstat(rooted(f.root, node.AgentConfigPath)); statErr != nil ||
		info.Mode().Perm() != 0600 {
		t.Fatalf("agent.json mode = %v, %v", info.Mode(), statErr)
	}
	if _, statErr := os.Lstat(rooted(f.root, nodeUpgradeClaimPath)); statErr != nil {
		t.Fatalf("the convergence removed the claim: %v", statErr)
	}
}

// TestConvergeHandoffConfigRefusesUnprovenClaims covers every way the claim can
// fail to prove the pair. None of them may publish agent.json.
func TestConvergeHandoffConfigRefusesUnprovenClaims(t *testing.T) {
	t.Run("no claim", func(t *testing.T) {
		f := makeConvergeFixture(t)
		if err := os.Remove(rooted(f.root, nodeUpgradeClaimPath)); err != nil {
			t.Fatal(err)
		}
		assertConvergeRefused(t, f, "HANDOFF_CONVERGE_NO_CLAIM")
	})
	t.Run("another operation", func(t *testing.T) {
		f := makeConvergeFixture(t)
		assertConvergeRefused(t, &convergeFixture{root: f.root, operationID: strings.Repeat("b", 32), newSHA256: f.newSHA256},
			"HANDOFF_CONVERGE_CLAIM_MISMATCH")
	})
	t.Run("another digest", func(t *testing.T) {
		f := makeConvergeFixture(t)
		assertConvergeRefused(t, &convergeFixture{root: f.root, operationID: f.operationID, newSHA256: strings.Repeat("e", 64)},
			"HANDOFF_CONVERGE_CLAIM_MISMATCH")
	})
	t.Run("disk binary differs from the claim", func(t *testing.T) {
		f := makeConvergeFixture(t)
		if err := os.WriteFile(rooted(f.root, node.AgentBinaryPath), []byte("rolled back binary"), 0755); err != nil {
			t.Fatal(err)
		}
		assertConvergeRefused(t, f, "HANDOFF_CONVERGE_BINARY_MISMATCH")
	})
	t.Run("agent.json is unsafe", func(t *testing.T) {
		f := makeConvergeFixture(t)
		if err := os.Chmod(rooted(f.root, node.AgentConfigPath), 0644); err != nil {
			t.Fatal(err)
		}
		assertConvergeRefused(t, f, "AGENT_CONFIG_UNAVAILABLE")
	})
	t.Run("claim is unsafe", func(t *testing.T) {
		f := makeConvergeFixture(t)
		if err := os.Chmod(rooted(f.root, nodeUpgradeClaimPath), 0644); err != nil {
			t.Fatal(err)
		}
		assertConvergeRefused(t, f, "UPGRADE_CLAIM_UNSAFE")
	})
}

func assertConvergeRefused(t *testing.T, f *convergeFixture, want string) {
	t.Helper()
	before, err := os.ReadFile(rooted(f.root, node.AgentConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	err = ConvergeHandoffConfig(f.root, f.operationID, f.newSHA256)
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %s", err, want)
	}
	after, readErr := os.ReadFile(rooted(f.root, node.AgentConfigPath))
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("a refused convergence rewrote agent.json: %v", readErr)
	}
}
