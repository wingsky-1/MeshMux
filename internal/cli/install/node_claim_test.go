package install

// The crash-window claim contract (#11c-2 Task 4, fix round 1). The installer
// renames the Agent binary first, records the claimed digest, then writes
// agent.json. A crash between the binary and the config must leave the claim on
// disk; a complete apply removes it. These are fixture-root tests: no host path
// is touched.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

func claimState(operationID string) InstallState {
	return InstallState{
		Schema: 1, OperationID: operationID,
		ManagedFiles: map[string]string{},
	}
}

func claimManaged() map[string]nodeManagedFile {
	return map[string]nodeManagedFile{
		node.AgentConfigPath: {
			Path: node.AgentConfigPath, Mode: 0600, Owner: "root:root", Static: true,
		},
	}
}

func TestApplyNodeFilesWritesClaimBetweenBinaryAndConfig(t *testing.T) {
	operationID := strings.Repeat("a", 32)
	binaryBody := []byte("new-agent-binary")

	t.Run("claim remains when the config apply crashes", func(t *testing.T) {
		root := t.TempDir()
		stagedBinary := filepath.Join(root, "staged-binary")
		if err := os.WriteFile(stagedBinary, binaryBody, 0755); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{
			node.AgentBinaryPath: stagedBinary,
			node.AgentConfigPath: filepath.Join(root, "missing-config"),
		}
		err := applyNodeFiles(context.Background(), NodeApplyOptions{Root: root},
			standaloneNodeLayout(), claimState(operationID), claimManaged(), files, "")
		if err == nil {
			t.Fatal("a missing agent.json source was accepted")
		}
		// The binary rename happened before the failing config write: that is
		// exactly the window the claim record covers.
		copied, readErr := os.ReadFile(rooted(root, node.AgentBinaryPath))
		if readErr != nil || string(copied) != string(binaryBody) {
			t.Fatalf("Agent binary was not applied first: %v", readErr)
		}
		data, readErr := os.ReadFile(rooted(root, nodeUpgradeClaimPath))
		if readErr != nil {
			t.Fatalf("crash window left no claim: %v", readErr)
		}
		var claim nodeUpgradeClaim
		if err := json.Unmarshal(data, &claim); err != nil {
			t.Fatal(err)
		}
		wantHash, err := sha256File(stagedBinary)
		if err != nil {
			t.Fatal(err)
		}
		if claim.OperationID != operationID || claim.NewSHA256 != wantHash {
			t.Fatalf("claim = %+v, want %s/%s", claim, operationID, wantHash)
		}
		if _, err := os.Lstat(rooted(root, node.AgentConfigPath)); !os.IsNotExist(err) {
			t.Fatalf("failed config apply left agent.json behind: %v", err)
		}
	})

	t.Run("claim is removed when the pair is consistent", func(t *testing.T) {
		root := t.TempDir()
		stagedBinary := filepath.Join(root, "staged-binary")
		stagedConfig := filepath.Join(root, "staged-config")
		if err := os.WriteFile(stagedBinary, binaryBody, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stagedConfig, []byte("agent-config-body"), 0600); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{
			node.AgentBinaryPath: stagedBinary,
			node.AgentConfigPath: stagedConfig,
		}
		if err := applyNodeFiles(context.Background(), NodeApplyOptions{Root: root},
			standaloneNodeLayout(), claimState(operationID), claimManaged(), files, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(rooted(root, nodeUpgradeClaimPath)); !os.IsNotExist(err) {
			t.Fatalf("successful apply left the claim behind: %v", err)
		}
		got, err := os.ReadFile(rooted(root, node.AgentConfigPath))
		if err != nil || string(got) != "agent-config-body" {
			t.Fatalf("agent.json = %q, %v", got, err)
		}
	})
}
