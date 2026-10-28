package node

// TestAgentConfigEncodingUnchanged pins the byte contract of the fourth Line
// pin (#11d Task 6): the executor's RenderNodeAgentConfig must produce exactly
// the document nodeManagedFiles writes for /etc/meshmux/agent.json. The two
// renderers stay independent on purpose; a delegated single function would make
// this comparison vacuous.

import (
	"strings"
	"testing"

	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

func TestAgentConfigEncodingUnchanged(t *testing.T) {
	cfg := corenode.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: corenode.RoleEdge, VLESSPort: 443, SSHPort: 2222,
		AgentVersion: "1.0.0-dev", AgentSHA256: strings.Repeat("b", 64),
	}
	identity := corenode.Identity{NodeID: cfg.NodeID, IdentityToken: strings.Repeat("A", 43)}
	files, err := nodeManagedFiles(cfg, []int{2222}, identity)
	if err != nil {
		t.Fatal(err)
	}
	installed := files[corenode.AgentConfigPath].Body
	rendered, err := RenderNodeAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if installed != string(rendered) {
		t.Fatalf("agent.json encoders drifted:\n%s\nwant:\n%s", rendered, installed)
	}
	if !strings.HasSuffix(installed, "\n") || !strings.Contains(installed, "\n  \"hub_url\"") {
		t.Fatalf("agent.json is not the indented installer document:\n%s", installed)
	}
}
