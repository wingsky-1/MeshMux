package rootexec

// TestAgentConfigEncodingUnchanged pins the byte contract of the fourth Line
// pin (#11d Task 6). The executor must rewrite agent.json with exactly the
// encoder internal/install uses for nodeManagedFiles: MarshalIndent two spaces
// plus one trailing newline. A second encoder would make the next recorded-state
// repair see a document the installer would never have written.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

func TestAgentConfigEncodingUnchanged(t *testing.T) {
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 443, SSHPort: 2222,
		AgentVersion: "1.0.0-dev", AgentSHA256: strings.Repeat("b", 64),
	}
	got, err := renderAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want, err := install.RenderNodeAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("agent.json encoding drifted:\n%s\nwant:\n%s", got, want)
	}
	if !bytes.HasSuffix(got, []byte("\n")) || !bytes.Contains(got, []byte("\n  \"hub_url\"")) {
		t.Fatalf("agent.json is not the indented installer document:\n%s", got)
	}
}
