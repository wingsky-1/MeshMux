package node

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serverRouteFixture is the shape compiler.RenderServerRoute emits. Keeping it
// literal avoids importing the compiler from the node test: the subscription
// acceptance test imports node, so that edge would close a test-only cycle.
const serverRouteFixture = `{
  "rules": [
    {"domain": ["chat.example.invalid"], "outbound": "out"},
    {"ip_cidr": ["203.0.113.0/24"], "outbound": "direct"}
  ],
  "rule_set": [
    {"type": "remote", "tag": "geosite-ai@2026.10.21", "format": "binary",
     "url": "https://rulesets.example.invalid/geosite/ai/2026.10.21.srs"}
  ],
  "final": "direct"
}`

// TestCompileCandidateWithRoute proves the fragment lands in the native
// document deterministically, a route-free candidate keeps the zero-Out
// document, and a route that selects "out" without an Out is refused.
func TestCompileCandidateWithRoute(t *testing.T) {
	edge := validCandidate()
	edge.Role = RoleEdge
	plain, err := CompileCandidate(edge)
	if err != nil || bytes.Contains(plain, []byte(`"route"`)) {
		t.Fatalf("candidate without a route rendered one: %v", err)
	}
	first, err := CompileCandidateWithRoute(edge, json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileCandidateWithRoute(edge, json.RawMessage(serverRouteFixture), true)
	if err != nil || !bytes.Equal(first, second) ||
		!bytes.Contains(first, []byte(`"tag": "geosite-ai@2026.10.21"`)) {
		t.Fatalf("route render is not deterministic or lost the rule_set: %v", err)
	}
	for _, fragment := range []string{serverRouteFixture, `{"rules": [], "final": "out"}`} {
		if _, err := CompileCandidateWithRoute(edge, json.RawMessage(fragment), false); err == nil ||
			!strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID") {
			t.Fatalf("unbound Out error = %v, want OUT_BINDING_INVALID", err)
		}
	}
}

// TestCompileCandidateRouteNativeCheck asks the real sing-box binary to accept
// the assembled Line document. The fixture supplies the Out access path's
// referenced tag as a block stub; this proves schema, never a traffic path.
func TestCompileCandidateRouteNativeCheck(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native candidate check")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY is not executable")
	}
	document, err := CompileCandidateWithRoute(v2Candidate(), json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	var assembled map[string]any
	if err := json.Unmarshal(document, &assembled); err != nil {
		t.Fatal(err)
	}
	assembled["outbounds"] = append(assembled["outbounds"].([]any), map[string]any{"type": "block", "tag": "out"})
	document, err = json.MarshalIndent(assembled, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, binary, "check", "-c", path).Run(); err != nil {
		t.Fatal("sing-box rejected the assembled Line candidate")
	}
}
