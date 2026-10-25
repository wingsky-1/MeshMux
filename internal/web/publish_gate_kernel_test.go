package web

// The publish gate's real-kernel evidence. The fixture verifier proves the
// pipeline; this file asks the pinned sing-box binary whether the documents the
// Hub would actually store are valid, both with and without an Out.
//
// The Out case is the I1 regression: the publication route named "out" while
// the candidate only declared "direct", and `sing-box check` accepts an unknown
// route tag, so the old gate passed a document the kernel could not route. The
// renderer now declares direct/out/block and the real kernel checks exactly
// those bytes.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/route"
)

// realPublishGate builds the production verifier against the pinned kernel.
func realPublishGate(t *testing.T) publishVerifier {
	t.Helper()
	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native publish-gate check")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY is not executable")
	}
	verifier, err := newPublishVerifier(publishGateConfig{SingBoxPath: binary}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// gatedLineOutbounds returns the outbound tags of the Line document the gate
// checked, keyed by tag. The document is the exact byte slice the Hub would
// store, so this reads what the kernel actually validated.
func gatedLineOutbounds(t *testing.T, assembly policyAssembly) map[string]string {
	t.Helper()
	if len(assembly.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(assembly.Targets))
	}
	compiled := assembly.Targets[0].Config
	var document struct {
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(compiled, &document); err != nil {
		t.Fatal("compiled candidate is not valid JSON")
	}
	tags := make(map[string]string, len(document.Outbounds))
	for _, outbound := range document.Outbounds {
		tags[outbound.Tag] = outbound.Type
	}
	return tags
}

// TestPublishGateRealKernelOutCandidate runs the production gate over a Line
// whose route selects a healthy Out, then over the same Line without an Out.
func TestPublishGateRealKernelOutCandidate(t *testing.T) {
	verifier := realPublishGate(t)
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-real-gate"}`))
	if err != nil {
		t.Fatal(err)
	}

	// State 1: no Out. The Line is a direct Line and the candidate keeps the
	// single direct outbound.
	direct := newPublishFixture(t)
	direct.activatePolicy(t, PolicyLayerServer, publishServerDirect, "")
	assembly, err := direct.store.assemblePolicyPublication(context.Background(), verifier, request, direct.now)
	if err != nil {
		t.Fatalf("the real kernel refused the Out-free Line candidate: %v", err)
	}
	if assembly.EgressState != route.AIEgressLine {
		t.Fatalf("egress = %s/%s, want line", assembly.EgressState, assembly.EgressCode)
	}
	if tags := gatedLineOutbounds(t, assembly); len(tags) != 1 || tags["direct"] != "direct" {
		t.Fatalf("Out-free candidate outbounds = %v, want only direct", tags)
	}

	// State 2: a healthy Out selected by the AI rule. The gate must accept the
	// document that actually carries the named "out" outbound.
	out := pairedStoreNode(t, direct.store, "out", direct.now)
	markLineOnline(t, direct.store, out, direct.now)
	if err := direct.store.setOutBindingAt(OutBinding{OutID: out, LineID: direct.line, Enabled: true}, direct.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, direct.store, out)
	confirmChain(t, direct.store, out, direct.now)
	direct.activatePolicy(t, PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`, "")

	assembly, err = direct.store.assemblePolicyPublication(context.Background(), verifier, request, direct.now)
	if err != nil {
		t.Fatalf("the real kernel refused the Out-selecting Line candidate: %v", err)
	}
	if assembly.EgressState != route.AIEgressOut {
		t.Fatalf("egress = %s/%s, want out", assembly.EgressState, assembly.EgressCode)
	}
	tags := gatedLineOutbounds(t, assembly)
	if len(tags) != 3 || tags["direct"] != "direct" || tags["out"] != "block" || tags["block"] != "block" {
		t.Fatalf("Out candidate outbounds = %v, want direct/out/block", tags)
	}
	// The published digest is the digest of the checked bytes, so the gate and
	// the node agree on the exact document.
	if assembly.Targets[0].ConfigHash != compiler.Hash(assembly.Targets[0].Config) {
		t.Fatal("the target digest does not match the gated document")
	}
	if !strings.Contains(assembly.Targets[0].ConfigHash, "") || node.SingBoxPublishVersion == "" {
		t.Fatal("the gate reported success without a versioned document")
	}
}
