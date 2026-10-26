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

// serverRouteFixture is the shape policy.RenderServerRoute emits. Keeping it
// literal avoids importing the policy package from the node test: the subscription
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

// directRouteFixture is the same shape with no Out reference: the Out-free
// deployment, where the Line egresses directly.
const directRouteFixture = `{"rules":[{"domain":["ai.example.invalid"],"outbound":"direct"}],"final":"direct"}`

// renderedOutbounds maps one rendered document's outbound tags to their types.
func renderedOutbounds(t *testing.T, document []byte) map[string]string {
	t.Helper()
	var decoded struct {
		Outbounds []singBoxOutbound `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal("rendered candidate is not valid JSON")
	}
	tags := make(map[string]string, len(decoded.Outbounds))
	for _, outbound := range decoded.Outbounds {
		if _, duplicate := tags[outbound.Tag]; duplicate {
			t.Fatalf("rendered candidate repeats the outbound tag %q", outbound.Tag)
		}
		tags[outbound.Tag] = outbound.Type
	}
	return tags
}

// routeTags returns every egress tag a rendered route references.
func routeTags(t *testing.T, fragment []byte) []string {
	t.Helper()
	var route struct {
		Rules []struct {
			Outbound string `json:"outbound"`
		} `json:"rules"`
		Final string `json:"final"`
	}
	if err := json.Unmarshal(fragment, &route); err != nil {
		t.Fatal("route fragment is not valid JSON")
	}
	tags := make([]string, 0, len(route.Rules)+1)
	tags = append(tags, route.Final)
	for _, rule := range route.Rules {
		tags = append(tags, rule.Outbound)
	}
	return tags
}

// TestCompileCandidateWithRoute declares every egress the route names.
//
// This is the I1 regression: a route that selects "out" used to land in a
// document whose only outbound was "direct", so the kernel resolved the AI rule
// against a missing egress. The document now carries `direct`, `out` and
// `block`, and "out" is a block stub because the Out access path still owns the
// real body: traffic selected for the Out is refused instead of leaving from
// the Line. Availability is not re-derived here — the Hub's ResolveServerPolicy
// refuses an unavailable Out before any bytes exist.
func TestCompileCandidateWithRoute(t *testing.T) {
	edge := validCandidate()
	edge.Role = RoleEdge
	plain, err := CompileCandidate(edge)
	if err != nil || bytes.Contains(plain, []byte(`"route"`)) {
		t.Fatalf("candidate without a route rendered one: %v", err)
	}
	if tags := renderedOutbounds(t, plain); len(tags) != 1 || tags[singBoxDirectTag] != singBoxDirectTag {
		t.Fatalf("route-free candidate outbounds = %v, want only direct", tags)
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

	// The Out trio: direct for the fallback rules, the named "out" tag and the
	// explicit block tag. Both Out-selecting tags are block stubs.
	tags := renderedOutbounds(t, first)
	if len(tags) != 3 || tags[singBoxDirectTag] != "direct" ||
		tags[singBoxOutTag] != singBoxBlockTag || tags[singBoxBlockTag] != singBoxBlockTag {
		t.Fatalf("Out candidate outbounds = %v, want direct/out/block", tags)
	}
	// Every egress the route names must exist in the document, or `sing-box
	// check` (which accepts an unknown route tag) would pass a broken config.
	for _, tag := range routeTags(t, json.RawMessage(serverRouteFixture)) {
		if _, declared := tags[tag]; !declared {
			t.Fatalf("route names %q but the candidate declares %v", tag, tags)
		}
	}

	// A direct-only route keeps the single direct outbound: the frozen bytes of
	// an Out-free Line do not grow.
	direct, err := CompileCandidateWithRoute(edge, json.RawMessage(directRouteFixture), false)
	if err != nil {
		t.Fatal(err)
	}
	if tags := renderedOutbounds(t, direct); len(tags) != 1 || tags[singBoxDirectTag] != "direct" {
		t.Fatalf("direct route outbounds = %v, want only direct", tags)
	}

	// The block tag is rendered on demand, so a route that refuses traffic
	// explicitly is schema-complete too.
	blockOnly, err := CompileCandidateWithRoute(edge, json.RawMessage(`{"rules":[],"final":"block"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if tags := renderedOutbounds(t, blockOnly); tags[singBoxBlockTag] != singBoxBlockTag {
		t.Fatalf("block route outbounds = %v, want a block outbound", tags)
	}

	// An Out reference without an Out is refused, never rewritten to direct.
	for _, fragment := range []string{serverRouteFixture, `{"rules": [], "final": "out"}`} {
		if _, err := CompileCandidateWithRoute(edge, json.RawMessage(fragment), false); err == nil ||
			!strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID") {
			t.Fatalf("unbound Out error = %v, want OUT_BINDING_INVALID", err)
		}
	}

	// An unknown egress tag cannot be declared by this renderer, so it is a Hub
	// defect: refuse it instead of publishing a document the kernel would
	// resolve against a missing outbound.
	for _, fragment := range []string{
		`{"rules":[],"final":"unknown"}`,
		`{"rules":[{"domain":["a.example.invalid"],"outbound":"proxy"}],"final":"direct"}`,
	} {
		if _, err := CompileCandidateWithRoute(edge, json.RawMessage(fragment), true); err == nil ||
			!strings.HasPrefix(err.Error(), "CANDIDATE_ROUTE_INVALID") {
			t.Fatalf("unknown egress error = %v, want CANDIDATE_ROUTE_INVALID", err)
		}
	}
}

// TestCompileCandidateRouteNativeCheck asks the real sing-box binary to accept
// the assembled Line document, both with and without an Out. The rendered
// document is checked as-is: the Out outbound is part of the renderer's output,
// not appended by the test.
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
	for name, testCase := range map[string]struct {
		fragment      string
		outConfigured bool
	}{
		"out":    {fragment: serverRouteFixture, outConfigured: true},
		"direct": {fragment: directRouteFixture, outConfigured: false},
		"block":  {fragment: `{"rules":[],"final":"block"}`, outConfigured: false},
	} {
		t.Run(name, func(t *testing.T) {
			document, err := CompileCandidateWithRoute(v2Candidate(), json.RawMessage(testCase.fragment), testCase.outConfigured)
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
		})
	}
	// A route naming an egress the document does not carry never reaches a
	// check: the renderer refuses it. `sing-box check` itself accepts an
	// unknown route tag, which is exactly why this refusal lives here.
	if _, err := CompileCandidateWithRoute(v2Candidate(), json.RawMessage(`{"rules":[],"final":"missing"}`), true); err == nil {
		t.Fatal("the renderer accepted a route that names an unknown egress")
	}
}
