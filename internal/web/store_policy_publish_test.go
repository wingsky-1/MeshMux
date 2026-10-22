package web

// Assembly tests for the publication pipeline (10d-2b): the three Out states,
// the fail-closed refusals, the ruleset pin gate and the kernel gate ordering.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/route"
)

// publishFixture is one Hub with a paired Line, stored transport and an active
// server intent, so a publication has a real target.
type publishFixture struct {
	store    *store
	now      time.Time
	line     string
	lineName string
}

// newPublishFixture builds the fixture without any Out: the "Line direct"
// configured state, which is the default deployment.
func newPublishFixture(t *testing.T) publishFixture {
	t.Helper()
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)
	settings := testLine(line, "line-a")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := s.setLine(settings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, s, line, now)
	if _, _, err := s.createSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	seedInitialChain(t, s, line, now)
	confirmChain(t, s, line, now)
	return publishFixture{store: s, now: now, line: line, lineName: "line-a"}
}

// activatePolicy creates and activates one policy revision for a layer.
func (f publishFixture) activatePolicy(t *testing.T, layer PolicyLayer, payload, pins string) RoutePolicy {
	t.Helper()
	if pins == "" {
		pins = `{}`
	}
	created, err := f.store.createRoutePolicy(layer, "策略-"+string(layer),
		json.RawMessage(payload), json.RawMessage(pins), "op-create", f.now)
	if err != nil {
		t.Fatalf("create %s policy: %v", layer, err)
	}
	active, err := f.store.activateRoutePolicy(created.ID, created.Revision, "op-activate", f.now)
	if err != nil {
		t.Fatalf("activate %s policy: %v", layer, err)
	}
	return active
}

const publishServerDirect = `{"default":"direct","rules":[]}`

func TestPublishAssemblyOutStates(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, PolicyLayerServer, publishServerDirect, "")

	// State 1: no Out configured. The Line egresses directly and the route
	// names no Out, so the assembled candidate is a valid Line document.
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	assembly, err := f.store.assemblePolicyPublication(context.Background(), verifier, request, f.now)
	if err != nil {
		t.Fatalf("direct assembly: %v", err)
	}
	if assembly.EgressState != route.AIEgressLine || assembly.EgressCode != "" {
		t.Fatalf("egress = %s/%s, want line/none", assembly.EgressState, assembly.EgressCode)
	}
	if len(assembly.Targets) != 1 || assembly.Targets[0].LineID != f.line {
		t.Fatalf("targets = %+v", assembly.Targets)
	}
	if !strings.Contains(string(assembly.RouteFragment), `"final": "direct"`) {
		t.Fatalf("route fragment = %s", assembly.RouteFragment)
	}
	if strings.Contains(string(assembly.RouteFragment), `"out"`) {
		t.Fatal("a Line without an Out rendered an out reference")
	}
	if assembly.PolicySchema != policySchemaVersion || assembly.RoutePolicyRevisions["server"] == 0 {
		t.Fatalf("manifest fields = schema %d revisions %v", assembly.PolicySchema, assembly.RoutePolicyRevisions)
	}

	// State 2: an Out is bound and healthy. The AI rule selects the Out and the
	// route names it, so the Line document must be compiled with the Out fact.
	out := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, out, f.now)
	if err := f.store.setOutBindingAt(OutBinding{OutID: out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, f.store, out)
	confirmChain(t, f.store, out, f.now)
	f.activatePolicy(t, PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`, "")

	verifier = &fixturePublishVerifier{}
	assembly, err = f.store.assemblePolicyPublication(context.Background(), verifier, request, f.now)
	if err != nil {
		t.Fatalf("out assembly: %v", err)
	}
	if assembly.EgressState != route.AIEgressOut {
		t.Fatalf("egress = %s/%s, want out", assembly.EgressState, assembly.EgressCode)
	}
	if !strings.Contains(string(assembly.RouteFragment), `"outbound": "out"`) {
		t.Fatalf("route fragment does not select the Out: %s", assembly.RouteFragment)
	}
	if !verifier.hasSingBoxDocument(`"outbound": "out"`) {
		t.Fatal("the gated Line document does not carry the Out rule")
	}

	// State 3: the Out is unhealthy. The publication fails closed and stores
	// nothing, and no kernel check runs on a document that must not exist.
	if err := f.store.setOutBindingAt(OutBinding{OutID: out, LineID: f.line, Enabled: false}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	if err := f.store.setOutBindingAt(OutBinding{OutID: out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, f.store, out)
	verifier = &fixturePublishVerifier{}
	candidatesBefore := candidateCount(t, f.store, f.line)
	_, err = f.store.assemblePolicyPublication(context.Background(), verifier, request, f.now)
	if err == nil || !strings.HasPrefix(err.Error(), route.CodeOutOfflineFailClosed) {
		t.Fatalf("unhealthy Out assembly = %v, want %s", err, route.CodeOutOfflineFailClosed)
	}
	if singBox, mihomo := verifier.counts(); singBox != 0 || mihomo != 0 {
		t.Fatalf("failed-closed assembly ran %d sing-box and %d mihomo checks", singBox, mihomo)
	}
	if got := candidateCount(t, f.store, f.line); got != candidatesBefore {
		t.Fatalf("failed-closed assembly stored %d candidates, want %d", got, candidatesBefore)
	}
}

func TestPublishAssemblyFallbackNeedsOperationID(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`, "")
	out := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, out, f.now)
	if err := f.store.setOutBindingAt(OutBinding{OutID: out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}

	// Without the explicit opt-in, an unhealthy Out fails closed.
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.assemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), route.CodeOutOfflineFailClosed) {
		t.Fatalf("assembly without opt-in = %v, want fail-closed", err)
	}
	// With the opt-in the fallback resolves, and the receipt records both the
	// line-fallback state and the reason the deviation happened.
	fallback, err := parsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-fallback","fallback_to_line":true}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.assemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, fallback, f.now)
	if err != nil {
		t.Fatalf("fallback assembly: %v", err)
	}
	if assembly.EgressState != route.AIEgressLineFallback || assembly.EgressCode != route.CodeOutOfflineFailClosed {
		t.Fatalf("fallback egress = %s/%s", assembly.EgressState, assembly.EgressCode)
	}
	if strings.Contains(string(assembly.RouteFragment), `"outbound": "out"`) {
		t.Fatal("the fallback route still selects the Out")
	}
	// An unaudited fallback is impossible: the request requires an operation id,
	// and the parser refuses an empty one before the store sees it.
	if _, err := parsePolicyPublishRequest(json.RawMessage(`{"fallback_to_line":true}`)); err == nil ||
		!strings.HasPrefix(err.Error(), "POLICY_OPERATION_REQUIRED") {
		t.Fatalf("empty operation id = %v", err)
	}
}

func TestPublishAssemblyRefusesUnpinnedAndInvalidPolicy(t *testing.T) {
	f := newPublishFixture(t)
	// A geo rule needs its pin. The create path already proves this, so the
	// regression here is the assembly path: a stored row whose pins were
	// emptied behind the store's back must be refused, not rendered as a
	// "use the built-in database" fallback.
	pinned := `{"geosite":{"ai":{"source":"https://rulesets.example.invalid/geosite/ai/2026.10.21.srs","version":"2026.10.21","sha256":"` + strings.Repeat("a", 64) + `"}}}`
	record := f.activatePolicy(t, PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"geosite":["ai"]},"action":"direct"}]}`, pinned)
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"layer":"server","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE route_policies SET pins='{}' WHERE id=? AND revision=?`, record.ID, record.Revision); err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	if _, err := f.store.assemblePolicyPublication(context.Background(), verifier, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), compiler.CodeRulesetUnpinned) {
		t.Fatalf("unpinned ruleset = %v, want %s", err, compiler.CodeRulesetUnpinned)
	}
	if singBox, mihomo := verifier.counts(); singBox != 0 || mihomo != 0 {
		t.Fatal("an unpinned ruleset reached the kernel gate")
	}
	// A layer without any active revision is a 404-class refusal.
	none, err := parsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.assemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, none, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), codePublishNoPolicy) {
		t.Fatalf("missing client policy = %v, want %s", err, codePublishNoPolicy)
	}
	// A server policy with no Line to publish to is refused explicitly.
	if _, err := f.store.db.Exec(`UPDATE route_policies SET pins=? WHERE id=? AND revision=?`, pinned, record.ID, record.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`DELETE FROM line_settings`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.assemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), codePublishNoLines) {
		t.Fatalf("policy without a line = %v, want %s", err, codePublishNoLines)
	}
}

func TestPublishAssemblyClientDocuments(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, PolicyLayerClient,
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`, "")
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	assembly, err := f.store.assemblePolicyPublication(context.Background(), verifier, request, f.now)
	if err != nil {
		t.Fatalf("client assembly: %v", err)
	}
	if len(assembly.ClientDocument) == 0 || len(assembly.MihomoDocument) == 0 {
		t.Fatal("the client assembly rendered only one client format")
	}
	if !strings.Contains(string(assembly.ClientDocument), `"meshmux-selector"`) ||
		!strings.Contains(string(assembly.ClientDocument), `"outbound": "direct"`) {
		t.Fatalf("sing-box client document = %s", assembly.ClientDocument)
	}
	if !strings.Contains(string(assembly.MihomoDocument), "MATCH,PROXY") ||
		!strings.Contains(string(assembly.MihomoDocument), "DOMAIN,news.example.invalid,DIRECT") {
		t.Fatalf("mihomo client document = %s", assembly.MihomoDocument)
	}
	singBox, mihomo := verifier.counts()
	if singBox != 1 || mihomo != 1 {
		t.Fatalf("client gate ran sing-box=%d mihomo=%d, want 1/1", singBox, mihomo)
	}
	if len(assembly.Targets) != 0 {
		t.Fatalf("a client-only publication assembled %d line candidates", len(assembly.Targets))
	}
	if assembly.RoutePolicyRevisions["client"] == 0 {
		t.Fatal("client revision missing from the manifest fields")
	}
}

func TestPublishGateRefusals(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, PolicyLayerServer, publishServerDirect, "")
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		verifier *fixturePublishVerifier
		want     string
	}{
		{"sing-box refuses the line candidate", &fixturePublishVerifier{rejectSingBoxAt: 1}, node.CodePublishCheckSingBox},
		{"sing-box is missing", &fixturePublishVerifier{missingSingBox: true}, node.CodePublishSingBoxMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := candidateCount(t, f.store, f.line)
			if _, err := f.store.assemblePolicyPublication(context.Background(), tc.verifier, request, f.now); err == nil ||
				!strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("gate refusal = %v, want %s", err, tc.want)
			}
			if got := candidateCount(t, f.store, f.line); got != before {
				t.Fatalf("a refused gate stored %d candidates", got-before)
			}
		})
	}

	// A client publication requires the Mihomo kernel: a missing binary is a
	// refusal, never a silently skipped check.
	f.activatePolicy(t, PolicyLayerClient,
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`, "")
	clientRequest, err := parsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.assemblePolicyPublication(context.Background(),
		&fixturePublishVerifier{missingMihomo: true}, clientRequest, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), node.CodePublishMihomoMissing) {
		t.Fatalf("missing mihomo = %v, want %s", err, node.CodePublishMihomoMissing)
	}
	if _, err := f.store.assemblePolicyPublication(context.Background(),
		&fixturePublishVerifier{}, clientRequest, f.now); err != nil {
		t.Fatalf("client assembly with both kernels: %v", err)
	}
}

func TestPublishRequestValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"missing operation id", `{}`, "POLICY_OPERATION_REQUIRED"},
		{"blank operation id", `{"operation_id":"  "}`, "POLICY_OPERATION_REQUIRED"},
		{"illegal layer", `{"layer":"mesh","operation_id":"op"}`, "POLICY_LAYER_INVALID"},
		{"unknown field", `{"operation_id":"op","payload":{}}`, "POLICY_PAYLOAD_INVALID"},
		{"not json", `not json`, "POLICY_PAYLOAD_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePolicyPublishRequest(json.RawMessage(tc.body)); err == nil ||
				!strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("%s = %v, want %s", tc.name, err, tc.want)
			}
		})
	}
	// The documented body parses, and layer defaults to both layers.
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-1","fallback_to_line":true}`))
	if err != nil || request.Layer != "" || !request.FallbackToLine || request.OperationID != "op-1" {
		t.Fatalf("documented body = %+v err=%v", request, err)
	}
}

func TestPublishAssemblyCarriesManifestFields(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, PolicyLayerServer, publishServerDirect, "")
	request, err := parsePolicyPublishRequest(json.RawMessage(`{"layer":"server","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.assemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if assembly.PolicySchema != 8 {
		t.Fatalf("policy_schema = %d, want 8", assembly.PolicySchema)
	}
	if got := assembly.RoutePolicyRevisions; len(got) != 1 || got["server"] != 1 {
		t.Fatalf("route_policy_revisions = %v", got)
	}
}
