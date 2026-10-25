package handler

// Assembly tests for the publication pipeline (10d-2b): the three Out states,
// the fail-closed refusals, the ruleset pin gate and the kernel gate ordering.

import (
	"context"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/route"
)

// publishFixture is one Hub with a paired Line, stored transport and an active
// server intent, so a publication has a real target.
type publishFixture struct {
	store    *store.Store
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
	if _, err := s.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, s, line, now)
	if _, _, err := s.CreateSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	seedInitialChain(t, s, line, now)
	confirmChain(t, s, line, now)
	return publishFixture{store: s, now: now, line: line, lineName: "line-a"}
}

// activatePolicy creates and activates one policy revision for a layer.
func (f publishFixture) activatePolicy(t *testing.T, layer store.PolicyLayer, payload, pins string) store.RoutePolicy {
	t.Helper()
	if pins == "" {
		pins = `{}`
	}
	created, err := f.store.CreateRoutePolicy(layer, "策略-"+string(layer),
		json.RawMessage(payload), json.RawMessage(pins), "op-create", f.now)
	if err != nil {
		t.Fatalf("create %s policy: %v", layer, err)
	}
	active, err := f.store.ActivateRoutePolicy(created.ID, created.Revision, "op-activate", f.now)
	if err != nil {
		t.Fatalf("activate %s policy: %v", layer, err)
	}
	return active
}

const publishServerDirect = `{"default":"direct","rules":[]}`

// assertRealOutEgress proves the assembled Line document carries the Hub's
// Out access path: the "out" tag is a Shadowsocks outbound (Ruling R7: the
// bare-VLESS double-hop is gone) that dials the selected Out node's
// configured address/port with the Hub-issued link key, not the fail-closed
// block stub.
func assertRealOutEgress(t *testing.T, document []byte) {
	t.Helper()
	var decoded struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server,omitempty"`
			ServerPort int    `json:"server_port,omitempty"`
			Method     string `json:"method,omitempty"`
			Password   string `json:"password,omitempty"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal("assembled Line document is not valid JSON")
	}
	for _, outbound := range decoded.Outbounds {
		if outbound.Tag != "out" {
			continue
		}
		if outbound.Type != "shadowsocks" {
			t.Fatalf("assembled out outbound type = %q, want shadowsocks", outbound.Type)
		}
		if outbound.Method != "2022-blake3-aes-128-gcm" {
			t.Fatalf("assembled out method = %q, want the pinned SS method", outbound.Method)
		}
		if outbound.Server != "out.example.invalid" || outbound.ServerPort != 8443 {
			t.Fatalf("assembled out endpoint = %s:%d, want the configured Out node address/port",
				outbound.Server, outbound.ServerPort)
		}
		if outbound.Password == "" {
			t.Fatal("assembled out outbound carries no Hub-issued link key")
		}
		return
	}
	t.Fatal("assembled Line document declares no out outbound")
}

func TestPublishAssemblyOutStates(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")

	// State 1: no Out configured. The Line egresses directly and the route
	// names no Out, so the assembled candidate is a valid Line document.
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), verifier, request, f.now)
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
	if assembly.PolicySchema != store.PolicySchemaVersion || assembly.RoutePolicyRevisions["server"] == 0 {
		t.Fatalf("manifest fields = schema %d revisions %v", assembly.PolicySchema, assembly.RoutePolicyRevisions)
	}

	// State 2: an Out is bound and healthy. The AI rule selects the Out and the
	// route names it, so the Line document must be compiled with the Out fact.
	out := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, out, f.now)
	configureOut(t, f.store, out, f.now)
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, f.store, out)
	confirmChain(t, f.store, out, f.now)
	f.activatePolicy(t, store.PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`, "")

	verifier = &fixturePublishVerifier{}
	assembly, err = f.store.AssemblePolicyPublication(context.Background(), verifier, request, f.now)
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
	// The gated document must declare the tag its route names, or the kernel
	// would resolve the AI rule against a missing egress. The bound Out
	// renders the real VLESS egress from its configured transport and the
	// Hub-issued credential; the fail-closed block stub only remains for the
	// never-route tag.
	if !verifier.hasSingBoxDocument(`"tag": "out"`) {
		t.Fatal("the gated Line document does not declare the out outbound")
	}
	assertRealOutEgress(t, assembly.Targets[0].Config)
	if !verifier.hasSingBoxDocument(`"type": "block"`) {
		t.Fatal("the gated Line document does not carry the fail-closed block stub")
	}

	// State 3: the Out is unhealthy. The publication fails closed and stores
	// nothing, and no kernel check runs on a document that must not exist.
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: out, LineID: f.line, Enabled: false}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, f.store, out)
	verifier = &fixturePublishVerifier{}
	candidatesBefore := candidateCount(t, f.store, f.line)
	_, err = f.store.AssemblePolicyPublication(context.Background(), verifier, request, f.now)
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
	f.activatePolicy(t, store.PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`, "")
	out := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, out, f.now)
	configureOut(t, f.store, out, f.now)
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}

	// Without the explicit opt-in, an unhealthy Out fails closed.
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), route.CodeOutOfflineFailClosed) {
		t.Fatalf("assembly without opt-in = %v, want fail-closed", err)
	}
	// With the opt-in the fallback resolves, and the receipt records both the
	// line-fallback state and the reason the deviation happened.
	fallback, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-fallback","fallback_to_line":true}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, fallback, f.now)
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
	if _, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"fallback_to_line":true}`)); err == nil ||
		!strings.HasPrefix(err.Error(), "POLICY_OPERATION_REQUIRED") {
		t.Fatalf("empty operation id = %v", err)
	}
}

// TestPublishAssemblyAggregatesEveryLineEgress is the I3 regression: a
// publication targets every Line, but the receipt used to take the first Line's
// egress state and present it for the whole fleet. A healthy Line next to a
// fail-closed Line must read as "mixed" while each Line keeps its own state.
func TestPublishAssemblyAggregatesEveryLineEgress(t *testing.T) {
	f := newPublishFixture(t)
	healthy := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, healthy, f.now)
	configureOut(t, f.store, healthy, f.now)
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: healthy, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, f.store, healthy)
	confirmChain(t, f.store, healthy, f.now)

	// The second Line has a bound Out that stopped reporting: its own state is
	// fail-closed, which must not be replaced by the healthy Line's "out".
	second := pairedStoreNode(t, f.store, "edge", f.now)
	settings := testLine(second, "line-b")
	settings.Server = "198.51.100.9"
	settings.ServerName = "line-b.example.invalid"
	settings.SortOrder = 2
	if _, err := f.store.SetLine(settings, f.now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, f.store, second, f.now)
	offline := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, offline, f.now)
	configureOut(t, f.store, offline, f.now)
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: offline, LineID: second, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, offline); err != nil {
		t.Fatal(err)
	}

	// The policy does not select the Out, so the offline Out is a reported
	// per-Line state rather than a refusal: the publication still assembles.
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatalf("mixed assembly: %v", err)
	}
	if assembly.EgressState != store.PolicyEgressMixed {
		t.Fatalf("egress_state = %q, want %q for a healthy and a fail-closed line", assembly.EgressState, store.PolicyEgressMixed)
	}
	if assembly.EgressCode != route.CodeOutOfflineFailClosed {
		t.Fatalf("egress_code = %q, want %q", assembly.EgressCode, route.CodeOutOfflineFailClosed)
	}
	perLine := map[string]string{}
	for _, target := range assembly.Targets {
		perLine[target.LineID] = target.Egress
	}
	if perLine[f.line] != route.AIEgressOut || perLine[second] != store.PolicyEgressFailClosed {
		t.Fatalf("per-line egress = %v", perLine)
	}
}

// TestPublishAssemblyWithholdsSharedFragmentWhenLinesDiffer pins the other
// first-only artifact: the assembly used to return the first Line's route
// fragment as if it were the published one. An explicit fallback on one Line
// next to a healthy Out renders different bytes, so no shared fragment can be
// reported and each candidate keeps its own.
func TestPublishAssemblyWithholdsSharedFragmentWhenLinesDiffer(t *testing.T) {
	f := newPublishFixture(t)
	healthy := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, healthy, f.now)
	configureOut(t, f.store, healthy, f.now)
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: healthy, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, f.store, healthy)
	confirmChain(t, f.store, healthy, f.now)

	second := pairedStoreNode(t, f.store, "edge", f.now)
	settings := testLine(second, "line-b")
	settings.Server = "198.51.100.9"
	settings.ServerName = "line-b.example.invalid"
	settings.SortOrder = 2
	if _, err := f.store.SetLine(settings, f.now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, f.store, second, f.now)
	offline := pairedStoreNode(t, f.store, "out", f.now)
	markLineOnline(t, f.store, offline, f.now)
	configureOut(t, f.store, offline, f.now)
	if err := f.store.SetOutBindingAt(store.OutBinding{OutID: offline, LineID: second, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, offline); err != nil {
		t.Fatal(err)
	}

	f.activatePolicy(t, store.PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-fallback","fallback_to_line":true}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatalf("fallback assembly: %v", err)
	}
	if assembly.EgressState != store.PolicyEgressMixed {
		t.Fatalf("egress_state = %q, want mixed", assembly.EgressState)
	}
	if assembly.RouteFragment != nil {
		t.Fatalf("a mixed fleet reported one shared fragment: %s", assembly.RouteFragment)
	}
	perLine := map[string]store.PublishTarget{}
	for _, target := range assembly.Targets {
		perLine[target.LineID] = target
	}
	if perLine[f.line].Egress != route.AIEgressOut ||
		!strings.Contains(string(perLine[f.line].Candidate.Route), `"outbound": "out"`) {
		t.Fatalf("healthy line target = %+v", perLine[f.line])
	}
	if perLine[second].Egress != route.AIEgressLineFallback ||
		strings.Contains(string(perLine[second].Candidate.Route), `"outbound": "out"`) {
		t.Fatalf("fallback line target = %+v", perLine[second])
	}
}

// TestAggregatePolicyEgress pins the precedence rule directly: identical states
// pass through, any disagreement is mixed, and the reported code is a real
// reason from one of the Lines.
func TestAggregatePolicyEgress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		states []string
		codes  []string
		want   string
		code   string
	}{
		{"empty", nil, nil, "", ""},
		{"one line", []string{route.AIEgressLine}, []string{""}, route.AIEgressLine, ""},
		{"every line direct", []string{route.AIEgressLine, route.AIEgressLine}, []string{"", ""}, route.AIEgressLine, ""},
		{"every line out", []string{route.AIEgressOut, route.AIEgressOut}, []string{"", ""}, route.AIEgressOut, ""},
		{"healthy and fail-closed", []string{route.AIEgressOut, store.PolicyEgressFailClosed},
			[]string{"", route.CodeOutOfflineFailClosed}, store.PolicyEgressMixed, route.CodeOutOfflineFailClosed},
		{"fail-closed first", []string{store.PolicyEgressFailClosed, route.AIEgressOut},
			[]string{route.CodeOutOfflineFailClosed, ""}, store.PolicyEgressMixed, route.CodeOutOfflineFailClosed},
		{"out and line", []string{route.AIEgressOut, route.AIEgressLine}, []string{"", ""}, store.PolicyEgressMixed, ""},
		{"fallback and out", []string{route.AIEgressLineFallback, route.AIEgressOut},
			[]string{route.CodeOutOfflineFailClosed, ""}, store.PolicyEgressMixed, route.CodeOutOfflineFailClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, code := store.AggregatePolicyEgress(tc.states, tc.codes)
			if state != tc.want || code != tc.code {
				t.Fatalf("aggregate = %q/%q, want %q/%q", state, code, tc.want, tc.code)
			}
		})
	}
}

func TestPublishAssemblyRefusesUnpinnedAndInvalidPolicy(t *testing.T) {
	f := newPublishFixture(t)
	// A geo rule needs its pin. The create path already proves this, so the
	// regression here is the assembly path: a stored row whose pins were
	// emptied behind the store's back must be refused, not rendered as a
	// "use the built-in database" fallback.
	pinned := `{"geosite":{"ai":{"source":"https://rulesets.example.invalid/geosite/ai/2026.10.21.srs","version":"2026.10.21","sha256":"` + strings.Repeat("a", 64) + `"}}}`
	record := f.activatePolicy(t, store.PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"geosite":["ai"]},"action":"direct"}]}`, pinned)
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"server","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE route_policies SET pins='{}' WHERE id=? AND revision=?`, record.ID, record.Revision); err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), verifier, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), compiler.CodeRulesetUnpinned) {
		t.Fatalf("unpinned ruleset = %v, want %s", err, compiler.CodeRulesetUnpinned)
	}
	if singBox, mihomo := verifier.counts(); singBox != 0 || mihomo != 0 {
		t.Fatal("an unpinned ruleset reached the kernel gate")
	}
	// A layer without any active revision is a 404-class refusal.
	none, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, none, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePublishNoPolicy) {
		t.Fatalf("missing client policy = %v, want %s", err, store.CodePublishNoPolicy)
	}
	// A server policy with no Line to publish to is refused explicitly.
	if _, err := f.store.DB.Exec(`UPDATE route_policies SET pins=? WHERE id=? AND revision=?`, pinned, record.ID, record.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`DELETE FROM line_settings`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePublishNoLines) {
		t.Fatalf("policy without a line = %v, want %s", err, store.CodePublishNoLines)
	}
}

func TestPublishAssemblyClientDocuments(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerClient,
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), verifier, request, f.now)
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
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
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
			if _, err := f.store.AssemblePolicyPublication(context.Background(), tc.verifier, request, f.now); err == nil ||
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
	f.activatePolicy(t, store.PolicyLayerClient,
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`, "")
	clientRequest, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(),
		&fixturePublishVerifier{missingMihomo: true}, clientRequest, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), node.CodePublishMihomoMissing) {
		t.Fatalf("missing mihomo = %v, want %s", err, node.CodePublishMihomoMissing)
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(),
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
			if _, err := store.ParsePolicyPublishRequest(json.RawMessage(tc.body)); err == nil ||
				!strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("%s = %v, want %s", tc.name, err, tc.want)
			}
		})
	}
	// The documented body parses, and layer defaults to both layers.
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-1","fallback_to_line":true}`))
	if err != nil || request.Layer != "" || !request.FallbackToLine || request.OperationID != "op-1" {
		t.Fatalf("documented body = %+v err=%v", request, err)
	}
}

func TestPublishAssemblyCarriesManifestFields(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"server","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
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

// TestPublishCandidateRouteIsInCandidateDocument proves the route reaches the
// candidate document the Agent pulls, instead of only reaching the gate.
func TestPublishCandidateRouteIsInCandidateDocument(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerServer,
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"server","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := f.store.PublishPolicyAssembly(assembly, f.now)
	if err != nil {
		t.Fatalf("store publication: %v", err)
	}
	if len(publication.Lines) != 1 || publication.Lines[0].Status != "queued" {
		t.Fatalf("publication = %+v", publication)
	}
	stored, err := f.store.LatestCandidate(f.line)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Document.Schema != node.CandidateSchemaV3 {
		t.Fatalf("candidate schema = %s, want v3", stored.Document.Schema)
	}
	if !strings.Contains(string(stored.Document.Route), "ai.example.invalid") {
		t.Fatalf("stored candidate route = %s", stored.Document.Route)
	}
	// The stored digest is the digest of the compiled document, and the
	// compiled document carries the route.
	compiled, err := node.CompileCandidate(stored.Document.Candidate())
	if err != nil {
		t.Fatalf("compile stored candidate: %v", err)
	}
	if !strings.Contains(string(compiled), "ai.example.invalid") {
		t.Fatalf("compiled candidate lost the route: %s", compiled)
	}
	if compiler.Hash(compiled) != stored.ConfigSHA256 {
		t.Fatalf("stored digest %s does not match the compiled document", stored.ConfigSHA256)
	}
	// The four fixed task kinds are queued for the publication.
	tasks := chainRevisionParams(t, f.store, f.line, stored.Revision)
	if len(tasks) != len(protocolKinds()) {
		t.Fatalf("chain length = %d, want %d", len(tasks), len(protocolKinds()))
	}
	for index, kind := range protocolKinds() {
		if tasks[index].Kind != kind {
			t.Fatalf("chain[%d] = %s, want %s", index, tasks[index].Kind, kind)
		}
	}
}

func TestPublishRefusesChangedSnapshotAndUnfinishedChain(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// A chain in flight must not be replaced by a publication.
	if _, err := f.store.DB.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=?`, f.line); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PublishPolicyAssembly(assembly, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePublishTasksInProgress) {
		t.Fatalf("unfinished chain = %v, want %s", err, store.CodePublishTasksInProgress)
	}
	settleTasks(t, f.store, f.line)

	// A candidate revision that advanced after the gate makes the gated bytes
	// stale, so the publication is refused rather than storing them.
	assembly, err = f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.ReconcileNode(f.line, f.now); err != nil {
		t.Fatalf("advance the line: %v", err)
	}
	settleTasks(t, f.store, f.line)
	if _, err := f.store.PublishPolicyAssembly(assembly, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePublishRevisionChanged) {
		t.Fatalf("stale assembly = %v, want %s", err, store.CodePublishRevisionChanged)
	}
}

func protocolKinds() []string { return protocol.PublicationKinds }
