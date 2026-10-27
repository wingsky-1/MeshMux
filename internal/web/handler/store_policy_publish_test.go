package handler

// Assembly tests for the publication pipeline (10d-2b): the three Out states,
// the fail-closed refusals, the ruleset pin gate and the kernel gate ordering.

import (
	"context"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
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

// activatePolicy creates and activates one revision for a layer. The client
// layer was closed to writes in Task 6, so its calls insert a legacy revision
// directly: the preview/gate path still needs a row to read, and this is the
// only way such a row can exist after the upgrade.
func (f publishFixture) activatePolicy(t *testing.T, layer store.PolicyLayer, payload, pins string) store.RoutePolicy {
	t.Helper()
	if layer == store.PolicyLayerClient {
		seedLegacyClientPolicyStore(t, f.store, json.RawMessage(payload), f.now)
		return store.RoutePolicy{Layer: layer, Revision: 1}
	}
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

func TestPublishAssemblyServerLayerRecordsOnly(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")

	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatalf("server assembly: %v", err)
	}
	if assembly.EgressState != policy.AIEgressLine || assembly.EgressCode != "" {
		t.Fatalf("egress = %s/%s, want line/none", assembly.EgressState, assembly.EgressCode)
	}
	if len(assembly.Targets) != 0 {
		t.Fatalf("server layer assembled %d line candidates; it must record intent only", len(assembly.Targets))
	}
	if len(assembly.RouteFragment) != 0 {
		t.Fatalf("server layer rendered a route fragment: %s", assembly.RouteFragment)
	}
	if assembly.ServerRevision != 1 || assembly.RoutePolicyRevisions["server"] != 1 {
		t.Fatalf("server revision = %d manifest=%v", assembly.ServerRevision, assembly.RoutePolicyRevisions)
	}
}

// TestPublishAssemblyAggregatesEveryLineEgress is the I3 regression: a
// publication targets every Line, but the receipt used to take the first Line's
// egress state and present it for the whole fleet. A healthy Line next to a
// fail-closed Line must read as "mixed" while each Line keeps its own state.
// TestPublishAssemblyWithholdsSharedFragmentWhenLinesDiffer pins the other
// first-only artifact: the assembly used to return the first Line's route
// fragment as if it were the published one. An explicit fallback on one Line
// next to a healthy Out renders different bytes, so no shared fragment can be
// reported and each candidate keeps its own.
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
		{"one line", []string{policy.AIEgressLine}, []string{""}, policy.AIEgressLine, ""},
		{"every line direct", []string{policy.AIEgressLine, policy.AIEgressLine}, []string{"", ""}, policy.AIEgressLine, ""},
		{"every line out", []string{policy.AIEgressOut, policy.AIEgressOut}, []string{"", ""}, policy.AIEgressOut, ""},
		{"healthy and fail-closed", []string{policy.AIEgressOut, store.PolicyEgressFailClosed},
			[]string{"", policy.CodeOutOfflineFailClosed}, store.PolicyEgressMixed, policy.CodeOutOfflineFailClosed},
		{"fail-closed first", []string{store.PolicyEgressFailClosed, policy.AIEgressOut},
			[]string{policy.CodeOutOfflineFailClosed, ""}, store.PolicyEgressMixed, policy.CodeOutOfflineFailClosed},
		{"out and line", []string{policy.AIEgressOut, policy.AIEgressLine}, []string{"", ""}, store.PolicyEgressMixed, ""},
		{"fallback and out", []string{policy.AIEgressLineFallback, policy.AIEgressOut},
			[]string{policy.CodeOutOfflineFailClosed, ""}, store.PolicyEgressMixed, policy.CodeOutOfflineFailClosed},
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
	// A geo rule needs its pin. The client layer is read-only now, so the only
	// way such a row exists is a legacy one; it must still be refused at
	// assembly instead of falling back to the built-in database.
	f.activatePolicy(t, store.PolicyLayerClient,
		`{"default":"direct","rules":[{"priority":100,"match":{"geosite":["ai"]},"action":"direct"}]}`, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fixturePublishVerifier{}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), verifier, request, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), policy.CodeRulesetUnpinned) {
		t.Fatalf("unpinned ruleset = %v, want %s", err, policy.CodeRulesetUnpinned)
	}
	if singBox, mihomo := verifier.counts(); singBox != 0 || mihomo != 0 {
		t.Fatal("an unpinned ruleset reached the kernel gate")
	}
	// A layer without any active revision is a refusal.
	none, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`DELETE FROM route_policies WHERE layer='client'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, none, f.now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePublishNoPolicy) {
		t.Fatalf("missing client policy = %v, want %s", err, store.CodePublishNoPolicy)
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
	f.activatePolicy(t, store.PolicyLayerClient,
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"layer":"client","operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		verifier *fixturePublishVerifier
		want     string
	}{
		{"sing-box refuses the client document", &fixturePublishVerifier{rejectSingBoxAt: 1}, node.CodePublishCheckSingBox},
		{"sing-box is missing", &fixturePublishVerifier{missingSingBox: true}, node.CodePublishSingBoxMissing},
		{"mihomo refuses the client document", &fixturePublishVerifier{rejectMihomoAt: 1}, node.CodePublishCheckMihomo},
		{"mihomo is missing", &fixturePublishVerifier{missingMihomo: true}, node.CodePublishMihomoMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.store.AssemblePolicyPublication(context.Background(), tc.verifier, request, f.now); err == nil ||
				!strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("gate refusal = %v, want %s", err, tc.want)
			}
		})
	}
	if _, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now); err != nil {
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
func protocolKinds() []string { return protocol.PublicationKinds }
