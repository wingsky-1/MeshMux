package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func testModel() subscription.MeshConfigModel {
	return subscription.MeshConfigModel{
		DeviceID:        "0123456789abcdef0123456789abcdef",
		DisplayName:     "alice-iphone",
		Hostname:        "mesh-alice-iphone",
		ControlURL:      "https://headscale.example.invalid",
		TailnetPrefixes: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		LineLabels:      []string{"tokyo-1", "osaka-1"},
	}
}

// TestGeneratorsFollowPolicyDataNotHardcodedLists proves both generators are
// pure functions of the policy: an empty policy has no rules, a custom policy
// is rendered in priority order, and the same input yields the same bytes and
// hash.
func TestGeneratorsFollowPolicyDataNotHardcodedLists(t *testing.T) {
	policy := ClientPolicy{
		Default: ActionProxy,
		Rules: []Rule{
			{Priority: 10, Match: Match{Domains: []string{"ai.example.invalid"}}, Action: ActionDirect},
			{Priority: 20, Match: Match{DomainSuffixes: []string{"example.invalid"}}, Action: ActionProxy},
			{Priority: 30, Match: Match{IPCIDRs: []string{"203.0.113.0/24"}}, Action: ActionDirect},
		},
	}
	first, err := RenderSingBox(policy, RuleSetPins{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderSingBox(policy, RuleSetPins{})
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || Hash(first) != Hash(second) {
		t.Fatal("sing-box generation is not deterministic")
	}
	var document struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Route.Rules) != 3 || document.Route.Final != singBoxProxyTag {
		t.Fatalf("sing-box route = %#v, want three rules and the proxy final", document.Route)
	}
	if got := document.Route.Rules[0]["domain"].([]any)[0]; got != "ai.example.invalid" {
		t.Fatalf("first rule = %#v, want the priority-10 domain rule", document.Route.Rules[0])
	}
	if document.Route.Rules[0]["outbound"] != singBoxDirectTag {
		t.Fatalf("first rule outbound = %#v, want direct", document.Route.Rules[0]["outbound"])
	}
	if got := document.Route.Rules[2]["ip_cidr"].([]any)[0]; got != "203.0.113.0/24" {
		t.Fatalf("last rule = %#v, want the priority-30 CIDR rule", document.Route.Rules[2])
	}

	mihomo, err := RenderMihomo(policy, RuleSetPins{})
	if err != nil {
		t.Fatal(err)
	}
	want := "rules:\n" +
		"  - \"DOMAIN,ai.example.invalid,DIRECT\"\n" +
		"  - \"DOMAIN-SUFFIX,example.invalid,PROXY\"\n" +
		"  - \"IP-CIDR,203.0.113.0/24,DIRECT,no-resolve\"\n" +
		"  - \"MATCH,PROXY\"\n"
	if string(mihomo) != want {
		t.Fatalf("mihomo fragment = %q, want %q", mihomo, want)
	}

	empty, err := RenderSingBox(ClientPolicy{Default: ActionDirect}, RuleSetPins{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(empty), `"outbound"`) != 0 || !strings.Contains(string(empty), `"final": "direct"`) {
		t.Fatalf("empty policy rendered hardcoded rules: %s", empty)
	}
	if Hash(first) == Hash(empty) {
		t.Fatal("different policies hashed to the same document")
	}
}

// TestRulesetVersionLockAndChecksum covers the Geo/remote pin contract: a
// mutable channel is a configuration defect, an unpinned identifier never
// reaches a generator, and downloaded bytes are usable only when non-empty,
// bounded and matching the pinned SHA-256.
func TestRulesetVersionLockAndChecksum(t *testing.T) {
	payload := []byte(`{"version":1,"rules":[]}`)
	pin := RulesetPin{
		Source:  "https://rulesets.example.invalid/geosite/cn/2026.10.21.srs",
		Version: "2026.10.21",
		SHA256:  digest(payload),
	}
	pins := RuleSetPins{GeoSite: map[string]RulesetPin{"cn": pin}}
	policy := ClientPolicy{
		Default: ActionProxy,
		Rules: []Rule{{
			Priority: 10,
			Match:    Match{GeoSite: []string{"cn"}},
			Action:   ActionDirect,
		}},
	}
	if _, err := RenderSingBox(policy, pins); err != nil {
		t.Fatalf("pinned geosite rejected: %v", err)
	}
	mihomo, err := RenderMihomo(policy, pins)
	if err != nil || !strings.Contains(string(mihomo), "RULE-SET,geosite-cn,DIRECT") {
		t.Fatalf("mihomo pinned geosite = %s err=%v", mihomo, err)
	}

	mutable := pin
	for _, version := range []string{"latest", "head", "main", "master", "stable", "dev", "nightly"} {
		mutable.Version = version
		if _, err := RenderSingBox(policy, RuleSetPins{GeoSite: map[string]RulesetPin{"cn": mutable}}); err == nil ||
			!strings.HasPrefix(err.Error(), CodeRulesetPinInvalid) {
			t.Fatalf("mutable version %q error = %v, want %s", version, err, CodeRulesetPinInvalid)
		}
	}
	for name, source := range map[string]string{
		"http":     "http://rulesets.example.invalid/geosite/cn/2026.10.21.srs",
		"query":    "https://rulesets.example.invalid/geosite/cn/2026.10.21.srs?x=1",
		"fragment": "https://rulesets.example.invalid/geosite/cn/2026.10.21.srs#x",
	} {
		unsafe := pin
		unsafe.Source = source
		if _, err := RenderSingBox(policy, RuleSetPins{GeoSite: map[string]RulesetPin{"cn": unsafe}}); err == nil ||
			!strings.HasPrefix(err.Error(), CodeRulesetPinInvalid) {
			t.Fatalf("%s source error = %v, want %s", name, err, CodeRulesetPinInvalid)
		}
	}

	policy.Rules[0].Match.GeoSite = []string{"us"}
	if _, err := RenderSingBox(policy, pins); err == nil || !strings.HasPrefix(err.Error(), CodeRulesetUnpinned) {
		t.Fatalf("unpinned geosite error = %v, want %s", err, CodeRulesetUnpinned)
	}

	if _, err := VerifyRuleset(pin, payload); err != nil {
		t.Fatalf("matching ruleset rejected: %v", err)
	}
	for name, body := range map[string][]byte{
		"empty":     nil,
		"tampered":  []byte(`{"version":1,"rules":[{"domain_suffix":["evil.invalid"]}]}`),
		"oversized": make([]byte, MaxRulesetBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRuleset(pin, body); err == nil ||
				!strings.HasPrefix(err.Error(), CodeRulesetFetchFailed) {
				t.Fatalf("VerifyRuleset(%s) error = %v, want %s", name, err, CodeRulesetFetchFailed)
			}
		})
	}
}

// TestServerPolicyFailsClosedOnOutOffline pins the #8 handover: a configured but
// unavailable Out never becomes a direct Line silently. Only an explicit,
// audited fallback resolves to direct; a missing Out or an unaudited fallback
// is refused.
func TestServerPolicyFailsClosedOnOutOffline(t *testing.T) {
	policy := ServerPolicy{
		Default:       ActionDirect,
		OutConfigured: true,
		Rules: []Rule{{
			Priority: 10,
			Match:    Match{Domains: []string{"ai.example.invalid"}},
			Action:   ActionOut,
		}},
	}
	if _, err := ResolveServerPolicy(policy); err == nil {
		t.Fatal("offline Out resolved without a decision")
	} else {
		var blocked *BlockedError
		if !errors.As(err, &blocked) || blocked.Code != CodeOutOfflineFailClosed || blocked.Detail != "OUT_OFFLINE" {
			t.Fatalf("offline error = %v, want OUT_OFFLINE_FAIL_CLOSED/OUT_OFFLINE", err)
		}
	}

	policy.FallbackToLine = true
	if _, err := ResolveServerPolicy(policy); err == nil ||
		!strings.HasPrefix(err.Error(), CodeOutFallbackUnaudited) {
		t.Fatalf("unaudited fallback error = %v, want %s", err, CodeOutFallbackUnaudited)
	}

	policy.OperationID = "abcdefghijklmnopqrstuv"
	resolved, err := ResolveServerPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Rules[0].Action != ActionDirect || resolved.Default != ActionDirect {
		t.Fatalf("audited fallback did not rewrite the Out action: %#v", resolved)
	}

	policy.OutAvailable = true
	resolved, err = ResolveServerPolicy(policy)
	if err != nil || resolved.Rules[0].Action != ActionOut {
		t.Fatalf("healthy Out resolved = %#v err=%v", resolved, err)
	}

	missing := policy
	missing.OutConfigured = false
	missing.OutAvailable = false
	if _, err := ResolveServerPolicy(missing); err == nil ||
		!strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID") {
		t.Fatalf("missing Out error = %v, want OUT_BINDING_INVALID", err)
	}
	direct := ServerPolicy{Default: ActionDirect}
	if resolved, err := ResolveServerPolicy(direct); err != nil || resolved.Default != ActionDirect {
		t.Fatalf("out-free direct policy = %#v err=%v", resolved, err)
	}
}

// TestMeshModelIsConsumedReadOnly proves the compiler copies the non-secret view
// model and never guesses a missing node: an unknown or empty Line label is
// refused, while the tailnet prefixes become the Tailscale rule.
func TestMeshModelIsConsumedReadOnly(t *testing.T) {
	model := testModel()
	policy, err := MeshClientPolicy(model, "tokyo-1")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mesh.DeviceID != model.DeviceID || policy.Mesh.DisplayName != model.DisplayName ||
		policy.Mesh.Hostname != model.Hostname || policy.Mesh.ControlURL != model.ControlURL {
		t.Fatalf("mesh identity was not consumed read-only: %#v", policy.Mesh)
	}
	if len(policy.Rules) != 1 || policy.Rules[0].Action != ActionTailscale ||
		policy.Rules[0].Match.IPCIDRs[0] != "100.64.0.0/10" {
		t.Fatalf("mesh policy = %#v, want tailnet-first rules", policy)
	}
	for _, label := range []string{"", "missing-1"} {
		if _, err := MeshClientPolicy(model, label); err == nil ||
			!strings.HasPrefix(err.Error(), CodePolicyNodeUnknown) {
			t.Fatalf("label %q error = %v, want %s", label, err, CodePolicyNodeUnknown)
		}
	}
	model.TailnetPrefixes[0] = "198.51.100.0/24"
	model.LineLabels[0] = "changed"
	if policy.Mesh.TailnetPrefixes[0] != "100.64.0.0/10" || policy.Mesh.LineLabels[0] != "tokyo-1" {
		t.Fatal("the compiler retained caller-owned mesh slices")
	}
	body, err := RenderSingBox(policy, RuleSetPins{})
	if err != nil || !strings.Contains(string(body), singBoxTailscaleTag) {
		t.Fatalf("mesh render = %s err=%v", body, err)
	}
	if _, err := RenderMihomo(policy, RuleSetPins{}); err == nil ||
		!strings.HasPrefix(err.Error(), CodeRenderUnsupported) {
		t.Fatalf("Mihomo accepted a Tailscale action: %v", err)
	}
}

// TestPolicyRejectsConflictsAndCrossRoleActions covers the validation the Web
// layer needs before a candidate can be compiled.
func TestPolicyRejectsConflictsAndCrossRoleActions(t *testing.T) {
	cases := []struct {
		name   string
		policy ClientPolicy
		want   string
	}{
		{"duplicate priority", ClientPolicy{Default: ActionProxy, Rules: []Rule{
			{Priority: 1, Match: Match{Domains: []string{"a.example.invalid"}}, Action: ActionDirect},
			{Priority: 1, Match: Match{Domains: []string{"b.example.invalid"}}, Action: ActionDirect},
		}}, CodePolicyConflict},
		{"two matchers", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1,
			Match:    Match{Domains: []string{"a.example.invalid"}, IPCIDRs: []string{"203.0.113.0/24"}},
			Action:   ActionDirect,
		}}}, CodePolicyInvalid},
		{"host bits", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1, Match: Match{IPCIDRs: []string{"203.0.113.7/24"}}, Action: ActionDirect,
		}}}, CodePolicyInvalid},
		{"client out", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1, Match: Match{Domains: []string{"a.example.invalid"}}, Action: ActionOut,
		}}}, CodePolicyInvalid},
		{"empty matcher", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1, Action: ActionDirect,
		}}}, CodePolicyInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %s", err, tc.want)
			}
		})
	}
	if err := (ServerPolicy{Default: ActionProxy}).Validate(); err == nil ||
		!strings.HasPrefix(err.Error(), CodePolicyInvalid) {
		t.Fatalf("server proxy default error = %v, want %s", err, CodePolicyInvalid)
	}
}
