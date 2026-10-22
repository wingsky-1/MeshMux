package compiler

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRenderServerRouteFollowsPolicyAndPins proves the fragment is a pure
// function of the policy and pins: priority order, Out/direct tags, a
// version-locked rule_set, determinism and no embedded AI list.
func TestRenderServerRouteFollowsPolicyAndPins(t *testing.T) {
	policy := ServerPolicy{
		Default:       ActionDirect,
		OutConfigured: true,
		OutAvailable:  true,
		Rules: []Rule{
			{Priority: 10, Match: Match{Domains: []string{"chat.example.invalid"}}, Action: ActionOut},
			{Priority: 20, Match: Match{IPCIDRs: []string{"203.0.113.0/24"}}, Action: ActionDirect},
			{Priority: 30, Match: Match{GeoSite: []string{"ai"}}, Action: ActionOut},
		},
	}
	pin := map[string]RulesetPin{"ai": {
		Source: "https://rulesets.example.invalid/geosite/ai/2026.10.21.srs", Version: "2026.10.21", SHA256: strings.Repeat("0", 64),
	}}
	first, err := RenderServerRoute(policy, RuleSetPins{GeoSite: pin})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderServerRoute(policy, RuleSetPins{GeoSite: pin})
	if err != nil || string(first) != string(second) || Hash(first) != Hash(second) {
		t.Fatalf("render is not deterministic: %v", err)
	}
	var document serverRoute
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Rules) != 3 || document.Final != "direct" ||
		document.Rules[0]["outbound"] != "out" || document.Rules[1]["outbound"] != "direct" {
		t.Fatalf("route = %#v, want priority order and final direct", document)
	}
	tags, ok := document.Rules[2]["rule_set"].([]any)
	if !ok || len(tags) != 1 || tags[0] != "geosite-ai@2026.10.21" {
		t.Fatalf("ruleset rule = %#v, want the pinned label", document.Rules[2])
	}
	if len(document.RuleSet) != 1 || document.RuleSet[0].Tag != "geosite-ai@2026.10.21" ||
		document.RuleSet[0].URL != pin["ai"].Source || strings.Contains(string(first), "openai") {
		t.Fatalf("rule_set = %#v, want the pinned remote reference and no AI list", document.RuleSet)
	}
	pin["ai"] = RulesetPin{Source: pin["ai"].Source, Version: "2026.10.22", SHA256: pin["ai"].SHA256}
	other, err := RenderServerRoute(policy, RuleSetPins{GeoSite: pin})
	if err != nil || Hash(other) == Hash(first) || !strings.Contains(string(other), "geosite-ai@2026.10.22") {
		t.Fatalf("a changed pin version did not change the fragment: %v", err)
	}
}

// TestRenderServerRouteRefusals covers malformed matchers, unpinned rulesets
// and an Out that the caller did not resolve.
func TestRenderServerRouteRefusals(t *testing.T) {
	base := ServerPolicy{Default: ActionDirect, OutConfigured: true, OutAvailable: true}
	out := Match{Domains: []string{"chat.example.invalid"}}
	cases := []struct {
		name   string
		policy ServerPolicy
		pins   RuleSetPins
		want   string
	}{
		{"invalid domain", withRule(base, Match{Domains: []string{"Chat.Example.invalid"}}), RuleSetPins{}, CodePolicyInvalid},
		{"invalid cidr", withRule(base, Match{IPCIDRs: []string{"203.0.113.7/24"}}), RuleSetPins{}, CodePolicyInvalid},
		{"unpinned geosite", withRule(base, Match{GeoSite: []string{"ai"}}), RuleSetPins{}, CodeRulesetUnpinned},
		{"unbound out", withRule(ServerPolicy{Default: ActionDirect}, out), RuleSetPins{}, "OUT_BINDING_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderServerRoute(tc.policy, tc.pins); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("RenderServerRoute() error = %v, want %s", err, tc.want)
			}
		})
	}
}

func withRule(policy ServerPolicy, match Match) ServerPolicy {
	policy.Rules = []Rule{{Priority: 10, Match: match, Action: ActionOut}}
	return policy
}
