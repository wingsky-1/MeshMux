package compiler

import (
	"strings"
	"testing"
)

// TestSSIDPolicy pins canonicalization and the measured support: sing-box
// 1.14.3 accepts wifi_ssid; Mihomo 1.19.32 has no SSID rule type.
func TestSSIDPolicy(t *testing.T) {
	if got := NormalizeSSID(" Home WiFi "); got != "homewifi" {
		t.Fatalf("NormalizeSSID = %q", got)
	}
	for _, ssid := range []string{"home-wifi", "Home-WiFi", "home wifi", "", "home/wifi"} {
		err := (Match{SSIDs: []string{ssid}}).Validate()
		if bad := ssid != "home-wifi"; (err != nil) != bad || (bad && !strings.HasPrefix(err.Error(), CodePolicyInvalid)) {
			t.Fatalf("SSID %q error = %v", ssid, err)
		}
	}
	if err := (Match{DNS: "system"}).Validate(); err == nil || !strings.HasPrefix(err.Error(), CodePolicyInvalid) {
		t.Fatalf("unknown DNS annotation error = %v", err)
	}
	policy := ClientPolicy{Default: ActionProxy, Rules: []Rule{{1, Match{SSIDs: []string{"home-wifi"}}, ActionDirect}}}
	if body, err := RenderSingBox(policy, RuleSetPins{}); err != nil || !strings.Contains(string(body), `"wifi_ssid"`) {
		t.Fatalf("sing-box fragment = %s err=%v", body, err)
	}
	if _, err := RenderMihomo(policy, RuleSetPins{}); err == nil || !strings.HasPrefix(err.Error(), CodeRenderUnsupported) {
		t.Fatalf("Mihomo accepted an SSID matcher: %v", err)
	}
}

// TestDefaultClientPolicy pins order, DNS consistency, fallback and hit chain.
func TestDefaultClientPolicy(t *testing.T) {
	policy, err := DefaultClientPolicy(testModel(), "tokyo-1", ClientDefaults{
		Exceptions: []string{"dl.example.invalid"}, RemoteLANPrefixes: []string{"192.168.50.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Default != ActionProxy || len(policy.Rules) != 3 {
		t.Fatalf("default policy = %#v", policy)
	}
	if tailnet := policy.Rules[0]; tailnet.Action != ActionTailscale || tailnet.Match.DNS != DNSEncrypted ||
		len(tailnet.Match.IPCIDRs) != 3 || tailnet.Match.IPCIDRs[2] != "192.168.50.0/24" {
		t.Fatalf("tailnet rule = %#v", tailnet)
	}
	if policy.Rules[1].Match.GeoSite[0] != "cn" || policy.Rules[2].Match.Domains[0] != "dl.example.invalid" {
		t.Fatalf("domestic/exception rules = %#v", policy.Rules)
	}
	if _, err := DefaultClientPolicy(testModel(), "tokyo-1", ClientDefaults{RemoteLANPrefixes: []string{"192.168.50.7/24"}}); err == nil {
		t.Fatal("non-canonical remote LAN accepted")
	}
	// SSID direct first, then the derived tailnet and CN rules.
	withSSID := ClientPolicy{Default: ActionProxy, Rules: append([]Rule{{50, Match{SSIDs: []string{"home-wifi"}}, ActionDirect}}, policy.Rules...)}
	if err := withSSID.Validate(); err != nil {
		t.Fatalf("SSID + tailnet + CN refused: %v", err)
	}
	policy.Rules = append(policy.Rules, Rule{400, Match{IPCIDRs: []string{"203.0.113.0/24"}, DNS: DNSEncrypted}, ActionProxy})
	for target, want := range map[string]HitExplanation{
		"100.64.0.5":         {100, "ip_cidr 100.64.0.0/10", ActionTailscale, "meshmux-ts (Tailscale endpoint)", DNSEncrypted},
		"dl.example.invalid": {300, "domain dl.example.invalid", ActionDirect, "direct", DNSDomestic},
		"203.0.113.9":        {400, "ip_cidr 203.0.113.0/24", ActionProxy, "meshmux-selector (selected Line)", DNSEncrypted},
	} {
		if got, err := ExplainHit(target, policy); err != nil || got != want {
			t.Fatalf("ExplainHit(%q) = %#v err=%v", target, got, err)
		}
	}
	disabled := policy
	disabled.Rules = nil
	if got, err := ExplainHit("news.example.invalid", disabled); err != nil ||
		got != (HitExplanation{0, "fallback", ActionProxy, "meshmux-selector (selected Line)", DNSEncrypted}) {
		t.Fatalf("fallback hit = %#v err=%v", got, err)
	}
}

// TestClientPolicyRefusesConflicts proves overlaps and DNS disagreement are
// refused with POLICY_CONFLICT, never silently merged.
func TestClientPolicyRefusesConflicts(t *testing.T) {
	conflicts := map[string][]Rule{
		"ssid after proxy":   {{1, Match{IPCIDRs: []string{"100.64.0.0/10"}}, ActionTailscale}, {2, Match{SSIDs: []string{"home-wifi"}}, ActionDirect}},
		"duplicate ssid":     {{1, Match{SSIDs: []string{"home-wifi"}}, ActionDirect}, {2, Match{SSIDs: []string{"home-wifi"}}, ActionDirect}},
		"ssid via proxy":     {{1, Match{SSIDs: []string{"home-wifi"}}, ActionProxy}},
		"cn overlap":         {{1, Match{GeoSite: []string{"cn"}}, ActionDirect}, {2, Match{GeoSite: []string{"cn"}}, ActionProxy}},
		"exception shadowed": {{1, Match{DomainSuffixes: []string{"example.invalid"}}, ActionProxy}, {2, Match{Domains: []string{"dl.example.invalid"}}, ActionDirect}},
		"tailnet shadowed":   {{1, Match{IPCIDRs: []string{"100.64.0.0/10"}}, ActionDirect}, {2, Match{IPCIDRs: []string{"100.64.1.0/24"}}, ActionTailscale}},
		"dns mismatch":       {{1, Match{Domains: []string{"a.example.invalid"}, DNS: DNSEncrypted}, ActionDirect}},
	}
	for name, rules := range conflicts {
		if err := (ClientPolicy{Default: ActionProxy, Rules: rules}).Validate(); err == nil ||
			!strings.HasPrefix(err.Error(), CodePolicyConflict) {
			t.Fatalf("%s: Validate() = %v", name, err)
		}
	}
	ordered := ClientPolicy{Default: ActionProxy, Rules: []Rule{
		{1, Match{Domains: []string{"dl.example.invalid"}}, ActionDirect},
		{2, Match{DomainSuffixes: []string{"example.invalid"}}, ActionProxy},
	}}
	if err := ordered.Validate(); err != nil {
		t.Fatalf("ordered exception refused: %v", err)
	}
}
