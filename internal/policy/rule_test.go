package policy

import (
	"strings"
	"testing"
)

func TestRuleValidateAcceptsAllSixMatcherKinds(t *testing.T) {
	cases := []Rule{
		{StableKey: "r-domain", Name: "镜像站例外", Action: ActionDirect, Kind: MatcherDomain, Values: []string{"dl.example.invalid"}},
		{StableKey: "r-suffix", Name: "跟踪后缀", Action: ActionReject, Kind: MatcherDomainSuffix, Values: []string{"ads.example.invalid", "tracker.example.invalid"}},
		{StableKey: "r-cidr", Name: "内网段", Action: ActionDirect, Kind: MatcherIPCIDR, Values: []string{"100.64.0.0/10"}},
		{StableKey: "r-geosite", Name: "国内域名", Action: ActionDirect, Kind: MatcherGeoSite, Values: []string{"cn"}},
		{StableKey: "r-geoip", Name: "国内 IP", Action: ActionDirect, Kind: MatcherGeoIP, Values: []string{"cn"}},
		{StableKey: "r-ruleset", Name: "AI 服务", Action: ActionProxy, Kind: MatcherRuleSet, Values: []string{"ai"}},
	}
	for _, r := range cases {
		if err := r.Validate(); err != nil {
			t.Fatalf("%s (%s) refused: %v", r.StableKey, r.Kind, err)
		}
		if got := r.ToCompilerMatchWith(r.Values); len(got.Domains)+len(got.DomainSuffixes)+len(got.IPCIDRs)+len(got.GeoSite)+len(got.GeoIP)+len(got.RuleSets) != len(r.Values) {
			t.Fatalf("%s compiler bridge dropped values: %+v", r.StableKey, got)
		}
	}
}

func TestRuleValidateRefusesBadInput(t *testing.T) {
	base := Rule{StableKey: "r-ok", Name: "正常规则", Action: ActionDirect, Kind: MatcherGeoSite, Values: []string{"cn"}}
	for _, tc := range []struct {
		name   string
		mutate func(*Rule)
		want   string
	}{
		{"bad key", func(r *Rule) { r.StableKey = "Bad Key!" }, "RULE_INVALID"},
		{"empty key", func(r *Rule) { r.StableKey = "" }, "RULE_INVALID"},
		{"preset prefix squat", func(r *Rule) { r.StableKey = "preset-evil" }, "RULE_PRESET_IMMUTABLE"},
		{"empty name", func(r *Rule) { r.Name = "" }, "RULE_INVALID"},
		{"secret in name", func(r *Rule) { r.Name = "泄露 uuid 的规则" }, "RULE_INVALID"},
		{"bad action", func(r *Rule) { r.Action = "out" }, "RULE_INVALID"},
		{"tailscale action", func(r *Rule) { r.Action = "tailscale" }, "RULE_INVALID"},
		{"bad kind", func(r *Rule) { r.Kind = "ssid" }, "RULE_INVALID"},
		{"empty values", func(r *Rule) { r.Values = nil }, "RULE_INVALID"},
		{"blank value", func(r *Rule) { r.Values = []string{"  "} }, "RULE_INVALID"},
		{"duplicate values", func(r *Rule) { r.Values = []string{"cn", "cn"} }, "RULE_INVALID"},
		{"bad domain", func(r *Rule) { r.Kind, r.Values = MatcherDomain, []string{"not a domain!!"} }, "RULE_INVALID"},
		{"non canonical cidr", func(r *Rule) { r.Kind, r.Values = MatcherIPCIDR, []string{"10.0.0.1/8"} }, "RULE_INVALID"},
		{"bad geosite tag", func(r *Rule) { r.Kind, r.Values = MatcherGeoSite, []string{"CN"} }, "RULE_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Values = append([]string(nil), base.Values...)
			tc.mutate(&r)
			if err := r.Validate(); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want prefix %q", err, tc.want)
			}
		})
	}
}

func TestPresetBundleCoversAllSixKinds(t *testing.T) {
	if PresetBundleVersion < 1 {
		t.Fatal("preset bundle version must be positive")
	}
	seen := map[MatcherKind]int{}
	for _, p := range Presets {
		if !IsPresetKey(p.StableKey) {
			t.Fatalf("preset key %q escapes the preset- namespace", p.StableKey)
		}
		// Preset rows are seed data, not operator input: their fields validate
		// under a neutral key, while the real key stays in the reserved
		// namespace (Validate refuses it as operator input, I3).
		shadow := Rule{StableKey: "seed-shape-check", Name: p.Name, Action: p.Action, Kind: p.Kind, Values: p.Values}
		if err := shadow.Validate(); err != nil {
			t.Fatalf("preset %q has invalid fields: %v", p.StableKey, err)
		}
		if err := (Rule{StableKey: p.StableKey, Name: p.Name, Action: p.Action, Kind: p.Kind, Values: p.Values}.Validate()); err == nil ||
			!strings.HasPrefix(err.Error(), "RULE_PRESET_IMMUTABLE") {
			t.Fatalf("preset key %q accepted as operator input: %v", p.StableKey, err)
		}
		seen[p.Kind]++
	}
	for _, kind := range []MatcherKind{MatcherDomain, MatcherDomainSuffix, MatcherIPCIDR, MatcherGeoSite, MatcherGeoIP, MatcherRuleSet} {
		if seen[kind] == 0 {
			t.Fatalf("no preset covers matcher kind %q", kind)
		}
	}
}
