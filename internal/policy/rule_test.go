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
		if got := r.ToCompilerMatch(); len(got.Domains)+len(got.DomainSuffixes)+len(got.IPCIDRs)+len(got.GeoSite)+len(got.GeoIP)+len(got.RuleSets) != len(r.Values) {
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

func TestValidateRuleSetRefusesShadowingAndDuplicates(t *testing.T) {
	direct := Rule{StableKey: "a", Name: "A", Action: ActionDirect, Kind: MatcherDomainSuffix, Values: []string{"example.invalid"}}
	shadow := Rule{StableKey: "b", Name: "B", Action: ActionProxy, Kind: MatcherDomain, Values: []string{"x.example.invalid"}}
	if err := ValidateRuleSet([]Rule{direct, shadow}); err == nil || !strings.HasPrefix(err.Error(), "RULE_CONFLICT") {
		t.Fatalf("shadowing pair accepted: %v", err)
	}
	dupe := Rule{StableKey: "c", Name: "C", Action: ActionDirect, Kind: MatcherGeoSite, Values: []string{"cn"}}
	dupe2 := Rule{StableKey: "d", Name: "D", Action: ActionDirect, Kind: MatcherGeoSite, Values: []string{"cn"}}
	if err := ValidateRuleSet([]Rule{dupe, dupe2}); err == nil || !strings.HasPrefix(err.Error(), "RULE_CONFLICT") {
		t.Fatalf("duplicate pair accepted: %v", err)
	}
	harmless := Rule{StableKey: "e", Name: "E", Action: ActionDirect, Kind: MatcherGeoIP, Values: []string{"cn"}}
	if err := ValidateRuleSet([]Rule{direct, harmless}); err != nil {
		t.Fatalf("disjoint pair refused: %v", err)
	}
	for _, bad := range [][]Rule{
		{{StableKey: "x", Name: "X", Action: ActionDirect, Kind: MatcherGeoSite, Values: []string{"bad value!!"}}},
		{{StableKey: "preset-squat", Name: "X", Action: ActionDirect, Kind: MatcherGeoSite, Values: []string{"cn"}}},
	} {
		if err := ValidateRuleSet(bad); err == nil {
			t.Fatalf("invalid set accepted: %+v", bad)
		}
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
		r := Rule{StableKey: p.StableKey, Name: p.Name, Action: p.Action, Kind: p.Kind, Values: p.Values}
		if err := r.Validate(); err != nil {
			t.Fatalf("preset %q invalid: %v", p.StableKey, err)
		}
		seen[p.Kind]++
	}
	for _, kind := range []MatcherKind{MatcherDomain, MatcherDomainSuffix, MatcherIPCIDR, MatcherGeoSite, MatcherGeoIP, MatcherRuleSet} {
		if seen[kind] == 0 {
			t.Fatalf("no preset covers matcher kind %q", kind)
		}
	}
	if _, ok := PresetByKey("preset-direct-cn"); !ok {
		t.Fatal("PresetByKey misses a seeded key")
	}
	if _, ok := PresetByKey("no-such-key"); ok {
		t.Fatal("PresetByKey hits a missing key")
	}
}
