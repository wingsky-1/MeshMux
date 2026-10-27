package ir

import (
	"strings"
	"testing"
)

// The IR package is the shared vocabulary of the subscription composer and the
// policy generators. These tests pin the predicates that must agree in both
// layers, plus the anti-corruption check of the one foreign structure policy
// consumes.

func TestPinDetailAcceptsOneImmutableArtifact(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if detail := PinDetail("https://rulesets.example.invalid/2026-10-26.srs", "20261026", digest); detail != "" {
		t.Fatalf("valid pin refused: %s", detail)
	}
	cases := map[string][3]string{
		"http source":      {"http://rulesets.example.invalid/a.srs", "1", digest},
		"query":            {"https://rulesets.example.invalid/a.srs?x=1", "1", digest},
		"mutable version":  {"https://rulesets.example.invalid/a.srs", "latest", digest},
		"mutable path":     {"https://rulesets.example.invalid/main/a.srs", "1", digest},
		"loopback literal": {"https://127.0.0.1/a.srs", "1", digest},
		"private literal":  {"https://10.0.0.1/a.srs", "1", digest},
		"short digest":     {"https://rulesets.example.invalid/a.srs", "1", "abc"},
		"uppercase digest": {"https://rulesets.example.invalid/a.srs", "1", strings.ToUpper(digest)},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if detail := PinDetail(input[0], input[1], input[2]); detail == "" {
				t.Fatalf("invalid pin accepted: %+v", input)
			}
		})
	}
}

func TestValidMatcherValues(t *testing.T) {
	if !ValidDomain("dl.example.invalid") || ValidDomain("DL.example.invalid") || ValidDomain("single") {
		t.Fatal("domain predicate is not canonical")
	}
	if !ValidTag("geosite-cn") || ValidTag("CN") || ValidTag("-bad") {
		t.Fatal("tag predicate is not canonical")
	}
	if !ValidSSID("home-wifi") || ValidSSID("Home Wifi") {
		t.Fatal("ssid predicate is not canonical")
	}
	if got := NormalizeSSID(" Home  Wifi "); got != "homewifi" {
		t.Fatalf("normalize = %q", got)
	}
	if !ValidID("11111111111111111111111111111111") || ValidID("1111111111111111111111111111111") || ValidID("G1111111111111111111111111111111") {
		t.Fatal("identity predicate is not canonical")
	}
}

// TestMeshViewValidateIsTheAntiCorruptionBoundary proves the shared projection
// refuses hostile or malformed input before a policy reads it, and accepts the
// canonical shape the subscription package produces.
func TestMeshViewValidateIsTheAntiCorruptionBoundary(t *testing.T) {
	good := MeshView{
		DeviceID:        "0123456789abcdef0123456789abcdef",
		DisplayName:     "alice-iphone",
		Hostname:        "mesh-alice-iphone",
		ControlURL:      "https://headscale.example.invalid",
		TailnetPrefixes: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		LineLabels:      []string{"tokyo-1 [0123456789abcdef0123456789abcdef]"},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("canonical view refused: %v", err)
	}
	cases := map[string]MeshView{
		"bad identity":  {DeviceID: "short"},
		"bad hostname":  {Hostname: "Mesh-Alice"},
		"host route":    {TailnetPrefixes: []string{"100.64.0.1/10"}},
		"not a cidr":    {TailnetPrefixes: []string{"tailnet"}},
		"control char":  {LineLabels: []string{"line\x00"}},
		"empty label":   {LineLabels: []string{""}},
		"display name":  {DisplayName: " "},
		"too many nets": {TailnetPrefixes: make([]string, MaxMeshLabels+1)},
	}
	for name, view := range cases {
		t.Run(name, func(t *testing.T) {
			if err := view.Validate(); err == nil {
				t.Fatalf("invalid view accepted: %+v", view)
			}
		})
	}
}

// TestGeoTagVocabulary pins the one spelling of a rendered geo rule-set tag.
// The composer prefixes a code with the matcher kind, the policy generators and
// the client-document adapter read the tag back, so the round trip must hold
// for the codes the pin maps are keyed by.
func TestGeoTagVocabulary(t *testing.T) {
	if GeoSiteTagPrefix != "geosite-" || GeoIPTagPrefix != "geoip-" {
		t.Fatalf("prefixes = %q/%q; the rendered kernel tags are frozen", GeoSiteTagPrefix, GeoIPTagPrefix)
	}
	for code, want := range map[string]struct{ site, ip string }{
		"cn":               {"geosite-cn", "geoip-cn"},
		"ai@2026.10.21":    {"geosite-ai@2026.10.21", "geoip-ai@2026.10.21"},
		"private@20261026": {"geosite-private@20261026", "geoip-private@20261026"},
	} {
		if got := GeoSiteTag(code); got != want.site {
			t.Fatalf("GeoSiteTag(%q) = %q, want %q", code, got, want.site)
		}
		if got := GeoIPTag(code); got != want.ip {
			t.Fatalf("GeoIPTag(%q) = %q, want %q", code, got, want.ip)
		}
	}

	// Round trip: every rendered tag names its kind and its code, so the adapter
	// that resolves a pin can never read a GeoSite tag as a GeoIP one.
	for _, tag := range []string{"geosite-cn", "geoip-cn", "geosite-ai@2026.10.21", "geoip-ai@2026.10.21"} {
		kind, code, ok := SplitGeoTag(tag)
		if !ok {
			t.Fatalf("%q is not recognised as a geo tag", tag)
		}
		rendered := ""
		switch kind {
		case MatcherGeoSite:
			rendered = GeoSiteTag(code)
		case MatcherGeoIP:
			rendered = GeoIPTag(code)
		default:
			t.Fatalf("%q resolved to matcher kind %q", tag, kind)
		}
		if rendered != tag {
			t.Fatalf("round trip of %q = %q", tag, rendered)
		}
	}

	// A remote tag is not a geo tag, and a bare prefix names no code.
	for _, tag := range []string{"", "cn", "ai@20261026", "geosite", "geosite-", "geoip-", "GEOSITE-cn", "xgeosite-cn"} {
		if _, _, ok := SplitGeoTag(tag); ok {
			t.Fatalf("%q was accepted as a geo rule-set tag", tag)
		}
	}
}
