package clientdoc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

func TestSingBoxAddsEndpointOnlyForARouteReference(t *testing.T) {
	tests := []struct {
		name     string
		fragment string
		want     bool
	}{
		{
			name:     "rule outbound references the endpoint",
			fragment: `{"route":{"rules":[{"ip_cidr":["100.64.0.0/10"],"outbound":"meshmux-ts"}],"final":"direct"}}`,
			want:     true,
		},
		{
			name:     "final references the endpoint",
			fragment: `{"route":{"rules":[],"final":"meshmux-ts"}}`,
			want:     true,
		},
		{
			name:     "a domain merely contains the tag",
			fragment: `{"route":{"rules":[{"domain_suffix":["meshmux-ts.example.invalid"],"outbound":"direct"}],"final":"direct"}}`,
			want:     false,
		},
		{
			name:     "no reference at all",
			fragment: `{"route":{"rules":[{"outbound":"direct"}],"final":"direct"}}`,
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := SingBox([]byte(tt.fragment))
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Endpoints []struct {
					Tag string `json:"tag"`
				} `json:"endpoints"`
			}
			if err := json.Unmarshal(body, &document); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, endpoint := range document.Endpoints {
				if endpoint.Tag == protocol.TailscaleEndpointTag {
					found = true
				}
			}
			if found != tt.want {
				t.Fatalf("endpoint present = %v, want %v; document: %s", found, tt.want, body)
			}
		})
	}
}

func TestSingBoxRefusesAFragmentWithoutRoute(t *testing.T) {
	for _, fragment := range []string{`not json`, `{}`, `{"route":[]}`} {
		if _, err := SingBox([]byte(fragment)); err == nil ||
			!strings.HasPrefix(err.Error(), "RENDER_SINGBOX_FAILED") {
			t.Fatalf("SingBox(%q) = %v, want RENDER_SINGBOX_FAILED", fragment, err)
		}
	}
}

func TestMihomoRuleProviderURLIsAQuotedYAMLScalar(t *testing.T) {
	source := "https://rulesets.example.invalid/2026-10-24/rules:v1#lock"
	providers, err := mihomoRuleProviders(
		policy.RuleSetPins{Remote: map[string]policy.RulesetPin{"lock": {Source: source}}},
		[]policy.CompilerRule{{Match: policy.Match{RuleSets: []string{"lock"}}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(providers, `url: "`+source+`"`) {
		t.Fatalf("URL is not a quoted YAML scalar:\n%s", providers)
	}
	if strings.Contains(providers, "url: "+source) {
		t.Fatalf("URL is emitted as a plain YAML scalar:\n%s", providers)
	}
}

func TestMihomoRefusesAnUnpinnedRuleSet(t *testing.T) {
	_, err := Mihomo([]byte("rules: []\n"),
		policy.RuleSetPins{},
		[]policy.CompilerRule{{Match: policy.Match{RuleSets: []string{"lock"}}}})
	if err == nil || !strings.HasPrefix(err.Error(), policy.CodeRulesetUnpinned) {
		t.Fatalf("Mihomo() = %v, want %s", err, policy.CodeRulesetUnpinned)
	}
}

// TestMihomoResolvesGeoProvidersThroughTheSharedVocabulary pins the geo tag
// round trip at the adapter boundary. The tag is produced by the policy
// renderer and read back here to choose the pin and the provider behavior; both
// directions go through internal/core/subscription/ir, so a GeoSite code can
// never be looked up as a GeoIP pin even when the two share a code.
func TestMihomoResolvesGeoProvidersThroughTheSharedVocabulary(t *testing.T) {
	pins := policy.RuleSetPins{
		GeoSite: map[string]policy.RulesetPin{"cn": {Source: "https://rulesets.example.invalid/geosite/cn.srs"}},
		GeoIP:   map[string]policy.RulesetPin{"cn": {Source: "https://rulesets.example.invalid/geoip/cn.srs"}},
	}
	providers, err := mihomoRuleProviders(pins, []policy.CompilerRule{{Match: policy.Match{
		GeoSite: []string{"cn"},
		GeoIP:   []string{"cn"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(providers, "geosite-cn:") || !strings.Contains(providers, "geoip-cn:") {
		t.Fatalf("providers do not declare both geo tags:\n%s", providers)
	}
	// The two entries must point at their own artifact and carry their own
	// behavior; a shared code must not collapse them into one provider.
	for _, want := range []struct{ tag, behavior, source string }{
		{"geosite-cn", "domain", pins.GeoSite["cn"].Source},
		{"geoip-cn", "ipcidr", pins.GeoIP["cn"].Source},
	} {
		block := "  " + want.tag + ":\n    type: http\n    behavior: " + want.behavior + "\n    url: \"" + want.source + "\"\n"
		if !strings.Contains(providers, block) {
			t.Fatalf("provider %s is not the expected block %q:\n%s", want.tag, block, providers)
		}
	}
}
