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
