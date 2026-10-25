package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/compiler"
)

func TestAssembleSingBoxClientAddsEndpointOnlyForARouteReference(t *testing.T) {
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
			body, err := assembleSingBoxClient([]byte(tt.fragment))
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
				if endpoint.Tag == clientTailscaleTag {
					found = true
				}
			}
			if found != tt.want {
				t.Fatalf("endpoint present = %v, want %v; document: %s", found, tt.want, body)
			}
		})
	}
}

func TestMihomoRuleProviderURLIsAQuotedYAMLScalar(t *testing.T) {
	source := "https://rulesets.example.invalid/2026-10-24/rules:v1#lock"
	providers, err := mihomoRuleProviders(
		compiler.RuleSetPins{Remote: map[string]compiler.RulesetPin{"lock": {Source: source}}},
		[]compiler.Rule{{Match: compiler.Match{RuleSets: []string{"lock"}}}},
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
