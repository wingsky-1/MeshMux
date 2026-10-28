package spec

// Route tests: the resolved server route travels as an optional block of the
// one v1 candidate document, so the Agent compiles and applies exactly what
// the Hub gated.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const v3RouteFixture = `{"rules":[{"domain":["ai.example.invalid"],"outbound":"direct"}],"final":"direct"}`

func testV3Candidate(t *testing.T) Candidate {
	t.Helper()
	candidate := testV2Candidate(t)
	candidate.Route = json.RawMessage(v3RouteFixture)
	return candidate
}

// TestCandidateRouteCarriesRouteRoundTrip proves the route block round-trips
// with its route intact on the single v1 schema.
func TestCandidateV3CarriesRouteRoundTrip(t *testing.T) {
	candidate := testV3Candidate(t)
	document := NewCandidateDocument(candidate)
	if document.Schema != CandidateSchema {
		t.Fatalf("schema = %q, want %q", document.Schema, CandidateSchema)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"route":{"rules":[`)) {
		t.Fatalf("candidate document lost the route: %s", body)
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != CandidateSchema || !decoded.Candidate().Equal(candidate) {
		t.Fatalf("decoded = %+v", decoded)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestCandidateRouteRequiresReality proves a route is not smuggled into a
// credential-free baseline: the optional route block needs the REALITY
// transport of the Line it belongs to.
func TestCandidateRouteRequiresReality(t *testing.T) {
	baseline := NewCandidateDocument(validCandidate())
	baseline.Route = json.RawMessage(v3RouteFixture)
	if err := baseline.Validate(); err == nil {
		t.Fatal("a credential-free document accepted a route")
	}
	edge := validCandidate()
	edge.Role = RoleEdge
	edge.Route = json.RawMessage(v3RouteFixture)
	document := NewCandidateDocument(edge)
	if err := document.Validate(); err == nil {
		t.Fatal("an edge document without reality accepted a route")
	}
	if err := NewCandidateDocument(testV3Candidate(t)).Validate(); err != nil {
		t.Fatalf("a routed Line candidate was rejected: %v", err)
	}
}

// TestCandidateRouteRejectsMalformedRoute proves the route shape gate: only one
// route object with bounded string values, never a nested payload, an unknown
// key or an outbound-less rule.
func TestCandidateRouteRejectsMalformedRoute(t *testing.T) {
	for name, route := range map[string]string{
		"not json":            `{`,
		"missing rules":       `{"final":"direct"}`,
		"null rules":          `{"rules":null,"final":"direct"}`,
		"missing final":       `{"rules":[]}`,
		"unknown key":         `{"rules":[],"final":"direct","dns":{"servers":[]}}`,
		"rule without out":    `{"rules":[{"domain":["a.example.invalid"]}],"final":"direct"}`,
		"rule with object":    `{"rules":[{"domain":{"x":1},"outbound":"direct"}],"final":"direct"}`,
		"rule with number":    `{"rules":[{"ip_cidr":[1],"outbound":"direct"}],"final":"direct"}`,
		"oversized tag":       `{"rules":[{"domain":["a.example.invalid"],"outbound":"` + strings.Repeat("x", 65) + `"}],"final":"direct"}`,
		"rule_set not array":  `{"rules":[],"rule_set":{"tag":"x"},"final":"direct"}`,
		"rule_set with value": `{"rules":[],"rule_set":[{"tag":1}],"final":"direct"}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(`{"schema":"meshmux-node/v1","node_id":"`+strings.Repeat("a", 32)+
				`","role":"edge","revision":9,"vless_port":8443,"kernel_version":"`+KernelVersion+
				`","users":[],"reality":{"server_name":"www.example.invalid","handshake_server":"www.example.invalid",`+
				`"handshake_port":443,"private_key":"tnILRhHeIrUXzzvieuqqZkSh8BvSiMYsWeZJjyjP8fg","short_id":"0123456789abcdef"},`+
				`"route":`+route+`}`, "x", "x", 1)
			var document CandidateDocument
			if err := json.Unmarshal([]byte(body), &document); err == nil {
				t.Fatalf("malformed route was accepted: %s", document.Route)
			}
		})
	}
}

// TestRouteValueGateAcceptsRenderedRoutes proves the real renderer output is
// accepted: a pinned rule_set and a mixed rule/final route both validate.
func TestRouteValueGateAcceptsRenderedRoutes(t *testing.T) {
	for name, route := range map[string]string{
		"empty rules":     `{"rules":[],"final":"direct"}`,
		"rule set":        `{"rules":[{"rule_set":["geosite-ai@2026.10.21"],"outbound":"out"}],"rule_set":[{"type":"remote","tag":"geosite-ai@2026.10.21","format":"binary","url":"https://rulesets.example.invalid/ai.srs"}],"final":"out"}`,
		"domain and cidr": `{"rules":[{"domain":["a.example.invalid"],"outbound":"out"},{"ip_cidr":["203.0.113.0/24"],"outbound":"direct"}],"final":"direct"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCandidateRoute([]byte(route)); err != nil {
				t.Fatalf("renderer output rejected: %v", err)
			}
		})
	}
}
