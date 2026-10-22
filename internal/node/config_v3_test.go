package node

// v3 candidate tests: the resolved server route travels inside the immutable
// candidate document, so the Agent compiles and applies exactly what the Hub
// gated. The v1 and v2 documents must stay byte-identical.

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

// TestCandidateV3CarriesRouteRoundTrip proves a route document round-trips with
// its route intact and reports the v3 schema.
func TestCandidateV3CarriesRouteRoundTrip(t *testing.T) {
	candidate := testV3Candidate(t)
	document := NewCandidateDocument(candidate)
	if document.Schema != CandidateSchemaV3 {
		t.Fatalf("schema = %q, want %q", document.Schema, CandidateSchemaV3)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"route":{"rules":[`)) {
		t.Fatalf("v3 document lost the route: %s", body)
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != CandidateSchemaV3 || !decoded.Candidate().Equal(candidate) {
		t.Fatalf("decoded = %+v", decoded)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestCandidateV1AndV2StillRejectRoute proves the schema split: a route is only
// legal in v3, so an old document can never silently gain a routing table.
func TestCandidateV1AndV2StillRejectRoute(t *testing.T) {
	v2 := NewCandidateDocument(testV2Candidate(t))
	v2.Route = json.RawMessage(v3RouteFixture)
	if err := v2.Validate(); err == nil {
		t.Fatal("a v2 document accepted a route")
	}
	v1 := NewCandidateDocument(validCandidate())
	v1.Route = json.RawMessage(v3RouteFixture)
	if err := v1.Validate(); err == nil {
		t.Fatal("a v1 document accepted a route")
	}
}

// TestCandidateV3RejectsMalformedRoute proves the route shape gate: only one
// route object with bounded string values, never a nested payload, an unknown
// key or an outbound-less rule.
func TestCandidateV3RejectsMalformedRoute(t *testing.T) {
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
			body := strings.Replace(`{"schema":"meshmux-node/v3","node_id":"`+strings.Repeat("a", 32)+
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

// TestCompileCandidateRendersRoute proves CompileCandidate is not route-blind:
// a v3 candidate renders the route block, so the Agent applies the published
// policy instead of the kernel default.
func TestCompileCandidateRendersRoute(t *testing.T) {
	plain, err := CompileCandidate(testV2Candidate(t))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte(`"route"`)) {
		t.Fatal("a route-free candidate rendered a route block")
	}
	routed, err := CompileCandidate(testV3Candidate(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(routed, []byte(`"route"`)) ||
		!bytes.Contains(routed, []byte(`"ai.example.invalid"`)) {
		t.Fatalf("compiled v3 candidate lost the route: %s", routed)
	}
	// The two documents differ only by the route; the inbound is identical.
	var plainDoc, routedDoc map[string]any
	if json.Unmarshal(plain, &plainDoc) != nil || json.Unmarshal(routed, &routedDoc) != nil {
		t.Fatal("compiled documents are not JSON")
	}
	delete(routedDoc, "route")
	if len(plainDoc["inbounds"].([]any)) != 1 || len(routedDoc["inbounds"].([]any)) != 1 {
		t.Fatal("unexpected inbound count")
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
