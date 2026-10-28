package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

// outV4Candidate returns an Out-role candidate with configured transport: the
// frozen six fields plus the optional link-key egress, nothing else.
func outV4Candidate() Candidate {
	return Candidate{
		NodeID:        strings.Repeat("b", 32),
		Role:          RoleOut,
		Revision:      7,
		VLESSPort:     8444,
		KernelVersion: KernelVersion,
		Out:           &OutEgress{Server: "203.0.113.10", Port: 8444, Key: outLinkKeyFixture},
	}
}

// TestCandidateV4Document pins the Out SS document: the v1 document carries the
// frozen six fields plus the optional out egress, round-trips byte-identically,
// and compiles to the SS guard.
func TestCandidateV4Document(t *testing.T) {
	document := NewCandidateDocument(outV4Candidate())
	if document.Schema != CandidateSchema {
		t.Fatalf("schema = %q, want %q", document.Schema, CandidateSchema)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"schema":"meshmux-node/v1"`,
		`"out":{"server":"203.0.113.10","port":8444,"key":"` + outLinkKeyFixture + `"}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("v4 document misses %s: %s", want, raw)
		}
	}
	for _, forbidden := range []string{`"users"`, `"reality"`, `"route"`, `"uuid"`, `"vless"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("v4 document carries %q: %s", forbidden, raw)
		}
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != CandidateSchema || !decoded.Candidate().Equal(outV4Candidate()) {
		t.Fatalf("v4 round trip changed the candidate: %+v", decoded)
	}
}

// TestCandidateV4RejectsNonOutShapes pins the Out document purity: users,
// reality, a route, an edge role, a missing key or a legacy UUID are all
// refused, never silently dropped.
func TestCandidateV4RejectsNonOutShapes(t *testing.T) {
	base := outV4Candidate()
	for name, mutate := range map[string]func(*Candidate){
		"edge role": func(c *Candidate) { c.Role = RoleEdge },
		"users": func(c *Candidate) {
			c.Users = []VLESSUser{{CredentialID: strings.Repeat("a", 32), UUID: "123e4567-e89b-42d3-a456-426614174001"}}
		},
		"reality": func(c *Candidate) {
			c.Reality = &RealityConfig{ServerName: "line.example.invalid", HandshakeServer: "handshake.example.invalid", HandshakePort: 443, PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "0123456789abcdef"}
		},
		"route": func(c *Candidate) { c.Route = json.RawMessage(`{"rules":[],"final":"direct"}`) },
		"legacy uuid": func(c *Candidate) {
			c.Out = &OutEgress{Server: "203.0.113.10", Port: 8444, UUID: "123e4567-e89b-42d3-a456-426614174001"}
		},
		"empty key": func(c *Candidate) { c.Out = &OutEgress{Server: "203.0.113.10", Port: 8444} },
		"key and uuid": func(c *Candidate) {
			c.Out = &OutEgress{Server: "203.0.113.10", Port: 8444, Key: outLinkKeyFixture, UUID: "123e4567-e89b-42d3-a456-426614174001"}
		},
	} {
		broken := base
		out := *broken.Out
		broken.Out = &out
		mutate(&broken)
		document := NewCandidateDocument(broken)
		if _, err := json.Marshal(document); err == nil {
			t.Fatalf("v4 marshalled %s", name)
		}
		if err := document.Candidate().Validate(); err == nil {
			t.Fatalf("v4 candidate validated %s", name)
		}
	}
	// An Out without transport is the credential-free v1 baseline, so its
	// stored digest still verifies.
	bare := base
	bare.Out = nil
	bareDocument := NewCandidateDocument(bare)
	if bareDocument.Schema != CandidateSchema {
		t.Fatalf("transport-free out schema = %q, want v1", bareDocument.Schema)
	}
	if _, err := json.Marshal(bareDocument); err != nil {
		t.Fatalf("transport-free out rejected: %v", err)
	}
}

// TestCandidateV4DecodingIsStrict pins the Out wire shape: the v1 document
// plus the optional out object; an unknown or mistyped field is refused.
func TestCandidateV4DecodingIsStrict(t *testing.T) {
	raw, err := json.Marshal(NewCandidateDocument(outV4Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(raw, &decoded); err != nil || !decoded.Candidate().Equal(outV4Candidate()) {
		t.Fatalf("out decode = %+v err=%v", decoded, err)
	}
	node := strings.Repeat("b", 32)
	for name, body := range map[string]string{
		"unknown field": `{"schema":"meshmux-node/v1","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"key":"` + outLinkKeyFixture + `"},"extra":1}`,
		"v2 schema":     `{"schema":"meshmux-node/v2","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"key":"` + outLinkKeyFixture + `"}}`,
		"uuid shape":    `{"schema":"meshmux-node/v1","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"uuid":"123e4567-e89b-42d3-a456-426614174001"}}`,
		"bad key":       `{"schema":"meshmux-node/v1","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"key":"short"}}`,
		"wrong role":    `{"schema":"meshmux-node/v1","node_id":"` + node + `","role":"edge","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"key":"` + outLinkKeyFixture + `"}}`,
	} {
		var document CandidateDocument
		if err := json.Unmarshal([]byte(body), &document); err == nil {
			t.Fatalf("out document decoded %s: %+v", name, document)
		}
	}
}
