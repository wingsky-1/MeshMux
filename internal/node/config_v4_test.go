package node

import (
	"encoding/json"
	"strings"
	"testing"
)

// outV4Candidate returns an Out-role candidate with configured transport: the
// v4 shape (frozen six fields plus the link key, nothing else).
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

// TestCandidateV4Document pins the Out SS document: v4 carries exactly the
// frozen six fields plus the required out egress, round-trips byte-identically,
// and compiles to the SS guard.
func TestCandidateV4Document(t *testing.T) {
	document := NewCandidateDocument(outV4Candidate())
	if document.Schema != CandidateSchemaV4 {
		t.Fatalf("schema = %q, want %q", document.Schema, CandidateSchemaV4)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"schema":"meshmux-node/v4"`,
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
	if decoded.Schema != CandidateSchemaV4 || !decoded.Candidate().Equal(outV4Candidate()) {
		t.Fatalf("v4 round trip changed the candidate: %+v", decoded)
	}
	compiled, err := CompileCandidate(decoded.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			ListenPort int    `json:"listen_port"`
			Method     string `json:"method,omitempty"`
			Password   string `json:"password,omitempty"`
		} `json:"inbounds"`
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(compiled, &rendered); err != nil {
		t.Fatal(err)
	}
	if len(rendered.Inbounds) != 1 {
		t.Fatalf("v4 inbounds = %d, want exactly the SS guard", len(rendered.Inbounds))
	}
	inbound := rendered.Inbounds[0]
	if inbound.Type != "shadowsocks" || inbound.Tag != "meshmux-ss-r7" ||
		inbound.ListenPort != 8444 || inbound.Method != OutLinkMethod || inbound.Password != outLinkKeyFixture {
		t.Fatalf("v4 inbound = %+v, want the SS guard with the link key", inbound)
	}
	if len(rendered.Outbounds) != 1 || rendered.Outbounds[0].Type != "direct" {
		t.Fatalf("v4 outbounds = %+v, want a single direct", rendered.Outbounds)
	}
}

// TestCandidateV4RejectsNonOutShapes pins the v4 purity: users, reality, a
// route, an edge role, a missing key or a legacy UUID are all refused,
// never silently dropped.
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
	// An Out without transport is not v4 at all: it keeps the frozen v1
	// baseline, so its stored digest still verifies.
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

// TestCandidateV4DecodingIsStrict pins the v4 wire shape: exactly the seven
// frozen fields plus the required out object; extra, missing or mistyped
// fields are refused.
func TestCandidateV4DecodingIsStrict(t *testing.T) {
	raw, err := json.Marshal(NewCandidateDocument(outV4Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(raw, &decoded); err != nil || !decoded.Candidate().Equal(outV4Candidate()) {
		t.Fatalf("v4 decode = %+v err=%v", decoded, err)
	}
	node := strings.Repeat("b", 32)
	for name, body := range map[string]string{
		"users key":   `{"schema":"meshmux-node/v4","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","users":[],"out":{"server":"203.0.113.10","port":8444,"key":"` + outLinkKeyFixture + `"}}`,
		"missing out": `{"schema":"meshmux-node/v4","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `"}`,
		"uuid shape":  `{"schema":"meshmux-node/v4","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"uuid":"123e4567-e89b-42d3-a456-426614174001"}}`,
		"bad key":     `{"schema":"meshmux-node/v4","node_id":"` + node + `","role":"out","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"key":"short"}}`,
		"wrong role":  `{"schema":"meshmux-node/v4","node_id":"` + node + `","role":"edge","revision":7,"vless_port":8444,"kernel_version":"` + KernelVersion + `","out":{"server":"203.0.113.10","port":8444,"key":"` + outLinkKeyFixture + `"}}`,
	} {
		var document CandidateDocument
		if err := json.Unmarshal([]byte(body), &document); err == nil {
			t.Fatalf("v4 decoded %s: %+v", name, document)
		}
	}
}
