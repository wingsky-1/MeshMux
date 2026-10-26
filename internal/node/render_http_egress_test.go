package node

// TestHTTPProxyEgress is the R11 gate: a Line whose subscription picks an
// external HTTP proxy renders the route's "out" tag as a real sing-box http
// outbound ({server, server_port, username?, password?}), and the assembled
// document passes the real sing-box check. The HTTP proxy is an external
// endpoint: it has no Agent, no readback and no ACL, so this candidate is the
// only place its dial body is allowed to live.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// httpEgressCandidate returns a configured edge candidate whose route selects
// the out tag and whose egress is one external HTTP proxy.
func httpEgressCandidate() Candidate {
	candidate := v2Candidate()
	candidate.Route = json.RawMessage(serverRouteFixture)
	candidate.Out = &OutEgress{
		Type:     OutEgressHTTP,
		Server:   "proxy.example.invalid",
		Port:     8080,
		Username: "alice",
		Password: "s3cret-directory-secret",
	}
	return candidate
}

func TestHTTPProxyEgressRendersHTTPOutbound(t *testing.T) {
	candidate := httpEgressCandidate()
	if err := candidate.Out.Validate(); err != nil {
		t.Fatalf("valid http egress rejected: %v", err)
	}
	document, err := CompileCandidateWithRoute(candidate, json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server,omitempty"`
			ServerPort int    `json:"server_port,omitempty"`
			Method     string `json:"method,omitempty"`
			Username   string `json:"username,omitempty"`
			Password   string `json:"password,omitempty"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("rendered candidate is not valid JSON: %v", err)
	}
	var found bool
	for _, outbound := range decoded.Outbounds {
		if outbound.Tag != singBoxOutTag {
			continue
		}
		found = true
		if outbound.Type != "http" {
			t.Fatalf("out outbound type = %q, want http", outbound.Type)
		}
		if outbound.Method != "" {
			t.Fatalf("http out outbound carries method %q", outbound.Method)
		}
		if outbound.Server != "proxy.example.invalid" || outbound.ServerPort != 8080 {
			t.Fatalf("out endpoint = %s:%d", outbound.Server, outbound.ServerPort)
		}
		if outbound.Username != "alice" || outbound.Password != "s3cret-directory-secret" {
			t.Fatal("http out outbound does not carry the stored credentials")
		}
	}
	if !found {
		t.Fatalf("rendered candidate declares no %q outbound: %s", singBoxOutTag, document)
	}

	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native http-egress check")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, binary, "check", "-c", path).Run(); err != nil {
		t.Fatalf("sing-box rejected the Line candidate with a real http out egress: %v\n%s", err, document)
	}
}

// TestHTTPProxyEgressWithoutCredentialsOmitsAuth pins the credential-free
// shape: no username and no password means the outbound carries neither key.
func TestHTTPProxyEgressWithoutCredentialsOmitsAuth(t *testing.T) {
	candidate := httpEgressCandidate()
	candidate.Out.Username = ""
	candidate.Out.Password = ""
	document, err := CompileCandidateWithRoute(candidate, json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range decoded.Outbounds {
		var tag string
		_ = json.Unmarshal(outbound["tag"], &tag)
		if tag != singBoxOutTag {
			continue
		}
		if _, ok := outbound["username"]; ok {
			t.Fatal("credential-free http outbound carries username")
		}
		if _, ok := outbound["password"]; ok {
			t.Fatal("credential-free http outbound carries password")
		}
	}
}

// TestParseHTTPProxyURL pins the operator URL contract: exactly one http URL
// with a host and an explicit port; credentials are split out so the stored URL
// never carries them.
func TestParseHTTPProxyURL(t *testing.T) {
	withAuth, err := ParseHTTPProxyURL("http://alice:s3cret@proxy.example.invalid:8080")
	if err != nil {
		t.Fatalf("valid URL rejected: %v", err)
	}
	if withAuth.Type != OutEgressHTTP || withAuth.Server != "proxy.example.invalid" ||
		withAuth.Port != 8080 || withAuth.Username != "alice" || withAuth.Password != "s3cret" {
		t.Fatalf("parsed egress = %+v", withAuth)
	}
	if got := withAuth.ProxyURL(); got != "http://proxy.example.invalid:8080" {
		t.Fatalf("canonical URL = %q", got)
	}
	bare, err := ParseHTTPProxyURL("http://203.0.113.20:3128/")
	if err != nil {
		t.Fatalf("bare URL rejected: %v", err)
	}
	if bare.Username != "" || bare.Password != "" || bare.Server != "203.0.113.20" || bare.Port != 3128 {
		t.Fatalf("bare egress = %+v", bare)
	}
	for _, raw := range []string{
		"",
		"proxy.example.invalid:8080",
		"https://proxy.example.invalid:8080",
		"socks5://proxy.example.invalid:1080",
		"http://proxy.example.invalid",
		"http://proxy.example.invalid:0",
		"http://proxy.example.invalid:65536",
		"http://proxy.example.invalid:8080/path",
		"http://proxy.example.invalid:8080?x=1",
		"http://proxy.example.invalid:8080#frag",
		"http://:pass@proxy.example.invalid:8080",
		"http://alice@proxy.example.invalid:8080:8081",
		"http:// proxy.example.invalid:8080",
	} {
		if _, err := ParseHTTPProxyURL(raw); err == nil {
			t.Fatalf("URL %q accepted", raw)
		}
	}
}

// TestHTTPProxyEgressDocumentRoundTrip pins the v3 candidate document: an
// HTTP egress decodes back exactly, and the legacy SS/void shapes stay valid.
func TestHTTPProxyEgressDocumentRoundTrip(t *testing.T) {
	candidate := httpEgressCandidate()
	document := NewCandidateDocument(candidate)
	if document.Schema != CandidateSchemaV3 {
		t.Fatalf("schema = %s, want v3", document.Schema)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("http egress document rejected: %v", err)
	}
	if decoded.Out == nil || decoded.Out.Type != OutEgressHTTP ||
		decoded.Out.Username != "alice" || decoded.Out.Password != "s3cret-directory-secret" {
		t.Fatalf("decoded out = %+v", decoded.Out)
	}
	// A type:"http" egress may never carry the SS key or the void UUID.
	for name, raw := range map[string]string{
		"key with http":   `{"schema":"meshmux-node/v3","node_id":"0123456789abcdef0123456789abcdef","role":"edge","revision":1,"vless_port":8443,"kernel_version":"1.14.3","users":[],"reality":null,"route":{"rules":[],"final":"direct"},"out":{"server":"proxy.example.invalid","port":8080,"type":"http","key":"MDEyMzQ1Njc4OWFiY2RlZg=="}}`,
		"uuid with http":  `{"schema":"meshmux-node/v3","node_id":"0123456789abcdef0123456789abcdef","role":"edge","revision":1,"vless_port":8443,"kernel_version":"1.14.3","users":[],"reality":null,"route":{"rules":[],"final":"direct"},"out":{"server":"proxy.example.invalid","port":8080,"type":"http","uuid":"123e4567-e89b-42d3-a456-426614174001"}}`,
		"unknown type":    `{"schema":"meshmux-node/v3","node_id":"0123456789abcdef0123456789abcdef","role":"edge","revision":1,"vless_port":8443,"kernel_version":"1.14.3","users":[],"reality":null,"route":{"rules":[],"final":"direct"},"out":{"server":"proxy.example.invalid","port":8080,"type":"socks"}}`,
		"orphan password": `{"schema":"meshmux-node/v3","node_id":"0123456789abcdef0123456789abcdef","role":"edge","revision":1,"vless_port":8443,"kernel_version":"1.14.3","users":[],"reality":null,"route":{"rules":[],"final":"direct"},"out":{"server":"proxy.example.invalid","port":8080,"type":"http","password":"secret"}}`,
	} {
		var target CandidateDocument
		if err := json.Unmarshal([]byte(raw), &target); err == nil {
			t.Fatalf("%s accepted: %+v", name, target.Out)
		}
	}
}

// TestHTTPProxyEgressIsNotAnAgentNode pins the boundary: http is a Hub-visible
// role with no installable Agent config, metadata or candidate.
func TestHTTPProxyEgressIsNotAnAgentNode(t *testing.T) {
	if _, err := ParseRole(string(RoleHTTP)); err == nil {
		t.Fatal("install CLI accepted the http proxy role")
	}
	if RoleHTTP.valid() {
		t.Fatal("agent role validation accepted the external http proxy role")
	}
	config := validConfig()
	config.Role = RoleHTTP
	if err := config.Validate(); err == nil {
		t.Fatal("Agent config accepted the external http proxy role")
	}
}
