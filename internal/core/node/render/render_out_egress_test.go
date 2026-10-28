package render

// TestOutEgressRealEndpoint is the SS-switch TDD gate: a Line candidate whose
// route selects the Out must render the "out" tag as a real Shadowsocks
// outbound (2022-blake3-aes-128-gcm, the selected Out node's address/port plus
// the Hub-issued link key), and the assembled document must pass the real
// sing-box check.
//
// The VLESS dial body is gone: under Ruling R7 the Line→Out path is an
// encrypted SS double-hop, never bare VLESS on the public internet. The
// fail-closed block stub still exists only while the Out access path owns no
// endpoint: a bound Out with transport renders the dialable body instead of a
// refusal masquerading as an egress.

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

// outLinkKeyFixture is one fixed 16-byte link key (base64-std): the exact
// length 2022-blake3-aes-128-gcm requires on the dial side. A 32-byte key is
// refused by `sing-box check` with "bad key length, required 16", so the
// method pins the length, not the other way round.
const outLinkKeyFixture = "MDEyMzQ1Njc4OWFiY2RlZg=="

// outEgressCandidate returns a configured edge candidate whose route selects
// the Out, with the Hub-issued link key attached.
func outEgressCandidate() Candidate {
	candidate := v2Candidate()
	candidate.Route = json.RawMessage(serverRouteFixture)
	candidate.Out = &OutEgress{
		Server: "203.0.113.10",
		Port:   8444,
		Key:    outLinkKeyFixture,
	}
	return candidate
}

func TestOutEgressRealEndpoint(t *testing.T) {
	candidate := outEgressCandidate()
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
			Password   string `json:"password,omitempty"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal("rendered candidate is not valid JSON")
	}
	byTag := make(map[string]int, len(decoded.Outbounds))
	for i, outbound := range decoded.Outbounds {
		byTag[outbound.Tag] = i
	}
	index, ok := byTag[singBoxOutTag]
	if !ok {
		t.Fatalf("rendered candidate declares no %q outbound: %s", singBoxOutTag, document)
	}
	out := decoded.Outbounds[index]
	if out.Type != "shadowsocks" {
		t.Fatalf("out outbound type = %q, want shadowsocks (bare VLESS is not a dialable egress)", out.Type)
	}
	if out.Method != OutLinkMethod {
		t.Fatalf("out method = %q, want %q", out.Method, OutLinkMethod)
	}
	if out.Server != "203.0.113.10" || out.ServerPort != 8444 {
		t.Fatalf("out endpoint = %s:%d, want the selected Out node address/port", out.Server, out.ServerPort)
	}
	if out.Password != outLinkKeyFixture {
		t.Fatal("out outbound carries no Hub-issued link key")
	}

	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native out-egress check")
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
		t.Fatal("sing-box rejected the Line candidate with a real SS out egress")
	}
}

// TestOutEgressValidation pins the egress contract: the endpoint is one IP or
// DNS name with a bounded port, the link key is 16 bytes of base64-std (the
// length the 2022-blake3-aes-128-gcm dial side requires), and the egress
// belongs to edge candidates only.
func TestOutEgressValidation(t *testing.T) {
	valid := OutEgress{Server: "203.0.113.10", Port: 8444, Key: outLinkKeyFixture}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid out egress rejected: %v", err)
	}
	for name, mutate := range map[string]func(*OutEgress){
		"empty server":  func(e *OutEgress) { e.Server = "" },
		"server URL":    func(e *OutEgress) { e.Server = "https://out.example.invalid" },
		"server port":   func(e *OutEgress) { e.Server = "out.example.invalid:8444" },
		"zero port":     func(e *OutEgress) { e.Port = 0 },
		"large port":    func(e *OutEgress) { e.Port = 65536 },
		"empty key":     func(e *OutEgress) { e.Key = "" },
		"bad key":       func(e *OutEgress) { e.Key = "not-base64!!" },
		"short key":     func(e *OutEgress) { e.Key = "YWJj" },
		"long key":      func(e *OutEgress) { e.Key = "MDEyMzQ1Njc4OWFiY2RlZgABEefgh0==" },
		"uppercase dns": func(e *OutEgress) { e.Server = "Out.Example.Invalid" },
	} {
		broken := valid
		mutate(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatalf("out egress %s accepted: %+v", name, broken)
		}
	}
	dns := valid
	dns.Server = "out.example.invalid"
	if err := dns.Validate(); err != nil {
		t.Fatalf("DNS out endpoint rejected: %v", err)
	}
	if _, err := NewOutLinkKey(); err != nil {
		t.Fatalf("link key issuance failed: %v", err)
	}
	for range 8 {
		key, err := NewOutLinkKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := (OutEgress{Server: "203.0.113.10", Port: 8444, Key: key}).Validate(); err != nil {
			t.Fatalf("issued link key rejected: %v", err)
		}
	}
}

// TestOutEgressLegacyUUIDStaysStable pins the void-but-stable history: a
// stored document that still carries the Task-2 UUID shape keeps decoding and
// rendering byte-identical VLESS bytes (so its pinned digest still verifies),
// while every new issuance uses the SS link key. The old credential no longer
// authenticates anywhere: the Out side is SS-only.
func TestOutEgressLegacyUUIDStaysStable(t *testing.T) {
	legacy := OutEgress{Server: "203.0.113.10", Port: 8444, UUID: "123e4567-e89b-42d3-a456-426614174001"}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy out egress rejected: %v", err)
	}
	mixed := OutEgress{Server: "203.0.113.10", Port: 8444, Key: outLinkKeyFixture, UUID: "123e4567-e89b-42d3-a456-426614174001"}
	if err := mixed.Validate(); err == nil {
		t.Fatal("out egress with both key and legacy UUID accepted")
	}
	candidate := v2Candidate()
	candidate.Route = json.RawMessage(serverRouteFixture)
	candidate.Out = &legacy
	document, err := CompileCandidateWithRoute(candidate, json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
			UUID string `json:"uuid,omitempty"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range decoded.Outbounds {
		if outbound.Tag != singBoxOutTag {
			continue
		}
		if outbound.Type != "vless" || outbound.UUID != "123e4567-e89b-42d3-a456-426614174001" {
			t.Fatalf("legacy out egress changed shape: %+v", outbound)
		}
	}
}

// TestOutEgressWithoutEndpointStaysFailClosed pins the stub's remaining role:
// a route that names "out" while no egress is attached still renders the
// block stub instead of silently leaving from the Line address.
func TestOutEgressWithoutEndpointStaysFailClosed(t *testing.T) {
	document, err := CompileCandidateWithRoute(v2Candidate(), json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	if tags := renderedOutbounds(t, document); tags[singBoxOutTag] != singBoxBlockTag {
		t.Fatalf("endpoint-free out candidate outbounds = %v, want the fail-closed block stub", tags)
	}
}

// TestOutInboundRealEndpoint pins the Out side of Ruling R7: an Out candidate
// that carries the link key renders an SS inbound (same method, the key as
// password) instead of the credential-free VLESS baseline, and the assembled
// document passes the real sing-box check. The nft whitelist is untouched:
// it still gates port plus source IP around whatever inbound listens.
func TestOutInboundRealEndpoint(t *testing.T) {
	candidate := validCandidate()
	candidate.Role = RoleOut
	candidate.Out = &OutEgress{Server: "203.0.113.10", Port: 8444, Key: outLinkKeyFixture}
	document, err := CompileCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			ListenPort int    `json:"listen_port"`
			Method     string `json:"method,omitempty"`
			Password   string `json:"password,omitempty"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Inbounds) != 1 {
		t.Fatalf("out candidate inbounds = %d, want exactly the SS guard", len(decoded.Inbounds))
	}
	inbound := decoded.Inbounds[0]
	if inbound.Type != "shadowsocks" || inbound.Method != OutLinkMethod || inbound.Password != outLinkKeyFixture {
		t.Fatalf("out inbound = %+v, want the SS guard with the link key", inbound)
	}
	if inbound.ListenPort != 8443 {
		t.Fatalf("out inbound port = %d, want the node VLESS port", inbound.ListenPort)
	}

	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native out-inbound check")
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
		t.Fatal("sing-box rejected the Out candidate with the SS inbound")
	}
}
