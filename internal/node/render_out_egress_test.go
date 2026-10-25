package node

// TestOutEgressRealEndpoint is the Task 2 TDD gate: a Line candidate whose
// route selects the Out must render the "out" tag as a real VLESS outbound
// (the selected Out node's address/port plus the Hub-issued credential), and
// the assembled document must pass the real sing-box check.
//
// The fail-closed block stub exists only while the Out access path owns no
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

// outEgressCandidate returns a configured edge candidate whose route selects
// the Out, with the Hub-issued egress attached.
func outEgressCandidate() Candidate {
	candidate := v2Candidate()
	candidate.Route = json.RawMessage(serverRouteFixture)
	candidate.Out = &OutEgress{
		Server: "203.0.113.10",
		Port:   8444,
		UUID:   "123e4567-e89b-42d3-a456-426614174001",
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
			UUID       string `json:"uuid,omitempty"`
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
	if out.Type != "vless" {
		t.Fatalf("out outbound type = %q, want vless (the block stub is not a dialable egress)", out.Type)
	}
	if out.Server != "203.0.113.10" || out.ServerPort != 8444 {
		t.Fatalf("out endpoint = %s:%d, want the selected Out node address/port", out.Server, out.ServerPort)
	}
	if out.UUID != "123e4567-e89b-42d3-a456-426614174001" {
		t.Fatal("out outbound carries no Hub-issued credential")
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
		t.Fatal("sing-box rejected the Line candidate with a real out egress")
	}
}

// TestOutEgressValidation pins the egress contract: the endpoint is one IP or
// DNS name with a bounded port, the credential is one UUIDv4, and the egress
// belongs to edge candidates only.
func TestOutEgressValidation(t *testing.T) {
	valid := OutEgress{Server: "203.0.113.10", Port: 8444, UUID: "123e4567-e89b-42d3-a456-426614174001"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid out egress rejected: %v", err)
	}
	for name, mutate := range map[string]func(*OutEgress){
		"empty server":  func(e *OutEgress) { e.Server = "" },
		"server URL":    func(e *OutEgress) { e.Server = "https://out.example.invalid" },
		"server port":   func(e *OutEgress) { e.Server = "out.example.invalid:8444" },
		"zero port":     func(e *OutEgress) { e.Port = 0 },
		"large port":    func(e *OutEgress) { e.Port = 65536 },
		"bad uuid":      func(e *OutEgress) { e.UUID = "not-a-uuid" },
		"empty uuid":    func(e *OutEgress) { e.UUID = "" },
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
}

// TestOutEgressWithoutEndpointStaysFailClosed pins the stub's remaining role:
// a route that names "out" while no egress is attached still renders the block
// stub instead of silently leaving from the Line address.
func TestOutEgressWithoutEndpointStaysFailClosed(t *testing.T) {
	document, err := CompileCandidateWithRoute(v2Candidate(), json.RawMessage(serverRouteFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	if tags := renderedOutbounds(t, document); tags[singBoxOutTag] != singBoxBlockTag {
		t.Fatalf("endpoint-free out candidate outbounds = %v, want the fail-closed block stub", tags)
	}
}
