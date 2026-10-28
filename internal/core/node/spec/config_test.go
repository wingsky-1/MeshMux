package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		HubURL:       "https://hub.example.invalid",
		NodeID:       strings.Repeat("a", 32),
		Role:         RoleOut,
		VLESSPort:    8443,
		SSHPort:      2222,
		AgentVersion: CurrentAgentVersion(),
		AgentSHA256:  strings.Repeat("b", 64),
		KernelSHA256: strings.Repeat("c", 64),
	}
}

func validCandidate() Candidate {
	return Candidate{
		NodeID:        strings.Repeat("a", 32),
		Role:          RoleOut,
		Revision:      9,
		VLESSPort:     8443,
		KernelVersion: KernelVersion,
	}
}

func TestParseRoleAcceptsNodeRolesOnly(t *testing.T) {
	for _, name := range []string{"edge", "out"} {
		role, err := ParseRole(name)
		if err != nil || string(role) != name {
			t.Fatalf("ParseRole(%q) = %q, %v", name, role, err)
		}
	}
	// "hub" is resolved on the install side, never as a node.Role; the rest
	// are the injection cases inherited from the removed internal/product tests.
	for _, name := range []string{"", "nas", "line", "root", "hub", "hub;rm -rf /"} {
		if _, err := ParseRole(name); err == nil {
			t.Fatalf("ParseRole(%q) unexpectedly succeeded", name)
		}
	}
}

func TestFixedHostContract(t *testing.T) {
	got := []string{
		AgentBinaryPath,
		SingBoxBinaryPath,
		AgentConfigPath,
		IdentityPath,
		RuntimeStatePath,
		ActiveCandidatePath,
		ActiveConfigPath,
		ACLPath,
		AgentUnit,
		SingBoxUnit,
		ACLUnit,
		ACLTable,
	}
	want := []string{
		"/usr/local/libexec/meshmuxd",
		"/usr/local/libexec/meshmux-sing-box",
		"/etc/meshmux/agent.json",
		"/var/lib/meshmux-agent/identity.json",
		"/var/lib/meshmux-agent/state.json",
		"/var/lib/meshmux-agent/active-candidate.json",
		"/var/lib/meshmux-singbox/config.json",
		"/var/lib/meshmux-agent/out.nft",
		"meshmux-agent.service",
		"meshmux-sing-box.service",
		"meshmux-out-acl.service",
		"meshmux_out",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fixed contract %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestConfigEnrollmentAndInstalledValidation(t *testing.T) {
	config := validConfig()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateInstalled(); err != nil {
		t.Fatal(err)
	}
	metadata := config.Metadata()
	metadata.ConfigRevision = 1
	if err := metadata.ValidateFor(config); err != nil {
		t.Fatal(err)
	}
	identity := Identity{NodeID: config.NodeID, IdentityToken: strings.Repeat("A", 43)}
	if err := identity.ValidateFor(config); err != nil {
		t.Fatal(err)
	}

	loopback := config
	loopback.HubURL = "https://127.0.0.1:9443"
	if err := loopback.Validate(); err != nil {
		t.Fatalf("TLS loopback test origin rejected: %v", err)
	}
}

func TestConfigRejectsUnsafeHubURLsWithoutEcho(t *testing.T) {
	for _, hub := range []string{
		"http://hub.example.invalid",
		"https://user:secret@hub.example.invalid",
		"https://hub.example.invalid/",
		"https://hub.example.invalid/api",
		"https://hub.example.invalid?token=secret",
		"https://hub.example.invalid#fragment",
		"https://hub.example.invalid\nInjected: true",
		"https://hub.example.invalid:https",
		"https://" + strings.Repeat("a", 500) + ".example.invalid",
	} {
		config := validConfig()
		config.HubURL = hub
		err := config.Validate()
		if err == nil {
			t.Fatalf("unsafe Hub URL accepted: %q", hub)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), hub) {
			t.Fatalf("error echoed rejected URL: %v", err)
		}
	}
}

func TestIdentityRoleAndMetadataBindings(t *testing.T) {
	config := validConfig()
	identity := Identity{NodeID: config.NodeID, IdentityToken: strings.Repeat("A", 43)}
	identity.NodeID = strings.Repeat("d", 32)
	if err := identity.ValidateFor(config); err == nil {
		t.Fatal("identity for another node accepted")
	}

	metadata := config.Metadata()
	metadata.ConfigRevision = 1
	metadata.Role = RoleEdge
	if err := metadata.ValidateFor(config); err == nil {
		t.Fatal("metadata with the wrong role accepted")
	}
	metadata = config.Metadata()
	metadata.ConfigRevision = 1
	metadata.VLESSPort++
	if err := metadata.ValidateFor(config); err == nil {
		t.Fatal("metadata with a different port accepted")
	}
	metadata = config.Metadata()
	if err := metadata.ValidateFor(config); err == nil {
		t.Fatal("metadata without a published revision accepted")
	}
}

func TestInstalledConfigRequiresPinnedAgentAndDigests(t *testing.T) {
	config := validConfig()
	config.AgentVersion = "1.0"
	if err := config.ValidateInstalled(); err == nil {
		t.Fatal("protocol version accepted as Agent program version")
	}
	config = validConfig()
	config.KernelSHA256 = "short"
	if err := config.ValidateInstalled(); err == nil {
		t.Fatal("short kernel digest accepted")
	}
	config = validConfig()
	config.AgentSHA256 = strings.ToUpper(config.AgentSHA256)
	if err := config.ValidateInstalled(); err == nil {
		t.Fatal("non-canonical Agent digest accepted")
	}
}

func TestCandidateStrictDecoding(t *testing.T) {
	valid := `{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"vless_port":8443,"kernel_version":"1.14.3"}`
	var candidate CandidateDocument
	if err := json.Unmarshal([]byte(valid), &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.Schema != CandidateSchema || !candidate.Candidate().Equal(validCandidate()) {
		t.Fatalf("decoded candidate = %+v", candidate)
	}
	if err := candidate.ValidateFor(validConfig()); err != nil {
		t.Fatal(err)
	}
	invalidDocument := NewCandidateDocument(validCandidate())
	invalidDocument.Schema = "meshmux-node/v2"
	if err := invalidDocument.ValidateFor(validConfig()); err == nil {
		t.Fatal("candidate document with the wrong schema accepted")
	}

	cases := []string{
		`{"schema":"meshmux-node/v2","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"hub","revision":9,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":0,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":1.5,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"vless_port":8443,"kernel_version":"1.15.0"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"vless_port":8443,"kernel_version":"1.14.3","users":null}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":null,"revision":9,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"revision":10,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","Node_ID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"vless_port":8443,"kernel_version":"1.14.3"}`,
		`{"schema":"meshmux-node/v1","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"out","revision":9,"vless_port":8443,"kernel_version":"1.14.3"} {}`,
	}
	for _, body := range cases {
		if err := json.Unmarshal([]byte(body), &candidate); err == nil {
			t.Fatalf("invalid candidate accepted: %s", body)
		}
	}
}

func TestCandidateSupportsIndependentPositiveRevisions(t *testing.T) {
	for _, revision := range []int64{1, 2, 99, 1<<63 - 1} {
		candidate := validCandidate()
		candidate.Revision = revision
		if err := candidate.ValidateFor(validConfig()); err != nil {
			t.Fatalf("revision %d rejected: %v", revision, err)
		}
	}
}

func TestReadbackValidate(t *testing.T) {
	readback := Readback{
		Architecture:   "amd64",
		AgentVersion:   CurrentAgentVersion(),
		AgentSHA256:    strings.Repeat("b", 64),
		KernelVersion:  KernelVersion,
		KernelSHA256:   strings.Repeat("c", 64),
		ActiveRevision: 9,
		ConfigSHA256:   strings.Repeat("d", 64),
		LocalActive:    true,
		OutDefaultDeny: true,
	}
	if err := readback.Validate(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(readback)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= 512 {
		t.Fatalf("readback detail is %d bytes, want <512", len(body))
	}
	readback.KernelVersion = "1.15.0"
	if err := readback.Validate(); err == nil {
		t.Fatal("unpinned kernel readback accepted")
	}
}
