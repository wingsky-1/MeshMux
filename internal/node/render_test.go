package node

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestCompileCandidateProducesFixedNativeShape(t *testing.T) {
	document, err := json.Marshal(NewCandidateDocument(validCandidate()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(document, []byte(`"schema":"meshmux-node/v1"`)) {
		t.Fatalf("candidate document has no frozen schema: %s", document)
	}

	first, err := CompileCandidate(validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(first, &config); err != nil {
		t.Fatal(err)
	}
	if config["log"].(map[string]any)["disabled"] != true {
		t.Fatal("logging is not disabled")
	}
	inbounds := config["inbounds"].([]any)
	inbound := inbounds[0].(map[string]any)
	if inbound["type"] != "vless" || inbound["listen"] != "0.0.0.0" ||
		inbound["listen_port"] != float64(8443) || inbound["tag"] != "meshmux-vless-r9" {
		t.Fatalf("unexpected inbound: %#v", inbound)
	}
	if users, ok := inbound["users"].([]any); !ok || len(users) != 0 {
		t.Fatalf("candidate must have no credential users: %#v", inbound["users"])
	}
	outbound := config["outbounds"].([]any)[0].(map[string]any)
	if outbound["type"] != "direct" || outbound["tag"] != "direct" {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
	lower := strings.ToLower(string(first))
	for _, forbidden := range []string{"uuid", "subscribe", "tls", "server_name", "https://"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("candidate unexpectedly contains %q", forbidden)
		}
	}

	other := validCandidate()
	other.Revision++
	second, err := CompileCandidate(other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("different revisions produced the same configuration")
	}
}

func TestCompileACLIsOutOnlyDefaultDeny(t *testing.T) {
	edge := validCandidate()
	edge.Role = RoleEdge
	acl, err := CompileACL(edge)
	if err != nil {
		t.Fatal(err)
	}
	if acl != nil {
		t.Fatalf("edge node rendered an Out table: %q", acl)
	}

	acl, err = CompileACL(validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet meshmux_out",
		"delete table inet meshmux_out",
		"type filter hook input priority -10; policy accept;",
		"tcp dport 8443 drop",
		"udp dport 8443 drop",
	} {
		if !bytes.Contains(acl, []byte(want)) {
			t.Fatalf("ACL missing %q:\n%s", want, acl)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "tcp dport 22", "ct state established"} {
		if strings.Contains(string(acl), forbidden) {
			t.Fatalf("ACL contains unsafe rule %q:\n%s", forbidden, acl)
		}
	}
	if strings.Contains(strings.ReplaceAll(string(acl), "policy accept", ""), "accept") {
		t.Fatalf("ACL contains a broad accept rule:\n%s", acl)
	}
	if !strings.Contains(string(acl), "table inet meshmux_out {}\ndelete table inet meshmux_out") {
		t.Fatalf("ACL lacks idempotent exact-table replacement:\n%s", acl)
	}
	for _, table := range []string{"table inet other", "table ip ", "table inet filter"} {
		if strings.Contains(string(acl), table) {
			t.Fatalf("ACL references another table %q", table)
		}
	}
	if slices.Contains([]string{"tcp dport 22 drop", "udp dport 22 drop"}, strings.TrimSpace(string(acl))) {
		t.Fatal("ACL replaced SSH handling")
	}
}
