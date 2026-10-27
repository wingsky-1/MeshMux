package node

import (
	"bytes"
	"encoding/json"
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
