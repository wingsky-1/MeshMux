package subscription

// The server publish gate is retired, so the pinned-kernel evidence moved to
// the document the Hub actually serves now: the client subscription carries the
// selected Out egress itself (client-chain egress). This gated test renders
// that document, asks the pinned sing-box to check the exact bytes, and then
// proves the data path: the composed client dials the real SS guard with the
// Hub-issued link key and one HTTP request crosses it.
//
// The fixture binds loopback only, starts the pinned binary as an isolated
// subprocess, and keeps every child's output in a private log. No host state is
// touched and no document or credential is printed on failure.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestComposeSubscriptionOutClientChainDataPath is the client-chain equivalent
// of the retired Out-selecting publish gate. It skips only when no pinned
// binary is supplied; the CI script sets it and rejects a SKIP.
func TestComposeSubscriptionOutClientChainDataPath(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the client-chain data-path gate")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY is not executable")
	}

	dir := t.TempDir()
	linkKey, err := node.NewOutLinkKey()
	if err != nil {
		t.Fatal("error_code=COMPOSE_DATAPATH_LINK_KEY_FAILED")
	}

	// The Out side is the real guard the Agent would run: the compiled candidate
	// carries the SS inbound with the Hub-issued link key.
	outPort := freeDataPathPort(t)
	guardDocument, err := node.CompileCandidate(node.Candidate{
		NodeID:        strings.Repeat("e", 32),
		Role:          node.RoleOut,
		Revision:      1,
		VLESSPort:     outPort,
		KernelVersion: node.KernelVersion,
		Out:           &node.OutEgress{Server: "127.0.0.1", Port: outPort, Key: linkKey},
	})
	if err != nil {
		t.Fatal("error_code=COMPOSE_DATAPATH_GUARD_COMPILE_FAILED")
	}
	guard := startDataPathProcess(t, binary, dir, "out-guard", "run", "-c",
		writeDataPathConfig(t, dir, "out-guard.json", loopbackFirstInbound(t, guardDocument, outPort)))
	waitDataPathPort(t, guard, outPort)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, exportDataPathMarker)
	}))
	t.Cleanup(target.Close)

	// One Line plus one selected Out. The IP rule sends the loopback target to
	// the Out egress, so the request can only succeed through the SS guard; the
	// final egress stays the Line selector for every unmatched destination.
	line := composeFixture(t, strings.Repeat("1", 32), "香港 01", 0)
	out := []ComposeOut{{
		OutID: strings.Repeat("2", 32), DisplayName: "东京 Out",
		Server: "127.0.0.1", Port: outPort, LinkKey: linkKey,
	}}
	rules := []ComposeRule{{
		StableKey: "gate-out", Version: 1, Action: ActionProxy,
		Kind: MatcherIPCIDR, Values: []string{"127.0.0.1/32"},
	}}
	documents, diagnostics := ComposeSubscription([]ComposeLine{line}, out, rules, nil)
	if anyBlocking(diagnostics) {
		t.Fatalf("the client-chain selection was refused: %+v", diagnostics)
	}
	for _, required := range []string{
		`"type": "shadowsocks"`, `"tag": "out"`, `"server": "127.0.0.1"`,
		`"server_port": ` + strconv.Itoa(outPort),
		`"method": "2022-blake3-aes-128-gcm"`, `"password": "` + linkKey + `"`,
		`"outbound": "out"`,
	} {
		if !strings.Contains(string(documents.SingBox), required) {
			t.Fatalf("client-chain document misses %q", required)
		}
	}
	if !strings.Contains(string(documents.SingBox), `"final": "meshmux-selector"`) {
		t.Fatal("the client-chain document lost the Line selector as its final egress")
	}

	// The exact bytes the Hub stores must pass the pinned kernel check.
	ctx, cancel := context.WithTimeout(context.Background(), exportDataPathBudget)
	defer cancel()
	clientPath := writeDataPathConfig(t, dir, "client-check.json", documents.SingBox)
	if output, err := exec.CommandContext(ctx, binary, "check", "-c", clientPath).CombinedOutput(); err != nil {
		t.Fatalf("the pinned kernel refused the client-chain document: %v\n%s", err, output)
	}

	// Real handshake: run the checked document and send one request through it.
	mixedPort := freeDataPathPort(t)
	client := startDataPathProcess(t, binary, dir, "client", "run", "-c",
		writeDataPathConfig(t, dir, "client.json", loopbackFirstInbound(t, documents.SingBox, mixedPort)))
	waitDataPathPort(t, client, mixedPort)
	assertDataPathThroughProxy(t, "client-chain", target.URL, mixedPort)
}

// loopbackFirstInbound rewrites the one inbound of a compiled document to the
// given loopback port. The fixture never depends on a public bind address, and
// the document keeps every other byte the compiler produced.
func loopbackFirstInbound(t *testing.T, document []byte, port int) []byte {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(document, &parsed); err != nil {
		t.Fatal("error_code=COMPOSE_DATAPATH_DOCUMENT_INVALID")
	}
	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatal("error_code=COMPOSE_DATAPATH_DOCUMENT_INVALID")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatal("error_code=COMPOSE_DATAPATH_DOCUMENT_INVALID")
	}
	inbound["listen"] = "127.0.0.1"
	inbound["listen_port"] = port
	body, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		t.Fatal("error_code=COMPOSE_DATAPATH_DOCUMENT_INVALID")
	}
	return body
}
