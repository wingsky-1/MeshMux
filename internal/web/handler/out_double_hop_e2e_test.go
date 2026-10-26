package handler

// AI double-hop end-to-end fixture (Task 5, ADR-0008 §3; Ruling R10).
//
// This is the acceptance evidence the authorization migration owes. The Hub authorizes
// the Line at the Out because both are enrolled members (Ruling R10: node membership, not
// a subscription), the Line renders a real Shadowsocks hop to the Out its route selects,
// and an AI-domain request really traverses Line -> Out on the pinned kernel.
//
// What the fixture proves, and with which evidence level:
//
//   - The Hub derived exactly the Line's address from the enrollment set and published it
//     in the Out chain (Hub-side proof: derived set == published set). The subscription
//     created by the fixture only makes the Line's route name the Out; it contributes no
//     source, and the assertion below states that explicitly.
//   - The rendered nft guard is accepted and installed by the real kernel
//     nftables parser inside a private network namespace (concept proof: it is a
//     private namespace, not the host's ruleset, so no host state changes).
//   - A real request to the AI domain succeeds through
//     client -> VLESS/REALITY (Line) -> Shadowsocks (Out) -> target, and both
//     kernels' own logs attribute the flow to the expected hop (C-minus proof:
//     real kernel, real handshake, loopback only).
//
// What it does NOT prove: public reachability, a cloud security group, a real
// client app, or the Out guard being enforced on a production host. Those stay
// open and are named in the report.
//
// The fixture never installs anything, never touches a systemd unit, never writes
// outside a private temporary directory, and never contacts a public network: the
// AI domain is pinned to loopback through the kernel's own hosts resolver, and
// every listener is overridden to 127.0.0.1. Those two rewrites are the only
// changes applied to the compiled documents, and they are test scaffolding only.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/policy"
	"github.com/wingsky-1/MeshMux/internal/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/store"
)

// doubleHopDomain is the AI domain of the fixture. It is a reserved invalid name,
// so it can never resolve to a public host even if a resolver is reached.
const doubleHopDomain = "ai.meshmux-fixture.invalid"

// doubleHopMarker is the body the isolated target returns, so a successful request
// can only come from the fixture target.
const doubleHopMarker = "MESHMUX-DOUBLE-HOP-TARGET"

// doubleHopBudget bounds the whole fixture. Every phase shares one deadline, so a
// hung subprocess cannot stall a CI job.
const doubleHopBudget = 90 * time.Second

// doubleHopFixture holds one running AI double-hop topology.
type doubleHopFixture struct {
	t            *testing.T
	ctx          context.Context
	binary       string
	dir          string
	store        *store.Store
	lineID       string
	outID        string
	subscriberID string
	lineKey      string // the Out's SS link key, read from the private table
	linePort     int
	outPort      int
	socksPort    int
	targetPort   int
	handshake    int
	uuid         string
}

// newDoubleHopFixture builds the Hub state and the isolated targets, then returns
// the topology without starting any kernel process.
func newDoubleHopFixture(t *testing.T) *doubleHopFixture {
	t.Helper()
	fixture := &doubleHopFixture{
		t:          t,
		binary:     doubleHopBinary(t),
		dir:        t.TempDir(),
		linePort:   doubleHopFreePort(t),
		outPort:    doubleHopFreePort(t),
		socksPort:  doubleHopFreePort(t),
		targetPort: doubleHopFreePort(t),
		handshake:  doubleHopFreePort(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), doubleHopBudget)
	t.Cleanup(cancel)
	fixture.ctx = ctx

	fixture.startTLSTarget()
	fixture.startHTTPTarget()
	fixture.buildHubState(t)
	return fixture
}

// doubleHopBinary verifies the pinned sing-box kernel.
//
// The binary is never searched on PATH: the environment variable must carry an
// absolute path, and its digest is compared with the in-tree release pin, so the
// environment cannot point the fixture at a different or tampered build.
func doubleHopBinary(t *testing.T) string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if raw == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the real AI double-hop fixture")
	}
	if !filepath.IsAbs(raw) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	info, err := os.Lstat(raw)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY is not a regular file")
	}
	release, ok := node.KernelReleaseFor(runtime.GOARCH)
	if !ok {
		t.Fatalf("no pinned sing-box release for architecture %s", runtime.GOARCH)
	}
	body, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal("could not read the pinned sing-box binary")
	}
	sum := sha256.Sum256(body)
	if digest := hex.EncodeToString(sum[:]); digest != release.BinarySHA256 {
		t.Fatalf("the binary SHA-256 does not match the pinned %s release for %s", release.Version, runtime.GOARCH)
	}
	out, err := exec.CommandContext(t.Context(), raw, "version").Output()
	if err != nil {
		t.Fatal("the pinned sing-box binary did not run")
	}
	fields := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	if len(fields) != 3 || fields[0] != "sing-box" || fields[1] != "version" || fields[2] != release.Version {
		t.Fatalf("the binary version is not the pinned %s release", release.Version)
	}
	return raw
}

// doubleHopFreePort reserves an ephemeral loopback port and releases it again, so
// the fixture never collides with a real service.
func doubleHopFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a loopback port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// startTLSTarget starts the isolated REALITY handshake target: a real TLS 1.3
// server with a self-signed certificate for the reserved invalid name.
func (f *doubleHopFixture) startTLSTarget() {
	t := f.t
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not build the fixture handshake key")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "meshmux-double-hop.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"meshmux-double-hop.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("could not sign the fixture handshake certificate")
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal("could not encode the fixture handshake key")
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal("could not assemble the fixture handshake certificate")
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:"+strconv.Itoa(f.handshake), &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("could not start the fixture handshake target: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(doubleHopBudget))
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
}

// startHTTPTarget starts the isolated target the AI request must reach. It answers
// every request with the fixture marker, so a wrong hop cannot produce the body.
func (f *doubleHopFixture) startHTTPTarget() {
	t := f.t
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(f.targetPort))
	if err != nil {
		t.Fatalf("could not start the fixture target: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(doubleHopBudget))
				// The request head is read, not drained to EOF: a proxy keeps the
				// connection open for the response, so waiting for EOF would
				// deadlock the fixture. The response closes the connection itself.
				reader := bufio.NewReader(io.LimitReader(conn, 8<<10))
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				body := "HTTP/1.1 200 OK\r\nContent-Length: " +
					strconv.Itoa(len(doubleHopMarker)) + "\r\nConnection: close\r\n\r\n" + doubleHopMarker
				_, _ = io.WriteString(conn, body)
			}(conn)
		}
	}()
}

// buildHubState creates the two nodes, the subscription selection and the derived
// authorization the fixture publishes.
func (f *doubleHopFixture) buildHubState(t *testing.T) {
	t.Helper()
	s, now := subscriberStoreFixture(t)
	f.store = s

	// The Line is addressed by loopback: the fixture never leaves the host, so the
	// derived ACL source is 127.0.0.1/32 and the REALITY listener is local.
	line, _, err := s.CreateNode("edge", "line-double-hop", f.linePort, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`,
		line.ID, []byte{0x02}, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired' WHERE id=?`, line.ID); err != nil {
		t.Fatal(err)
	}
	pair, err := subscription.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := subscription.NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLine(subscription.Line{
		NodeID: line.ID, DisplayName: "line-double-hop", Server: "127.0.0.1", Port: f.linePort, SortOrder: 1,
		ServerName: "meshmux-double-hop.invalid", HandshakeServer: "127.0.0.1", HandshakePort: f.handshake,
		PrivateKey: pair.PrivateKey, PublicKey: pair.PublicKey, ShortID: shortID,
	}, now); err != nil {
		t.Fatal(err)
	}

	out, _, err := s.CreateNode("out", "out-double-hop", f.outPort, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`,
		out.ID, []byte{0x03}, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired' WHERE id=?`, out.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetOutTransport(out.ID, "127.0.0.1", f.outPort, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT link_key FROM out_settings WHERE node_id=?`, out.ID).Scan(&f.lineKey); err != nil {
		t.Fatal(err)
	}

	// Selecting the Out is the authorization: no binding row exists anywhere.
	sub, _, err := s.CreateSubscriber("double-hop", []string{line.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The subscription only makes this Line's route name the Out (Ruling R10): the ACL
	// authorization below comes from enrollment, which is why the E2E asserts that
	// dropping this selection leaves the guard untouched.
	if _, err := s.SaveSubscriptionSelection(sub.ID, store.SelectionSpec{
		LineIDs: []string{line.ID}, OutID: out.ID,
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT uuid FROM proxy_credentials WHERE subscriber_id=? AND node_id=? AND active=1`,
		sub.ID, line.ID).Scan(&f.uuid); err != nil {
		t.Fatal(err)
	}
	f.lineID, f.outID, f.subscriberID = line.ID, out.ID, sub.ID
}

// dropOutSelection removes the Out from the fixture subscription while keeping the Line
// selected, so the caller can prove the ACL does not depend on it.
func (f *doubleHopFixture) dropOutSelection() error {
	_, err := f.store.SaveSubscriptionSelection(f.subscriberID, store.SelectionSpec{
		LineIDs: []string{f.lineID},
	}, time.Now())
	return err
}

// restoreOutSelection re-selects the Out, restoring the route the fixture renders.
func (f *doubleHopFixture) restoreOutSelection() error {
	_, err := f.store.SaveSubscriptionSelection(f.subscriberID, store.SelectionSpec{
		LineIDs: []string{f.lineID}, OutID: f.outID,
	}, time.Now())
	return err
}

// derivedAllowlist reads the authorization the Hub publishes for the Out.
func (f *doubleHopFixture) derivedAllowlist(t *testing.T) []string {
	t.Helper()
	allowed, err := f.store.DeriveOutAllowlist(f.outID)
	if err != nil {
		t.Fatalf("derive the out allowlist: %v", err)
	}
	return allowed
}

// outDocument renders the Out's own candidate document: the SS guard listener with
// the Hub-issued link key.
func (f *doubleHopFixture) outDocument(t *testing.T) []byte {
	t.Helper()
	tx, err := f.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	candidate, err := store.BuildLineCandidateTx(tx, f.outID, 1)
	if err != nil {
		t.Fatal(err)
	}
	document, err := node.CompileCandidate(candidate)
	if err != nil {
		t.Fatalf("the Out candidate did not compile: %v", err)
	}
	return document
}

// lineDocument renders the Line's candidate with the AI route the Hub resolves and
// the real Out egress it attached.
func (f *doubleHopFixture) lineDocument(t *testing.T) []byte {
	t.Helper()
	serverIntent, err := policy.ResolveServerPolicy(policy.ServerPolicy{
		Default:       policy.CompilerActionDirect,
		Rules:         []policy.CompilerRule{{Priority: 100, Match: policy.Match{Domains: []string{doubleHopDomain}}, Action: policy.CompilerActionOut}},
		OutConfigured: true,
		OutAvailable:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := policy.RenderServerRoute(serverIntent, policy.RuleSetPins{})
	if err != nil {
		t.Fatalf("the server route did not render: %v", err)
	}
	tx, err := f.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	candidate, err := store.BuildLineCandidateTx(tx, f.lineID, 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Route = fragment
	document, err := node.CompileCandidateWithRoute(candidate, fragment, true)
	if err != nil {
		t.Fatalf("the Line candidate did not compile: %v", err)
	}
	return document
}

// clientDocument renders the client side: a local SOCKS inbound in front of a real
// VLESS/REALITY outbound for the Line.
func (f *doubleHopFixture) clientDocument(t *testing.T) []byte {
	t.Helper()
	var settings struct {
		ServerName string `json:"server_name"`
		PublicKey  string `json:"public_key"`
		ShortID    string `json:"short_id"`
	}
	var serverName, publicKey, shortID string
	if err := f.store.DB.QueryRow(`SELECT server_name, public_key, short_id FROM line_settings WHERE node_id=?`, f.lineID).
		Scan(&serverName, &publicKey, &shortID); err != nil {
		t.Fatal(err)
	}
	settings.ServerName, settings.PublicKey, settings.ShortID = serverName, publicKey, shortID
	document := map[string]any{
		"log": map[string]any{"disabled": false, "level": "info", "timestamp": false},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "fixture-socks", "listen": "127.0.0.1", "listen_port": f.socksPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "vless", "tag": "line", "server": "127.0.0.1", "server_port": f.linePort,
			"uuid": f.uuid, "flow": "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled": true, "server_name": settings.ServerName,
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": settings.PublicKey, "short_id": settings.ShortID},
			},
		}},
		"route": map[string]any{"final": "line"},
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// fixtureDocument applies the two fixture-only overrides to a compiled document:
// every listener moves to loopback, and the AI domain is pinned to loopback through
// the kernel's own hosts resolver so the fixture never contacts public DNS.
//
// Returns the rewritten document and a function that reverses the rewrite for the
// assertions that read the document under test.
func (f *doubleHopFixture) fixtureDocument(t *testing.T, body []byte, pinDomain bool) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("the compiled document is not valid JSON: %v", err)
	}
	if inbounds, ok := document["inbounds"].([]any); ok {
		for _, raw := range inbounds {
			inbound, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			inbound["listen"] = "127.0.0.1"
		}
	}
	document["log"] = map[string]any{"disabled": false, "level": "info", "timestamp": false}
	if pinDomain {
		document["dns"] = map[string]any{
			"servers": []any{map[string]any{
				"type": "hosts", "tag": "fixture-hosts",
				"predefined": map[string]any{doubleHopDomain: []string{"127.0.0.1"}},
			}},
			"final": "fixture-hosts",
		}
		route, _ := document["route"].(map[string]any)
		if route == nil {
			route = map[string]any{}
			document["route"] = route
		}
		route["default_domain_resolver"] = "fixture-hosts"
	}
	rewritten, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return rewritten
}

// writeConfig writes one fixture configuration into the private directory.
func (f *doubleHopFixture) writeConfig(t *testing.T, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(f.dir, name+".json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("could not write the %s fixture config", name)
	}
	return path
}

// doubleHopProcess is one managed sing-box subprocess.
type doubleHopProcess struct {
	cmd    *exec.Cmd
	log    string
	closed bool
}

// start starts the pinned binary as an unprivileged child of the test process.
func (f *doubleHopFixture) start(t *testing.T, configPath, name string) *doubleHopProcess {
	t.Helper()
	logPath := filepath.Join(f.dir, name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal("could not create the fixture log")
	}
	cmd := exec.CommandContext(f.ctx, f.binary, "run", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + f.dir, "TMPDIR=" + os.TempDir()}
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the %s fixture process: %v", name, err)
	}
	process := &doubleHopProcess{cmd: cmd, log: logPath}
	t.Cleanup(process.stop)
	return process
}

// stop terminates the subprocess and waits for it.
func (p *doubleHopProcess) stop() {
	if p.closed || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	p.closed = true
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

// waitPort waits until a loopback port accepts a connection.
func (f *doubleHopFixture) waitPort(t *testing.T, port int) {
	t.Helper()
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-f.ctx.Done():
			t.Fatalf("the fixture process did not start listening on port %d", port)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// logContains reports whether one process log contains the given line. The
// subprocess writes asynchronously, so the helper polls for a bounded budget and
// never dumps the raw log: a failure reports a stable reason code instead.
func (p *doubleHopProcess) logContains(needle string) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if body, err := os.ReadFile(p.log); err == nil && strings.Contains(string(body), needle) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// socksGetDomain performs one HTTP GET through the fixture SOCKS proxy, asking the
// proxy to resolve the AI domain so the Line receives the domain rather than an
// address. It uses the standard library only.
func socksGetDomain(t *testing.T, proxyPort int, domain string, targetPort int) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(proxyPort), 5*time.Second)
	if err != nil {
		t.Fatalf("could not reach the fixture SOCKS proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(doubleHopBudget))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal("could not greet the fixture SOCKS proxy")
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal("the fixture SOCKS proxy did not answer the greeting")
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("the fixture SOCKS proxy rejected the greeting: %v", greeting)
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	request = append(request, domain...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(targetPort))
	request = append(request, portBytes[:]...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal("could not send the fixture SOCKS request")
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal("the fixture SOCKS proxy did not answer the request")
	}
	if reply[1] != 0x00 {
		return 0, ""
	}
	switch reply[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		length := make([]byte, 1)
		_, _ = io.ReadFull(conn, length)
		_, _ = io.ReadFull(conn, make([]byte, int(length[0])+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 16+2))
	}
	httpRequest := "GET / HTTP/1.1\r\nHost: " + domain + ":" + strconv.Itoa(targetPort) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, httpRequest); err != nil {
		t.Fatal("could not send the fixture HTTP request")
	}
	body, err := io.ReadAll(conn)
	if err != nil && len(body) == 0 {
		t.Fatalf("the fixture HTTP request failed: %v", err)
	}
	parts := bytes.SplitN(body, []byte("\r\n\r\n"), 2)
	status := 0
	if _, err := fmt.Sscanf(string(parts[0]), "HTTP/1.1 %d", &status); err != nil {
		return 0, ""
	}
	payload := ""
	if len(parts) > 1 {
		payload = string(parts[1])
	}
	return status, payload
}

// TestOutAuthorization_AIDoubleHopEndToEnd is the brief's Step 4 evidence: a real
// AI-domain request traverses Line -> Out on the pinned kernel, and the Out guard
// the Hub derived is accepted by the real nftables parser.
func TestOutAuthorization_AIDoubleHopEndToEnd(t *testing.T) {
	fixture := newDoubleHopFixture(t)

	// 1. The Hub derived exactly the Line's address from the enrollment set (Ruling R10),
	//    and published it in the Out chain. This is the authorization the data plane
	//    below is expected to match.
	allowed := fixture.derivedAllowlist(t)
	if len(allowed) != 1 || allowed[0] != "127.0.0.1/32" {
		t.Fatalf("derived allowlist = %v, want the line address from the enrollment set", allowed)
	}
	// The publish itself is pinned by the store tests; a pending chain must not fail
	// the data-plane fixture, so the error is deliberately ignored here.
	_ = fixture.store.RetryOutSync(fixture.outID, time.Now())

	// 1b. The subscription is not an ACL input: dropping it leaves the authorized set —
	//     and therefore the guard the Agent is told to apply — byte-identical. This is the
	//     Ruling R10 assertion that the E2E itself carries, so the fixture cannot be read
	//     as "a subscription drove the ACL".
	//
	//     The selection pinned outside this comparison is the one the fixture uses to
	//     build its route; it is restored right after, before any document is rendered.
	if err := fixture.dropOutSelection(); err != nil {
		t.Fatalf("drop the fixture's out selection: %v", err)
	}
	withoutSelection := fixture.derivedAllowlist(t)
	if len(withoutSelection) != len(allowed) || withoutSelection[0] != allowed[0] {
		t.Fatalf("dropping the subscription changed the ACL: %v != %v", withoutSelection, allowed)
	}
	if got := fixture.renderedACL(t, withoutSelection); !bytes.Equal(got, fixture.renderedACL(t, allowed)) {
		t.Fatal("dropping the subscription changed the rendered guard")
	}
	if err := fixture.restoreOutSelection(); err != nil {
		t.Fatalf("restore the fixture's out selection: %v", err)
	}

	// 2. The rendered nft guard is the exact bytes the Agent would apply, and the
	//    real nftables parser accepts and installs it in a private network namespace.
	acl := fixture.renderedACL(t, allowed)
	for _, want := range []string{
		"table inet meshmux_out {",
		"ip saddr 127.0.0.1/32 tcp dport " + strconv.Itoa(fixture.outPort) + " accept",
		"tcp dport " + strconv.Itoa(fixture.outPort) + " drop",
		"udp dport " + strconv.Itoa(fixture.outPort) + " drop",
	} {
		if !strings.Contains(string(acl), want) {
			t.Fatalf("the derived guard misses %q:\n%s", want, acl)
		}
	}
	applyACLInPrivateNamespace(t, acl)

	// 3. Start the real topology: Out (SS guard), Line (REALITY + SS hop), client.
	outDocument := fixture.fixtureDocument(t, fixture.outDocument(t), true)
	lineDocument := fixture.fixtureDocument(t, fixture.lineDocument(t), false)
	clientDocument := fixture.fixtureDocument(t, fixture.clientDocument(t), false)
	outProcess := fixture.start(t, fixture.writeConfig(t, "out", outDocument), "out")
	fixture.waitPort(t, fixture.outPort)
	lineProcess := fixture.start(t, fixture.writeConfig(t, "line", lineDocument), "line")
	fixture.waitPort(t, fixture.linePort)
	_ = fixture.start(t, fixture.writeConfig(t, "client", clientDocument), "client")
	fixture.waitPort(t, fixture.socksPort)

	// 4. The AI request really traverses both hops: the body can only come from the
	//    isolated target, and each kernel attributes its own leg in its own log.
	status, payload := socksGetDomain(t, fixture.socksPort, doubleHopDomain, fixture.targetPort)
	if status != http.StatusOK {
		t.Fatalf("DOUBLE_HOP_REQUEST_FAILED: the AI request did not complete (status=%d)", status)
	}
	if payload != doubleHopMarker {
		t.Fatal("DOUBLE_HOP_TARGET_MISMATCH: the request reached the wrong target")
	}
	if !lineProcess.logContains("outbound/shadowsocks[out]") {
		t.Fatal("DOUBLE_HOP_LINE_HOP_MISSING: the Line did not send the flow to its Shadowsocks outbound")
	}
	if !lineProcess.logContains("inbound/vless") {
		t.Fatal("DOUBLE_HOP_LINE_INBOUND_MISSING: the Line did not serve the flow on its REALITY inbound")
	}
	if !outProcess.logContains("inbound/shadowsocks") {
		t.Fatal("DOUBLE_HOP_OUT_INBOUND_MISSING: the Out did not receive the flow on its SS guard")
	}
	if !outProcess.logContains("outbound/direct[direct]") {
		t.Fatal("DOUBLE_HOP_OUT_EGRESS_MISSING: the Out did not egress the flow to the target")
	}
}

// renderedACL renders the Out guard exactly as the Agent would for the derived
// allowlist.
func (f *doubleHopFixture) renderedACL(t *testing.T, allowed []string) []byte {
	t.Helper()
	tx, err := f.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	candidate, err := store.BuildLineCandidateTx(tx, f.outID, 1)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := node.CompileACL(candidate, allowed)
	if err != nil {
		t.Fatalf("the derived guard did not render: %v", err)
	}
	return acl
}

// applyACLInPrivateNamespace proves the rendered guard is accepted and installed by
// the real nftables implementation, without touching the host ruleset.
//
// It runs in a private network namespace (user + net), so the table lives and dies
// with that namespace. When the environment does not allow unprivileged namespaces
// or nft is absent, the check is recorded as skipped instead of silently passing.
func applyACLInPrivateNamespace(t *testing.T, acl []byte) {
	t.Helper()
	nftPath := nftBinaryPath()
	if nftPath == "" {
		t.Skip("NFT_GUARD_SKIPPED: nft is not installed, so the rendered guard was not applied")
	}
	unsharePath, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("NFT_GUARD_SKIPPED: unshare is not installed, so no private namespace can be used")
	}
	path := filepath.Join(t.TempDir(), "out.nft")
	if err := os.WriteFile(path, acl, 0o600); err != nil {
		t.Fatal("could not write the rendered guard")
	}
	// --net keeps the table out of the host namespace; --map-root-user makes the
	// namespace usable by an unprivileged test process.
	command := exec.Command(unsharePath, "-rn", "sh", "-c",
		shellQuote(nftPath)+" -f "+shellQuote(path)+" && "+shellQuote(nftPath)+" list table inet meshmux_out")
	output, err := command.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "Operation not permitted") ||
			strings.Contains(string(output), "unshare failed") {
			t.Skip("NFT_GUARD_SKIPPED: unprivileged network namespaces are not available in this environment")
		}
		t.Fatalf("NFT_GUARD_REJECTED: the real nftables implementation refused the derived guard")
	}
	if !strings.Contains(string(output), "table inet meshmux_out") {
		t.Fatal("NFT_GUARD_NOT_INSTALLED: the guard was accepted but the table was not read back")
	}
}

// shellQuote single-quotes one path for the fixed sh -c invocation above. The path
// comes from exec.LookPath, never from a request.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// nftBinaryPath locates the nftables userspace tool.
//
// PATH is not enough on Debian: nft lives in /usr/sbin, which an unprivileged login
// shell often omits. The candidates are fixed absolute paths, so the fixture can never
// be pointed at an arbitrary binary by the environment.
func nftBinaryPath() string {
	for _, candidate := range []string{"nft", "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}
