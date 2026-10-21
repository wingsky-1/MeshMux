package node

// This file holds the isolated native REALITY handshake acceptance fixture
// for the Issue #7 first PR.
//
// The fixture is deliberately NOT a production path:
//
//   - It never runs during an ordinary `go test`. It is gated behind
//     MESHMUX_REALITY_INTEGRATION_BINARY, which must point at an absolute
//     path whose SHA-256 matches the pinned sing-box 1.14.3 release for the
//     test architecture.
//   - It never installs anything, never touches a systemd unit, never writes
//     outside a private temporary directory and never changes host state.
//   - It never performs a public-network handshake. The REALITY handshake
//     target is an isolated TLS 1.3 server on loopback and the proxy target
//     is an isolated HTTP server on loopback. The pinned binary runs as an
//     unprivileged subprocess of the test process.
//
// The compiled-configuration check itself lives in reality_check_test.go
// (TestRealityNativeCheck). This file adds what a configuration check cannot
// prove: a real VLESS/REALITY handshake over a real transport.
//
// What this fixture proves and what it does not:
//
//   - It DOES prove that a real VLESS/REALITY handshake succeeds for the
//     correct UUID, is denied for a wrong UUID, is denied for a deleted
//     UUID, and that two live credentials are served without mixing.
//   - It does NOT prove public reachability, cloud security group behaviour
//     or real client app usability. Those remain unverified.
//
// Fixture-only overrides: the compiled candidate is used verbatim except for
// the listen address and the log level, which the fixture rewrites so it can
// bind an isolated loopback port and read the per-credential attribution
// line. Those overrides are test scaffolding only. The production candidate
// keeps the production listen address and a disabled log, so the production
// node never writes this attribution line at all.
//
// Secrets: the fixture generates its own throwaway X25519 key pair and uses
// throwaway UUIDv4 credentials. No production key, real credential or
// personal address is used, and no secret value is printed. A fixture
// failure reports a stable reason code and never dumps a raw sing-box log.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
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
)

const (
	// realityIntegrationBinaryEnv points at the absolute path of the pinned,
	// hash-verified sing-box 1.14.3 binary used by the fixture.
	realityIntegrationBinaryEnv = "MESHMUX_REALITY_INTEGRATION_BINARY"

	// realityFixtureHandshakeServerName is the SNI the fixture uses. It is a
	// reserved invalid domain, so it can never resolve to a public host.
	realityFixtureHandshakeServerName = "meshmux-reality-handshake.invalid"

	// realityFixtureShortID is a throwaway REALITY short id for the fixture.
	realityFixtureShortID = "0123456789abcdef"

	// realityFixtureBudget bounds the whole fixture. Every phase shares one
	// deadline, so a hung subprocess cannot stall a CI job.
	realityFixtureBudget = 70 * time.Second
)

// realityFixtureUUIDs are throwaway UUIDv4 credentials for the fixture only.
// They are not production credentials.
var realityFixtureUUIDs = []string{
	"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
	"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d",
	"11111111-2222-4333-8444-555555555555",
}

// realityFixture holds the shared state of one running fixture test.
type realityFixture struct {
	ctx         context.Context
	binary      string
	dir         string
	privateKey  string
	publicKey   string
	handshake   int
	markerA     string
	markerB     string
	targetPortA int
	targetPortB int
}

// newRealityFixture prepares the isolated fixture: one private directory, the
// loopback handshake target, the loopback proxy targets and one throwaway
// REALITY key pair.
func newRealityFixture(t *testing.T) *realityFixture {
	t.Helper()
	fixture := &realityFixture{
		binary:      realityBinary(t),
		dir:         t.TempDir(),
		markerA:     "meshmux-reality-fixture-alpha",
		markerB:     "meshmux-reality-fixture-beta",
		targetPortA: realityFreePort(t),
		targetPortB: realityFreePort(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), realityFixtureBudget)
	t.Cleanup(cancel)
	fixture.ctx = ctx

	fixture.privateKey, fixture.publicKey = realityKeyPair(t)
	fixture.handshake = realityFreePort(t)
	realityHandshakeTarget(t, fixture.handshake)
	realityLoopbackServer(t, fixture.targetPortA, fixture.markerA)
	realityLoopbackServer(t, fixture.targetPortB, fixture.markerB)
	return fixture
}

// candidate builds the v2 candidate under test.
func (f *realityFixture) candidate(t *testing.T, vlessPort int, users []VLESSUser) Candidate {
	t.Helper()
	return Candidate{
		NodeID:        strings.Repeat("a", 32),
		Role:          RoleEdge,
		Revision:      1,
		VLESSPort:     vlessPort,
		KernelVersion: KernelVersion,
		Users:         users,
		Reality: &RealityConfig{
			ServerName:      realityFixtureHandshakeServerName,
			HandshakeServer: "127.0.0.1",
			HandshakePort:   f.handshake,
			PrivateKey:      f.privateKey,
			ShortID:         realityFixtureShortID,
		},
	}
}

// realityBinary locates and verifies the pinned sing-box binary.
//
// The binary is never searched on PATH: the environment variable must carry
// an absolute path, so a stray binary in PATH can never be picked up by
// accident. The digest is compared against the in-tree release pin for the
// test architecture, so the environment cannot point the fixture at a
// different or tampered build.
func realityBinary(t *testing.T) string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(realityIntegrationBinaryEnv))
	if raw == "" {
		t.Skipf("set %s to an absolute path of the pinned sing-box %s binary to run the REALITY handshake fixture", realityIntegrationBinaryEnv, KernelVersion)
	}
	if !filepath.IsAbs(raw) {
		t.Fatalf("%s must be an absolute path", realityIntegrationBinaryEnv)
	}
	release, ok := KernelReleaseFor(runtime.GOARCH)
	if !ok {
		t.Fatalf("no pinned sing-box release for architecture %s", runtime.GOARCH)
	}
	info, err := os.Lstat(raw)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("%s is not a regular file", realityIntegrationBinaryEnv)
	}
	digest, err := nativeCheckSHA256(raw)
	if err != nil {
		t.Fatalf("could not hash %s", realityIntegrationBinaryEnv)
	}
	if digest != release.BinarySHA256 {
		t.Fatalf("the binary SHA-256 does not match the pinned %s release for %s", release.Version, runtime.GOARCH)
	}
	out, err := exec.CommandContext(t.Context(), raw, "version").Output()
	if err != nil {
		t.Fatalf("the pinned sing-box binary did not run: %v", err)
	}
	fields := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	if len(fields) != 3 || fields[0] != "sing-box" || fields[1] != "version" || fields[2] != release.Version {
		t.Fatalf("the binary version is not the pinned %s release", release.Version)
	}
	return raw
}

// realityFreePort reserves an ephemeral loopback port and releases it again,
// so the fixture never collides with a real service.
func realityFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a loopback port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// realityLoopbackServer starts a plain loopback listener that answers every
// connection with a fixed marker. It is the isolated proxy target.
func realityLoopbackServer(t *testing.T, port int, marker string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("could not start the loopback target: %v", err)
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
				_ = conn.SetDeadline(time.Now().Add(realityFixtureBudget))
				body := "HTTP/1.1 200 OK\r\nContent-Length: " +
					strconv.Itoa(len(marker)) + "\r\nConnection: close\r\n\r\n" + marker
				_, _ = io.WriteString(conn, body)
			}(conn)
		}
	}()
}

// realityHandshakeTarget starts the isolated REALITY handshake target.
//
// A REALITY server dials this target and mirrors the TLS 1.3 handshake bytes
// through it, so the target has to be a real TLS 1.3 server rather than a
// bare TCP listener. It runs on loopback with a self-signed certificate for
// a reserved invalid name, so the fixture never contacts a public domain and
// never depends on a public network path.
func realityHandshakeTarget(t *testing.T, port int) {
	t.Helper()
	certificate, err := realitySelfSignedCertificate(t)
	if err != nil {
		t.Fatalf("could not build the fixture handshake certificate: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("could not start the REALITY handshake target: %v", err)
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
				_ = conn.SetDeadline(time.Now().Add(realityFixtureBudget))
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
}

// realitySelfSignedCertificate builds the self-signed certificate of the
// isolated REALITY handshake target.
func realitySelfSignedCertificate(t *testing.T) (tls.Certificate, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: realityFixtureHandshakeServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{realityFixtureHandshakeServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

// realityKeyPair generates one throwaway X25519 REALITY key pair. The
// private key is the fixture's node secret; it never leaves the temporary
// directory and is never printed.
func realityKeyPair(t *testing.T) (privateKey, publicKey string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a fixture REALITY key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// compiledConfig is the compiled sing-box configuration of the v2 candidate,
// with the fixture-only listen address and log level applied.
//
// The compiler deliberately renders the production listen address and a
// disabled log. The fixture overrides both, so the test can bind an isolated
// loopback port and read the per-credential attribution line. It does so by
// rewriting the compiled document, never by replacing the compiled shape.
func (f *realityFixture) compiledConfig(t *testing.T, candidate Candidate, listenPort int) map[string]any {
	t.Helper()
	compiled, err := CompileCandidate(candidate)
	if err != nil {
		t.Fatalf("the v2 candidate did not compile: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(compiled, &document); err != nil {
		t.Fatalf("the compiled candidate is not valid JSON: %v", err)
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatal("the compiled candidate does not carry exactly one inbound")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatal("the compiled inbound is not an object")
	}
	inbound["listen"] = "127.0.0.1"
	inbound["listen_port"] = listenPort
	document["log"] = map[string]any{"disabled": false, "level": "info", "timestamp": false}
	return document
}

// writeConfig writes one sing-box configuration into the private fixture
// directory.
func (f *realityFixture) writeConfig(t *testing.T, name string, document map[string]any) string {
	t.Helper()
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("could not render the %s fixture config: %v", name, err)
	}
	path := filepath.Join(f.dir, name+".json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("could not write the %s fixture config: %v", name, err)
	}
	return path
}

// realityProcess is one managed sing-box subprocess of the fixture.
type realityProcess struct {
	cmd    *exec.Cmd
	closed bool
}

// startProcess starts the pinned binary as an unprivileged child process of
// the test process.
func (f *realityFixture) startProcess(t *testing.T, configPath, logName string) *realityProcess {
	t.Helper()
	logFile, err := os.Create(filepath.Join(f.dir, logName+".log"))
	if err != nil {
		t.Fatalf("could not create the %s fixture log: %v", logName, err)
	}
	cmd := exec.CommandContext(f.ctx, f.binary, "run", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// The fixture subprocess gets a minimal environment. It inherits no
	// proxy variables and no ambient configuration.
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + f.dir,
		"TMPDIR=" + os.TempDir(),
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the %s fixture process: %v", logName, err)
	}
	process := &realityProcess{cmd: cmd}
	t.Cleanup(process.stop)
	return process
}

// stop terminates the subprocess and waits for it.
func (p *realityProcess) stop() {
	if p.closed || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	p.closed = true
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

// logContains reports whether the fixture log of one process contains the
// given substring.
//
// The subprocess writes its log asynchronously, so a single read races the
// writer: the line that proves the expected behaviour may not have reached
// the file yet. The helper therefore polls the log for a bounded budget. It
// still returns false on timeout, so a genuinely missing line fails the
// caller's own assertion with its stable reason code.
//
// The helper returns a boolean on purpose. A fixture failure must never dump
// the raw sing-box log: the log carries connection metadata and would turn a
// test failure into a disclosure. The caller reports a stable reason code
// instead.
func (f *realityFixture) logContains(name, needle string) bool {
	const (
		pollInterval = 100 * time.Millisecond
		pollBudget   = 5 * time.Second
	)
	path := filepath.Join(f.dir, name+".log")
	deadline := time.Now().Add(pollBudget)
	for {
		body, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(body), needle) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-f.ctx.Done():
			return false
		case <-time.After(pollInterval):
		}
	}
}

// waitPort waits until a loopback port accepts a connection. It shares the
// fixture deadline, so a listener that never appears fails the test instead
// of hanging it.
func (f *realityFixture) waitPort(t *testing.T, port int) {
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

// waitPortFree waits until a loopback port no longer accepts a connection,
// so a restarted listener can bind it again.
func (f *realityFixture) waitPortFree(t *testing.T, port int) {
	t.Helper()
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err != nil {
			return
		}
		_ = conn.Close()
		select {
		case <-f.ctx.Done():
			t.Fatalf("the fixture listener on port %d did not stop", port)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// realitySocksGet performs one HTTP request through a local SOCKS5 proxy and
// returns the HTTP status code and the response body.
//
// The client side uses the standard library only, so the fixture adds no new
// dependency and no new module.
func realitySocksGet(t *testing.T, proxyPort, targetPort int) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(proxyPort), 5*time.Second)
	if err != nil {
		t.Fatalf("could not reach the fixture SOCKS proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(realityFixtureBudget))

	// Greeting: SOCKS5 with no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("could not greet the fixture SOCKS proxy: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("the fixture SOCKS proxy did not answer the greeting: %v", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("the fixture SOCKS proxy rejected the greeting: %v", greeting)
	}

	// CONNECT to the isolated loopback target.
	request := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(targetPort))
	request = append(request, portBytes[:]...)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("could not send the fixture SOCKS request: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("the fixture SOCKS proxy did not answer the request: %v", err)
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

	httpRequest := "GET /meshmux-reality-fixture HTTP/1.1\r\nHost: 127.0.0.1:" +
		strconv.Itoa(targetPort) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, httpRequest); err != nil {
		t.Fatalf("could not send the fixture HTTP request: %v", err)
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

// clientConfig renders the client side of the fixture: a local SOCKS inbound
// in front of a real VLESS/REALITY outbound.
func (f *realityFixture) clientConfig(socksPort, vlessPort int, uuid string) map[string]any {
	return map[string]any{
		"log": map[string]any{"disabled": false, "level": "info", "timestamp": false},
		"inbounds": []any{map[string]any{
			"type":        "socks",
			"tag":         "meshmux-fixture-socks",
			"listen":      "127.0.0.1",
			"listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{
			"type":        "vless",
			"tag":         "meshmux-fixture-vless",
			"server":      "127.0.0.1",
			"server_port": vlessPort,
			"uuid":        uuid,
			"flow":        vlessFlow,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": realityFixtureHandshakeServerName,
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": f.publicKey,
					"short_id":   realityFixtureShortID,
				},
			},
		}},
		"route": map[string]any{"final": "meshmux-fixture-vless"},
	}
}

// TestWriteRealityReleasePin renders the in-tree release pin of this package
// as a TSV manifest, so a CI script can fetch and verify the pinned kernel
// without hardcoding a second copy of the pin.
//
// The manifest is written only when MESHMUX_REALITY_PIN_DIR names a
// directory. The format is the same one internal/install renders:
// architecture, version, source_url, archive_sha256 and binary_sha256.
func TestWriteRealityReleasePin(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv("MESHMUX_REALITY_PIN_DIR"))
	if dir == "" {
		t.Skip("only used by the Debian 13 native REALITY CI script")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	manifest.WriteString("architecture\tversion\tsource_url\tarchive_sha256\tbinary_sha256\n")
	for _, arch := range []string{"amd64", "arm64"} {
		release, ok := KernelReleaseFor(arch)
		if !ok {
			t.Fatalf("%s Node kernel release is not pinned", arch)
		}
		if release.Version != KernelVersion ||
			!strings.HasPrefix(release.SourceURL, "https://github.com/SagerNet/sing-box/releases/download/v") {
			t.Fatalf("%s Node release is not the fixed official version", arch)
		}
		if len(release.ArchiveSHA256) != 64 || len(release.BinarySHA256) != 64 {
			t.Fatalf("%s Node release digests are incomplete", arch)
		}
		if _, err := fmt.Fprintf(&manifest, "%s\t%s\t%s\t%s\t%s\n",
			arch, release.Version, release.SourceURL, release.ArchiveSHA256, release.BinarySHA256); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "releases.tsv"), []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestRealityIntegrationHandshakeAcceptsAndDeniesCredentials is the gated
// native handshake acceptance fixture of the Issue #7 first PR.
//
// It proves, against the real pinned sing-box 1.14.3 kernel:
//
//  1. A real VLESS/REALITY handshake succeeds for the correct UUID and the
//     response is the isolated loopback target's own marker.
//  2. A wrong UUID is denied and no data plane is established.
//  3. A deleted UUID is denied after the credential was removed from the
//     candidate, while the remaining credential keeps working.
//  4. Two live credentials do not mix: each session is served by the
//     credential that presented it.
//
// The fixture never leaves the loopback interface and never contacts a
// public domain.
func TestRealityIntegrationHandshakeAcceptsAndDeniesCredentials(t *testing.T) {
	fixture := newRealityFixture(t)

	uuidA := realityFixtureUUIDs[0]
	uuidB := realityFixtureUUIDs[1]
	wrongUUID := realityFixtureUUIDs[2]
	credentialA := strings.Repeat("1", 32)
	credentialB := strings.Repeat("2", 32)
	users := []VLESSUser{
		{CredentialID: credentialA, UUID: uuidA},
		{CredentialID: credentialB, UUID: uuidB},
	}

	vlessPort := realityFreePort(t)
	socksPort := realityFreePort(t)

	// --- The correct UUID is served. ---
	serverPath := fixture.writeConfig(t, "server",
		fixture.compiledConfig(t, fixture.candidate(t, vlessPort, users), vlessPort))
	server := fixture.startProcess(t, serverPath, "server")
	fixture.waitPort(t, vlessPort)

	clientPath := fixture.writeConfig(t, "client-a", fixture.clientConfig(socksPort, vlessPort, uuidA))
	client := fixture.startProcess(t, clientPath, "client-a")
	fixture.waitPort(t, socksPort)

	status, payload := realitySocksGet(t, socksPort, fixture.targetPortA)
	if status != http.StatusOK {
		t.Fatalf("REALITY_HANDSHAKE_ACCEPT_FAILED: the real VLESS/REALITY handshake did not succeed (status=%d)", status)
	}
	if payload != fixture.markerA {
		t.Fatal("REALITY_TARGET_MISMATCH: the handshake reached the wrong loopback target")
	}
	if !fixture.logContains("server", "["+credentialA+"]") {
		t.Fatal("REALITY_ATTRIBUTION_MISSING: the server did not attribute the connection to the expected credential")
	}

	// --- A wrong UUID is denied. ---
	client.stop()
	wrongPath := fixture.writeConfig(t, "client-wrong", fixture.clientConfig(socksPort, vlessPort, wrongUUID))
	wrongClient := fixture.startProcess(t, wrongPath, "client-wrong")
	fixture.waitPort(t, socksPort)

	status, payload = realitySocksGet(t, socksPort, fixture.targetPortA)
	if status == http.StatusOK || payload != "" {
		t.Fatalf("REALITY_WRONG_UUID_ACCEPTED: a wrong UUID was served (status=%d)", status)
	}
	if !fixture.logContains("server", "unknown UUID") {
		t.Fatal("REALITY_WRONG_UUID_NOT_RECORDED: the server did not record the denied UUID")
	}
	wrongClient.stop()

	// --- A deleted UUID is denied, the remaining one still works. ---
	// The listener is restarted with the credential removed, so the denial
	// below is caused by the removed credential and not by a broken listener.
	server.stop()
	fixture.waitPortFree(t, vlessPort)
	deletedPath := fixture.writeConfig(t, "server-deleted",
		fixture.compiledConfig(t, fixture.candidate(t, vlessPort, users[1:]), vlessPort))
	deletedServer := fixture.startProcess(t, deletedPath, "server-deleted")
	fixture.waitPort(t, vlessPort)

	deletedClientPath := fixture.writeConfig(t, "client-deleted", fixture.clientConfig(socksPort, vlessPort, uuidA))
	deletedClient := fixture.startProcess(t, deletedClientPath, "client-deleted")
	fixture.waitPort(t, socksPort)

	status, payload = realitySocksGet(t, socksPort, fixture.targetPortA)
	if status == http.StatusOK || payload != "" {
		t.Fatalf("REALITY_DELETED_UUID_ACCEPTED: a deleted UUID was still served (status=%d)", status)
	}
	deletedClient.stop()

	// The remaining credential still works, so the denial above is caused by
	// the removed credential and not by a broken listener.
	remainingPath := fixture.writeConfig(t, "client-remaining", fixture.clientConfig(socksPort, vlessPort, uuidB))
	remainingClient := fixture.startProcess(t, remainingPath, "client-remaining")
	fixture.waitPort(t, socksPort)

	status, payload = realitySocksGet(t, socksPort, fixture.targetPortB)
	if status != http.StatusOK {
		t.Fatalf("REALITY_REMAINING_CREDENTIAL_DENIED: the remaining credential was denied (status=%d)", status)
	}
	if payload != fixture.markerB {
		t.Fatal("REALITY_TARGET_MISMATCH: the remaining credential reached the wrong loopback target")
	}
	remainingClient.stop()
	deletedServer.stop()

	// --- Two live credentials do not mix. ---
	// Both client processes are alive at the same time and each one is
	// served by its own credential, so a credential that leaked into the
	// other session would show up as a target mismatch. The two requests
	// are issued one after another, so this proves per-credential
	// attribution, not parallel request throughput.
	fixture.waitPortFree(t, vlessPort)
	mixedPath := fixture.writeConfig(t, "server-mixed",
		fixture.compiledConfig(t, fixture.candidate(t, vlessPort, users), vlessPort))
	mixedServer := fixture.startProcess(t, mixedPath, "server-mixed")
	fixture.waitPort(t, vlessPort)

	socksPortA := realityFreePort(t)
	socksPortB := realityFreePort(t)
	clientAPath := fixture.writeConfig(t, "client-mixed-a", fixture.clientConfig(socksPortA, vlessPort, uuidA))
	clientA := fixture.startProcess(t, clientAPath, "client-mixed-a")
	fixture.waitPort(t, socksPortA)

	clientBPath := fixture.writeConfig(t, "client-mixed-b", fixture.clientConfig(socksPortB, vlessPort, uuidB))
	clientB := fixture.startProcess(t, clientBPath, "client-mixed-b")
	fixture.waitPort(t, socksPortB)

	statusA, payloadA := realitySocksGet(t, socksPortA, fixture.targetPortA)
	statusB, payloadB := realitySocksGet(t, socksPortB, fixture.targetPortB)
	if statusA != http.StatusOK || statusB != http.StatusOK {
		t.Fatalf("REALITY_TWO_CREDENTIALS_FAILED: the two credential handshakes did not both succeed (a=%d b=%d)", statusA, statusB)
	}
	if payloadA != fixture.markerA || payloadB != fixture.markerB {
		t.Fatal("REALITY_CREDENTIALS_MIXED: a credential was served by the other credential's session")
	}
	clientA.stop()
	clientB.stop()
	mixedServer.stop()
}
