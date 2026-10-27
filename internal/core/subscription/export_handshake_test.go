package subscription

// This file is the gated data-plane acceptance fixture for the subscription
// exporters. It is NOT part of an ordinary `go test`: both client binaries
// must be supplied through the same environment variables as
// TestSubscriptionClientImport, and the CI script verifies their checksums.
//
// The fixture runs two real pinned sing-box 1.14.3 REALITY servers on
// loopback, asks the real exporters for client configurations, imports those
// configurations into the real sing-box and mihomo clients and sends one HTTP
// request through each client's exported mixed proxy. It proves that each of
// the two Lines carries data through both exported client formats.
//
// It does not prove public reachability, deletion revocation (covered by the
// gated node test) or real mobile-app usability. No host state is touched and
// no process output or configuration is printed on failure.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	// exportDataPathHandshakeName is the reserved SNI of the loopback target.
	exportDataPathHandshakeName = "handshake.example.invalid"
	// exportDataPathMarker is the body the isolated HTTP target returns.
	exportDataPathMarker = "meshmux-export-data-path"
	// exportDataPathBudget bounds one process start or HTTP request.
	exportDataPathBudget = 60 * time.Second
	// exportProcessStopTimeout bounds the wait for one killed child process.
	exportProcessStopTimeout = 5 * time.Second
	// exportMihomoVersion is pinned by scripts/ci-subscription-clients.sh.
	exportMihomoVersion = "1.19.32"
)

// TestSubscriptionExportHandshakeDataPath proves the exported client data path
// for two Lines. Both clients import the genuine exporter output; the only
// fixture overrides are the ephemeral mixed port and the selected Line.
func TestSubscriptionExportHandshakeDataPath(t *testing.T) {
	singBoxBinary, mihomoBinary := clientImportBinaries(t)
	assertExportClientVersion(t, "sing-box", singBoxBinary, []string{"version"}, node.KernelVersion)
	assertExportClientVersion(t, "mihomo", mihomoBinary, []string{"-v"}, exportMihomoVersion)

	dir := t.TempDir()
	handshakePort := startDataPathHandshakeTarget(t)
	lines, credentials := newDataPathLines(t, handshakePort)

	// Two real sing-box REALITY listeners, one per Line and credential.
	for index, line := range lines {
		startDataPathServer(t, singBoxBinary, dir, fmt.Sprintf("server-%d", index), line, credentials[index], line.Port)
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, exportDataPathMarker)
	}))
	t.Cleanup(target.Close)

	// sing-box: one exported document, the mixed port and the selector
	// default are the only overrides, once per Line.
	for index, credential := range credentials {
		mixedPort := freeDataPathPort(t)
		config := exportedSingBoxForCredential(t, lines, credentials, mixedPort, credential.UUID)
		process := startDataPathProcess(t, singBoxBinary, dir, fmt.Sprintf("sing-box-%d", index), "run", "-c", writeDataPathConfig(t, dir, fmt.Sprintf("sing-box-%d.json", index), config))
		waitDataPathPort(t, process, mixedPort)
		assertDataPathThroughProxy(t, "sing-box", target.URL, mixedPort)
		process.stop()
	}

	// Mihomo has no portable selector default, so the exported Line order is
	// changed through SortOrder and each ordered export is run in turn.
	for index := range lines {
		mixedPort := freeDataPathPort(t)
		config := exportedMihomoWithFirstLine(t, lines, credentials, index, mixedPort)
		// A fresh home per run prevents the previous run's cached selector
		// choice from bypassing the reordered first Line.
		home := filepath.Join(dir, fmt.Sprintf("mihomo-home-%d", index))
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatalf("error_code=EXPORT_DATAPATH_CONFIG_WRITE_FAILED")
		}
		process := startDataPathProcess(t, mihomoBinary, dir, fmt.Sprintf("mihomo-%d", index), "-f", writeDataPathConfig(t, dir, fmt.Sprintf("mihomo-%d.yaml", index), config), "-d", home)
		waitDataPathPort(t, process, mixedPort)
		assertDataPathThroughProxy(t, "mihomo", target.URL, mixedPort)
		process.stop()
	}
}

// assertExportClientVersion runs the client's own version command so a
// checksum-verified but wrong build is rejected before any traffic is sent.
func assertExportClientVersion(t *testing.T, label, binary string, args []string, version string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), exportDataPathBudget)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, args...).Output()
	if err != nil || !strings.Contains(string(output), version) {
		t.Fatalf("error_code=EXPORT_DATAPATH_CLIENT_VERSION_INVALID client=%s", label)
	}
}

// startDataPathHandshakeTarget starts an isolated TLS 1.3 target. REALITY
// mirrors the target's handshake, so a real TLS server is required. The
// server's own request log is discarded: the fixture only replays handshake
// bytes through it.
func startDataPathHandshakeTarget(t *testing.T) int {
	t.Helper()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, exportDataPathMarker)
	}))
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	target.StartTLS()
	t.Cleanup(target.Close)
	return target.Listener.Addr().(*net.TCPAddr).Port
}

// newDataPathLines builds two Lines on loopback and one credential per Line
// for the same Subscriber.
func newDataPathLines(t *testing.T, handshakePort int) ([]Line, []Credential) {
	t.Helper()
	subscriberID, err := NewID()
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_FIXTURE_INVALID")
	}
	lines := make([]Line, 0, 2)
	credentials := make([]Credential, 0, 2)
	for index := range 2 {
		nodeID, keyPair, shortID := newDataPathIdentity(t)
		line := Line{
			NodeID:          nodeID,
			DisplayName:     "line-data-path-" + strconv.Itoa(index+1),
			Server:          "127.0.0.1",
			Port:            freeDataPathPort(t),
			SortOrder:       index,
			ServerName:      exportDataPathHandshakeName,
			HandshakeServer: "127.0.0.1",
			HandshakePort:   handshakePort,
			PrivateKey:      keyPair.PrivateKey,
			PublicKey:       keyPair.PublicKey,
			ShortID:         shortID,
		}
		if err := line.Validate(); err != nil {
			t.Fatalf("error_code=EXPORT_DATAPATH_FIXTURE_INVALID")
		}
		credential, err := NewCredential(subscriberID, nodeID)
		if err != nil {
			t.Fatalf("error_code=EXPORT_DATAPATH_FIXTURE_INVALID")
		}
		lines = append(lines, line)
		credentials = append(credentials, credential)
	}
	return lines, credentials
}

func newDataPathIdentity(t *testing.T) (string, RealityKeyPair, string) {
	t.Helper()
	nodeID, err := NewID()
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_FIXTURE_INVALID")
	}
	keyPair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_FIXTURE_INVALID")
	}
	shortID, err := NewShortID()
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_FIXTURE_INVALID")
	}
	return nodeID, keyPair, shortID
}

// startDataPathServer compiles the v2 candidate for one Line and starts it.
// The compiled listen address is changed from 0.0.0.0 to 127.0.0.1 so the
// fixture cannot expose a port beyond loopback.
func startDataPathServer(t *testing.T, binary, dir, name string, line Line, credential Credential, port int) {
	t.Helper()
	candidate := node.Candidate{
		NodeID:        line.NodeID,
		Role:          node.RoleEdge,
		Revision:      1,
		VLESSPort:     port,
		KernelVersion: node.KernelVersion,
		Users: []node.VLESSUser{{
			CredentialID: credential.ID,
			UUID:         credential.UUID,
		}},
		Reality: &node.RealityConfig{
			ServerName:      line.ServerName,
			HandshakeServer: line.HandshakeServer,
			HandshakePort:   line.HandshakePort,
			PrivateKey:      line.PrivateKey,
			ShortID:         line.ShortID,
		},
	}
	compiled, err := node.CompileCandidate(candidate)
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SERVER_COMPILE_FAILED")
	}
	var document map[string]any
	if err = json.Unmarshal(compiled, &document); err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SERVER_COMPILE_FAILED")
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("error_code=EXPORT_DATAPATH_SERVER_COMPILE_FAILED")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("error_code=EXPORT_DATAPATH_SERVER_COMPILE_FAILED")
	}
	inbound["listen"] = "127.0.0.1"
	inbound["listen_port"] = port
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SERVER_COMPILE_FAILED")
	}
	process := startDataPathProcess(t, binary, dir, name, "run", "-c", writeDataPathConfig(t, dir, name+".json", body))
	waitDataPathPort(t, process, port)
}

// exportedSingBoxForCredential exports the real configuration and selects the
// Line carrying the credential. The exporter tag is read from the VLESS
// outbound with the matching UUID, never assumed from a naming scheme.
func exportedSingBoxForCredential(t *testing.T, lines []Line, credentials []Credential, mixedPort int, uuid string) []byte {
	t.Helper()
	encoded, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	var document map[string]any
	if err = json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	inbound["listen_port"] = mixedPort

	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	selected := ""
	var selector map[string]any
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
		}
		switch outbound["type"] {
		case "vless":
			if outbound["uuid"] == uuid {
				selected, _ = outbound["tag"].(string)
			}
		case "selector":
			selector = outbound
		}
	}
	if selected == "" || selector == nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	selector["default"] = selected
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_SINGBOX_EXPORT_FAILED")
	}
	return body
}

// exportedMihomoWithFirstLine orders the export so the chosen Line is the
// first proxy and therefore the select group's default, then replaces only
// the fixed mixed port.
func exportedMihomoWithFirstLine(t *testing.T, lines []Line, credentials []Credential, lineIndex, mixedPort int) []byte {
	t.Helper()
	ordered := make([]Line, len(lines))
	copy(ordered, lines)
	for index := range ordered {
		ordered[index].SortOrder = 1
	}
	ordered[lineIndex].SortOrder = 0
	encoded, err := ExportMihomo(ordered, credentials)
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_MIHOMO_EXPORT_FAILED")
	}
	fixed := []byte("mixed-port: " + strconv.Itoa(exportClientPort))
	if bytes.Count(encoded, fixed) != 1 {
		t.Fatalf("error_code=EXPORT_DATAPATH_MIHOMO_EXPORT_FAILED")
	}
	return bytes.Replace(encoded, fixed, []byte("mixed-port: "+strconv.Itoa(mixedPort)), 1)
}

// assertDataPathThroughProxy sends one HTTP request through the exported mixed
// proxy and requires the isolated target's marker.
func assertDataPathThroughProxy(t *testing.T, label, targetURL string, mixedPort int) {
	t.Helper()
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_PROXY_INVALID client=%s", label)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   exportDataPathBudget,
	}
	response, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_REQUEST_FAILED client=%s", label)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil || response.StatusCode != http.StatusOK || string(body) != exportDataPathMarker {
		t.Fatalf("error_code=EXPORT_DATAPATH_RESPONSE_INVALID client=%s status=%d", label, response.StatusCode)
	}
}

// dataPathProcess is one managed child; output goes to a private log that is
// never printed, so failures cannot disclose configuration material.
type dataPathProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func startDataPathProcess(t *testing.T, binary, dir, name string, args ...string) *dataPathProcess {
	t.Helper()
	logFile, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_PROCESS_START_FAILED")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + os.TempDir()}
	if err = cmd.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		t.Fatalf("error_code=EXPORT_DATAPATH_PROCESS_START_FAILED")
	}
	process := &dataPathProcess{cmd: cmd, cancel: cancel, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
		close(process.done)
	}()
	t.Cleanup(process.stop)
	return process
}

func (p *dataPathProcess) stop() {
	p.once.Do(func() {
		p.cancel()
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		select {
		case <-p.done:
		case <-time.After(exportProcessStopTimeout):
		}
	})
}

func waitDataPathPort(t *testing.T, process *dataPathProcess, port int) {
	t.Helper()
	deadline := time.Now().Add(exportDataPathBudget)
	for {
		select {
		case <-process.done:
			t.Fatalf("error_code=EXPORT_DATAPATH_PROCESS_EXITED port=%d", port)
		default:
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("error_code=EXPORT_DATAPATH_PORT_TIMEOUT port=%d", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func writeDataPathConfig(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_CONFIG_WRITE_FAILED")
	}
	return path
}

func freeDataPathPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("error_code=EXPORT_DATAPATH_PORT_RESERVE_FAILED")
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
