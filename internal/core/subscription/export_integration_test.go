package subscription

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The import check runs the real client binaries against the real exporter
// output. The binaries are supplied by the validation script, which also
// verifies their checksums; this test only validates that the binary paths
// are absolute and usable.
const (
	envSingBoxBinary = "MESHMUX_SINGBOX_TEST_BINARY"
	envMihomoBinary  = "MESHMUX_MIHOMO_TEST_BINARY"
)

// clientCheckTimeout bounds one client configuration check.
const clientCheckTimeout = 10 * time.Second

// Stable error codes. Failures never print the exported document, because it
// carries client credentials.
const (
	codeBinaryEnvIncomplete      = "CLIENT_IMPORT_BINARY_ENV_INCOMPLETE"
	codeBinaryPathInvalid        = "CLIENT_IMPORT_BINARY_PATH_INVALID"
	codeFixtureInvalid           = "CLIENT_IMPORT_FIXTURE_INVALID"
	codeExportSingBoxFailed      = "EXPORT_SING_BOX_FAILED"
	codeExportMihomoFailed       = "EXPORT_MIHOMO_FAILED"
	codeConfigSecretLeak         = "CLIENT_IMPORT_SECRET_LEAK"
	codeConfigMaterialMissing    = "CLIENT_IMPORT_MATERIAL_MISSING"
	codeConfigDocumentInvalid    = "CLIENT_IMPORT_DOCUMENT_INVALID"
	codeConfigOutboundMismatch   = "CLIENT_IMPORT_OUTBOUND_MISMATCH"
	codeConfigFileMismatch       = "CLIENT_IMPORT_FILE_MISMATCH"
	codeClientCheckFailed        = "CLIENT_IMPORT_CHECK_FAILED"
	codeClientCheckTimeout       = "CLIENT_IMPORT_CHECK_TIMEOUT"
	codeClientCheckNotExecutable = "CLIENT_IMPORT_CHECK_NOT_EXECUTABLE"
)

// TestSubscriptionClientImport exports the standard subscriptions with the
// real exporters and asks the real sing-box and mihomo binaries to import the
// generated files.
//
// Scope: this proves that the client applications accept the exported
// configuration. It does not prove a REALITY handshake, public reachability or
// working proxying; no traffic is sent from this test.
func TestSubscriptionClientImport(t *testing.T) {
	singBoxBinary, mihomoBinary := clientImportBinaries(t)

	lines := newImportLines(t)
	credentials := newImportCredentials(t, lines)

	singBoxConfig, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("error_code=%s ExportSingBox returned an error", codeExportSingBoxFailed)
	}
	mihomoConfig, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("error_code=%s ExportMihomo returned an error", codeExportMihomoFailed)
	}

	assertImportConfigSafe(t, "sing-box", singBoxConfig, lines, credentials)
	assertImportConfigSafe(t, "mihomo", mihomoConfig, lines, credentials)
	assertSingBoxVLESSOutbounds(t, singBoxConfig, lines, credentials)

	workDir := t.TempDir()
	singBoxConfigPath := filepath.Join(workDir, "sing-box-client.json")
	mihomoConfigPath := filepath.Join(workDir, "mihomo-client.yaml")
	writeImportConfig(t, singBoxConfigPath, singBoxConfig)
	writeImportConfig(t, mihomoConfigPath, mihomoConfig)

	runClientConfigCheck(t, "sing-box", singBoxBinary, "check", "-c", singBoxConfigPath)
	runClientConfigCheck(t, "mihomo", mihomoBinary, "-t", "-f", mihomoConfigPath, "-d", workDir)

	// The device-scoped document of 9c is separately imported. Its endpoint
	// fields (including the purpose-pinned accept_routes) are only proven
	// against the real 1.14.3 parser here; this says nothing about reaching a
	// tailnet or a peer subnet.
	meshConfig, err := ExportMeshDevice(MeshDeviceInput{
		DisplayName: "import-mesh",
		Hostname:    "mesh-import",
		Purpose:     MeshPurposeProxyMesh,
		ControlURL:  "https://headscale.example.invalid",
		AuthKey:     "hskey-auth-import-example",
		Lines:       lines,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatalf("error_code=%s ExportMeshDevice returned an error", codeExportSingBoxFailed)
	}
	meshConfigPath := filepath.Join(workDir, "mesh-client.json")
	writeImportConfig(t, meshConfigPath, meshConfig)
	runClientConfigCheck(t, "sing-box", singBoxBinary, "check", "-c", meshConfigPath)
}

// clientImportBinaries resolves both client binaries. Both unset skips the
// test; exactly one set is a configuration error and fails the test.
func clientImportBinaries(t *testing.T) (string, string) {
	t.Helper()

	singBoxBinary := strings.TrimSpace(os.Getenv(envSingBoxBinary))
	mihomoBinary := strings.TrimSpace(os.Getenv(envMihomoBinary))

	switch {
	case singBoxBinary == "" && mihomoBinary == "":
		t.Skipf("%s and %s are not set: skipping the external client import check", envSingBoxBinary, envMihomoBinary)
	case singBoxBinary == "" || mihomoBinary == "":
		t.Fatalf(
			"error_code=%s %s and %s must both be set to run the client import check",
			codeBinaryEnvIncomplete, envSingBoxBinary, envMihomoBinary,
		)
	}

	for _, candidate := range []struct {
		name string
		path string
	}{
		{name: envSingBoxBinary, path: singBoxBinary},
		{name: envMihomoBinary, path: mihomoBinary},
	} {
		if !filepath.IsAbs(candidate.path) {
			t.Fatalf("error_code=%s %s must be an absolute path", codeBinaryPathInvalid, candidate.name)
		}
		info, err := os.Stat(candidate.path)
		if err != nil {
			t.Fatalf("error_code=%s %s is not usable", codeBinaryPathInvalid, candidate.name)
		}
		if info.IsDir() {
			t.Fatalf("error_code=%s %s is not usable", codeBinaryPathInvalid, candidate.name)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("error_code=%s %s is not executable", codeClientCheckNotExecutable, candidate.name)
		}
	}

	return singBoxBinary, mihomoBinary
}

// newImportLines builds two distinct Line fixtures on the example.invalid
// documentation domain, each with its own port, key pair and short ID.
func newImportLines(t *testing.T) []Line {
	t.Helper()

	specs := []struct {
		displayName string
		port        int
	}{
		{displayName: "line-example-01", port: 8443},
		{displayName: "line-example-02", port: 9443},
	}

	lines := make([]Line, 0, len(specs))
	for index, spec := range specs {
		nodeID, err := NewID()
		if err != nil {
			t.Fatalf("error_code=%s NewID returned an error", codeFixtureInvalid)
		}
		pair, err := NewRealityKeyPair()
		if err != nil {
			t.Fatalf("error_code=%s NewRealityKeyPair returned an error", codeFixtureInvalid)
		}
		shortID, err := NewShortID()
		if err != nil {
			t.Fatalf("error_code=%s NewShortID returned an error", codeFixtureInvalid)
		}
		line := Line{
			NodeID:          nodeID,
			DisplayName:     spec.displayName,
			Server:          "example.invalid",
			Port:            spec.port,
			SortOrder:       index,
			ServerName:      "handshake.example.invalid",
			HandshakeServer: "handshake.example.invalid",
			HandshakePort:   443,
			PrivateKey:      pair.PrivateKey,
			PublicKey:       pair.PublicKey,
			ShortID:         shortID,
		}
		if err = line.Validate(); err != nil {
			t.Fatalf("error_code=%s the generated line fixture is invalid", codeFixtureInvalid)
		}
		lines = append(lines, line)
	}
	return lines
}

// newImportCredentials builds one credential per Line for the same
// subscriber, so the export must carry two independent VLESS identities.
func newImportCredentials(t *testing.T, lines []Line) []Credential {
	t.Helper()

	subscriberID, err := NewID()
	if err != nil {
		t.Fatalf("error_code=%s NewID returned an error", codeFixtureInvalid)
	}

	credentials := make([]Credential, 0, len(lines))
	for _, line := range lines {
		credential, err := NewCredential(subscriberID, line.NodeID)
		if err != nil {
			t.Fatalf("error_code=%s NewCredential returned an error", codeFixtureInvalid)
		}
		if err = credential.Validate(); err != nil {
			t.Fatalf("error_code=%s the generated credential fixture is invalid", codeFixtureInvalid)
		}
		credentials = append(credentials, credential)
	}
	return credentials
}

// assertImportConfigSafe checks that an exported client configuration carries
// client-side material only: every credential UUID and every Reality public
// key must be present, while Line private keys and server-side field names
// must be absent.
func assertImportConfigSafe(t *testing.T, label string, config []byte, lines []Line, credentials []Credential) {
	t.Helper()

	text := string(config)

	for _, forbidden := range []string{"private_key", "handshake_server"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("error_code=%s %s configuration contains the forbidden field %q", codeConfigSecretLeak, label, forbidden)
		}
	}

	for _, line := range lines {
		if line.PrivateKey == "" {
			t.Fatalf("error_code=%s %s configuration is missing a Line private key to compare against", codeConfigMaterialMissing, label)
		}
		if strings.Contains(text, line.PrivateKey) {
			t.Fatalf("error_code=%s %s configuration contains a Line private key", codeConfigSecretLeak, label)
		}
	}

	for _, credential := range credentials {
		if credential.UUID == "" {
			t.Fatalf("error_code=%s %s configuration is missing a credential UUID", codeConfigMaterialMissing, label)
		}
		if !strings.Contains(text, credential.UUID) {
			t.Fatalf("error_code=%s %s configuration is missing a credential UUID", codeConfigMaterialMissing, label)
		}
	}

	for _, line := range lines {
		if line.PublicKey == "" {
			t.Fatalf("error_code=%s %s configuration is missing a Reality public key", codeConfigMaterialMissing, label)
		}
		if !strings.Contains(text, line.PublicKey) {
			t.Fatalf("error_code=%s %s configuration is missing a Reality public key", codeConfigMaterialMissing, label)
		}
	}
}

// assertSingBoxVLESSOutbounds verifies that the exported sing-box document
// declares exactly one VLESS outbound per Line, and that the outbounds carry
// the expected client identities.
func assertSingBoxVLESSOutbounds(t *testing.T, config []byte, lines []Line, credentials []Credential) {
	t.Helper()

	var document struct {
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
			UUID string `json:"uuid"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatalf("error_code=%s the exported sing-box configuration is not valid JSON", codeConfigDocumentInvalid)
	}

	got := 0
	for _, outbound := range document.Outbounds {
		if outbound.Type != "vless" {
			continue
		}
		got++
		if outbound.UUID == "" {
			t.Fatalf("error_code=%s a VLESS outbound carries no UUID", codeConfigMaterialMissing)
		}
		if outbound.Tag == "" {
			t.Fatalf("error_code=%s a VLESS outbound carries no tag", codeConfigMaterialMissing)
		}
	}

	if got != len(lines) {
		t.Fatalf("error_code=%s the exported sing-box configuration declares %d VLESS outbounds, want %d", codeConfigOutboundMismatch, got, len(lines))
	}

	expected := make(map[string]bool, len(credentials))
	for _, credential := range credentials {
		expected[credential.UUID] = true
	}
	for _, outbound := range document.Outbounds {
		if outbound.Type != "vless" {
			continue
		}
		if !expected[outbound.UUID] {
			t.Fatalf("error_code=%s a VLESS outbound carries an unknown UUID", codeConfigOutboundMismatch)
		}
		delete(expected, outbound.UUID)
	}
	if len(expected) != 0 {
		t.Fatalf("error_code=%s the exported sing-box configuration misses a credential UUID", codeConfigOutboundMismatch)
	}
}

// writeImportConfig stores the exporter output unchanged with restrictive
// permissions and verifies that the stored bytes are identical to the
// exporter output.
func writeImportConfig(t *testing.T, path string, config []byte) {
	t.Helper()

	if !filepath.IsAbs(path) {
		t.Fatalf("error_code=%s the configuration path must be absolute", codeBinaryPathInvalid)
	}
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatalf("error_code=%s writing the configuration failed", codeConfigFileMismatch)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error_code=%s reading the configuration failed", codeConfigFileMismatch)
	}
	if !bytes.Equal(stored, config) {
		t.Fatalf("error_code=%s the stored configuration differs from the exporter output", codeConfigFileMismatch)
	}
}

// runClientConfigCheck runs a client binary in configuration-check mode. The
// output is discarded so that no configuration material can leak into the
// test log; failures are reported with stable error codes only.
func runClientConfigCheck(t *testing.T, label, binary string, args ...string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), clientCheckTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	// A nil stream connects the child directly to the null device. A pipe
	// would keep the copy goroutine alive until every descendant of the
	// client binary released it, which would defeat the timeout below.
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("error_code=%s %s configuration check timed out", codeClientCheckTimeout, label)
		}
		t.Fatalf("error_code=%s %s configuration check failed", codeClientCheckFailed, label)
	}
}
