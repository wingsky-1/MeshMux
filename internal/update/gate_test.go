package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// TestRunDefersToCanonicalManifestGate pins finding #5: Run calls
// upgrade.Manifest.Validate, so a manifest naming another policy schema or
// architecture is refused at stage time, before any package byte is read.
func TestRunDefersToCanonicalManifestGate(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Target: "1.0.1", ManifestSHA256: shaOf(body), OperationID: strings.Repeat("a", 32),
		WorkDir: t.TempDir(), FetchManifest: func(context.Context) ([]byte, error) { return body, nil }}
	// A fixture manifest carries only one component, so the canonical table
	// gate refuses it: proof that Validate (not a local re-implementation) ran.
	if code := runCode(t, cfg); code != "MANIFEST_COMPONENT_INVALID" {
		t.Fatalf("fixture manifest: code = %q, want MANIFEST_COMPONENT_INVALID", code)
	}

	foreign := m
	foreign.PolicySchema = upgrade.PolicySchema + 1
	foreignBody, err := json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ManifestSHA256 = shaOf(foreignBody)
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return foreignBody, nil }
	if code := runCode(t, cfg); code != "MANIFEST_POLICY_SCHEMA_INVALID" {
		t.Fatalf("foreign policy schema: code = %q, want MANIFEST_POLICY_SCHEMA_INVALID", code)
	}
}

func runCode(t *testing.T, cfg Config) string {
	t.Helper()
	_, err := Run(context.Background(), cfg, &fixtureRunner{})
	if err == nil {
		return ""
	}
	return codeOf(err)
}

// TestReadAgentFileRefusesUnsafeFiles pins the ownership/mode half of finding
// #3: the update path applies the same 0600 + owner rule as the Agent, and
// names the failing file in its code.
func TestReadAgentFileRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"node_id":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := readAgentFile(good, &v, "AGENT_CONFIG_UNAVAILABLE"); err != nil || v["node_id"] != "x" {
		t.Fatalf("valid file: err %v, value %v", err, v)
	}

	loose := filepath.Join(dir, "loose.json")
	if err := os.WriteFile(loose, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := readAgentFile(loose, &v, "AGENT_IDENTITY_UNAVAILABLE"); err == nil || err.Error() != "AGENT_IDENTITY_UNAVAILABLE" {
		t.Fatalf("world-readable file: err %v, want AGENT_IDENTITY_UNAVAILABLE", err)
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := readAgentFile(broken, &v, "AGENT_CONFIG_UNAVAILABLE"); err == nil || err.Error() != "AGENT_CONFIG_UNAVAILABLE" {
		t.Fatalf("invalid JSON: err %v, want AGENT_CONFIG_UNAVAILABLE", err)
	}
}
