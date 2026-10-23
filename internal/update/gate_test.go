package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// TestRunStagesChangedMeshmuxdTable is the regression test for the target gate:
// a genuine target manifest differs from the running build's pinned table (new
// meshmuxd version and digest), and it must reach staged bytes through the real
// gate. Running-build table equality would refuse it here.
func TestRunStagesChangedMeshmuxdTable(t *testing.T) {
	pkg := []byte("new meshmuxd build\n")
	m := fixtureManifest(t, pkg, shaOf(pkg))
	// The target ships a newer executor build than the running one; the
	// running build's canonical table can never match this.
	m.Components[0].Version = "dev-20261024"
	if err := m.Validate(); codeOf(err) != "MANIFEST_COMPONENT_INVALID" {
		t.Fatalf("running-build self-check accepted a target table: %v", err)
	}
	cfg := fixtureConfig(t, m)

	result, err := Run(context.Background(), cfg, &fixtureRunner{})
	if err != nil {
		t.Fatalf("handoff: %v", err)
	}
	if staged, readErr := os.ReadFile(result.VerifiedPath); readErr != nil || string(staged) != string(pkg) {
		t.Fatalf("staged bytes = %q, err %v", staged, readErr)
	}
	if result.Manifest.Components[0].Version != "dev-20261024" {
		t.Fatalf("result carries the running build's component: %+v", result.Manifest.Components[0])
	}
}

// TestRunRefusesForeignPolicySchema keeps the stored-policy gate: a target that
// names another stored policy schema cannot be applied by this binary, and the
// refusal is the handoff's own compat code.
func TestRunRefusesForeignPolicySchema(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	m.PolicySchema = upgrade.PolicySchema + 1
	cfg := fixtureConfig(t, m)
	if code := runCode(t, cfg); code != "UPDATE_SCHEMA_INCOMPATIBLE" {
		t.Fatalf("code = %q, want UPDATE_SCHEMA_INCOMPATIBLE", code)
	}
}

// TestRunRefusesUntrustedComponentSource pins the source-class rule restored in
// the target gate: a digest alone never makes an arbitrary URL executable.
func TestRunRefusesUntrustedComponentSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*upgrade.Component)
	}{
		{"dev build from a plain http source", func(c *upgrade.Component) { c.Source = "http://example.invalid/meshmuxd" }},
		{"dev build without the dev- prefix", func(c *upgrade.Component) { c.Version = "1.0.1" }},
		{"release build from a file source", func(c *upgrade.Component) { c.Dev, c.Source = false, "file:///tmp/meshmuxd" }},
		{"release build from a foreign host", func(c *upgrade.Component) { c.Dev, c.Source = false, "https://example.invalid/meshmuxd" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
			tc.mutate(&m.Components[0])
			if code := runCode(t, fixtureConfig(t, m)); code != "MANIFEST_COMPONENT_INVALID" {
				t.Fatalf("code = %q, want MANIFEST_COMPONENT_INVALID", code)
			}
		})
	}
}

// TestRunRefusesManifestForAnotherTarget keeps the version binding: the pinned
// manifest must describe exactly the approved target.
func TestRunRefusesManifestForAnotherTarget(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	m.Version = "1.0.2"
	if code := runCode(t, fixtureConfig(t, m)); code != "UPDATE_TARGET_INVALID" {
		t.Fatalf("code = %q, want UPDATE_TARGET_INVALID", code)
	}
}

// TestRunRefusesManifestForAnotherArchitecture keeps the architecture binding.
func TestRunRefusesManifestForAnotherArchitecture(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	m.Architecture = "riscv64"
	if code := runCode(t, fixtureConfig(t, m)); code != "MANIFEST_ARCH_INVALID" {
		t.Fatalf("code = %q, want MANIFEST_ARCH_INVALID", code)
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
