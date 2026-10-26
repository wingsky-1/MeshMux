package hubupgrade

// Gate tests for the root-preset target manifest (#11d Task 3, spec §5.8).
// The manifest is a trust anchor, not a configuration file: a missing file, a
// non-root owner, a loose mode, an unknown field, a wrong arch/source/digest, a
// policy schema mismatch, a non-increasing version or an unknown
// database_migration value all collapse into MANIFEST_UNAVAILABLE with zero
// writes.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

func hubManifest(target string) upgrade.Manifest {
	return upgrade.Manifest{
		Schema:       upgrade.Schema,
		Version:      target,
		Architecture: runtime.GOARCH,
		PolicySchema: upgrade.PolicySchema,
		Components: []upgrade.Component{{
			Name: "meshmuxd", Version: "dev-" + target, Architecture: runtime.GOARCH,
			Source: "file:///tmp/meshmuxd-dev", SHA256: strings.Repeat("a", 64), Dev: true,
		}},
	}
}

func writeHubManifest(t *testing.T, dir, target string, mutate func(*upgrade.Manifest)) string {
	t.Helper()
	m := hubManifest(target)
	if mutate != nil {
		mutate(&m)
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest-"+target+".json")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManifestGate(t *testing.T) {
	readerOwner := os.Geteuid()
	cases := []struct {
		name   string
		dir    func(t *testing.T) string
		target string
		mutate func(*upgrade.Manifest)
		after  func(t *testing.T, dir, target string)
		read   func(dir, target string) (TargetManifest, error)
		code   string
	}{
		{name: "additive default", target: "1.0.1"},
		{name: "explicit additive", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.DatabaseMigration = "additive" }},
		{name: "irreversible", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.DatabaseMigration = "irreversible" }},
		{name: "unknown migration", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.DatabaseMigration = "drop" }, code: "MANIFEST_UNAVAILABLE"},
		{name: "not newer", target: "1.0.0-dev", code: "MANIFEST_UNAVAILABLE"},
		{name: "wrong arch", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.Architecture = "mips" }, code: "MANIFEST_UNAVAILABLE"},
		{name: "bad digest", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.Components[0].SHA256 = strings.Repeat("A", 64) }, code: "MANIFEST_UNAVAILABLE"},
		{name: "release from file", target: "1.0.1", mutate: func(m *upgrade.Manifest) {
			m.Components[0].Dev = false
			m.Components[0].Source = "file:///tmp/meshmuxd"
		}, code: "MANIFEST_UNAVAILABLE"},
		{name: "wrong policy schema", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.PolicySchema = upgrade.PolicySchema - 1 }, code: "MANIFEST_UNAVAILABLE"},
		{name: "missing component", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.Components = nil }, code: "MANIFEST_UNAVAILABLE"},
		{name: "wrong schema", target: "1.0.1", mutate: func(m *upgrade.Manifest) { m.Schema = "other/v1" }, code: "MANIFEST_UNAVAILABLE"},
		{name: "loose file mode", target: "1.0.1", after: func(t *testing.T, dir, target string) {
			if err := os.Chmod(filepath.Join(dir, "manifest-"+target+".json"), 0600); err != nil {
				t.Fatal(err)
			}
		}, code: "MANIFEST_UNAVAILABLE"},
		{name: "missing file", dir: func(t *testing.T) string { return t.TempDir() }, target: "1.0.1", code: "MANIFEST_UNAVAILABLE"},
		{name: "foreign owner", target: "1.0.1", read: func(dir, target string) (TargetManifest, error) {
			return readRootManifest(dir, target, readerOwner+1)
		}, code: "MANIFEST_UNAVAILABLE"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "manifests")
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if tc.dir != nil {
				dir = tc.dir(t)
			} else {
				writeHubManifest(t, dir, tc.target, tc.mutate)
				if tc.after != nil {
					tc.after(t, dir, tc.target)
				}
			}
			read := tc.read
			if read == nil {
				read = func(dir, target string) (TargetManifest, error) {
					return readRootManifest(dir, target, readerOwner)
				}
			}
			got, err := read(dir, tc.target)
			if tc.code != "" {
				if err == nil || codeOf(err) != tc.code {
					t.Fatalf("error = %v, want code %s", err, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid manifest refused: %v", err)
			}
			if got.SHA256 == "" || got.Package.SHA256 != strings.Repeat("a", 64) {
				t.Fatalf("manifest anchors missing: %+v", got)
			}
			wantMigration := "additive"
			if tc.mutate != nil && tc.name == "irreversible" {
				wantMigration = "irreversible"
			}
			if got.DatabaseMigration != wantMigration {
				t.Fatalf("database_migration %q want %q", got.DatabaseMigration, wantMigration)
			}
		})
	}
}

func TestManifestRejectsUnknownFieldAndTrailingData(t *testing.T) {
	readerOwner := os.Geteuid()
	cases := map[string]func([]byte) []byte{
		"unknown field": func(body []byte) []byte { return []byte(strings.Replace(string(body), "{", `{"future":true,`, 1)) },
		"trailing":      func(body []byte) []byte { return append(body, []byte("{}")...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeHubManifest(t, dir, "1.0.1", nil)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mutate(body), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := readRootManifest(dir, "1.0.1", readerOwner); err == nil || codeOf(err) != "MANIFEST_UNAVAILABLE" {
				t.Fatalf("%s manifest error = %v", name, err)
			}
		})
	}
}

func TestManifestTargetMustMatchRequestedVersion(t *testing.T) {
	readerOwner := os.Geteuid()
	dir := t.TempDir()
	writeHubManifest(t, dir, "1.0.2", nil)
	if _, err := readRootManifest(dir, "1.0.1", readerOwner); err == nil || codeOf(err) != "MANIFEST_UNAVAILABLE" {
		t.Fatalf("a manifest for another target was accepted: %v", err)
	}
}
