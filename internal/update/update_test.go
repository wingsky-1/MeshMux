package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// fixtureRunner records every fixed argv the future handoff would run; the
// verify-only segment must never execute one.
type fixtureRunner struct{ calls [][]string }

func (r *fixtureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil, nil
}

func shaOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fixtureConfig serves one dev meshmuxd manifest pointing at a local file, the
// source rule the pre-release dev build allows. ManifestSHA256 is the pin a Web
// approval would carry.
func fixtureConfig(t *testing.T, pkg []byte, componentSHA string) Config {
	t.Helper()
	source := filepath.Join(t.TempDir(), "meshmuxd")
	if err := os.WriteFile(source, pkg, 0600); err != nil {
		t.Fatal(err)
	}
	m := upgrade.Manifest{Schema: upgrade.Schema, Version: "1.0.1", Architecture: runtime.GOARCH,
		PolicySchema: upgrade.PolicySchema, Components: []upgrade.Component{{Name: "meshmuxd",
			Version: "dev-20261023", Architecture: runtime.GOARCH, Source: "file://" + source,
			SHA256: componentSHA, Format: "elf", Dev: true}}}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Target: "1.0.1", ManifestSHA256: shaOf(body), OperationID: strings.Repeat("a", 32),
		WorkDir: t.TempDir(), FetchManifest: func(context.Context) ([]byte, error) { return body, nil }}
}

func TestRunRefusesInvalidArguments(t *testing.T) {
	valid := Config{Target: "1.0.1", ManifestSHA256: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 32),
		WorkDir: t.TempDir(), FetchManifest: func(context.Context) ([]byte, error) { return nil, nil }}
	for _, tc := range []struct {
		name   string
		code   string
		mutate func(*Config)
	}{
		{"bad target", "UPDATE_TARGET_INVALID", func(c *Config) { c.Target = "1.0" }},
		{"bad digest", "UPDATE_DIGEST_INVALID", func(c *Config) { c.ManifestSHA256 = "not-a-digest" }},
		{"missing operation", "OPERATION_REQUIRED", func(c *Config) { c.OperationID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			runner := &fixtureRunner{}
			_, err := Run(context.Background(), cfg, runner)
			if code, _, _ := strings.Cut(err.Error(), ": "); code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("refused run executed %v", runner.calls)
			}
		})
	}
}
func TestRunRefusesTamperedPackage(t *testing.T) {
	cfg := fixtureConfig(t, []byte("fixture package\n"), strings.Repeat("0", 64))
	runner := &fixtureRunner{}
	_, err := Run(context.Background(), cfg, runner)
	if code, _, _ := strings.Cut(err.Error(), ": "); code != "UPDATE_DIGEST_MISMATCH" {
		t.Fatalf("code = %q, want UPDATE_DIGEST_MISMATCH (err %v)", code, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("digest mismatch executed %v", runner.calls)
	}
	if entries, readErr := os.ReadDir(cfg.WorkDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("scratch files left behind: %v", entries)
	}
}
func TestRunStagesVerifiedPackage(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, pkg, shaOf(pkg))
	runner := &fixtureRunner{}
	result, err := Run(context.Background(), cfg, runner)
	if code, _, _ := strings.Cut(err.Error(), ": "); code != "UPDATE_HANDOFF_NOT_IMPLEMENTED" {
		t.Fatalf("code = %q, want UPDATE_HANDOFF_NOT_IMPLEMENTED (err %v)", code, err)
	}
	staged, readErr := os.ReadFile(result.VerifiedPath)
	if result.Manifest.Version != cfg.Target || readErr != nil || string(staged) != string(pkg) {
		t.Fatalf("result = %+v, readErr %v", result, readErr)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("pre-handoff executed %v", runner.calls)
	}
}
