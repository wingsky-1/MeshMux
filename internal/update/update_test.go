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

func codeOf(err error) string {
	code, _, _ := strings.Cut(err.Error(), ": ")
	return code
}

func shaOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fixtureManifest(t *testing.T, pkg []byte, componentSHA string) upgrade.Manifest {
	t.Helper()
	source := filepath.Join(t.TempDir(), "meshmuxd")
	if err := os.WriteFile(source, pkg, 0600); err != nil {
		t.Fatal(err)
	}
	return upgrade.Manifest{Schema: upgrade.Schema, Version: "1.0.1", Architecture: runtime.GOARCH,
		PolicySchema: upgrade.PolicySchema, Components: []upgrade.Component{{Name: "meshmuxd",
			Version: "dev-20261023", Architecture: runtime.GOARCH, Source: "file://" + source,
			SHA256: componentSHA, Format: "elf", Dev: true}}}
}

// fixtureConfig pins one manifest body the way a Web approval pins its SHA-256.
// The fixture describes a target release, not the running build's table, so the
// real target gate is exercised.
func fixtureConfig(t *testing.T, m upgrade.Manifest) Config {
	t.Helper()
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
			if code := codeOf(err); code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("refused run executed %v", runner.calls)
			}
		})
	}
}

func TestRunRefusesTamperedPackage(t *testing.T) {
	cfg := fixtureConfig(t, fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("0", 64)))
	runner := &fixtureRunner{}
	_, err := Run(context.Background(), cfg, runner)
	if code := codeOf(err); code != "UPDATE_DIGEST_MISMATCH" {
		t.Fatalf("code = %q, want UPDATE_DIGEST_MISMATCH (err %v)", code, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("digest mismatch executed %v", runner.calls)
	}
	if entries, readErr := os.ReadDir(cfg.WorkDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("scratch files left behind: %v", entries)
	}
}

// TestRunRefusesUnpinnedManifest is the manifest-pin property: the approved
// SHA-256 is the only trust anchor, so a different valid manifest served by the
// Hub is refused before it is parsed, and a manifest naming another version is
// refused before any package is read.
func TestRunRefusesUnpinnedManifest(t *testing.T) {
	pkg := []byte("fixture package\n")
	approved := fixtureManifest(t, pkg, shaOf(pkg))
	cfg := fixtureConfig(t, approved)

	other := approved
	other.Version = "1.0.2"
	otherBody, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fixtureRunner{}
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return otherBody, nil }
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "UPDATE_DIGEST_MISMATCH" {
		t.Fatalf("unpinned manifest: code = %q, want UPDATE_DIGEST_MISMATCH (err %v)", codeOf(err), err)
	}

	// A pin that matches a manifest naming another target is refused as well.
	body, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return body, nil }
	cfg.ManifestSHA256 = shaOf(body)
	cfg.Target = "1.0.2"
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "UPDATE_TARGET_INVALID" {
		t.Fatalf("wrong target: code = %q, want UPDATE_TARGET_INVALID (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refusals executed %v", runner.calls)
	}
}

func TestRunStagesVerifiedPackage(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	runner := &fixtureRunner{}
	result, err := Run(context.Background(), cfg, runner)
	if code := codeOf(err); code != "UPDATE_HANDOFF_NOT_IMPLEMENTED" {
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
