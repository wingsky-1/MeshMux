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

// fixtureRunner records every fixed argv the handoff runs; a refusal must
// never execute one.
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

// fixtureSet mirrors the dual-arch manifest channel: the approved target as one
// set carrying both architecture tables. The other architecture's entry exists
// because the endpoint always serves a set; the Agent selects and verifies only
// its own projection.
func fixtureSet(own upgrade.Manifest) upgrade.ManifestSet {
	otherArch := "arm64"
	if own.Architecture == "arm64" {
		otherArch = "amd64"
	}
	other := own
	other.Architecture = otherArch
	other.Components = []upgrade.Component{{Name: "meshmuxd", Version: "dev-20261023", Architecture: otherArch,
		Source: "file:///tmp/meshmuxd-" + otherArch, SHA256: strings.Repeat("e", 64), Format: "elf", Dev: true}}
	return upgrade.ManifestSet{Schema: upgrade.SetSchema, Version: own.Version, PolicySchema: upgrade.PolicySchema,
		Manifests: map[string]upgrade.Manifest{own.Architecture: own, otherArch: other}}
}

// setBody encodes one target as the Hub serves it.
func setBody(t *testing.T, m upgrade.Manifest) []byte {
	t.Helper()
	body, err := json.Marshal(fixtureSet(m))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// fixtureConfig pins one manifest projection the way a Web approval pins its
// per-arch SHA-256, while the channel body is the set carrying both tables.
// The fixture describes a target release, not the running build's table, so the
// real target gate is exercised. The host seams are deterministic fixtures: the
// real ones read the installed Agent files, stat / and hash the installed
// executor.
func fixtureConfig(t *testing.T, m upgrade.Manifest) Config {
	t.Helper()
	pinned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	body := setBody(t, m)
	return Config{Target: "1.0.1", ManifestSHA256: shaOf(pinned), OperationID: strings.Repeat("a", 32),
		WorkDir: t.TempDir(), FetchManifest: func(context.Context) ([]byte, error) { return body, nil },
		CurrentVersion: "1.0.0", Releases: []string{"1.0.0", "1.0.1"},
		NodeConfig: fixtureInstalled, Space: func(string, uint64) error { return nil }}
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
// per-arch projection SHA-256 is the only trust anchor, so a different valid
// manifest set served by the Hub is refused before its target gates or any
// package read, and a set naming another version is refused before execution.
func TestRunRefusesUnpinnedManifest(t *testing.T) {
	pkg := []byte("fixture package\n")
	approved := fixtureManifest(t, pkg, shaOf(pkg))
	cfg := fixtureConfig(t, approved)

	other := approved
	other.Version = "1.0.2"
	otherBody := setBody(t, other)
	runner := &fixtureRunner{}
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return otherBody, nil }
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "UPDATE_DIGEST_MISMATCH" {
		t.Fatalf("unpinned manifest: code = %q, want UPDATE_DIGEST_MISMATCH (err %v)", codeOf(err), err)
	}

	// A pin that matches a set naming another target is refused as well.
	body := setBody(t, approved)
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return body, nil }
	pinned, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ManifestSHA256 = shaOf(pinned)
	cfg.Target = "1.0.2"
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "UPDATE_TARGET_INVALID" {
		t.Fatalf("wrong target: code = %q, want UPDATE_TARGET_INVALID (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refusals executed %v", runner.calls)
	}
}

// TestRunSelectsLocalArchitectureFromSet pins U4 on the executor side: the
// channel is a set, the Agent selects its own runtime.GOARCH entry, and the pin
// covers exactly that entry's bytes. Pinning another architecture's projection
// is a digest mismatch, never a fallback to the wrong-arch document.
func TestRunSelectsLocalArchitectureFromSet(t *testing.T) {
	pkg := []byte("fixture package\n")
	own := fixtureManifest(t, pkg, shaOf(pkg))
	cfg := fixtureConfig(t, own)
	runner := &fixtureRunner{}
	result, err := Run(context.Background(), cfg, runner)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Manifest.Architecture != runtime.GOARCH {
		t.Fatalf("selected architecture = %q, want %q", result.Manifest.Architecture, runtime.GOARCH)
	}

	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	otherProjection, err := json.Marshal(fixtureSet(own).Manifests[otherArch])
	if err != nil {
		t.Fatal(err)
	}
	cfg.ManifestSHA256 = shaOf(otherProjection)
	refused := &fixtureRunner{}
	if _, err := Run(context.Background(), cfg, refused); codeOf(err) != "UPDATE_DIGEST_MISMATCH" {
		t.Fatalf("wrong-arch pin: code = %q, want UPDATE_DIGEST_MISMATCH (err %v)", codeOf(err), err)
	}
	if len(refused.calls) != 0 {
		t.Fatalf("wrong-arch pin executed %v", refused.calls)
	}
}

// TestRunRejectsSetWithoutLocalArchitecture pins the unknown-arch refusal: a
// set that carries only another architecture is never guessed or downgraded.
func TestRunRejectsSetWithoutLocalArchitecture(t *testing.T) {
	own := fixtureManifest(t, []byte("fixture package\n"), shaOf([]byte("fixture package\n")))
	set := fixtureSet(own)
	delete(set.Manifests, runtime.GOARCH)
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fixtureConfig(t, own)
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return body, nil }
	runner := &fixtureRunner{}
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "MANIFEST_ARCH_INVALID" {
		t.Fatalf("missing local architecture: code = %q, want MANIFEST_ARCH_INVALID (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("missing architecture executed %v", runner.calls)
	}
	if entries, readErr := os.ReadDir(cfg.WorkDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("refused set left scratch files: %v", entries)
	}
}

// TestRunStagesVerifiedPackage pins the staged bytes the handoff receives: the
// verified path holds exactly the package, and the result names the manifest
// that was approved.
func TestRunStagesVerifiedPackage(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	runner := &fixtureRunner{}
	result, err := Run(context.Background(), cfg, runner)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	staged, readErr := os.ReadFile(result.VerifiedPath)
	if result.Manifest.Version != cfg.Target || readErr != nil || string(staged) != string(pkg) {
		t.Fatalf("result = %+v, readErr %v", result, readErr)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("handoff calls = %q, want exactly one transient unit start", runner.calls)
	}
	if len(runner.calls[0]) < 2 || runner.calls[0][0] != "/usr/bin/systemd-run" {
		t.Fatalf("handoff argv = %q", runner.calls[0])
	}
}
