package node

// The co-location and journald tests in this package install a real Hub ledger
// first. The Hub fixture lives in install/hub's own tests, which another
// package's test binary cannot import, so this file carries the same fixture
// for the Node-side tests. It stays test-only: production code never sees it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/install/hub"
)

type fakeHubInstallerRunner struct {
	users    map[string]bool
	calls    []string
	failUnit string
	// failCall fails the first command whose rendered call contains this
	// substring, then stops firing so rollback itself can still proceed.
	failCall string
	failUsed bool
	// packages records dpkg's "install ok installed" answers.
	packages map[string]bool
}

func (f *fakeHubInstallerRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failCall != "" && !f.failUsed && strings.Contains(call, f.failCall) {
		f.failUsed = true
		return nil, errors.New("fault injected")
	}
	switch name {
	case "getent":
		if len(args) == 2 && f.users[args[1]] {
			return []byte("existing-user"), nil
		}
		return nil, errors.New("user not found")
	case "useradd":
		if f.users == nil {
			f.users = map[string]bool{}
		}
		f.users[args[len(args)-1]] = true
	case "systemctl":
		if f.failUnit != "" && (strings.Contains(call, "enable --now "+f.failUnit) || strings.Contains(call, "restart "+f.failUnit)) {
			return nil, errors.New("fault injected")
		}
	case "chown":
		// Unit tests use a private filesystem root without changing system users.
	case "dpkg-query":
		// args are ["-W", "-f=${Status}", pkg].
		if len(args) == 3 && f.packages[args[2]] {
			return []byte("install ok installed"), nil
		}
		return nil, errors.New("package not installed")
	default:
		if len(args) == 1 && args[0] == "version" {
			if strings.Contains(name, "caddy") {
				return []byte("v2.11.7"), nil
			}
			return []byte("v0.29.5"), nil
		}
	}
	return nil, nil
}

type hubInstallerFixture struct {
	root   string
	runner *fakeHubInstallerRunner
	opts   core.ApplyOptions
	c      core.Config
}

func makeHubInstallerFixture(t *testing.T) hubInstallerFixture {
	t.Helper()
	root := t.TempDir()
	binaryDir := t.TempDir()
	source := filepath.Join(binaryDir, "meshmuxd")
	if err := os.WriteFile(source, []byte("isolated MeshMux test executable"), 0755); err != nil {
		t.Fatal(err)
	}
	assets := []core.Artifact{}
	for _, item := range []struct {
		component, version string
	}{
		{"caddy", "2.11.7"}, {"headscale", "0.29.5"},
	} {
		sourcePath := filepath.Join(binaryDir, item.component)
		data := []byte("verified test artifact " + item.component)
		if err := os.WriteFile(sourcePath, data, 0755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		assets = append(assets, core.Artifact{
			Component: item.component, Version: item.version,
			Source: "fixture://" + item.component, SHA256: hex.EncodeToString(sum[:]), Format: "elf",
		})
	}
	runner := &fakeHubInstallerRunner{users: map[string]bool{}}
	download := func(_ context.Context, a core.Artifact, _ string) (string, error) {
		return filepath.Join(binaryDir, a.Component), nil
	}
	return hubInstallerFixture{
		root: root, runner: runner,
		c: core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org"},
		opts: core.ApplyOptions{
			Root: root, Runner: runner, Executable: source, Artifacts: assets,
			DownloadArtifact: download,
			Preflight: func(context.Context, core.Config, bool) ([]core.Check, []int) {
				return []core.Check{{Name: "system", Status: "pass"}, {Name: "public_https", Status: "pending"}}, []int{60794}
			},
			Verify: func(context.Context, core.Config, core.CommandRunner, func(context.Context, string) error) error {
				return nil
			},
		},
	}
}

func invokeHubInstaller(t *testing.T, fixture hubInstallerFixture, op string, repair bool) (core.InstallResult, error) {
	t.Helper()
	return hub.InstallHub(context.Background(), fixture.c, op, repair, fixture.opts)
}

// vmOneFailureRunner injects exactly one systemctl failure, mirroring the Hub
// VM harness helper that this package's VM test cannot import.
type vmOneFailureRunner struct {
	core.ExecRunner
	target string
	used   bool
}

func (r *vmOneFailureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !r.used && name == "systemctl" && strings.Join(args, " ") == r.target {
		r.used = true
		return nil, errors.New("isolated VM injected failure")
	}
	return r.ExecRunner.Run(ctx, name, args...)
}

func mustReadVM(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// testLockRecovery is the recovery sentence the core lock test pins; the Node
// handoff tests need the same literal and cannot import another package's test
// declarations.
const testLockRecovery = "Check /run/lock ownership and symlinks."
