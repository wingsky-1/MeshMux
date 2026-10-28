package core

// This file is the one Hub installer fixture shared by the hub and node test
// packages. A declaration in a _test.go file cannot be imported across
// packages, and the repository's dupl gate rejects keeping a second copy, so
// the fixture lives in the leaf package both test binaries already import. It
// has no production caller and avoids *testing.T so core does not link the
// testing package into an installed binary.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// HubTestRunner is the CommandRunner used by Hub installer tests. It answers
// host probes from memory; exported fields let a test seed answers and inspect
// the commands that were attempted.
type HubTestRunner struct {
	Users map[string]bool
	Calls []string
	// FailUnit fails enable --now or restart of that one unit.
	FailUnit string
	// FailCall fails the first command whose rendered call contains this
	// substring, then stops firing so rollback itself can still proceed.
	FailCall string
	failUsed bool
	// Packages records dpkg's "install ok installed" answers.
	Packages map[string]bool
}

// Run implements CommandRunner.
func (f *HubTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.Calls = append(f.Calls, call)
	if f.FailCall != "" && !f.failUsed && strings.Contains(call, f.FailCall) {
		f.failUsed = true
		return nil, errors.New("fault injected")
	}
	switch name {
	case "getent":
		if len(args) == 2 && f.Users[args[1]] {
			return []byte("existing-user"), nil
		}
		return nil, errors.New("user not found")
	case "useradd":
		if f.Users == nil {
			f.Users = map[string]bool{}
		}
		f.Users[args[len(args)-1]] = true
	case "systemctl":
		if f.FailUnit != "" && (strings.Contains(call, "enable --now "+f.FailUnit) || strings.Contains(call, "restart "+f.FailUnit)) {
			return nil, errors.New("fault injected")
		}
	case "chown":
		// Unit tests use a private filesystem root without changing system users.
	case "dpkg-query":
		// args are ["-W", "-f=${Status}", pkg].
		if len(args) == 3 && f.Packages[args[2]] {
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

// HubInstallerFixture is one isolated Hub install: a private root, the fake
// runner and the matching apply options and domains.
type HubInstallerFixture struct {
	Root    string
	Runner  *HubTestRunner
	Options ApplyOptions
	Config  Config
}

// NewHubInstallerFixture builds the fixture under root. binaryDir holds the
// synthetic executable and artifacts the installer copies into the root.
// Filesystem failures panic: only test code calls this, and a broken fixture
// has no recoverable error path.
func NewHubInstallerFixture(root, binaryDir string) HubInstallerFixture {
	source := filepath.Join(binaryDir, "meshmuxd")
	if err := os.WriteFile(source, []byte("isolated MeshMux test executable"), 0755); err != nil {
		panic(err)
	}
	assets := []Artifact{}
	for _, item := range []struct {
		component, version string
	}{
		{"caddy", "2.11.7"}, {"headscale", "0.29.5"},
	} {
		sourcePath := filepath.Join(binaryDir, item.component)
		data := []byte("verified test artifact " + item.component)
		if err := os.WriteFile(sourcePath, data, 0755); err != nil {
			panic(err)
		}
		sum := sha256.Sum256(data)
		assets = append(assets, Artifact{
			Component: item.component, Version: item.version,
			Source: "fixture://" + item.component, SHA256: hex.EncodeToString(sum[:]), Format: "elf",
		})
	}
	runner := &HubTestRunner{Users: map[string]bool{}}
	download := func(_ context.Context, a Artifact, _ string) (string, error) {
		return filepath.Join(binaryDir, a.Component), nil
	}
	return HubInstallerFixture{
		Root: root, Runner: runner,
		Config: Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org"},
		Options: ApplyOptions{
			Root: root, Runner: runner, Executable: source, Artifacts: assets,
			DownloadArtifact: download,
			Preflight: func(context.Context, Config, bool) ([]Check, []int) {
				return []Check{{Name: "system", Status: "pass"}, {Name: "public_https", Status: "pending"}}, []int{60794}
			},
			Verify: func(context.Context, Config, CommandRunner, func(context.Context, string) error) error {
				return nil
			},
		},
	}
}
