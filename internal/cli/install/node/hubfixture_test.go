package node

// The co-location and journald tests in this package install a real Hub ledger
// first. The fixture lives in install/core, the leaf package both test binaries
// already import, because a _test.go declaration cannot cross package
// boundaries and the dupl gate rejects a second copy.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/install/hub"
)

type hubInstallerFixture = core.HubInstallerFixture

func makeHubInstallerFixture(t *testing.T) hubInstallerFixture {
	t.Helper()
	return core.NewHubInstallerFixture(t.TempDir(), t.TempDir())
}

func invokeHubInstaller(t *testing.T, fixture hubInstallerFixture, op string, repair bool) (core.InstallResult, error) {
	t.Helper()
	return hub.InstallHub(context.Background(), fixture.Config, op, repair, fixture.Options)
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
