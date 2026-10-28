package node

import (
	"context"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/install/hub"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestInstallNodeNonInteractiveRefusesPrompts is the handoff contract on the
// install side: a Web-driven run never waits for an operator. A fresh install
// would have to prompt for a pairing code, so it is refused before any file is
// staged with the update's own stable code.
func TestInstallNodeNonInteractiveRefusesPrompts(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	f.opts.NonInteractive = true
	runner := f.runner
	result, err := InstallNode(context.Background(), f.cfg, strings.Repeat("e", 32), false, "", f.opts)
	ie, ok := err.(*core.InstallError)
	if !ok || ie.Code != "UPDATE_INTERACTIVE_REFUSED" {
		t.Fatalf("err = %v, want UPDATE_INTERACTIVE_REFUSED", err)
	}
	if result.Status != "failed" || result.Stage != "preflight" {
		t.Fatalf("result = %+v", result)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused run touched the host: %v", runner.calls)
	}
}

// TestInstallHubNonInteractiveRefusesPrompts is the same rule for the Hub: a
// handoff must carry --repair, because anything else is an operator decision.
func TestInstallHubNonInteractiveRefusesPrompts(t *testing.T) {
	f := makeHubInstallerFixture(t)
	f.opts.NonInteractive = true
	result, err := hub.InstallHub(context.Background(), f.c, strings.Repeat("a", 32), false, f.opts)
	ie, ok := err.(*core.InstallError)
	if !ok || ie.Code != "UPDATE_INTERACTIVE_REFUSED" {
		t.Fatalf("err = %v, want UPDATE_INTERACTIVE_REFUSED", err)
	}
	if result.Status != "failed" || result.Stage != "preflight" {
		t.Fatalf("result = %+v", result)
	}
}
