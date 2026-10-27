package upgrade

// The development executor pin is read from the deployed dev drop, so every test
// in this package needs one: without it ForArch refuses an architecture this
// build cannot name verifiable bytes for, which is the intended production
// behaviour but not a useful test fixture.

import (
	"os"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/versions/devdropfixture"
)

func TestMain(m *testing.M) {
	cleanup := devdropfixture.New()
	code := m.Run()
	cleanup()
	os.Exit(code)
}
