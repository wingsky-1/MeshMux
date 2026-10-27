package handler

// The development executor pin is read from the deployed dev drop, so the whole
// package needs one: without it the Hub serves no executor manifest at all,
// which is the intended production behaviour for a build that published no
// artifact but not a useful HTTP fixture.

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
