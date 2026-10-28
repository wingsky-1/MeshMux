package dispatch

// The root-manifest fixture shared by the handoff tests. The manifest gate lives
// in the sibling backup package; this helper builds the same authenticated
// document shape so a handoff can be exercised end to end without root.

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
