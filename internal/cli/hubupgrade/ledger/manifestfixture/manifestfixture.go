// Package manifestfixture gives the backup and dispatch test packages one
// root-preset manifest document.
//
// The gate itself lives in backup, but both test binaries need the same
// authenticated document shape, and a _test.go declaration cannot cross package
// boundaries. The package has no production caller; it lives outside a _test.go
// file only because the repository's dupl gate rejects a second copy. It stays
// below the ledger group so the production ledger does not gain an edge to the
// upgrade package (and through it the installer).
package manifestfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

// HubManifest builds the valid dev-target manifest those tests start from.
func HubManifest(target string) upgrade.Manifest {
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

// WriteHubManifest writes one manifest-<target>.json and returns its path.
// A marshal or write failure panics: only test code calls this, and a broken
// fixture has no recoverable error path there.
func WriteHubManifest(dir, target string, mutate func(*upgrade.Manifest)) string {
	m := HubManifest(target)
	if mutate != nil {
		mutate(&m)
	}
	body, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	path := filepath.Join(dir, "manifest-"+target+".json")
	if err := os.WriteFile(path, body, 0644); err != nil {
		panic(err)
	}
	return path
}
