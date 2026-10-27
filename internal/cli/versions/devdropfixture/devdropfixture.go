// Package devdropfixture gives a test package an isolated dev artifact drop.
//
// A development build derives the executor pin from versions.DevArtifactDir, so
// every package that projects install.PinnedMeshmuxd into a manifest needs a
// drop that names both supported architectures. The digests are opaque: the
// projection never fetches the artifact, and the fetch path re-hashes the real
// file. Tests only need the document to exist so the pin is not empty.
//
// The package has no production caller. It lives outside any _test.go file only
// because TestMain is per-package and the fixture must be shared without
// duplicating it in each package (the repository's dupl gate rejects that).
package devdropfixture

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// New creates a temporary drop, points versions.DevArtifactDir at it and
// returns a cleanup that restores the previous directory and removes the tree.
// It panics on a filesystem error: it is only called from TestMain, which has
// no *testing.T to report to.
func New() (cleanup func()) {
	previous := versions.DevArtifactDir
	dir, err := os.MkdirTemp("", "meshmux-dev-drop-")
	if err != nil {
		panic(err)
	}
	versions.DevArtifactDir = dir
	body := strings.Join([]string{
		strings.Repeat("1", 64) + "  " + versions.DevArtifactName(versions.ArchitectureAMD64),
		strings.Repeat("2", 64) + "  " + versions.DevArtifactName(versions.ArchitectureARM64),
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, versions.DevChecksumsName), []byte(body), 0644); err != nil {
		panic(err)
	}
	return func() {
		versions.DevArtifactDir = previous
		_ = os.RemoveAll(dir)
	}
}
