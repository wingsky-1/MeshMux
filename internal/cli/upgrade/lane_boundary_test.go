package upgrade

// This file guards the cli/core/control/web split of the upgrade lane from the
// inside: the one-shot CLI entry packages must stay free of business-table
// access, and the shared leaves must stay leaves. cmd/meshmux's DAG test covers
// the module graph; this one covers the "cli does not read a business table"
// rule that the DAG alone cannot express.
//
// The assertion is the compiler's own import list (go list), not a source scan,
// so an aliased or dot import cannot slip past it.

import (
	"os/exec"
	"strings"
	"testing"
)

// lanePackages is the upgrade lane in dependency order: shared leaves first,
// then the core executors, then the control-plane producer and the launcher.
var lanePackages = []string{
	"github.com/wingsky-1/MeshMux/internal/cli/versions",
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo",
	"github.com/wingsky-1/MeshMux/internal/cli/backup",
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade",
	"github.com/wingsky-1/MeshMux/internal/cli/install",
	"github.com/wingsky-1/MeshMux/internal/cli/update",
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade",
	"github.com/wingsky-1/MeshMux/internal/cli/webcmd",
}

// cliOneShotPackages may not open a database: they parse one fixed command,
// start or stop one unit and return. Storage belongs to the web/control layer.
var cliOneShotPackages = map[string]bool{
	"github.com/wingsky-1/MeshMux/internal/cli/install":    true,
	"github.com/wingsky-1/MeshMux/internal/cli/update":     true,
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade": true,
	"github.com/wingsky-1/MeshMux/internal/cli/webcmd":     true,
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade":    true,
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo":  true,
	"github.com/wingsky-1/MeshMux/internal/cli/versions":   true,
	"github.com/wingsky-1/MeshMux/internal/cli/backup":     true,
}

// leafPackages must never grow an internal edge.
var leafPackages = map[string]bool{
	"github.com/wingsky-1/MeshMux/internal/cli/versions":  true,
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo": true,
	"github.com/wingsky-1/MeshMux/internal/cli/backup":    true,
}

func TestLaneImportsStayInLayer(t *testing.T) {
	imports := laneImportGraph(t)

	t.Run("cli one-shot packages do not read a business table", func(t *testing.T) {
		for path, list := range imports {
			if !cliOneShotPackages[path] {
				continue
			}
			for _, imported := range list {
				if imported == "database/sql" {
					t.Errorf("%s imports database/sql; the CLI lane performs one-shot actions and must not read a business table", path)
				}
				if strings.HasPrefix(imported, "github.com/wingsky-1/MeshMux/internal/control/store") ||
					strings.HasPrefix(imported, "github.com/wingsky-1/MeshMux/internal/web/handler") {
					t.Errorf("%s imports %s; business storage is the web layer's", path, imported)
				}
			}
		}
	})

	t.Run("shared leaves stay leaves", func(t *testing.T) {
		for path, list := range imports {
			if !leafPackages[path] {
				continue
			}
			for _, imported := range list {
				if strings.HasPrefix(imported, "github.com/wingsky-1/MeshMux/internal/") {
					t.Errorf("%s must stay a leaf but imports %s", path, imported)
				}
			}
		}
	})

	t.Run("control and launcher never reach the privileged installer entry", func(t *testing.T) {
		// internal/cli/upgrade is deliberately absent: it reads the pinned artifact
		// tables as data (docs/ARCHITECTURE) so the release manifest does not
		// keep a second copy. That edge is data-only and is legal per the module
		// DAG guard; the producer and the launcher must not have it at all.
		for _, path := range []string{
			"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade",
			"github.com/wingsky-1/MeshMux/internal/cli/webcmd",
		} {
			for _, imported := range imports[path] {
				if imported == "github.com/wingsky-1/MeshMux/internal/cli/install" {
					t.Errorf("%s imports the privileged installer; only its own rootexec subpackage may", path)
				}
			}
		}
	})

	t.Run("every lane package is listed", func(t *testing.T) {
		for _, path := range lanePackages {
			if _, ok := imports[path]; !ok {
				t.Fatalf("%s did not appear in the import graph; update lanePackages/laneImportGraph in the same commit", path)
			}
		}
	})
}

// laneImportGraph asks the toolchain for the production import list of every
// lane package. Test-only imports are excluded: a _test.go edge is not part of
// the shipped binary.
func laneImportGraph(t *testing.T) map[string][]string {
	t.Helper()
	args := append([]string{"list", "-f", "{{.ImportPath}}|{{join .Imports \" \"}}"}, lanePackages...)
	output, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatalf("go list lane packages: %v", err)
	}
	graph := make(map[string][]string, len(lanePackages))
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		path, list, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("unexpected go list line %q", line)
		}
		graph[path] = strings.Fields(list)
	}
	return graph
}
