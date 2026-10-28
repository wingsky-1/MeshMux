package backup

// Explicit cleanup of Hub backup generations (#11d Task 3r, spec §5.2.1/C18).
//
// backup.GC already refuses to collect anything that is not confirmed and keeps
// the newest `keep` confirmed generations. The Hub adds one call-site rule: keep
// must be at least 2. With keep=1 the collector would delete the newest
// confirmed generation, which is exactly the generation the flat pointer names
// after a refresh — a diagnostic pointer must never outlive its target by policy
// (the only tolerated case is a stale pointer after a failed refresh, which
// self-heals on the next publish).
//
// The floor is deliberately a call-site rule, not a package default:
// internal/backup.GC stays parameterized because the Node store has no flat
// pointer and keeps KeepConfirmed=1.
//
// CleanupConfirmed has no pointer parameter and never reads one: a pointer
// refresh failure can only ever add a pointer log line
// (HUB_BACKUP_POINTER_STALE / HUB_BACKUP_POINTER_UNFLUSHED), and the collector
// still runs (spec §5.2.1: refresh and GC are decoupled, and the pointer target is
// safe because a fresh staged record is never a candidate and the newest two
// confirmed generations are retained).

import (
	"os"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

// minHubKeep is the Hub's GC floor (spec §5.2.1).
const minHubKeep = 2

// MinHubKeep exposes the Hub's call-site GC floor to the dispatch confirmation.
const MinHubKeep = minHubKeep

// collectGenerations is the collector seam of CleanupConfirmed. Production is
// backup.GC; a test replaces it to prove that the producer never collects
// anything (B8) without reading this package's source.
var collectGenerations = backup.GC

// CleanupConfirmed collects confirmed generations beyond keep. keep < 2 is a
// parameter error and removes nothing; otherwise it is exactly backup.GC on the
// per-operation store.
func CleanupConfirmed(dataDir string, keep int) ([]string, error) {
	if keep < minHubKeep {
		return nil, fail("HUB_BACKUP_GC_REFUSED", "the Hub backup keep count must be at least 2")
	}
	root, err := dataPath(dataDir, DatabaseBackupDir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil, nil
	}
	return collectGenerations(root, keep)
}
