package backup

// Explicit-cleanup tests of #11d Task 3r (spec §5.2.1/C18): the Hub's keep floor
// is a call-site rule, so keep<2 is refused instead of collecting the generation
// the flat pointer names.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

// TestHubCleanupRejectsKeepBelowTwo pins the call-site floor: keep 1, 0 and -1
// are parameter errors that remove nothing, while keep=2 collects normally.
func TestHubCleanupRejectsKeepBelowTwo(t *testing.T) {
	f := newHubBackupFixture(t)
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ops := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)}
	for i, op := range ops {
		recordPath, _ := seedBackup(t, f.dataDir, op, false)
		record, err := backup.Read(f.root(), op, os.Geteuid())
		if err != nil {
			t.Fatal(err)
		}
		record.CreatedAt = base.Add(time.Duration(i) * time.Hour)
		if err := backup.WriteRecord(filepath.Dir(recordPath), record); err != nil {
			t.Fatal(err)
		}
		if _, err := ConfirmBackup(f.dataDir, op, record.TargetVersion, record.PackageSHA256, record.CreatedAt); err != nil {
			t.Fatal(err)
		}
	}
	for _, keep := range []int{1, 0, -1} {
		if removed, err := CleanupConfirmed(f.dataDir, keep); err == nil || len(removed) != 0 {
			t.Fatalf("keep=%d = %q, %v; want a parameter error and no removal", keep, removed, err)
		}
	}
	for _, op := range ops {
		if _, err := os.Lstat(filepath.Join(f.root(), op)); err != nil {
			t.Fatalf("keep<2 collected %s: %v", op, err)
		}
	}
	removed, err := CleanupConfirmed(f.dataDir, 2)
	if err != nil {
		t.Fatalf("keep=2: %v", err)
	}
	if len(removed) != 1 || removed[0] != ops[0] {
		t.Fatalf("keep=2 removed %q, want the oldest confirmed generation %q", removed, ops[0])
	}
	if _, err := os.Lstat(filepath.Join(f.root(), ops[0])); !os.IsNotExist(err) {
		t.Fatalf("the oldest confirmed generation survived: %v", err)
	}
	// A store root that does not exist yet is not an error: nothing to collect.
	empty := t.TempDir()
	if removed, err := CleanupConfirmed(empty, 2); err != nil || len(removed) != 0 {
		t.Fatalf("cleanup on an absent store = %q, %v", removed, err)
	}
}
