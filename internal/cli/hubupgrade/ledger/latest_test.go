package ledger

// "Current record" resolution tests of #11d Task 3r (spec §5.2): the latest
// backup is journal-backed, never inferred from the directory listing or mtime.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

// plantBackup writes one readable per-operation generation and its journal op
// with the given generation, so the selection order can be controlled exactly.
func plantBackup(t *testing.T, dataDir, operationID string, generation int64, updated time.Time) {
	t.Helper()
	root := filepath.Join(dataDir, DatabaseBackupDir)
	opDir, err := backup.Dir(root, operationID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := backup.Spec{
		OperationID: operationID, FromVersion: "1.0.0", TargetVersion: "1.0.1",
		DBSchema: 10, PolicySchema: 8,
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: strings.Repeat("c", 64),
	}
	if _, err := backup.Write(root, spec, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	op := Op{
		Schema: OpSchema, OperationID: operationID, Kind: KindUpdate, State: StateBackedUp,
		TargetVersion: "1.0.1", FromVersion: "1.0.0",
		ManifestSHA256: spec.ManifestSHA256, PackageSHA256: spec.PackageSHA256,
		DBSchema: 10, BackupGeneration: generation, UpdatedAt: updated,
	}
	if err := WriteOp(dataDir, op); err != nil {
		t.Fatal(err)
	}
}

// TestLatestIsJournalBacked pins the selection rule: the highest readable
// generation wins, an unreadable generation falls through to the next one, and an
// operation directory the journal does not name is never chosen however new it
// looks.
func TestLatestIsJournalBacked(t *testing.T) {
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	t.Run("highest generation", func(t *testing.T) {
		dataDir := t.TempDir()
		low, high := strings.Repeat("1", 32), strings.Repeat("2", 32)
		plantBackup(t, dataDir, low, 1, base)
		plantBackup(t, dataDir, high, 2, base.Add(time.Minute))
		op, record, ok, err := LatestBackup(dataDir, os.Geteuid())
		if err != nil || !ok {
			t.Fatalf("LatestBackup: ok=%v err=%v", ok, err)
		}
		if op.OperationID != high || record.OperationID != high {
			t.Fatalf("latest = %q/%q want %q", op.OperationID, record.OperationID, high)
		}
	})

	t.Run("unreadable generation falls through", func(t *testing.T) {
		dataDir := t.TempDir()
		readable, broken := strings.Repeat("3", 32), strings.Repeat("4", 32)
		plantBackup(t, dataDir, readable, 1, base)
		plantBackup(t, dataDir, broken, 2, base.Add(time.Minute))
		// A record that cannot be read (damaged mode) is not "the current
		// record"; the next generation is.
		brokenRecord := filepath.Join(dataDir, DatabaseBackupDir, broken, backup.RecordName)
		if err := os.Chmod(brokenRecord, 0644); err != nil {
			t.Fatal(err)
		}
		op, _, ok, err := LatestBackup(dataDir, os.Geteuid())
		if err != nil || !ok {
			t.Fatalf("LatestBackup: ok=%v err=%v", ok, err)
		}
		if op.OperationID != readable {
			t.Fatalf("latest = %q want the readable generation %q", op.OperationID, readable)
		}
	})

	t.Run("unrecorded directory is ignored", func(t *testing.T) {
		dataDir := t.TempDir()
		journaled, planted := strings.Repeat("5", 32), strings.Repeat("6", 32)
		plantBackup(t, dataDir, journaled, 1, base)
		root := filepath.Join(dataDir, DatabaseBackupDir)
		opDir, err := backup.Dir(root, planted)
		if err != nil {
			t.Fatal(err)
		}
		part := filepath.Join(opDir, backup.PayloadPart)
		if err := os.Mkdir(part, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("planted"), 0600); err != nil {
			t.Fatal(err)
		}
		spec := backup.Spec{
			OperationID: planted, FromVersion: "1.0.0", TargetVersion: "1.0.1",
			DBSchema: 10, PolicySchema: 8,
			ManifestSHA256: strings.Repeat("d", 64), PackageSHA256: strings.Repeat("e", 64),
		}
		if _, err := backup.Write(root, spec, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }}); err != nil {
			t.Fatal(err)
		}
		op, _, ok, err := LatestBackup(dataDir, os.Geteuid())
		if err != nil || !ok {
			t.Fatalf("LatestBackup: ok=%v err=%v", ok, err)
		}
		if op.OperationID != journaled {
			t.Fatalf("latest = %q; a directory the journal does not name was chosen", op.OperationID)
		}
	})

	t.Run("no journal", func(t *testing.T) {
		dataDir := t.TempDir()
		if _, _, ok, err := LatestBackup(dataDir, os.Geteuid()); err != nil || ok {
			t.Fatalf("empty journal: ok=%v err=%v", ok, err)
		}
	})

	t.Run("unreadable journal fails closed", func(t *testing.T) {
		dataDir := t.TempDir()
		plantBackup(t, dataDir, strings.Repeat("7", 32), 1, base)
		opsDir := filepath.Join(dataDir, OpsDir)
		if err := os.Chmod(opsDir, 0755); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := LatestBackup(dataDir, os.Geteuid()); err == nil || codeOf(err) != "HUB_BACKUP_JOURNAL_FAILED" {
			t.Fatalf("unreadable journal = %v, want HUB_BACKUP_JOURNAL_FAILED", err)
		}
	})
}

// TestLatestBackupSkipsRestoreOps pins the kind filter: a restore journal entry
// never becomes the "current backup" even at a higher generation.
func TestLatestBackupSkipsRestoreOps(t *testing.T) {
	dataDir := t.TempDir()
	backupOp := strings.Repeat("8", 32)
	plantBackup(t, dataDir, backupOp, 1, time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	restore := Op{
		Schema: OpSchema, OperationID: strings.Repeat("9", 32), Kind: KindRestore, State: StateConfirmed,
		TargetVersion: "1.0.0", FromVersion: "1.0.1",
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64),
		DBSchema: 10, BackupGeneration: 2, UpdatedAt: time.Date(2026, 10, 26, 13, 0, 0, 0, time.UTC),
	}
	if err := WriteOp(dataDir, restore); err != nil {
		t.Fatal(err)
	}
	op, _, ok, err := LatestBackup(dataDir, os.Geteuid())
	if err != nil || !ok || op.OperationID != backupOp {
		t.Fatalf("latest = %+v ok=%v err=%v want %q", op, ok, err, backupOp)
	}
}
