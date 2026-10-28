package backup

// Producer tests of the pre-migration snapshot: the one copy of the Hub database
// taken before a schema migration, so a downgraded binary's SCHEMA_TOO_NEW
// guidance names a record that really exists.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

type migrationSnapshotFixture struct {
	dataDir string
	vacuum  func(dst string) error
	check   func(path string) error
	space   func(path string, need uint64) error
	schema  int64
	publish func(root, operationID string) error
}

func newMigrationSnapshotFixture(t *testing.T) *migrationSnapshotFixture {
	t.Helper()
	f := &migrationSnapshotFixture{
		dataDir: filepath.Join(t.TempDir(), "data"),
		schema:  16,
		vacuum: func(dst string) error {
			return os.WriteFile(dst, []byte("fixture database copy"), 0600)
		},
		check: func(path string) error { return nil },
		space: func(string, uint64) error { return nil },
	}
	if err := os.Mkdir(f.dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *migrationSnapshotFixture) config() MigrationSnapshotConfig {
	return MigrationSnapshotConfig{
		DataDir:       f.dataDir,
		FromVersion:   "1.0.0",
		TargetVersion: "1.1.0",
		PackageSHA256: strings.Repeat("d", 64),
		Vacuum: func(_ context.Context, dst string) error {
			return f.vacuum(dst)
		},
		Integrity: func(_ context.Context, path string) error {
			return f.check(path)
		},
		Schema: func(context.Context) (int64, error) {
			return f.schema, nil
		},
		Space:          f.space,
		PublishPointer: f.publish,
	}
}

func (f *migrationSnapshotFixture) root() string {
	return filepath.Join(f.dataDir, DatabaseBackupDir)
}

func TestMigrationSnapshotPublishesRecordPayloadAndPointer(t *testing.T) {
	f := newMigrationSnapshotFixture(t)
	receipt, err := CreateMigrationSnapshot(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "staged" || receipt.FromVersion != "1.0.0" || receipt.DBSchema != 16 || !receipt.IntegrityOK {
		t.Fatalf("receipt = %+v", receipt)
	}
	pointer, err := backup.ReadFlatPointer(f.root(), os.Geteuid())
	if err != nil {
		t.Fatalf("flat pointer does not resolve: %v", err)
	}
	if pointer.RecordPath != filepath.Join(f.root(), PointerName) {
		t.Fatalf("record path = %s", pointer.RecordPath)
	}
	record := pointer.Record
	if record.OperationID != receipt.OperationID || record.FromVersion != "1.0.0" || record.TargetVersion != "1.1.0" {
		t.Fatalf("record identity = %+v", record)
	}
	if record.DBSchema != 16 || record.PolicySchema != upgrade.PolicySchema || record.State != backup.StateStaged {
		t.Fatalf("record versions = %+v", record)
	}
	// There is no root manifest on this path; both digest fields name the one
	// authenticated artifact in play, the running package.
	if record.ManifestSHA256 != strings.Repeat("d", 64) || record.PackageSHA256 != strings.Repeat("d", 64) {
		t.Fatalf("record digests = %+v", record)
	}
	copyBytes, err := os.ReadFile(pointer.PayloadPath)
	if err != nil || string(copyBytes) != "fixture database copy" {
		t.Fatalf("payload = %q, %v", copyBytes, err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(record.PayloadPath), backup.PayloadPart)); !os.IsNotExist(err) {
		t.Fatalf("scratch payload survived the commit: %v", err)
	}
}

func TestMigrationSnapshotIsOneGenerationPerCall(t *testing.T) {
	f := newMigrationSnapshotFixture(t)
	first, err := CreateMigrationSnapshot(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateMigrationSnapshot(context.Background(), f.config())
	if err != nil {
		t.Fatal(err)
	}
	if first.OperationID == second.OperationID {
		t.Fatal("two snapshots reused one operation id")
	}
	entries, err := os.ReadDir(f.root())
	if err != nil {
		t.Fatal(err)
	}
	generations := 0
	for _, entry := range entries {
		if entry.IsDir() {
			generations++
		}
	}
	if generations != 2 {
		t.Fatalf("generations = %d, want 2", generations)
	}
	// The flat pointer names the newest generation, which is what a downgraded
	// binary and the installer read.
	pointer, err := backup.ReadFlatPointer(f.root(), os.Geteuid())
	if err != nil || pointer.Record.OperationID != second.OperationID {
		t.Fatalf("pointer did not move to the newest generation: %+v, %v", pointer, err)
	}
}

func TestMigrationSnapshotFailureLeavesNoGeneration(t *testing.T) {
	cases := []struct {
		name string
		code string
		edit func(*migrationSnapshotFixture)
	}{
		{
			name: "vacuum",
			code: "HUB_BACKUP_VACUUM_FAILED",
			edit: func(f *migrationSnapshotFixture) {
				f.vacuum = func(string) error { return errors.New("disk full") }
			},
		},
		{
			name: "integrity",
			code: "HUB_BACKUP_INTEGRITY_FAILED",
			edit: func(f *migrationSnapshotFixture) {
				f.check = func(string) error { return errors.New("integrity_check failed") }
			},
		},
		{
			name: "space",
			code: "HUB_SPACE_INSUFFICIENT",
			edit: func(f *migrationSnapshotFixture) {
				f.space = func(string, uint64) error { return fail("HUB_SPACE_INSUFFICIENT", "fixture") }
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMigrationSnapshotFixture(t)
			tc.edit(f)
			_, err := CreateMigrationSnapshot(context.Background(), f.config())
			if err == nil || codeOf(err) != tc.code {
				t.Fatalf("error = %v, want code %s", err, tc.code)
			}
			if entries, readErr := os.ReadDir(f.root()); readErr == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						t.Fatalf("failed snapshot left a generation %s", entry.Name())
					}
				}
			}
		})
	}
}

func TestMigrationSnapshotPointerFailureIsFatal(t *testing.T) {
	f := newMigrationSnapshotFixture(t)
	f.publish = func(string, string) error { return errors.New("root not writable") }
	_, err := CreateMigrationSnapshot(context.Background(), f.config())
	if err == nil || codeOf(err) != CodeMigrationBackupPointer {
		t.Fatalf("error = %v, want %s", err, CodeMigrationBackupPointer)
	}
	if _, statErr := os.Lstat(filepath.Join(f.root(), PointerName)); !os.IsNotExist(statErr) {
		t.Fatalf("failed pointer publish left a flat pointer: %v", statErr)
	}
	// The committed per-operation record stays: it is a valid rollback source
	// even when the flat pointer could not be published.
	entries, readErr := os.ReadDir(f.root())
	if readErr != nil {
		t.Fatal(readErr)
	}
	found := false
	for _, entry := range entries {
		if entry.IsDir() {
			if _, statErr := os.Lstat(filepath.Join(f.root(), entry.Name(), backup.RecordName)); statErr == nil {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("committed generation disappeared after a pointer failure")
	}
}

func TestMigrationSnapshotRejectsUnsafeIdentity(t *testing.T) {
	cases := []struct {
		name string
		edit func(*MigrationSnapshotConfig)
	}{
		{"relative data dir", func(c *MigrationSnapshotConfig) { c.DataDir = "data" }},
		{"empty from version", func(c *MigrationSnapshotConfig) { c.FromVersion = "" }},
		{"from version with slash", func(c *MigrationSnapshotConfig) { c.FromVersion = "1.0.0/../x" }},
		{"target not a release", func(c *MigrationSnapshotConfig) { c.TargetVersion = "main" }},
		{"digest missing", func(c *MigrationSnapshotConfig) { c.PackageSHA256 = "" }},
		{"no vacuum", func(c *MigrationSnapshotConfig) { c.Vacuum = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMigrationSnapshotFixture(t)
			cfg := f.config()
			tc.edit(&cfg)
			if _, err := CreateMigrationSnapshot(context.Background(), cfg); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
			if _, err := os.Lstat(f.root()); !os.IsNotExist(err) {
				t.Fatalf("refused snapshot created the store: %v", err)
			}
		})
	}
}
