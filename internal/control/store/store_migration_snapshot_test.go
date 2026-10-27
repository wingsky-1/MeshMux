package store

// The pre-migration snapshot tests: the Hub database copy that makes a failed
// upgrade recoverable, and the SCHEMA_TOO_NEW guidance that must name a backup
// which really exists and really belongs to the binary asking.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
)

func openRawDatabase(t *testing.T, dir string) *sql.DB {
	t.Helper()
	path := filepath.Join(dir, databaseFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// The store's private-file rule is part of the fixture: SQLite would
	// otherwise create the file with the test process's umask.
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func setRawUserVersion(t *testing.T, dir string, version int) {
	t.Helper()
	db := openRawDatabase(t, dir)
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		t.Fatal(err)
	}
}

func rawUserVersion(t *testing.T, dir string) int {
	t.Helper()
	db := openRawDatabase(t, dir)
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func databaseBackupRoot(dir string) string {
	return filepath.Join(dir, DatabaseBackupDirName)
}

func generationCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(databaseBackupRoot(dir))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
}

// buildLegacyDatabase writes a real database at the last schema the sequential
// chain owns (15), with a confirmation row of the build that owned it. It is the
// state a previous release leaves behind before a newer binary migrates it.
func buildLegacyDatabase(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db := openRawDatabase(t, dir)
	legacy := &Store{DB: db}
	if err := legacy.migrateSchemaChain(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO database_versions(id, last_good_version, last_good_schema, confirmed_at)
	 VALUES(1,?,?,?)`, "1.0.0", 15, 1_700_000_000); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := rawUserVersion(t, dir); got != 15 {
		t.Fatalf("legacy fixture schema = %d, want 15", got)
	}
}

func TestFreshDatabaseCreatesNoSnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Lstat(databaseBackupRoot(dir)); !os.IsNotExist(err) {
		t.Fatalf("a fresh install created a backup store: %v", err)
	}
	if got := generationCount(t, dir); got != 0 {
		t.Fatalf("fresh database has %d backup generations", got)
	}
}

func TestMigrateSnapshotsTheDatabaseBeforeSchemaMove(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	buildLegacyDatabase(t, dir)

	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := rawUserVersion(t, dir); got != DatabaseSchemaVersion {
		t.Fatalf("user_version = %d, want %d", got, DatabaseSchemaVersion)
	}
	pointer, err := backup.ReadFlatPointer(databaseBackupRoot(dir), os.Geteuid())
	if err != nil {
		t.Fatalf("the migration produced no readable snapshot: %v", err)
	}
	record := pointer.Record
	if record.FromVersion != "1.0.0" || record.TargetVersion != buildinfo.Version {
		t.Fatalf("snapshot identity = %+v", record)
	}
	if record.DBSchema != 15 || !record.IntegrityOK || record.PayloadFiles != 1 {
		t.Fatalf("snapshot copy metadata = %+v", record)
	}
	// The copy is the pre-migration database, not the migrated one: a restore
	// with the previous binary starts from exactly the schema that binary owns.
	copyDB, err := sql.Open("sqlite", "file:"+pointer.PayloadPath+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	var copyVersion int
	if err := copyDB.QueryRow("PRAGMA user_version").Scan(&copyVersion); err != nil || copyVersion != 15 {
		copyDB.Close()
		t.Fatalf("snapshot copy user_version = %d, %v; want 15", copyVersion, err)
	}
	copyDB.Close()
	s.Close()

	// A restart at this build's schema only opens the database; it must not
	// accumulate another full copy on every boot.
	if _, err := OpenStore(dir); err != nil {
		t.Fatal(err)
	}
	if got := generationCount(t, dir); got != 1 {
		t.Fatalf("restart created another generation: %d", got)
	}
}

func TestRestoredSnapshotStartsTheWebAndMigratesAgain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	buildLegacyDatabase(t, dir)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := backup.ReadFlatPointer(databaseBackupRoot(dir), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// The failure rollback path: the migrated database is replaced by the
	// snapshot and the previous binary (here: this build, which only knows how
	// to migrate forward) can start again.
	restoreDatabaseCopy(t, dir, first.PayloadPath)
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("Web could not start from the restored snapshot: %v", err)
	}
	if got := rawUserVersion(t, dir); got != DatabaseSchemaVersion {
		t.Fatalf("restored database migrated to %d, want %d", got, DatabaseSchemaVersion)
	}
	if _, ok, err := reopened.LastGoodDatabaseVersion(); err != nil || !ok {
		t.Fatalf("restored database has no last-good row: ok=%v err=%v", ok, err)
	}
	reopened.Close()

	// The restored schema moved again, so a second generation is expected and
	// the flat pointer names it. No third generation appears on a plain restart.
	if got := generationCount(t, dir); got != 2 {
		t.Fatalf("generations after restore = %d, want 2", got)
	}
	if _, err := OpenStore(dir); err != nil {
		t.Fatal(err)
	}
	if got := generationCount(t, dir); got != 2 {
		t.Fatalf("restart after restore created another generation: %d", got)
	}
}

func restoreDatabaseCopy(t *testing.T, dir, copyPath string) {
	t.Helper()
	for _, name := range []string{databaseWALName, databaseSHMName} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, databaseFileName), body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaTooNewNamesTheMatchingSnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The newer release snapshots this database at this build's schema before
	// migrating it further.
	if err := s.snapshotBeforeMigration(); err != nil {
		t.Fatal(err)
	}
	pointer, err := backup.ReadFlatPointer(databaseBackupRoot(dir), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	setRawUserVersion(t, dir, DatabaseSchemaVersion+1)
	_, err = OpenStore(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "SCHEMA_TOO_NEW") {
		t.Fatalf("newer database accepted: %v", err)
	}
	message := err.Error()
	for _, want := range []string{
		pointer.RecordPath,
		pointer.PayloadPath,
		"from_version " + buildinfo.Version,
		fmt.Sprintf("db_schema %d", DatabaseSchemaVersion),
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal does not name %q: %s", want, message)
		}
	}
	if strings.Contains(message, "database_versions") {
		t.Fatalf("refusal points at a table instead of the record: %s", message)
	}

	// The named copy really restores this binary: the refusal is actionable.
	restoreDatabaseCopy(t, dir, pointer.PayloadPath)
	restored, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("Web could not start from the named copy: %v", err)
	}
	restored.Close()
}

func TestSchemaTooNewDoesNotClaimAForeignGeneration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// A snapshot taken from another release: restoring it would not return this
	// binary to its own last good state.
	if _, err := hubupgrade.CreateMigrationSnapshot(context.Background(), hubupgrade.MigrationSnapshotConfig{
		DataDir: dir, FromVersion: "0.9.0", TargetVersion: buildinfo.Version, PackageSHA256: digest,
		Vacuum: s.VacuumDatabaseCopy, Integrity: s.IntegrityCheckCopy,
		Schema: s.LiveDatabaseSchemaVersion, Space: hubupgrade.CheckFreeSpace,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	setRawUserVersion(t, dir, DatabaseSchemaVersion+1)

	_, err = OpenStore(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "SCHEMA_TOO_NEW") {
		t.Fatalf("newer database accepted: %v", err)
	}
	message := err.Error()
	if strings.Contains(message, "restore the verified database backup record") {
		t.Fatalf("foreign generation presented as the restore source: %s", message)
	}
	if !strings.Contains(message, "from_version 0.9.0") || !strings.Contains(message, "not this binary") {
		t.Fatalf("refusal does not explain the mismatch: %s", message)
	}
	if !strings.Contains(message, filepath.Join(databaseBackupRoot(dir), DatabaseBackupRecordName)) {
		t.Fatalf("refusal does not name the record path: %s", message)
	}
}
