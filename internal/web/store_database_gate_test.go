package web

// The Hub database gate of #11c-3 (spec §4.5, §4.10, §4.13, §6). Two version
// spaces meet here and must never be confused: `PRAGMA user_version` is the
// storage schema of this SQLite file, while `policy_schema` is the stored route
// policy contract named by an upgrade manifest. Only the storage schema moves
// with this migration; `policy_schema` stays 8 and is checked by the upgrade
// approval, not by the database gate.
//
// A database newer than this binary is never opened and never migrated down.
// The refusal names the verified Hub database backup record, because that is the
// only supported way back; the old binary may not be able to parse the record's
// schema, so it only checks that the fixed record file exists.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

func setUserVersion(t *testing.T, dir string, version int) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "meshmux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		t.Fatal(err)
	}
}

func userVersion(t *testing.T, dir string) int {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "meshmux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

// hubDatabaseRecord writes the fixed Hub database backup record the gate and the
// irreversible-confirmation action read. It is metadata only and 0600; the
// payload is one private database copy, because an approval must never confirm a
// record that holds nothing to restore.
func hubDatabaseRecord(t *testing.T, dataDir, operationID string, mutate func(*backup.Record)) (string, backup.Record) {
	t.Helper()
	root := filepath.Join(dataDir, databaseBackupDirName)
	payload := filepath.Join(root, databaseBackupPayloadDirName)
	if err := os.MkdirAll(payload, 0700); err != nil {
		t.Fatal(err)
	}
	// The payload bytes are a fixture copy, never opened by the approval path.
	if err := os.WriteFile(filepath.Join(payload, "meshmux.db"), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	record := backup.Record{
		Schema: backup.RecordSchema, OperationID: operationID,
		FromVersion: "1.0.0", TargetVersion: "1.0.1",
		DBSchema: databaseSchemaVersion - 1, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64),
		PayloadPath: payload, PayloadSHA256: strings.Repeat("c", 64),
		PayloadFiles: 1, IntegrityOK: true, State: backup.StateStaged,
		CreatedAt: time.Now().UTC(),
	}
	if mutate != nil {
		mutate(&record)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, databaseBackupRecordName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, record
}

func readStoredDatabaseRecord(t *testing.T, path string) backup.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record backup.Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("stored record is not JSON: %v", err)
	}
	return record
}

func TestSchemaTooNewNamesTheBackupRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	recordPath := filepath.Join(dir, databaseBackupDirName, databaseBackupRecordName)
	if err := os.MkdirAll(filepath.Dir(recordPath), 0700); err != nil {
		t.Fatal(err)
	}
	// Deliberately not a valid record: the old binary must not parse a schema it
	// cannot know, so existence is the whole check.
	if err := os.WriteFile(recordPath, []byte(`{"schema":99,"future":"unknown"}`), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(dir, "meshmux.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM database_versions`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.Close()
	setUserVersion(t, dir, databaseSchemaVersion+1)

	_, err = openStore(dir)
	if err == nil {
		t.Fatal("newer database accepted")
	}
	if !strings.HasPrefix(err.Error(), "SCHEMA_TOO_NEW") {
		t.Fatalf("wrong code: %v", err)
	}
	if !strings.Contains(err.Error(), recordPath) {
		t.Fatalf("refusal does not name the backup record %q: %v", recordPath, err)
	}
	if strings.Contains(err.Error(), "database_versions") {
		t.Fatalf("refusal points at the new table instead of the record: %v", err)
	}
	if !strings.Contains(err.Error(), "from_version") || !strings.Contains(err.Error(), "db_schema") {
		t.Fatalf("refusal does not explain what the record names: %v", err)
	}
	// The refusal is read-only: the future version is unchanged and the old
	// binary never writes a "last good" claim into a schema it does not own.
	if got := userVersion(t, dir); got != databaseSchemaVersion+1 {
		t.Fatalf("refusal rewrote user_version to %d", got)
	}
	raw, err = sql.Open("sqlite", filepath.Join(dir, "meshmux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var rows int
	if err := raw.QueryRow(`SELECT count(*) FROM database_versions`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("refused startup wrote a confirmation row: rows=%d err=%v", rows, err)
	}
}

func TestOldBinaryRefusesNewSchema(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	setUserVersion(t, dir, databaseSchemaVersion+1)

	_, err = openStore(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "SCHEMA_TOO_NEW") {
		t.Fatalf("newer database accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "no verified database backup record") {
		t.Fatalf("missing-record refusal is not explicit: %v", err)
	}

	// The same binary must name the record once one exists, without reading it.
	recordPath := filepath.Join(dir, databaseBackupDirName, databaseBackupRecordName)
	if err := os.MkdirAll(filepath.Dir(recordPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte("not even json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = openStore(dir)
	if err == nil || !strings.Contains(err.Error(), recordPath) {
		t.Fatalf("record not named for the downgraded binary: %v", err)
	}
}

func TestSchemaVersionConfirmedAfterStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != databaseSchemaVersion {
		t.Fatalf("user_version=%d err=%v want %d", version, err, databaseSchemaVersion)
	}
	var storedVersion string
	var storedSchema, confirmedAt int64
	if err := s.db.QueryRow(`SELECT last_good_version, last_good_schema, confirmed_at FROM database_versions WHERE id=1`).
		Scan(&storedVersion, &storedSchema, &confirmedAt); err != nil {
		t.Fatalf("last-good row missing: %v", err)
	}
	stored, ok, err := s.lastGoodDatabaseVersion()
	if err != nil || !ok {
		t.Fatalf("last-good readback: ok=%v err=%v", ok, err)
	}
	if storedVersion != node.CurrentAgentVersion || storedSchema != databaseSchemaVersion || confirmedAt <= 0 {
		t.Fatalf("last-good row = %q/%d/%d", storedVersion, storedSchema, confirmedAt)
	}
	if stored.Version != storedVersion || stored.Schema != int(storedSchema) || stored.ConfirmedAt.Unix() != confirmedAt {
		t.Fatalf("typed readback = %+v", stored)
	}
	var rows int
	if err := s.db.QueryRow(`SELECT count(*) FROM database_versions`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("database_versions rows=%d err=%v", rows, err)
	}

	// The migration transaction alone must not invent a confirmation: deleting
	// the row and replaying migrate() keeps it absent. Only the next startup
	// readback writes it again.
	if _, err := s.db.Exec(`DELETE FROM database_versions`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM database_versions`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("migration wrote a confirmation: rows=%d err=%v", rows, err)
	}
	s.Close()

	reopened, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.db.QueryRow(`SELECT last_good_version, last_good_schema, confirmed_at FROM database_versions WHERE id=1`).
		Scan(&storedVersion, &storedSchema, &confirmedAt); err != nil || storedSchema != databaseSchemaVersion {
		t.Fatalf("restart did not confirm the schema: %q/%d/%d err=%v", storedVersion, storedSchema, confirmedAt, err)
	}
	if err := reopened.db.QueryRow(`SELECT count(*) FROM database_versions`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("database_versions rows after restart=%d err=%v", rows, err)
	}
}
