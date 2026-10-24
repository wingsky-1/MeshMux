package web

// The Hub database gate of #11c-3 (spec §4.5, §4.13, §4.15, §6).
//
// Two version numbers are deliberately kept apart:
//
//   - `PRAGMA user_version` is the storage schema of this SQLite file. This
//     binary owns version 10 and refuses any newer file without opening it for
//     writes; a database is never downgraded in place.
//   - `policy_schema` is the stored route policy contract named by an upgrade
//     manifest (currently 8). It is checked by the upgrade approval and the
//     compat gate, never by this migration ceiling. A manifest with a newer
//     policy schema is refused, but it does not make the database "too new",
//     and a newer database is not a policy contract change.
//
// `database_versions` is the single last-known-good row. It is written only
// after the store opened, the migration transaction committed and the schema was
// read back at the expected version; it is never written inside a migration that
// could still roll back. The Hub has no Agent `config.readback` channel, so this
// post-migration readback is the Hub-side equivalent; 11d's Hub health readback
// consumes the row.
//
// A database newer than this binary names the verified Hub database backup
// record, never a table of the newer schema. The downgraded binary may not be
// able to parse that record's schema, so its check is existence-only. The same
// fixed record carries the Web irreversible-migration confirmation bit
// (`irreversible_approved`) required before 11d applies a destructive step; the
// bit lives on the record and no approval table is added.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/update"
)

var errDatabasePayloadUnsafe = errors.New("the Hub database backup payload is not a private file tree")

const (
	// databaseSchemaVersion is the storage schema this binary owns. 11c-3 adds
	// exactly version 10; a newer file is refused instead of opened.
	databaseSchemaVersion = 10

	// The Hub database backup is independent of the node rollback store
	// (spec §4.1 "Hub DB 记录独立"). One last verified backup is kept next to
	// the database, in the same private 0700 data directory, so a restore never
	// needs a path outside the deployment boundary.
	databaseBackupDirName        = "database-backup"
	databaseBackupPayloadDirName = "payload"
	databaseBackupRecordName     = "record.json"
	databaseBackupRecordPart     = "record.json.part"

	// databaseBackupRecordMaxBytes bounds the metadata file a reader parses.
	databaseBackupRecordMaxBytes = 64 << 10
)

// databaseBackupOperationPattern is the fixed operation id shape of one Hub
// upgrade. A form value never reaches a path or query before this check.
var databaseBackupOperationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// databaseVersion is the last-known-good pair of the Hub database.
type databaseVersion struct {
	Version     string
	Schema      int
	ConfirmedAt time.Time
}

// migrateSchema10 adds the single last-known-good row. It is purely additive:
// no existing table, row or index changes, so a rollback only needs to drop the
// table and set user_version back. IF NOT EXISTS keeps the migration replayable
// for fixtures that start from an older version while the table is already
// present; a replay must not fail on its own earlier write.
func migrateSchema10(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS database_versions (
  id INTEGER PRIMARY KEY CHECK(id=1),
  last_good_version TEXT NOT NULL DEFAULT '',
  last_good_schema INTEGER NOT NULL,
  confirmed_at INTEGER NOT NULL
);
PRAGMA user_version=10;
`); err != nil {
		return err
	}
	return nil
}

// confirmDatabaseVersion is the startup readback. It runs after migrate() has
// committed and after the database files passed the private-mode readback, so a
// row may only exist for a database this binary actually opened and can read at
// the version it owns. A failed readback writes nothing and fails startup rather
// than leaving a stale "last good" claim behind.
func (s *store) confirmDatabaseVersion(now time.Time) error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return errors.New("SCHEMA_READBACK_FAILED: the database schema could not be read back")
	}
	if version != databaseSchemaVersion {
		return fmt.Errorf("SCHEMA_READBACK_FAILED: the database reports user_version %d after migrating to %d", version, databaseSchemaVersion)
	}
	if _, err := s.db.Exec(`INSERT INTO database_versions(id, last_good_version, last_good_schema, confirmed_at)
 VALUES(1,?,?,?)
 ON CONFLICT(id) DO UPDATE SET
  last_good_version=excluded.last_good_version,
  last_good_schema=excluded.last_good_schema,
  confirmed_at=excluded.confirmed_at`,
		node.CurrentAgentVersion, version, now.UTC().Unix()); err != nil {
		return errors.New("SCHEMA_CONFIRM_FAILED: the last-good database version could not be recorded")
	}
	return nil
}

// lastGoodDatabaseVersion reads the confirmed row. An absent row is honest: the
// database was never confirmed by a started binary, which is not the same as a
// row naming an empty release.
func (s *store) lastGoodDatabaseVersion() (databaseVersion, bool, error) {
	var out databaseVersion
	var confirmed int64
	err := s.db.QueryRow(`SELECT last_good_version, last_good_schema, confirmed_at FROM database_versions WHERE id=1`).
		Scan(&out.Version, &out.Schema, &confirmed)
	if errors.Is(err, sql.ErrNoRows) {
		return databaseVersion{}, false, nil
	}
	if err != nil {
		return databaseVersion{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	out.ConfirmedAt = time.Unix(confirmed, 0).UTC()
	return out, true, nil
}

// schemaTooNew builds the refusal for a database written by a newer binary. The
// record check is existence-only: this binary cannot know the newer record's
// fields, and parsing them would be exactly the silent interpretation the gate
// exists to prevent.
func (s *store) schemaTooNew(version int) error {
	recordPath := filepath.Join(s.dir, databaseBackupDirName, databaseBackupRecordName)
	if info, err := os.Lstat(recordPath); err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
		return fmt.Errorf("SCHEMA_TOO_NEW: database user_version %d is newer than this binary (%d); restore the verified database backup record %s (from_version and db_schema name the last good state); do not downgrade in place",
			version, databaseSchemaVersion, recordPath)
	}
	return fmt.Errorf("SCHEMA_TOO_NEW: database user_version %d is newer than this binary (%d); no verified database backup record exists at %s; restore a matching binary and database, do not downgrade in place",
		version, databaseSchemaVersion, recordPath)
}

// readDatabaseBackupRecord reads the fixed Hub database backup record under the
// same private-file rules as the node rollback records. Unknown fields are
// refused: a future record schema must not be silently truncated into today's
// approval semantics.
func readDatabaseBackupRecord(path, operationID string) (update.BackupRecord, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_MISSING: no verified Hub database backup record exists")
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) || info.Size() > databaseBackupRecordMaxBytes {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record is not a private 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record is not readable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record update.BackupRecord
	if err := decoder.Decode(&record); err != nil {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record carries trailing data")
	}
	if record.Schema != update.BackupRecordSchema || record.OperationID != operationID {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record does not belong to this operation")
	}
	if record.DBSchema <= 0 {
		return update.BackupRecord{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record names no source database schema")
	}
	return record, nil
}

// verifyDatabaseBackupPayload closes the vacuous-gate class Task 2 fixed: a
// record that is staged and claims integrity but holds nothing must never be
// accepted as an irreversible-migration rollback source. The Hub copy is a large
// database file, so this check is metadata-only (presence, private modes and the
// recorded file count), not a re-hash on every operator click; 11d's restore step
// still runs PRAGMA integrity_check on the copy it opens.
func verifyDatabaseBackupPayload(record update.BackupRecord, root string) error {
	if record.PayloadFiles <= 0 {
		return errors.New("DB_BACKUP_RECORD_UNVERIFIED: the Hub database backup holds no payload files")
	}
	payload := filepath.Join(root, databaseBackupPayloadDirName)
	if filepath.Clean(record.PayloadPath) != payload {
		return errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record names another payload path")
	}
	info, err := os.Lstat(payload)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
		return errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup payload is not a private 0700 directory")
	}
	files := 0
	err = filepath.WalkDir(payload, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errDatabasePayloadUnsafe
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
				return errDatabasePayloadUnsafe
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) {
			return errDatabasePayloadUnsafe
		}
		files++
		return nil
	})
	if err != nil || files == 0 || files != record.PayloadFiles {
		return errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup payload does not match its record")
	}
	return nil
}

// databaseMigrationApproval is the accepted confirmation plus its stored record.
type databaseMigrationApproval struct {
	Record          update.BackupRecord
	RecordPath      string
	AlreadyApproved bool
}

// approveIrreversibleMigration stores the explicit Web confirmation bit on the
// Hub database backup record. It refuses without the bit, without a verified
// record, and for a record that is no longer staged; it never starts the
// migration itself (that is 11d). The write is staged and renamed so a reader
// sees either the old or the new record, never half of one.
func (s *store) approveIrreversibleMigration(operationID string, confirmed bool) (databaseMigrationApproval, error) {
	if !confirmed {
		return databaseMigrationApproval{}, errors.New("IRREVERSIBLE_CONFIRM_REQUIRED: an irreversible database migration requires the explicit Web confirmation")
	}
	if !databaseBackupOperationPattern.MatchString(operationID) {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_OPERATION_INVALID: the backup operation id is not 32 lowercase hex")
	}
	root := filepath.Join(s.dir, databaseBackupDirName)
	if err := privatePath(root, true); err != nil {
		if os.IsNotExist(err) {
			return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_MISSING: no verified Hub database backup record exists")
		}
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup directory is not private")
	}
	recordPath := filepath.Join(root, databaseBackupRecordName)
	record, err := readDatabaseBackupRecord(recordPath, operationID)
	if err != nil {
		return databaseMigrationApproval{}, err
	}
	if record.State != update.BackupStateStaged {
		return databaseMigrationApproval{}, fmt.Errorf("DB_BACKUP_RECORD_NOT_STAGED: the Hub database backup record is %q", record.State)
	}
	if !record.IntegrityOK {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_UNVERIFIED: the Hub database backup has no integrity readback")
	}
	if err := verifyDatabaseBackupPayload(record, root); err != nil {
		return databaseMigrationApproval{}, err
	}
	out := databaseMigrationApproval{Record: record, RecordPath: recordPath}
	if record.IrreversibleApproved {
		out.AlreadyApproved = true
		return out, nil
	}
	record.IrreversibleApproved = true
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record could not be encoded")
	}
	// Remove any stale scratch path first: os.WriteFile would follow a planted
	// symlink, while Remove unlinks the link itself inside the 0700 directory.
	part := filepath.Join(root, databaseBackupRecordPart)
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_APPROVAL_FAILED: the confirmation scratch path could not be cleared")
	}
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_APPROVAL_FAILED: the confirmation could not be staged")
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(part)
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_APPROVAL_FAILED: the confirmation could not be staged")
	}
	if err := os.Rename(part, recordPath); err != nil {
		_ = os.Remove(part)
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_APPROVAL_FAILED: the confirmation could not be stored")
	}
	out.Record = record
	return out, nil
}

// ownedByCurrentUser keeps the Hub record under the same ownership rule as the
// node rollback store: a file written by another account is never adopted.
func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
