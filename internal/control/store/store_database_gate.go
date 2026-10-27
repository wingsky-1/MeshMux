package store

// The Hub database gate of #11c-3 (spec §4.5, §4.13, §4.15, §6).
//
// Two version numbers are deliberately kept apart:
//
//   - `PRAGMA user_version` is the storage schema of this SQLite file. This
//     binary owns version 17 and refuses any newer file without opening it for
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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
)

var errDatabasePayloadUnsafe = errors.New("the Hub database backup payload is not a private file tree")

const (
	// DatabaseSchemaVersion is the storage schema this binary owns. Task 3 of
	// the subscription aggregation rebuild adds version 12 (rule library +
	// preset seeds), Task 4 adds version 13 (subscription edge tables +
	// selection snapshot), Task 5 adds version 14 (drop out_bindings now that the
	// Out authorization is node membership) and version 15 (narrow the candidate
	// immutability trigger so a node can be deleted); Task 8 adds version 16
	// (the external HTTP proxy node role and the private node_http_proxy table);
	// Task 6 adds version 17 (strip the retired exceptions/ssids keys from
	// stored route policy payloads). Version 11 stays reserved for 11d, whose
	// migration leg runs ahead of migrateSchema12 when it merges. A newer file
	// is refused instead of opened for writes; a database is never downgraded
	// in place.
	DatabaseSchemaVersion = 17

	// The Hub database backup is independent of the node rollback store
	// (spec §4.1 "Hub DB 记录独立"). Verified per-operation backups are kept next
	// to the database, in the same private 0700 data directory, so a restore
	// never needs a path outside the deployment boundary.
	//
	// The directory name is the upgrade producer's (internal/hubupgrade owns the
	// data-directory layout), and the record and payload names are the neutral
	// record package's, so the Hub slot, the root executor and the Node store
	// cannot drift apart. These are re-exports for the page layer, not second
	// definitions: never replace them with a literal.
	DatabaseBackupDirName        = hubupgrade.DatabaseBackupDir
	DatabaseBackupPayloadDirName = backup.PayloadDir
	DatabaseBackupRecordName     = backup.RecordName
)

// DatabaseBackupOperationPattern is the fixed operation id shape of one Hub
// upgrade. A form value never reaches a path or query before this check. The
// expression is the frozen record grammar of internal/backup; there is no
// second copy.
var DatabaseBackupOperationPattern = backup.OperationIDPattern

// DatabaseVersion is the last-known-good pair of the Hub database.
type DatabaseVersion struct {
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
//
// It is the only writer of `database_versions`, and it names this build through
// buildinfo.Version — the same single source as the release manifest projection
// and node.CurrentAgentVersion (#11d spec §5.3). A row left by another build is
// healed by the next start of this one, never by a health or management read.
func (s *Store) confirmDatabaseVersion(now time.Time) error {
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return errors.New("SCHEMA_READBACK_FAILED: the database schema could not be read back")
	}
	if version != DatabaseSchemaVersion {
		return fmt.Errorf("SCHEMA_READBACK_FAILED: the database reports user_version %d after migrating to %d", version, DatabaseSchemaVersion)
	}
	if _, err := s.DB.Exec(`INSERT INTO database_versions(id, last_good_version, last_good_schema, confirmed_at)
 VALUES(1,?,?,?)
 ON CONFLICT(id) DO UPDATE SET
  last_good_version=excluded.last_good_version,
  last_good_schema=excluded.last_good_schema,
  confirmed_at=excluded.confirmed_at`,
		buildinfo.Version, version, now.UTC().Unix()); err != nil {
		return errors.New("SCHEMA_CONFIRM_FAILED: the last-good database version could not be recorded")
	}
	return nil
}

// LastGoodDatabaseVersion reads the confirmed row. An absent row is honest: the
// database was never confirmed by a started binary, which is not the same as a
// row naming an empty release. It is the one place that parses the row, so the
// identity readback and every other consumer cannot drift apart.
func (s *Store) LastGoodDatabaseVersion() (DatabaseVersion, bool, error) {
	return LastGoodDatabaseVersionFrom(s.DB)
}

// LastGoodDatabaseVersionFrom is the explicit-handle form, so the identity
// readback can be replayed through a read-only connection in a test.
func LastGoodDatabaseVersionFrom(db *sql.DB) (DatabaseVersion, bool, error) {
	var out DatabaseVersion
	var confirmed int64
	err := db.QueryRow(`SELECT last_good_version, last_good_schema, confirmed_at FROM database_versions WHERE id=1`).
		Scan(&out.Version, &out.Schema, &confirmed)
	if errors.Is(err, sql.ErrNoRows) {
		return DatabaseVersion{}, false, nil
	}
	if err != nil {
		return DatabaseVersion{}, false, errors.New(CodeDatabaseUnavailable)
	}
	out.ConfirmedAt = time.Unix(confirmed, 0).UTC()
	return out, true, nil
}

// schemaTooNew builds the refusal for a database written by a newer binary. The
// record check is existence-only: this binary cannot know the newer record's
// fields, and parsing them would be exactly the silent interpretation the gate
// exists to prevent.
func (s *Store) schemaTooNew(version int) error {
	recordPath := filepath.Join(s.Dir, DatabaseBackupDirName, DatabaseBackupRecordName)
	if info, err := os.Lstat(recordPath); err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
		return fmt.Errorf("SCHEMA_TOO_NEW: database user_version %d is newer than this binary (%d); restore the verified database backup record %s (from_version and db_schema name the last good state); do not downgrade in place",
			version, DatabaseSchemaVersion, recordPath)
	}
	return fmt.Errorf("SCHEMA_TOO_NEW: database user_version %d is newer than this binary (%d); no verified database backup record exists at %s; restore a matching binary and database, do not downgrade in place",
		version, DatabaseSchemaVersion, recordPath)
}

// readDatabaseBackupRecord reads the fixed Hub database backup record under the
// same private-file rules as the node rollback records. Unknown fields are
// refused: a future record schema must not be silently truncated into today's
// approval semantics.
//
// This is the thin adapter over the neutral record package (#11d Task 1r): the
// strict decoding, the private-mode rule and the "belongs to this operation"
// check come from backup.Read on <root>/<operationID>/record.json, and the Web
// keeps only what is its own policy — the DB_BACKUP_* stable codes and the extra
// refusal of a record that names no source database schema. The flat
// <root>/record.json pointer is never read here.
func readDatabaseBackupRecord(root, operationID string) (backup.Record, error) {
	record, err := backup.Read(root, operationID, os.Geteuid())
	if err != nil {
		return backup.Record{}, databaseBackupRecordError(err)
	}
	if record.DBSchema <= 0 {
		return backup.Record{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record names no source database schema")
	}
	return record, nil
}

// databaseBackupRecordError maps the record layer's stable codes onto the Hub
// gate's DB_BACKUP_* vocabulary. The mapping is by code, never by message text,
// so a detail that happens to start with the same words cannot change behaviour.
func databaseBackupRecordError(err error) error {
	code, detail, _ := strings.Cut(err.Error(), ": ")
	switch code {
	case backup.CodeMissing:
		return errors.New("DB_BACKUP_RECORD_MISSING: no verified Hub database backup record exists")
	case backup.CodeCorrupt:
		return errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record is not a private, verified record: " + detail)
	default:
		return errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup record could not be read: " + detail)
	}
}

// verifyDatabaseBackupPayload closes the vacuous-gate class Task 2 fixed: a
// record that is staged and claims integrity but holds nothing must never be
// accepted as an irreversible-migration rollback source. The Hub copy is a large
// database file, so this check is metadata-only (presence, private modes and the
// recorded file count), not a re-hash on every operator click; 11d's restore step
// still runs PRAGMA integrity_check on the copy it opens.
func verifyDatabaseBackupPayload(record backup.Record, operationDir string) error {
	if record.PayloadFiles <= 0 {
		return errors.New("DB_BACKUP_RECORD_UNVERIFIED: the Hub database backup holds no payload files")
	}
	payload := filepath.Join(operationDir, DatabaseBackupPayloadDirName)
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
	Record          backup.Record
	RecordPath      string
	AlreadyApproved bool
}

// approveIrreversibleMigration stores the explicit Web confirmation bit on the
// Hub database backup record. It refuses without the bit, without a verified
// record, and for a record that is no longer staged; it never starts the
// migration itself (that is 11d). The write is staged and renamed so a reader
// sees either the old or the new record, never half of one.
func (s *Store) ApproveIrreversibleMigration(operationID string, confirmed bool) (databaseMigrationApproval, error) {
	if !confirmed {
		return databaseMigrationApproval{}, errors.New("IRREVERSIBLE_CONFIRM_REQUIRED: an irreversible database migration requires the explicit Web confirmation")
	}
	if !DatabaseBackupOperationPattern.MatchString(operationID) {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_OPERATION_INVALID: the backup operation id is not 32 lowercase hex")
	}
	root := filepath.Join(s.Dir, DatabaseBackupDirName)
	if err := privatePath(root, true); err != nil {
		if os.IsNotExist(err) {
			return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_MISSING: no verified Hub database backup record exists")
		}
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_CORRUPT: the Hub database backup directory is not private")
	}
	record, err := readDatabaseBackupRecord(root, operationID)
	if err != nil {
		return databaseMigrationApproval{}, err
	}
	if record.State != backup.StateStaged {
		return databaseMigrationApproval{}, fmt.Errorf("DB_BACKUP_RECORD_NOT_STAGED: the Hub database backup record is %q", record.State)
	}
	if !record.IntegrityOK {
		return databaseMigrationApproval{}, errors.New("DB_BACKUP_RECORD_UNVERIFIED: the Hub database backup has no integrity readback")
	}
	operationDir, err := backup.Dir(root, operationID)
	if err != nil {
		return databaseMigrationApproval{}, databaseBackupRecordError(err)
	}
	if err := verifyDatabaseBackupPayload(record, operationDir); err != nil {
		return databaseMigrationApproval{}, err
	}
	out := databaseMigrationApproval{Record: record, RecordPath: filepath.Join(operationDir, DatabaseBackupRecordName)}
	if record.IrreversibleApproved {
		out.AlreadyApproved = true
		return out, nil
	}
	record.IrreversibleApproved = true
	// The bit is written through the record layer's single encoder and its
	// staged-then-renamed publish, so an approval can never publish half a record
	// or a record the record layer would refuse to read back.
	if err := backup.WriteRecord(operationDir, record); err != nil {
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

// VacuumDatabaseCopy is the production VACUUM INTO callback for the Hub backup
// producer. The destination is fixed by the producer and must not exist: SQLite
// refuses an existing target, and a stale copy is deleted by the producer after
// the operation directory is created. VACUUM runs outside any transaction on
// the store's single connection.
func (s *Store) VacuumDatabaseCopy(ctx context.Context, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return errors.New("HUB_BACKUP_VACUUM_FAILED: the VACUUM destination already exists")
	} else if !os.IsNotExist(err) {
		return errors.New("HUB_BACKUP_VACUUM_FAILED: the VACUUM destination could not be inspected")
	}
	if _, err := s.DB.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return errors.New("HUB_BACKUP_VACUUM_FAILED: VACUUM INTO did not produce the copy")
	}
	return nil
}

// IntegrityCheckCopy opens the finished copy read-only and runs
// PRAGMA integrity_check. It never opens the live database and never writes the
// copy through a writer connection; immutable=1 makes the check itself prove it
// cannot touch the file.
func (s *Store) IntegrityCheckCopy(ctx context.Context, path string) error {
	u := url.URL{Scheme: "file", Path: path}
	copyDB, err := sql.Open("sqlite", u.String()+"?mode=ro&immutable=1")
	if err != nil {
		return errors.New("HUB_BACKUP_INTEGRITY_FAILED: the database copy could not be opened")
	}
	defer copyDB.Close()
	copyDB.SetMaxOpenConns(1)
	var result string
	if err := copyDB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return errors.New("HUB_BACKUP_INTEGRITY_FAILED: integrity_check could not run on the copy")
	}
	if result != "ok" {
		return errors.New("HUB_BACKUP_INTEGRITY_FAILED: integrity_check did not return ok")
	}
	return nil
}

// LiveDatabaseSchemaVersion is the live PRAGMA user_version. The producer
// records it as db_schema; it is never guessed from this build's constant,
// because a restore compares the copy against the record.
func (s *Store) LiveDatabaseSchemaVersion(ctx context.Context) (int64, error) {
	var version int64
	if err := s.DB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, errors.New("HUB_BACKUP_SCHEMA_FAILED: the database schema could not be read")
	}
	if version <= 0 {
		return 0, errors.New("HUB_BACKUP_SCHEMA_FAILED: the database reports no schema version")
	}
	return version, nil
}
