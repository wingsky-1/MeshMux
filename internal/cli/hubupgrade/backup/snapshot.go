package backup

// The pre-migration database snapshot of the Hub.
//
// The hardened installer replaces the Web package and then starts the new
// binary; that binary migrates the database to its own storage schema before it
// serves one request. The migration is one-way: after a failed start the
// installer restores the previous package, and the previous binary refuses the
// migrated file with SCHEMA_TOO_NEW. Without a copy of the pre-migration
// database the operator has no way back, and the SCHEMA_TOO_NEW guidance would
// name a backup record that was never produced.
//
// This producer closes that hole. It runs inside store.Migrate, in the Web
// process that owns the SQLite handle, immediately before the first migration
// step. It reuses the Hub backup layout (database-backup/<op32hex>/), the frozen
// record layer (backup.Write/ReadRecord), the single-database payload and the
// flat pointer, so the downgraded binary's gate, the installer's rollback note
// and a manual restore all name the same bytes. It is not a second backup
// mechanism: it is the same store and the same record, taken by the process that
// owns the database instead of by the Web upgrade handoff.
//
// It deliberately writes no upgrade journal entry: this is not an upgrade
// operation (there is no target package and no dispatcher handoff), and a
// non-terminal journal entry would block the Web self-upgrade single flight
// until the orphan timeout. A caller that needs an operation identity uses
// CreateBackup, which keeps the manifest gate and the journal.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

// migrationSnapshotSlack is the free space the snapshot keeps beyond its own
// copy. One copy plus this margin covers the record, the flat pointer and the
// scratch directory; the snapshot never needs the hub-upgrade package terms
// (no target package, no staged old binary).
const migrationSnapshotSlack = uint64(64 << 20)

// MigrationSnapshotConfig is one pre-migration Hub database snapshot request.
// The callbacks are the Web process's SQLite boundary; a fixture supplies fakes
// and never needs a driver.
type MigrationSnapshotConfig struct {
	// DataDir is the private Hub data directory that owns the store.
	DataDir string
	// FromVersion is the release that last opened the database before this
	// migration (database_versions.last_good_version). "unknown" records a
	// database that never confirmed a build; it can never be mistaken for the
	// running release by the SCHEMA_TOO_NEW gate.
	FromVersion string
	// TargetVersion is this build's release identity.
	TargetVersion string
	// PackageSHA256 is the digest of the running executable. There is no root
	// target manifest on this path — the database migrates itself, no package is
	// handed off — so ManifestSHA256 carries the same digest: both fields name
	// the one authenticated artifact in play.
	PackageSHA256 string
	// Now is the clock seam. A nil Now means time.Now.
	Now func() time.Time

	Vacuum    func(ctx context.Context, dst string) error
	Integrity func(ctx context.Context, path string) error
	Schema    func(ctx context.Context) (int64, error)
	Space     func(path string, need uint64) error
	// PublishPointer refreshes the flat existence-only pointer. A failure on
	// this path is fatal: the pointer is the SCHEMA_TOO_NEW recovery chain.
	PublishPointer func(root, operationID string) error
}

// snapshotSpace is the free-space requirement of one database copy: the copy
// itself plus the fixed slack.
func snapshotSpace(dbSize uint64) uint64 {
	const maxUint64 = ^uint64(0)
	if dbSize > (maxUint64-migrationSnapshotSlack)/2 {
		return maxUint64
	}
	return 2*dbSize + migrationSnapshotSlack
}

// CreateMigrationSnapshot performs the ordered pre-migration snapshot. Every
// failure leaves the existing generations byte-identical and removes this
// operation's scratch copy, so a retry starts clean and a failed snapshot never
// looks like a restore source. On success the per-operation record, its verified
// payload and the flat pointer all exist; the caller may migrate.
func CreateMigrationSnapshot(ctx context.Context, cfg MigrationSnapshotConfig) (BackupReceipt, error) {
	if err := validateMigrationSnapshot(cfg); err != nil {
		return BackupReceipt{}, err
	}
	operationID, err := newOperationID()
	if err != nil {
		return BackupReceipt{}, fail("HUB_BACKUP_FAILED", "an operation id could not be generated")
	}
	root := filepath.Join(cfg.DataDir, DatabaseBackupDir)
	if err := cfg.Space(cfg.DataDir, snapshotSpace(0)); err != nil {
		return BackupReceipt{}, err
	}
	opDir, err := backup.Dir(root, operationID)
	if err != nil {
		return BackupReceipt{}, fail("HUB_BACKUP_STORE_UNSAFE", "the Hub backup store is not a private directory")
	}
	failWith := func(code, detail string) (BackupReceipt, error) {
		// No committed record exists yet on any of these paths, so the whole
		// operation directory is dropped: a scratch copy is never a generation.
		discardUncommittedOperation(opDir)
		return BackupReceipt{}, fail(code, detail)
	}
	partDir, err := preparePayloadScratch(opDir)
	if err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED", "the snapshot scratch directory could not be prepared")
	}
	dst := filepath.Join(partDir, backup.SingleDBName)
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		return failWith("HUB_BACKUP_VACUUM_FAILED", "the snapshot destination already exists")
	}
	if err := cfg.Vacuum(ctx, dst); err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED", "the database copy could not be written")
	}
	info, err := os.Lstat(dst)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return failWith("HUB_BACKUP_VACUUM_FAILED", "the database copy is not a regular file")
	}
	if err := os.Chmod(dst, 0600); err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED", "the database copy could not be made private")
	}
	if err := cfg.Space(cfg.DataDir, snapshotSpace(uint64(info.Size()))); err != nil {
		return failWith("HUB_SPACE_INSUFFICIENT", "the Hub filesystem cannot keep the snapshot and its next copy")
	}
	dbSchema, err := cfg.Schema(ctx)
	if err != nil || dbSchema <= 0 {
		return failWith("HUB_BACKUP_SCHEMA_FAILED", "the database schema could not be read before migrating")
	}
	if err := cfg.Integrity(ctx, dst); err != nil {
		return failWith("HUB_BACKUP_INTEGRITY_FAILED", "the database copy did not pass integrity_check")
	}
	spec := backup.Spec{
		OperationID: operationID, FromVersion: cfg.FromVersion, TargetVersion: cfg.TargetVersion,
		DBSchema: dbSchema, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: cfg.PackageSHA256, PackageSHA256: cfg.PackageSHA256,
		Now: cfg.Now,
	}
	record, err := backup.Write(root, spec, backup.Payload{
		Kind: backup.PayloadSingleDB,
		// Integrity ran on exactly the bytes backup.Write hashes and publishes;
		// a second full scan would prove nothing more.
		Check: func(string) error { return nil },
	})
	if err != nil {
		return failWith("HUB_BACKUP_RECORD_FAILED", "the database backup record could not be published")
	}
	publish := cfg.PublishPointer
	if publish == nil {
		publish = PublishFlatPointer
	}
	// Unlike the Web upgrade producer, a pointer failure is fatal here: without
	// the flat pointer the downgraded binary's SCHEMA_TOO_NEW guidance has no
	// record to name. The migration is refused and the database stays at its old
	// schema, which is the safe state.
	if err := publish(root, operationID); err != nil {
		return BackupReceipt{}, fail(CodeMigrationBackupPointer, "the flat database backup pointer could not be published")
	}
	return BackupReceipt{
		Status: "staged", OperationID: record.OperationID, FromVersion: record.FromVersion,
		DBSchema: record.DBSchema, IntegrityOK: record.IntegrityOK, ManifestSHA256: record.ManifestSHA256,
	}, nil
}

func validateMigrationSnapshot(cfg MigrationSnapshotConfig) error {
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		return fail("HUB_BACKUP_FAILED", "the Hub data directory is not absolute")
	}
	if cfg.FromVersion == "" || len(cfg.FromVersion) > 128 || strings.ContainsAny(cfg.FromVersion, "\x00\n\r/") {
		return fail("HUB_BACKUP_FAILED", "the previous release identity is not a plain version string")
	}
	if !targetRE.MatchString(cfg.TargetVersion) {
		return fail("HUB_BACKUP_FAILED", "this build's release identity is not a SemVer release")
	}
	if !digestRE.MatchString(cfg.PackageSHA256) {
		return fail(CodeBackupIdentityMissing, "the running binary digest is unavailable")
	}
	if cfg.Vacuum == nil || cfg.Integrity == nil || cfg.Schema == nil || cfg.Space == nil {
		return fail("HUB_BACKUP_FAILED", "the database callbacks are incomplete")
	}
	return nil
}
