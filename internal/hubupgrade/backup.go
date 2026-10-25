package hubupgrade

// The Hub's pre-upgrade database backup producer (#11d Task 3, spec §5.2).
//
// Order is fixed and every step is fail-closed:
//
//  1. single-flight: another non-terminal operation, or an approved irreversible
//     bit on the current record, refuses with HUB_UPGRADE_BUSY and zero changes;
//  2. the root target manifest gate (MANIFEST_UNAVAILABLE, zero changes);
//  3. the running binary is staged as <data-dir>/upgrade/meshmuxd-<from>-<arch>
//     so a restore never starts with HUB_RESTORE_BINARY_MISSING;
//  4. the flat slot is reconciled, then a stale payload.part is removed before
//     VACUUM INTO (VACUUM refuses an existing target; recoverFlatSlot
//     deliberately leaves the scratch copy alone);
//  5. VACUUM INTO payload.part/meshmux.db, chmod 0600, exact space check,
//     real PRAGMA user_version, PRAGMA integrity_check on the copy;
//  6. backup.Write publishes the flat single-database payload and its staged
//     record; the journal advances to backed_up.
//
// No step calls backup.GC. GC only ever considers confirmed generations and the
// flat slot holds one generation; a new backup atomically replaces it, so the
// new staged record is the rollback source and the old one is never deleted
// before this replacement (spec C18, plan ruling 3).
//
// The caller supplies the SQLite operations (VACUUM, integrity, schema, space)
// because internal/web owns the store. This package never imports the driver and
// never opens the database itself.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const runningExecutablePath = "/proc/self/exe"

// BackupConfig is one Hub backup request. The callbacks are the Web process's
// SQLite boundary; a fixture supplies fakes and never needs a driver.
type BackupConfig struct {
	DataDir string
	Target  string
	// ManifestDir defaults to RootManifestDir when empty.
	ManifestDir string
	Now         func() time.Time

	// Vacuum writes the database copy to dst, which must not already exist.
	Vacuum func(ctx context.Context, dst string) error
	// Integrity runs PRAGMA integrity_check on the finished copy.
	Integrity func(ctx context.Context, path string) error
	// Schema returns the live PRAGMA user_version.
	Schema func(ctx context.Context) (int64, error)
	// Space refuses a path whose free bytes are below need.
	Space func(path string, need uint64) error

	// manifestOwner is the expected account of the root manifest directory.
	// Zero (production) means root. Tests point it at their own uid so a
	// B-level fixture can exercise the same owner rule without chowning.
	manifestOwner int
}

func (cfg BackupConfig) now() time.Time {
	if cfg.Now != nil {
		return cfg.Now().UTC()
	}
	return time.Now().UTC()
}

// BackupReceipt is the honest success receipt: a staged record exists and the
// copy passed integrity_check. It never claims the upgrade was applied.
type BackupReceipt struct {
	Status         string `json:"status"`
	OperationID    string `json:"operation_id"`
	FromVersion    string `json:"from_version"`
	DBSchema       int64  `json:"db_schema"`
	IntegrityOK    bool   `json:"integrity_ok"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// CreateBackup performs the ordered producer. A successful receipt names an
// operation that Task 5 may hand off; every failure leaves the previous
// generation byte-identical and cleans the staged copy.
func CreateBackup(ctx context.Context, cfg BackupConfig) (BackupReceipt, error) {
	if err := validateBackupConfig(cfg); err != nil {
		return BackupReceipt{}, err
	}
	// The lock covers the single-flight read, the slot reconciliation, the
	// publish and the record read; a Web reader that interleaves with the
	// record layer's own recovery could otherwise displace a published payload.
	unlock := LockFlatSlot()
	defer unlock()

	flatRoot := filepath.Join(cfg.DataDir, DatabaseBackupDir)
	if op, busy, err := Busy(cfg.DataDir, os.Geteuid()); err != nil {
		return BackupReceipt{}, err
	} else if busy {
		return BackupReceipt{}, fail("HUB_UPGRADE_BUSY", "operation "+op.OperationID+" is in state "+string(op.State))
	}
	if record, ok, err := currentFlatRecord(flatRoot); err != nil {
		return BackupReceipt{}, err
	} else if ok && record.IrreversibleApproved {
		return BackupReceipt{}, fail("HUB_UPGRADE_BUSY", "the current backup record carries the irreversible approval bit")
	}

	manifestDir := cfg.ManifestDir
	if manifestDir == "" {
		manifestDir = RootManifestDir
	}
	target, err := readRootManifest(manifestDir, cfg.Target, cfg.manifestOwner)
	if err != nil {
		return BackupReceipt{}, err
	}

	fromVersion := buildinfo.Version
	fromDigest, err := buildinfo.Digest()
	if err != nil || !digestRE.MatchString(fromDigest) {
		return BackupReceipt{}, fail("HUB_BACKUP_IDENTITY_MISSING", "the running binary digest is unavailable")
	}

	generation, err := nextBackupGeneration(cfg.DataDir)
	if err != nil {
		return BackupReceipt{}, err
	}
	operationID, err := newOperationID()
	if err != nil {
		return BackupReceipt{}, fail("HUB_BACKUP_FAILED", "an operation id could not be generated")
	}
	now := cfg.now()
	op := Op{
		Schema: OpSchema, OperationID: operationID, Kind: KindUpdate, State: StateBackingUp,
		TargetVersion: cfg.Target, FromVersion: fromVersion,
		ManifestSHA256: target.SHA256, PackageSHA256: target.Package.SHA256,
		BackupGeneration: generation, UpdatedAt: now,
	}
	if err := WriteOp(cfg.DataDir, op); err != nil {
		return BackupReceipt{}, err
	}
	failWith := func(code string) (BackupReceipt, error) {
		if next, advanceErr := Advance(op, StateFailed, code); advanceErr == nil {
			next.UpdatedAt = cfg.now()
			_ = WriteOp(cfg.DataDir, next)
		}
		return BackupReceipt{}, fail(code, "the Hub database backup did not complete")
	}

	if err := cfg.Space(cfg.DataDir, Floor(0)); err != nil {
		return failWith("HUB_SPACE_INSUFFICIENT")
	}
	if _, err := stageRunningBinary(cfg.DataDir, fromVersion, fromDigest); err != nil {
		return failWith(codeOf(err))
	}

	slot, err := backup.Dir(flatRoot, backup.LayoutFlat, operationID)
	if err != nil {
		return failWith("HUB_BACKUP_SLOT_CORRUPT")
	}
	partDir := filepath.Join(slot, backup.PayloadPart)
	// Reconcile first (backup.Dir above), then clear the scratch copy. VACUUM
	// INTO refuses an existing destination; recoverFlatSlot intentionally does
	// not delete it, so a crash after VACUUM would make every retry fail closed
	// forever without this removal.
	if err := os.RemoveAll(partDir); err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	if err := os.Mkdir(partDir, 0700); err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	dst := filepath.Join(partDir, backup.SingleDBName)
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	if err := cfg.Vacuum(ctx, dst); err != nil {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	info, err := os.Lstat(dst)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	if err := os.Chmod(dst, 0600); err != nil {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	if err := cfg.Space(cfg.DataDir, RequiredSpace(uint64(info.Size()))); err != nil {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_SPACE_INSUFFICIENT")
	}
	dbSchema, err := cfg.Schema(ctx)
	if err != nil || dbSchema <= 0 {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_SCHEMA_FAILED")
	}
	// Integrity is checked here, on exactly the bytes backup.Write is about to
	// hash and publish. The store's Check seam stays non-nil (a single-database
	// payload without one is refused) but performs no second scan.
	if err := cfg.Integrity(ctx, dst); err != nil {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_INTEGRITY_FAILED")
	}

	spec := backup.Spec{
		OperationID: operationID, FromVersion: fromVersion, TargetVersion: cfg.Target,
		DBSchema: dbSchema, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: target.SHA256, PackageSHA256: target.Package.SHA256,
		FromPackageSHA256: fromDigest, FromAgentSHA256: fromDigest, Now: cfg.Now,
	}
	record, err := backup.Write(flatRoot, spec, backup.LayoutFlat, backup.Payload{
		Kind:  backup.PayloadSingleDB,
		Check: func(string) error { return nil },
	})
	if err != nil {
		_ = os.RemoveAll(partDir)
		return failWith("HUB_BACKUP_RECORD_FAILED")
	}

	backedUp, err := Advance(op, StateBackedUp, "")
	if err != nil {
		return BackupReceipt{}, err
	}
	backedUp.DBSchema = dbSchema
	backedUp.UpdatedAt = cfg.now()
	if err := WriteOp(cfg.DataDir, backedUp); err != nil {
		return BackupReceipt{}, err
	}
	return BackupReceipt{
		Status: "staged", OperationID: record.OperationID, FromVersion: record.FromVersion,
		DBSchema: record.DBSchema, IntegrityOK: record.IntegrityOK, ManifestSHA256: target.SHA256,
	}, nil
}

func validateBackupConfig(cfg BackupConfig) error {
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		return fail("HUB_BACKUP_FAILED", "the Hub data directory is not absolute")
	}
	if !targetRE.MatchString(cfg.Target) {
		return fail("MANIFEST_UNAVAILABLE", "the requested target is not a SemVer release")
	}
	if cfg.Vacuum == nil || cfg.Integrity == nil || cfg.Schema == nil || cfg.Space == nil {
		return fail("HUB_BACKUP_FAILED", "the database callbacks are incomplete")
	}
	return nil
}

// currentFlatRecord reads the one generation without requiring its operation
// id. A missing slot is (zero, false, nil); a damaged slot is an error, because
// starting a new backup over an unreadable rollback source would destroy it.
func currentFlatRecord(flatRoot string) (backup.Record, bool, error) {
	record, err := backup.ReadFlat(flatRoot, os.Geteuid())
	if err != nil {
		if codeOf(err) == backup.CodeMissing {
			return backup.Record{}, false, nil
		}
		return backup.Record{}, false, fail("HUB_BACKUP_SLOT_CORRUPT", "the current flat backup slot is not readable")
	}
	return record, true, nil
}

// nextBackupGeneration increments the highest generation any journal document
// records. A missing journal starts at 1; a failed operation still consumed its
// generation, so a later backup never reuses it.
func nextBackupGeneration(dataDir string) (int64, error) {
	ops, err := ListOps(dataDir, os.Geteuid())
	if err != nil {
		return 0, err
	}
	var generation int64
	for _, op := range ops {
		if op.BackupGeneration > generation {
			generation = op.BackupGeneration
		}
	}
	return generation + 1, nil
}

func newOperationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// stageRunningBinary copies /proc/self/exe (the inode actually executing, not a
// replaceable path) into the fixed old-package name. A second call with the
// same digest reuses the existing file; a changed running digest replaces it
// atomically. The readback must equal the identity the Web recorded before the
// copy is accepted as a restore source.
func stageRunningBinary(dataDir, version, digest string) (string, error) {
	name, err := OldPackageName(version, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(dataDir, UpgradeDir)
	if err := ensurePrivateDirMode(dir); err != nil {
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the package directory is not private")
	}
	final := filepath.Join(dir, name)
	if info, err := os.Lstat(final); err == nil &&
		info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
		if got, err := hashPath(final); err == nil && got == digest {
			return final, nil
		}
	}
	source, err := os.Open(runningExecutablePath)
	if err != nil {
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the running binary could not be opened")
	}
	defer source.Close()
	part := final + ".part"
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the package scratch path could not be cleared")
	}
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the old package could not be written")
	}
	written, copyErr := io.Copy(out, io.LimitReader(source, 128<<20+1))
	if copyErr == nil {
		copyErr = out.Sync()
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil || written <= 0 || written > 128<<20 {
		_ = os.Remove(part)
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the old package could not be copied within its bound")
	}
	if err := os.Chmod(part, 0755); err != nil {
		_ = os.Remove(part)
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the old package could not be made executable")
	}
	if err := os.Rename(part, final); err != nil {
		_ = os.Remove(part)
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the old package could not be published")
	}
	if err := syncDir(dir); err != nil {
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the package directory could not be flushed")
	}
	got, err := hashPath(final)
	if err != nil || got != digest {
		return "", fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the staged old package does not match the running digest")
	}
	return final, nil
}

// ensurePrivateDirMode prepares the package directory: 0700 and owned by the
// Web process. It narrows an owned directory but never adopts a loose or
// foreign one.
func ensurePrivateDirMode(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0700 || !ownedBy(os.Geteuid(), info) {
		return errUnsafeDirectory
	}
	return nil
}

var errUnsafeDirectory = fail("HUB_BACKUP_BINARY_STAGE_FAILED", "the package directory is not a private directory")

func hashPath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, io.LimitReader(file, 128<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
