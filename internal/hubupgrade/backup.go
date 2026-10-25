package hubupgrade

// The Hub's pre-upgrade database backup producer (#11d Task 3r, spec §5.2).
//
// One backup is one per-operation generation: <data-dir>/database-backup/
// <op32hex>/{record.json,payload/meshmux.db}, committed atomically by the
// record layer. Order is fixed and every step is fail-closed:
//
//  1. an operation id is generated outside the lock (crypto/rand, 32 hex);
//  2. the root target manifest gate runs outside the lock (MANIFEST_UNAVAILABLE,
//     zero changes). It must come first: WriteOp(backing_up) validates the
//     manifest/package digests, and the manifest is a root-owned read-only file
//     that must not extend the critical section (plan ruling 6);
//  3. the process-wide producer mutex covers exactly the check-then-act
//     Busy → nextBackupGeneration → WriteOp(backing_up) triple, and the journal
//     is re-read inside it;
//  4. the running binary is staged as <data-dir>/upgrade/meshmuxd-<from>-<arch>
//     so a restore never starts with HUB_RESTORE_BINARY_MISSING;
//  5. the operation directory is created, a stale payload.part is removed before
//     VACUUM INTO (VACUUM refuses an existing target), then VACUUM INTO
//     payload.part/meshmux.db, chmod 0600, exact space check, real PRAGMA
//     user_version, PRAGMA integrity_check on the copy;
//  6. backup.Write publishes the per-operation single-database payload and its
//     staged record;
//  7. the journal advances to backed_up with the generation and the real schema;
//  8. the flat existence-only pointer is refreshed (spec §5.2.1). A pointer
//     failure is non-fatal and logged with its own code — HUB_BACKUP_POINTER_STALE
//     when nothing new was published, HUB_BACKUP_POINTER_UNFLUSHED when the copy
//     was renamed but its directory could not be flushed — because the operation
//     stays backed_up either way: the per-operation record is the authority.
//
// No step calls backup.GC. GC only ever considers confirmed generations, and a
// fresh staged backup is the rollback source the next restore needs, so the
// producer must never collect anything (spec C18/B8). GC is the confirmer's job
// (Task 5) and the explicit-cleanup entry (CleanupConfirmed) here.
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
	// PublishPointer refreshes the flat existence-only pointer after the
	// per-operation commit. Nil means PublishFlatPointer; a test injects a
	// failing or ordering-asserting replacement. It is never a Web input.
	PublishPointer func(root, operationID string) error
	// Log receives one stable code per non-fatal condition (HUB_BACKUP_POINTER_STALE
	// or HUB_BACKUP_POINTER_UNFLUSHED). It must not be used for secrets.
	Log func(code, operationID string)

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

// BackupReceipt is the honest success receipt: a staged per-operation record
// exists and the copy passed integrity_check. It never claims the upgrade was
// applied, and a pointer failure does not change it (the record is authoritative).
type BackupReceipt struct {
	Status         string `json:"status"`
	OperationID    string `json:"operation_id"`
	FromVersion    string `json:"from_version"`
	DBSchema       int64  `json:"db_schema"`
	IntegrityOK    bool   `json:"integrity_ok"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// CreateBackup performs the ordered producer. A successful receipt names an
// operation Task 5 may hand off; every failure leaves the previous generation
// byte-identical and cleans this operation's scratch copy.
func CreateBackup(ctx context.Context, cfg BackupConfig) (BackupReceipt, error) {
	if err := validateBackupConfig(cfg); err != nil {
		return BackupReceipt{}, err
	}
	operationID, err := newOperationID()
	if err != nil {
		return BackupReceipt{}, fail("HUB_BACKUP_FAILED", "an operation id could not be generated")
	}
	// The running identity is read before the journal is touched: a missing
	// digest would otherwise leave an operation stuck in backing_up with no
	// producer left to fail it.
	fromVersion := buildinfo.Version
	fromDigest, err := buildinfo.Digest()
	if err != nil || !digestRE.MatchString(fromDigest) {
		return BackupReceipt{}, fail("HUB_BACKUP_IDENTITY_MISSING", "the running binary digest is unavailable")
	}
	manifestDir := cfg.ManifestDir
	if manifestDir == "" {
		manifestDir = RootManifestDir
	}
	// The manifest gate is outside the producer mutex (plan ruling 6): it reads
	// a root-owned file and must never slow another request's check-then-act.
	target, err := readRootManifest(manifestDir, cfg.Target, cfg.manifestOwner)
	if err != nil {
		return BackupReceipt{}, err
	}

	// The operation document is built before the lock so a post-lock journal
	// read failure can still fail it: a journal entry left non-terminal would
	// block every later backup until Task 5's 30-minute orphan timeout.
	op := Op{
		Schema: OpSchema, OperationID: operationID, Kind: KindUpdate, State: StateBackingUp,
		TargetVersion: cfg.Target, FromVersion: fromVersion,
		ManifestSHA256: target.SHA256, PackageSHA256: target.Package.SHA256,
		UpdatedAt: cfg.now(),
	}

	// Check-then-act: the Busy read, the generation read and the backing_up
	// write are one critical section, and the journal is re-read inside it.
	unlock := LockBackupProduce()
	busyOp, busy, err := backupBusy(cfg.DataDir)
	if err == nil && busy {
		err = fail("HUB_UPGRADE_BUSY", "operation "+busyOp.OperationID+" is in state "+string(busyOp.State))
	}
	var generation int64
	if err == nil {
		generation, err = nextBackupGeneration(cfg.DataDir)
	}
	if err == nil {
		op.BackupGeneration = generation
		op.UpdatedAt = cfg.now()
		err = WriteOp(cfg.DataDir, op)
	}
	unlock()
	if err != nil {
		return BackupReceipt{}, err
	}

	stored, ok, err := readJournalOp(cfg.DataDir, operationID, os.Geteuid())
	if err != nil || !ok {
		if err == nil {
			err = fail("HUB_BACKUP_JOURNAL_FAILED", "the operation journal entry disappeared")
		}
		// The backing_up document was just published, so this read failing
		// means the journal became unreadable: fail the operation from the
		// in-memory copy instead of leaving a non-terminal entry behind.
		if failed, advanceErr := Advance(op, StateFailed, "HUB_BACKUP_JOURNAL_FAILED"); advanceErr == nil {
			failed.UpdatedAt = cfg.now()
			_ = WriteOp(cfg.DataDir, failed)
		}
		return BackupReceipt{}, backupJournalError(err)
	}
	op = stored
	var opDir string
	failWith := func(code string) (BackupReceipt, error) {
		// Every failure path clears this operation's scratch copy and leaves
		// the previous generation byte-identical. A directory with no committed
		// record is not a generation: it is dropped whole, so a retry starts
		// clean and no reader has to reason about a half-written operation. A
		// committed record is never removed here — it is a valid restore source
		// even when the journal transition failed.
		discardUncommittedOperation(opDir)
		discardEmptyUpgradeDir(cfg.DataDir)
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

	root := filepath.Join(cfg.DataDir, DatabaseBackupDir)
	opDir, err = backup.Dir(root, operationID)
	if err != nil {
		return failWith("HUB_BACKUP_STORE_UNSAFE")
	}
	partDir, err := preparePayloadScratch(opDir)
	if err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	dst := filepath.Join(partDir, backup.SingleDBName)
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	if err := cfg.Vacuum(ctx, dst); err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	info, err := os.Lstat(dst)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	if err := os.Chmod(dst, 0600); err != nil {
		return failWith("HUB_BACKUP_VACUUM_FAILED")
	}
	// Exact space check with the real copy size: the formula's dbSize term is
	// this file, not a guess.
	if err := cfg.Space(cfg.DataDir, RequiredSpace(uint64(info.Size()))); err != nil {
		return failWith("HUB_SPACE_INSUFFICIENT")
	}
	dbSchema, err := cfg.Schema(ctx)
	if err != nil || dbSchema <= 0 {
		return failWith("HUB_BACKUP_SCHEMA_FAILED")
	}
	// Integrity is checked here, on exactly the bytes backup.Write is about to
	// hash and publish. The store's Check seam stays non-nil (a single-database
	// payload without one is refused) but performs no second scan.
	if err := cfg.Integrity(ctx, dst); err != nil {
		return failWith("HUB_BACKUP_INTEGRITY_FAILED")
	}

	spec := backup.Spec{
		OperationID: operationID, FromVersion: fromVersion, TargetVersion: cfg.Target,
		DBSchema: dbSchema, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: target.SHA256, PackageSHA256: target.Package.SHA256,
		FromPackageSHA256: fromDigest, FromAgentSHA256: fromDigest, Now: cfg.Now,
	}
	record, err := backup.Write(root, spec, backup.Payload{
		Kind:  backup.PayloadSingleDB,
		Check: func(string) error { return nil },
	})
	if err != nil {
		return failWith("HUB_BACKUP_RECORD_FAILED")
	}

	backedUp, err := Advance(op, StateBackedUp, "")
	if err != nil {
		return BackupReceipt{}, err
	}
	backedUp.DBSchema = dbSchema
	backedUp.UpdatedAt = cfg.now()
	if err := WriteOp(cfg.DataDir, backedUp); err != nil {
		// The record is committed but the journal still says backing_up. Fail
		// the operation so a reader sees a terminal state; the committed record
		// stays readable (failWith never removes a directory that holds one),
		// and the reconcile row for a backing_up orphan remains the backstop if
		// this second journal write also fails.
		return failWith("HUB_BACKUP_JOURNAL_FAILED")
	}

	// The pointer is refreshed after the per-operation commit and after
	// backed_up, so its failure can never be mistaken for a failed backup. The
	// two failure codes are distinct: stale means nothing new was published,
	// unflushed means the rename happened but may not survive power loss.
	publish := cfg.PublishPointer
	if publish == nil {
		publish = PublishFlatPointer
	}
	if err := publish(root, operationID); err != nil {
		if cfg.Log != nil {
			cfg.Log(pointerLogCode(err), operationID)
		}
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

// nextBackupGeneration increments the highest generation any journal document
// records. A missing journal starts at 1; a failed operation still consumed its
// generation, so a later backup never reuses it and "latest" stays stable across
// a restore.
func nextBackupGeneration(dataDir string) (int64, error) {
	ops, err := ListOps(dataDir, os.Geteuid())
	if err != nil {
		return 0, backupJournalError(err)
	}
	var generation int64
	for _, op := range ops {
		if op.BackupGeneration > generation {
			generation = op.BackupGeneration
		}
	}
	return generation + 1, nil
}

// backupBusy is Busy with the producer's stable code for an unreadable journal
// (spec §5.2: fail closed as HUB_BACKUP_JOURNAL_FAILED, zero backup).
func backupBusy(dataDir string) (Op, bool, error) {
	op, busy, err := Busy(dataDir, os.Geteuid())
	if err != nil {
		return Op{}, false, backupJournalError(err)
	}
	return op, busy, nil
}

// backupJournalError maps the journal's own corruption code onto the backup
// group the operator sees on this route. The mapping is by code, never by text.
func backupJournalError(err error) error {
	if codeOf(err) == codeJournalCorrupt {
		return fail("HUB_BACKUP_JOURNAL_FAILED", "the operation journal is not readable")
	}
	return err
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

// readJournalOp is the producer's post-lock journal read. Production reads the
// journal; the seam exists so a test can prove that a failure here still leaves a
// terminal journal entry instead of a non-terminal one that blocks later backups
// until Task 5's orphan timeout.
var readJournalOp = ReadOp

// pointerLogCode is the one mapping from a pointer failure to the stable code the
// producer logs. A publisher that does not carry this package's code (a test
// seam) is reported as stale: it published nothing this package can vouch for.
func pointerLogCode(err error) string {
	switch codeOf(err) {
	case codePointerUnflushed:
		return codePointerUnflushed
	default:
		return codePointerStale
	}
}

// discardEmptyUpgradeDir removes the package directory when a failed stage left
// it empty. It never removes a staged package: an existing old-package copy is a
// restore source even when this attempt failed. Only a directory with no entries
// at all is dropped, so a failed first backup leaves no empty upgrade/ behind.
func discardEmptyUpgradeDir(dataDir string) {
	dir := filepath.Join(dataDir, UpgradeDir)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		return
	}
	_ = os.Remove(dir)
}

// discardUncommittedOperation removes an operation directory that holds no
// committed record. It is the failure-path cleanup of the producer: an empty or
// scratch-only directory is not a generation, while a directory with a record is
// a rollback source and is never touched here.
func discardUncommittedOperation(opDir string) {
	if opDir == "" {
		return
	}
	if _, err := os.Lstat(filepath.Join(opDir, backup.RecordName)); err == nil {
		return
	}
	_ = os.RemoveAll(opDir)
}

// preparePayloadScratch recreates the operation's scratch payload directory and
// returns it. The operation directory is created first (backup.Dir), then the
// scratch copy is cleared: VACUUM INTO refuses an existing destination, and a
// previous attempt of this same operation may have died after creating one, so
// without this removal every retry of the operation would fail closed forever.
// Only payload.part is touched — a committed payload and record are never
// removed here.
func preparePayloadScratch(opDir string) (string, error) {
	partDir := filepath.Join(opDir, backup.PayloadPart)
	if err := os.RemoveAll(partDir); err != nil {
		return "", err
	}
	if err := os.Mkdir(partDir, 0700); err != nil {
		return "", err
	}
	return partDir, nil
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
