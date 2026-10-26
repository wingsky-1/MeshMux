package hubupgrade

// The handoff of one backed-up operation to the privileged dispatcher (#11d
// Task 5, spec §5.2, §5.5, §5.8).
//
// The Web process cannot swap a binary, so a handoff only turns a verified
// backup into a queued operation: it stages the root-pinned target package and
// publishes one request under /run. Every authorization is re-derived on the
// root side; the request names an operation, never a path, target or digest.
//
// The order is fixed and fail-closed (spec §5.5):
//
//  1. re-read the journal entry for exactly this operation. It must still be a
//     backed_up update: a handoff never invents an operation, and
//     "backed_up 之前不得交接" is a journal rule, not a page rule;
//  2. read the per-operation record and re-verify its payload digest
//     (backup.Verify). The record and the journal must name the same from
//     version, target, digests and database schema;
//  3. re-authenticate the root manifest for the frozen target. A manifest that
//     no longer names the operation's package digest is
//     HUB_MANIFEST_PACKAGE_MISMATCH: the target is pinned by the record, so a
//     replaced manifest must never silently upgrade different bytes;
//  4. read the irreversible bit from exactly that operation's record. A target
//     that declares an irreversible database migration without the explicit
//     approval is IRREVERSIBLE_CONFIRM_REQUIRED with zero changes;
//  5. check the free space with the verified payload's real size;
//  6. stage the target package through update.FetchVerifiedSource (digest
//     verified before a byte is written, .part + fsync + rename). A staging
//     failure changes nothing: the operation stays backed_up and retryable, and
//     no request exists. The package is idempotent per digest;
//  7. advance the journal to queued (fsync + rename);
//  8. publish <request dir>/<op32hex>.json. A failure there fails the
//     operation as HUB_HANDOFF_WRITE_FAILED instead of leaving a queued entry
//     no dispatcher can see.
//
// The handoff takes no lock. The producer mutex covers only the producer's
// check-then-act triple (lock.go); a handoff reads the journal and writes only
// its own operation's file, and the record commit it depends on is a rename.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/update"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

const (
	// CodeHandoffInvalidState is the refusal of an operation that is not a
	// backed_up update (a missing journal, a restore kind, an already queued or
	// terminal operation). It changes nothing.
	// codeHandoffStage names a failed target-package stage (spec §5.5). The
	// operation stays backed_up: the rollback source is still verified and the
	// operator can retry the same handoff after fixing the source.
	codeHandoffStage = "HUB_BACKUP_STAGE_FAILED"
	// codeHandoffTimeout is the reconcile row for a queued operation whose
	// request was never answered (spec §5.5).
	codeHandoffTimeout = "HUB_HANDOFF_TIMEOUT"
)

// HandoffConfig is one handoff request. The Web route names the operation; the
// target, package and digests are read from the journal, the record and the
// root manifest, never from the form.
type HandoffConfig struct {
	DataDir     string
	OperationID string
	// ManifestDir defaults to RootManifestDir when empty.
	ManifestDir string
	// ManifestOwner is the expected account of the root manifest tree. Zero
	// (production) means root.
	ManifestOwner int
	// RecordOwner is the expected account of the per-operation record. Zero
	// means this process: the Web is the only writer of its data directory.
	RecordOwner int
	// RequestDir defaults to RequestDir when empty.
	RequestDir string
	// Now is the clock seam. A nil Now means time.Now.
	Now func() time.Time
	// Space refuses a path whose free bytes are below need.
	Space func(path string, need uint64) error
	// Fetch stages the target package and returns its path. Nil means the
	// production path: the already-authenticated component pinned by the root
	// manifest, staged with update.FetchVerifiedSource into <dataDir>/upgrade.
	// A test injects a replacement to prove the order without a package file.
	Fetch func(ctx context.Context, dataDir, target string) (string, error)
}

// HandoffReceipt is the honest handoff result: the operation is queued for the
// dispatcher. It never claims the upgrade was applied.
type HandoffReceipt struct {
	Status        string `json:"status"`
	OperationID   string `json:"operation_id"`
	TargetVersion string `json:"target_version"`
	PackageSHA256 string `json:"package_sha256"`
}

// nowUTC is the handoff clock. Journal timestamps after the stage are taken
// fresh, so a slow download never makes a just-queued operation look older than
// it is (the reconcile pass measures the handoff timeout from updated_at).
func (cfg HandoffConfig) nowUTC() time.Time {
	if cfg.Now != nil {
		return cfg.Now().UTC()
	}
	return time.Now().UTC()
}

// Handoff re-verifies one operation and queues it for the root dispatcher.
// Contract:
//
//	input     one HandoffConfig: the operation id, the target manifest path, the
//	          data directory, the request directory and the clock seam;
//	validate  journal state (backed_up/verifying only), record digest, manifest
//	          target/digest/package agreement, request-directory shape;
//	assemble  the frozen request document for this operation;
//	effects   publish the request through the staging sibling, then journal
//	          queued; no root call, no exec, no unit attribute;
//	return    a queued receipt. The root dispatcher performs the mutation and
//	          the Web only reconciles its result afterwards.
func Handoff(ctx context.Context, cfg HandoffConfig) (HandoffReceipt, error) {
	if err := normalizeHandoffConfig(&cfg); err != nil {
		return HandoffReceipt{}, err
	}
	op, ok, err := ReadOp(cfg.DataDir, cfg.OperationID, os.Geteuid())
	if err != nil {
		return HandoffReceipt{}, backupJournalError(err)
	}
	if !ok {
		return HandoffReceipt{}, fail(CodeHandoffInvalidState, "the operation has no journal entry")
	}
	if op.Kind != KindUpdate || op.State != StateBackedUp {
		return HandoffReceipt{}, fail(CodeHandoffInvalidState,
			"the operation is a "+string(op.Kind)+" in state "+string(op.State)+", not a backed_up update")
	}

	root, err := dataPath(cfg.DataDir, DatabaseBackupDir)
	if err != nil {
		return HandoffReceipt{}, err
	}
	// Read first: Verify needs the record's own anchors, and the record is the
	// only source of the from version, schema and policy schema this handoff
	// re-checks. Both calls are metadata reads; neither mutates the record.
	record, err := backup.Read(root, cfg.OperationID, cfg.recordOwner())
	if err != nil {
		return HandoffReceipt{}, err
	}
	verified, err := backup.Verify(root, cfg.OperationID, record.FromVersion, record.DBSchema, record.PolicySchema, cfg.recordOwner())
	if err != nil {
		return HandoffReceipt{}, err
	}
	if op.FromVersion != verified.FromVersion || op.TargetVersion != verified.TargetVersion ||
		op.ManifestSHA256 != verified.ManifestSHA256 || op.PackageSHA256 != verified.PackageSHA256 ||
		op.DBSchema != verified.DBSchema {
		return HandoffReceipt{}, fail(backup.CodeMismatch,
			"the journal and the backup record name different operations")
	}

	target, err := readRootManifest(cfg.ManifestDir, op.TargetVersion, cfg.ManifestOwner)
	if err != nil {
		return HandoffReceipt{}, err
	}
	if target.SHA256 != op.ManifestSHA256 || target.Package.SHA256 != op.PackageSHA256 {
		return HandoffReceipt{}, fail(CodeManifestPackageMismatch,
			"the root manifest no longer names the operation's target package")
	}
	// The bit is read from exactly this operation's verified record: never the
	// newest record, never a directory scan, never the flat pointer copy.
	if target.DatabaseMigration == MigrationIrreversible && !verified.IrreversibleApproved {
		return HandoffReceipt{}, fail("IRREVERSIBLE_CONFIRM_REQUIRED",
			"the target declares an irreversible database migration and this operation is not approved")
	}
	// The floor is the installer's 1 GiB preflight minimum (spec §5.9): the
	// target stage must never pass a weaker requirement than a fresh backup did
	// (T3r's producer uses the same Floor at backup.go's two space checks).
	if err := cfg.Space(cfg.DataDir, Floor(payloadSize(verified))); err != nil {
		return HandoffReceipt{}, err
	}

	fetch := cfg.Fetch
	if fetch == nil {
		fetch = func(ctx context.Context, dataDir, targetVersion string) (string, error) {
			return stageTargetPackage(ctx, dataDir, targetVersion, target.Package)
		}
	}
	// The stage happens before the journal moves, so a failure cannot leave a
	// queued entry whose request does not exist (the plan's TestHandoffOrder).
	if _, stageErr := fetch(ctx, cfg.DataDir, op.TargetVersion); stageErr != nil {
		return HandoffReceipt{}, fail(codeHandoffStage,
			"the target package could not be staged ("+codeOf(stageErr)+")")
	}

	// Re-read the journal after the stage. A stage can take minutes, and the
	// 30s reconcile ticker may have failed this operation in the meantime (a
	// backed_up orphan). The forward-only queued write must never clobber that
	// fact, and a concurrent handoff must not be run twice.
	fresh, ok, err := ReadOp(cfg.DataDir, cfg.OperationID, os.Geteuid())
	if err != nil {
		return HandoffReceipt{}, backupJournalError(err)
	}
	if !ok || fresh.State != StateBackedUp || fresh.ErrorCode != op.ErrorCode || !fresh.UpdatedAt.Equal(op.UpdatedAt) {
		return HandoffReceipt{}, fail(CodeHandoffInvalidState,
			"the operation changed while the target package was being staged")
	}
	queued, err := Advance(fresh, StateQueued, "")
	if err != nil {
		return HandoffReceipt{}, err
	}
	queued.UpdatedAt = cfg.nowUTC()
	if err := WriteOp(cfg.DataDir, queued); err != nil {
		// The operation is still backed_up in the journal: nothing was handed
		// off, and the next attempt can retry with the same staged package.
		return HandoffReceipt{}, fail("HUB_BACKUP_JOURNAL_FAILED", "the queued journal state could not be published")
	}

	if _, err := WriteRequest(cfg.RequestDir, Request{
		Schema: RequestSchema, Kind: KindUpdate, OperationID: cfg.OperationID, DataDir: cfg.DataDir,
	}); err != nil {
		// The journal already says queued but no dispatcher can see the intent.
		// Fail it now rather than wait for the 120s handoff timeout: the same
		// terminal state, without a hung operation blocking later backups.
		if failed, advanceErr := Advance(queued, StateFailed, codeRequestWrite); advanceErr == nil {
			failed.UpdatedAt = cfg.nowUTC()
			_ = WriteOp(cfg.DataDir, failed)
		}
		return HandoffReceipt{}, fail(codeRequestWrite, "the dispatch request could not be published")
	}

	return HandoffReceipt{
		Status: "queued", OperationID: cfg.OperationID,
		TargetVersion: op.TargetVersion, PackageSHA256: op.PackageSHA256,
	}, nil
}

func normalizeHandoffConfig(cfg *HandoffConfig) error {
	if cfg.ManifestDir == "" {
		cfg.ManifestDir = RootManifestDir
	}
	if cfg.RequestDir == "" {
		cfg.RequestDir = RequestDir
	}
	switch {
	case cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir):
		return fail(CodeHandoffInvalidState, "the Hub data directory is not absolute")
	case !opIDRE.MatchString(cfg.OperationID):
		return fail(CodeHandoffInvalidState, "the operation id is not 32 lowercase hex")
	case cfg.Space == nil:
		return fail(CodeHandoffInvalidState, "the space callback is missing")
	case !filepath.IsAbs(cfg.ManifestDir):
		return fail(CodeHandoffInvalidState, "the root manifest directory is not absolute")
	case !filepath.IsAbs(cfg.RequestDir):
		return fail(CodeHandoffInvalidState, "the request directory is not absolute")
	}
	return nil
}

// recordOwner is the expected account of the per-operation record: zero means
// this process. The Web process is the only writer of its data directory, so
// naming it explicitly keeps the private-file rule observable in a fixture.
func (cfg HandoffConfig) recordOwner() int {
	if cfg.RecordOwner != 0 {
		return cfg.RecordOwner
	}
	return os.Geteuid()
}

// stageTargetPackage stages the already-authenticated target component under
// its fixed package name. The component is the one the root manifest pinned;
// FetchVerifiedSource verifies the source class and the digest before it writes
// one byte, and publishes with fsync + rename. A second call with the same
// digest replaces identical bytes, so a retried handoff is idempotent.
func stageTargetPackage(ctx context.Context, dataDir, targetVersion string, component upgrade.Component) (string, error) {
	name, err := PackageName(targetVersion, runtime.GOARCH)
	if err != nil {
		return "", fail(codeHandoffStage, "the target package name could not be derived")
	}
	dir := filepath.Join(dataDir, UpgradeDir)
	if err := ensurePrivateDirMode(dir); err != nil {
		return "", fail(codeHandoffStage, "the package directory is not a private directory of this account")
	}
	return update.FetchVerifiedSource(ctx, dir, name, component)
}

// payloadSize is the verified database copy's size, the dbSize term of the
// space formula. A record whose payload cannot be measured keeps the floor: the
// space check then uses the 1 GiB minimum rather than a guess.
func payloadSize(record backup.Record) uint64 {
	info, err := os.Lstat(filepath.Join(record.PayloadPath, backup.SingleDBName))
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return 0
	}
	return uint64(info.Size())
}
