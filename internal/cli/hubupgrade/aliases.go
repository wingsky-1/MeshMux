// Package hubupgrade is the non-privileged half of the Hub self-upgrade of
// #11d (spec §5.2, §5.5, §5.8, §5.9). It is imported by internal/web, which owns
// the SQLite handle and therefore supplies the VACUUM, integrity, schema and
// space callbacks; it must never import internal/web or internal/install.
//
// The implementation is split into three acyclic groups below this forwarding
// package:
//
//   - ledger: the operation journal, claim, paths, codes and SemVer grammar;
//   - backup: the verified per-operation database backup and snapshot producer;
//   - dispatch: handoff, request/result documents, unit shape and reconcile.
//
// The privileged executor lives in the separate subpackage rootexec and is
// started only by the fixed systemd dispatcher. The Web process has no
// privilege, no ledger read and no way to name an executable: it writes the
// per-operation backup record, the journal and a request file under /run.
//
// The exported names below are the historical API of this package. They are
// forwarded so callers (internal/web, cmd/meshmux and rootexec) keep one import
// path and no call-site change; new code below this package should import the
// group it actually needs.
package hubupgrade

import (
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade/dispatch"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade/ledger"
)

// The operation grammar owned by the ledger group.
type (
	// State is one frozen journal state.
	State = ledger.State
	// Op is one operation journal document.
	Op = ledger.Op
	// Pins is the complete four-source pin set of one claim.
	Pins = ledger.Pins
	// Claim is the crash anchor of one update execution.
	Claim = ledger.Claim
	// BackupConfig is one Hub backup request.
	BackupConfig = backup.BackupConfig
	// BackupReceipt is the honest backup success receipt.
	BackupReceipt = backup.BackupReceipt
	// MigrationSnapshotConfig is one pre-migration snapshot request.
	MigrationSnapshotConfig = backup.MigrationSnapshotConfig
	// TargetManifest is one authenticated target manifest.
	TargetManifest = backup.TargetManifest
	// Request is one dispatch intent.
	Request = dispatch.Request
	// HandoffConfig is one handoff request.
	HandoffConfig = dispatch.HandoffConfig
	// HandoffReceipt is the queued handoff result.
	HandoffReceipt = dispatch.HandoffReceipt
	// ResultPhase is one frozen progress phase.
	ResultPhase = dispatch.ResultPhase
	// Result is one progress document.
	Result = dispatch.Result
	// RestoredMarker is the write-once restore fact.
	RestoredMarker = dispatch.RestoredMarker
	// ConfirmHooks are the side effects after a record is confirmed.
	ConfirmHooks = dispatch.ConfirmHooks
	// ReconcileConfig is one reconcile pass.
	ReconcileConfig = dispatch.ReconcileConfig
	// ReconcileChange is one journal transition of a pass.
	ReconcileChange = dispatch.ReconcileChange
	// ReconcileError is one operation a pass could not judge.
	ReconcileError = dispatch.ReconcileError
	// ReconcileReport is one pass's honest result.
	ReconcileReport = dispatch.ReconcileReport
)

// Fixed locations and document schemas.
const (
	// DatabaseBackupDir is the per-operation Hub backup store.
	DatabaseBackupDir = ledger.DatabaseBackupDir
	// UpgradeDir stages the old and target Hub packages.
	UpgradeDir = ledger.UpgradeDir
	// HubUpgradeDir carries the operation journal and the restored marker.
	HubUpgradeDir = ledger.HubUpgradeDir
	// OpsDir is the journal directory below HubUpgradeDir.
	OpsDir = ledger.OpsDir
	// RootManifestDir is where a root operator pre-places target manifests.
	RootManifestDir = ledger.RootManifestDir
	// ClaimDir is the fixed root-owned upgrade directory.
	ClaimDir = ledger.ClaimDir
	// ResultsDir is the fixed result directory.
	ResultsDir = dispatch.ResultsDir
	// RequestDir is the fixed request directory.
	RequestDir = dispatch.RequestDir
	// RequestStagingDir is the compatibility staging sibling.
	RequestStagingDir = dispatch.RequestStagingDir
	// RequestDoneDir holds consumed requests.
	RequestDoneDir = dispatch.RequestDoneDir
	// PointerName is the flat pointer file inside DatabaseBackupDir.
	PointerName = backup.PointerName

	// Operation kinds.
	KindUpdate  = ledger.KindUpdate
	KindRestore = ledger.KindRestore

	// Document schemas and bounds.
	OpSchema        = ledger.OpSchema
	JournalMaxBytes = ledger.JournalMaxBytes
	ClaimSchema     = ledger.ClaimSchema
	RequestSchema   = dispatch.RequestSchema
	RequestMaxBytes = dispatch.RequestMaxBytes
	ResultSchema    = dispatch.ResultSchema
	ResultMaxBytes  = dispatch.ResultMaxBytes
	RestoredSchema  = dispatch.RestoredSchema
)

// The frozen journal state set.
const (
	StateBackingUp  = ledger.StateBackingUp
	StateBackedUp   = ledger.StateBackedUp
	StateQueued     = ledger.StateQueued
	StateApplying   = ledger.StateApplying
	StateRestarting = ledger.StateRestarting
	StateVerifying  = ledger.StateVerifying
	StatePartial    = ledger.StatePartial
	StateConfirmed  = ledger.StateConfirmed
	StateReverted   = ledger.StateReverted
	StateFailed     = ledger.StateFailed
)

// Claim phases, migration classes and reconcile bounds.
const (
	ClaimPhaseSwapping    = ledger.ClaimPhaseSwapping
	ClaimPhaseRepinned    = ledger.ClaimPhaseRepinned
	MigrationAdditive     = backup.MigrationAdditive
	MigrationIrreversible = backup.MigrationIrreversible

	// OrphanTimeout is the pure-age bound of backing_up, backed_up, applying
	// and restarting.
	OrphanTimeout = dispatch.OrphanTimeout
	// HandoffTimeout is the bound on a queued operation no dispatcher answered.
	HandoffTimeout = dispatch.HandoffTimeout
)

// The frozen result phases.
const (
	ResultAccepted        = dispatch.ResultAccepted
	ResultSwapping        = dispatch.ResultSwapping
	ResultRestarting      = dispatch.ResultRestarting
	ResultRestartAccepted = dispatch.ResultRestartAccepted
	ResultRestored        = dispatch.ResultRestored
	ResultFailed          = dispatch.ResultFailed
	ResultPartial         = dispatch.ResultPartial
)

// The stable error codes both halves of the Hub self-upgrade emit.
const (
	CodeHandoffBusy             = ledger.CodeHandoffBusy
	CodeHandoffInvalidState     = ledger.CodeHandoffInvalidState
	CodeHandoffRequestInvalid   = ledger.CodeHandoffRequestInvalid
	CodeBackupIdentityMissing   = ledger.CodeBackupIdentityMissing
	CodeMigrationBackupPointer  = ledger.CodeMigrationBackupPointer
	CodeRestoreBinaryMissing    = ledger.CodeRestoreBinaryMissing
	CodeRestoreDigestMismatch   = ledger.CodeRestoreDigestMismatch
	CodeRestoreUnitShapeInvalid = ledger.CodeRestoreUnitShapeInvalid
	CodeManifestPackageMismatch = ledger.CodeManifestPackageMismatch
	CodeSharedBinaryRepinFailed = ledger.CodeSharedBinaryRepinFailed
)

// Journal, claim and manifest entry points.
var (
	// PackageName is the fixed file name of the target package inside UpgradeDir.
	PackageName = ledger.PackageName
	// OldPackageName is the fixed restore-source package name.
	OldPackageName = ledger.OldPackageName
	// LockBackupProduce acquires the process-wide producer mutex.
	LockBackupProduce = ledger.LockBackupProduce
	// Advance moves one journal document forward.
	Advance = ledger.Advance
	// WriteOp publishes one journal document.
	WriteOp = ledger.WriteOp
	// ReadOp returns one journal document.
	ReadOp = ledger.ReadOp
	// ListOps returns every readable journal document.
	ListOps = ledger.ListOps
	// Busy returns the newest non-terminal operation.
	Busy = ledger.Busy
	// LatestBackup returns the current update operation and its record.
	LatestBackup = ledger.LatestBackup
	// ReadClaim returns the crash claim of this upgrade directory.
	ReadClaim = ledger.ReadClaim
	// WriteClaim publishes one claim atomically.
	WriteClaim = ledger.WriteClaim
	// RemoveClaim deletes the claim and flushes its directory.
	RemoveClaim = ledger.RemoveClaim
	// ReadRootManifest authenticates the root manifest for the production owner.
	ReadRootManifest = backup.ReadRootManifest
	// ReadRootManifestFor authenticates the root manifest for a named owner.
	ReadRootManifestFor = backup.ReadRootManifestFor
)

// Backup, space and confirmation entry points.
var (
	// CreateBackup performs the ordered pre-upgrade backup producer.
	CreateBackup = backup.CreateBackup
	// CreateMigrationSnapshot performs the ordered pre-migration snapshot.
	CreateMigrationSnapshot = backup.CreateMigrationSnapshot
	// PublishFlatPointer republishes the flat existence-only pointer.
	PublishFlatPointer = backup.PublishFlatPointer
	// RequiredSpace is the free bytes one Hub upgrade needs.
	RequiredSpace = backup.RequiredSpace
	// Floor raises the requirement to the installer's 1 GiB preflight floor.
	Floor = backup.Floor
	// CheckFreeSpace is the production space callback.
	CheckFreeSpace = backup.CheckFreeSpace
	// CleanupConfirmed collects confirmed generations beyond keep.
	CleanupConfirmed = backup.CleanupConfirmed
	// ConfirmBackup confirms one staged record and clears its approval bit.
	ConfirmBackup = backup.ConfirmBackup
	// ConfirmAndCollect confirms, refreshes the pointer and collects.
	ConfirmAndCollect = dispatch.ConfirmAndCollect
)

// Dispatch, reconcile and document entry points.
var (
	// Reconcile runs one pass over every journaled operation.
	Reconcile = dispatch.Reconcile
	// ReadRestoredMarker returns the restore fact for the current account.
	ReadRestoredMarker = dispatch.ReadRestoredMarker
	// ReadRestoredMarkerFor returns the restore fact for a named owner.
	ReadRestoredMarkerFor = dispatch.ReadRestoredMarkerFor
	// Handoff re-verifies one operation and queues it for the dispatcher.
	Handoff = dispatch.Handoff

	// WriteRequest publishes one request document.
	WriteRequest = dispatch.WriteRequest
	// ReadRequest parses one request document.
	ReadRequest = dispatch.ReadRequest
	// ReadRequestAt reads a request relative to a directory handle.
	ReadRequestAt = dispatch.ReadRequestAt
	// OpenRequestDir opens and proves the watched directory.
	OpenRequestDir = dispatch.OpenRequestDir
	// OpenRequestDoneDir opens and proves the done directory.
	OpenRequestDoneDir = dispatch.OpenRequestDoneDir
	// DrainAt moves request entries into the done directory.
	DrainAt = dispatch.DrainAt
	// RemoveRequest unlinks one request document.
	RemoveRequest = dispatch.RemoveRequest

	// ParseWebExecStart returns the argv of one simple ExecStart line.
	ParseWebExecStart = dispatch.ParseWebExecStart
	// DataDirFromArgv extracts the single --data-dir value.
	DataDirFromArgv = dispatch.DataDirFromArgv
	// RenderDataDirDropIn renders the one restore drop-in.
	RenderDataDirDropIn = dispatch.RenderDataDirDropIn
	// ApplyExecStartDropIn folds a drop-in onto the effective argv.
	ApplyExecStartDropIn = dispatch.ApplyExecStartDropIn

	// WriteResult publishes one result document.
	WriteResult = dispatch.WriteResult
	// ReadResult returns the progress document of one operation.
	ReadResult = dispatch.ReadResult
)
