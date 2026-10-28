package dispatch

// The ledger grammar and backup operations the dispatch group reads. The
// journal, claim, paths and codes have one definition in the sibling ledger
// package; the record producer and its pointer/space helpers have one definition
// in the sibling backup package. These aliases carry no behavior of their own;
// they keep one name for one fact at the dispatch boundary.

import (
	hubbackup "github.com/wingsky-1/MeshMux/internal/cli/hubupgrade/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade/ledger"
)

type (
	// Op is the one operation journal document.
	Op = ledger.Op
	// State is the frozen journal state.
	State = ledger.State
	// Claim is the root-written crash anchor.
	Claim = ledger.Claim
	// Pins is the complete four-source pin set of one claim.
	Pins = ledger.Pins
	// TargetManifest is one authenticated root target.
	TargetManifest = hubbackup.TargetManifest
)

const (
	DatabaseBackupDir = ledger.DatabaseBackupDir
	UpgradeDir        = ledger.UpgradeDir
	HubUpgradeDir     = ledger.HubUpgradeDir
	OpsDir            = ledger.OpsDir
	RootManifestDir   = ledger.RootManifestDir

	KindUpdate  = ledger.KindUpdate
	KindRestore = ledger.KindRestore
	OpSchema    = ledger.OpSchema

	JournalMaxBytes = ledger.JournalMaxBytes

	ClaimDir           = ledger.ClaimDir
	ClaimSchema        = ledger.ClaimSchema
	ClaimPhaseSwapping = ledger.ClaimPhaseSwapping
	ClaimPhaseRepinned = ledger.ClaimPhaseRepinned

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

	CodeHandoffInvalidState     = ledger.CodeHandoffInvalidState
	CodeHandoffRequestInvalid   = ledger.CodeHandoffRequestInvalid
	CodeManifestPackageMismatch = ledger.CodeManifestPackageMismatch
	CodeRestoreUnitShapeInvalid = ledger.CodeRestoreUnitShapeInvalid

	MigrationIrreversible = hubbackup.MigrationIrreversible
	minHubKeep            = hubbackup.MinHubKeep
	codePointerStale      = hubbackup.CodePointerStale
)

var (
	fail     = ledger.Fail
	codeOf   = ledger.CodeOf
	dataPath = ledger.DataPath
	ownedBy  = ledger.OwnedBy
	opIDRE   = ledger.OperationIDPattern
	digestRE = ledger.DigestPattern
	targetRE = ledger.ReleaseVersionPattern

	ReadOp            = ledger.ReadOp
	WriteOp           = ledger.WriteOp
	Advance           = ledger.Advance
	ListOps           = ledger.ListOps
	Busy              = ledger.Busy
	LockBackupProduce = ledger.LockBackupProduce
	PackageName       = ledger.PackageName
	ReadClaim         = ledger.ReadClaim

	ensurePrivateDir    = ledger.EnsurePrivateDir
	syncDir             = ledger.SyncDir
	syncDirectory       = ledger.SyncDirectory
	marshalIndentNoHTML = ledger.MarshalIndentNoHTML
	meshmuxGroupID      = ledger.MeshmuxGroupID
	backupJournalError  = ledger.JournalError

	ConfirmBackup               = hubbackup.ConfirmBackup
	PublishFlatPointer          = hubbackup.PublishFlatPointer
	CleanupConfirmed            = hubbackup.CleanupConfirmed
	discardUncommittedOperation = hubbackup.DiscardUncommittedOperation
	ensurePrivateDirMode        = hubbackup.EnsurePrivateDirMode
	pointerLogCode              = hubbackup.PointerLogCode
	readRootManifest            = hubbackup.ReadRootManifestFor
	RequiredSpace               = hubbackup.RequiredSpace
	Floor                       = hubbackup.Floor
)
