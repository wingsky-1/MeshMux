package backup

// The ledger grammar the backup group reads. The journal, paths, codes and the
// stable error helpers have one definition in the sibling ledger package; these
// aliases keep the backup files readable without a second copy and give the
// tests the same names they used before the split. They carry no behavior of
// their own.

import ledger "github.com/wingsky-1/MeshMux/internal/cli/hubupgrade/ledger"

type (
	// Op is the one operation journal document.
	Op = ledger.Op
	// State is the frozen journal state.
	State = ledger.State
)

const (
	DatabaseBackupDir = ledger.DatabaseBackupDir
	UpgradeDir        = ledger.UpgradeDir
	HubUpgradeDir     = ledger.HubUpgradeDir
	OpsDir            = ledger.OpsDir
	RootManifestDir   = ledger.RootManifestDir

	KindUpdate = ledger.KindUpdate
	OpSchema   = ledger.OpSchema

	StateBackingUp  = ledger.StateBackingUp
	StateBackedUp   = ledger.StateBackedUp
	StateQueued     = ledger.StateQueued
	StateApplying   = ledger.StateApplying
	StateRestarting = ledger.StateRestarting
	StateVerifying  = ledger.StateVerifying
	StatePartial    = ledger.StatePartial
	StateConfirmed  = ledger.StateConfirmed
	StateFailed     = ledger.StateFailed

	CodeBackupIdentityMissing  = ledger.CodeBackupIdentityMissing
	CodeMigrationBackupPointer = ledger.CodeMigrationBackupPointer
)

var (
	fail           = ledger.Fail
	codeOf         = ledger.CodeOf
	dataPath       = ledger.DataPath
	ownedBy        = ledger.OwnedBy
	opIDRE         = ledger.OperationIDPattern
	digestRE       = ledger.DigestPattern
	targetRE       = ledger.ReleaseVersionPattern
	compareRelease = ledger.CompareRelease

	OldPackageName = ledger.OldPackageName

	LockBackupProduce = ledger.LockBackupProduce
	Busy              = ledger.Busy
	ListOps           = ledger.ListOps
	WriteOp           = ledger.WriteOp
	ReadOp            = ledger.ReadOp
	Advance           = ledger.Advance

	backupJournalError = ledger.JournalError
	syncDir            = ledger.SyncDir
)
