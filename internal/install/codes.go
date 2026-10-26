package install

import "github.com/wingsky-1/MeshMux/internal/versions"

// The installer's exported stable codes.
//
// A code that another package has to compare against — the Agent's revert
// mapping in internal/update reads the rollback family — is exported here, next
// to the phase that emits it. The literal exists exactly once; every call site
// uses the identifier, so a typo cannot create a second "almost the same" code.

// The rollback family. internal/update maps these onto the Agent's receipt
// vocabulary, so both sides must compare the same bytes.
const (
	// CodeRollbackSnapshotInvalid means the recorded snapshot tree is not the
	// private, verified shape this installer wrote.
	CodeRollbackSnapshotInvalid = "ROLLBACK_SNAPSHOT_INVALID"
	// CodeRollbackAnchorMismatch means the snapshot names another installed
	// release than the one the caller asked to restore.
	CodeRollbackAnchorMismatch = "ROLLBACK_ANCHOR_MISMATCH"
	// CodeRollbackRestoreFailed means the file restore itself failed.
	CodeRollbackRestoreFailed = "ROLLBACK_RESTORE_FAILED"
	// CodeRollbackSourceInvalid means no usable restore source exists.
	CodeRollbackSourceInvalid = "ROLLBACK_SOURCE_INVALID"
	// CodeRollbackSourceFailed means reading the restore source failed.
	CodeRollbackSourceFailed = "ROLLBACK_SOURCE_FAILED"
	// CodeRollbackSourceMissing means the restore source is absent.
	CodeRollbackSourceMissing = "ROLLBACK_SOURCE_MISSING"
	// CodeRollbackLedgerInvalid means the restored ledger is not a valid one.
	CodeRollbackLedgerInvalid = "ROLLBACK_LEDGER_INVALID"
	// CodeRollbackLedgerFailed means writing the restored ledger failed.
	CodeRollbackLedgerFailed = "ROLLBACK_LEDGER_FAILED"
	// CodeRollbackClaimClearFailed means the crash claim could not be removed,
	// so the host may still look mid-upgrade.
	CodeRollbackClaimClearFailed = "ROLLBACK_CLAIM_CLEAR_FAILED"
	// CodeRollbackStartFailed means the restored services did not start.
	CodeRollbackStartFailed = "ROLLBACK_START_FAILED"
)

// Codes shared with the CLI and the Agent executor.
const (
	// CodeOperationIDInvalid means an operation id is not 32 lowercase hex.
	// The value is frozen by internal/backup's record codes; this constant is
	// the installer's name for the same contract.
	CodeOperationIDInvalid = "OPERATION_ID_INVALID"
	// CodeInstallStateInvalid means the installer ledger is not the strict
	// shape this build wrote.
	CodeInstallStateInvalid = "INSTALL_STATE_INVALID"
	// CodeInstallStateUnavailable means the installer ledger cannot be read.
	CodeInstallStateUnavailable = "INSTALL_STATE_UNAVAILABLE"
	// CodeInstallStateWriteFailed means the ledger write failed.
	CodeInstallStateWriteFailed = "INSTALL_STATE_WRITE_FAILED"
	// CodeRepairStateMissing means a --repair run found no recorded install.
	CodeRepairStateMissing = "REPAIR_STATE_MISSING"
	// CodeAgentConfigUnavailable means the recorded Agent configuration is
	// unreadable or is not the private shape.
	CodeAgentConfigUnavailable = "AGENT_CONFIG_UNAVAILABLE"
	// CodeConfigConflict means the recorded configuration differs from the
	// request; an in-place repair never changes identity or ports. The value is
	// cross-layer (the Hub restore and the Agent revert refuse with the same
	// code), so it is owned by the versions leaf.
	CodeConfigConflict = versions.CodeConfigConflict
)
