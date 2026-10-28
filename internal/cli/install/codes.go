package install

// The stable installer error codes live in install/core; this file re-exports
// them so callers keep comparing install.Code* values. The numeric and textual
// values have exactly one definition, in install/core/codes.go.

import (
	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

const (
	CodeRollbackSnapshotInvalid  = core.CodeRollbackSnapshotInvalid
	CodeRollbackAnchorMismatch   = core.CodeRollbackAnchorMismatch
	CodeRollbackRestoreFailed    = core.CodeRollbackRestoreFailed
	CodeRollbackSourceInvalid    = core.CodeRollbackSourceInvalid
	CodeRollbackSourceFailed     = core.CodeRollbackSourceFailed
	CodeRollbackSourceMissing    = core.CodeRollbackSourceMissing
	CodeRollbackLedgerInvalid    = core.CodeRollbackLedgerInvalid
	CodeRollbackLedgerFailed     = core.CodeRollbackLedgerFailed
	CodeRollbackClaimClearFailed = core.CodeRollbackClaimClearFailed
	CodeRollbackStartFailed      = core.CodeRollbackStartFailed
	CodeOperationIDInvalid       = core.CodeOperationIDInvalid
	CodeInstallStateInvalid      = core.CodeInstallStateInvalid
	CodeInstallStateUnavailable  = core.CodeInstallStateUnavailable
	CodeInstallStateWriteFailed  = core.CodeInstallStateWriteFailed
	CodeRepairStateMissing       = core.CodeRepairStateMissing
	CodeAgentConfigUnavailable   = core.CodeAgentConfigUnavailable
	CodeConfigConflict           = core.CodeConfigConflict
)
