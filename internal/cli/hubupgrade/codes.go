package hubupgrade

// The stable error_code values that both halves of the Hub self-upgrade emit.
//
// Ownership: this package is the control-layer definition; internal/hubupgrade/
// rootexec consumes the same identifiers instead of keeping a second copy of the
// same literal. A code is an operator-visible contract (spec §5.9 grouping), so
// the value may never drift between the Web-side producer and the root-side
// executor that answers the same operation.
//
// Codes that only one half can emit stay private to that half.
const (
	// CodeHandoffBusy means another upgrade/restore already owns the host.
	CodeHandoffBusy = "HUB_HANDOFF_BUSY"
	// CodeHandoffInvalidState means the journal is not in a state this step
	// may act on.
	CodeHandoffInvalidState = "HUB_HANDOFF_INVALID_STATE"
	// CodeHandoffRequestInvalid means the request document is not the frozen
	// shape.
	CodeHandoffRequestInvalid = "HUB_HANDOFF_REQUEST_INVALID"
	// CodeBackupIdentityMissing means the running digest or its ledger entry
	// cannot be proven.
	CodeBackupIdentityMissing = "HUB_BACKUP_IDENTITY_MISSING"
	// CodeMigrationBackupPointer means the flat pointer of the pre-migration
	// database snapshot could not be published, so the schema migration must not
	// run (the downgraded binary's SCHEMA_TOO_NEW guidance needs that record).
	CodeMigrationBackupPointer = "HUB_BACKUP_POINTER_FAILED"
	// CodeRestoreBinaryMissing means the old package a restore must start does
	// not exist.
	CodeRestoreBinaryMissing = "HUB_RESTORE_BINARY_MISSING"
	// CodeRestoreDigestMismatch means a staged file's bytes do not match the
	// frozen record.
	CodeRestoreDigestMismatch = "HUB_RESTORE_DIGEST_MISMATCH"
	// CodeRestoreUnitShapeInvalid means the installed web unit (with its
	// drop-ins) does not bound one --data-dir the restore may flip.
	CodeRestoreUnitShapeInvalid = "HUB_RESTORE_UNIT_SHAPE_INVALID"
	// CodeManifestPackageMismatch means the target manifest pins another
	// package than the frozen record.
	CodeManifestPackageMismatch = "HUB_MANIFEST_PACKAGE_MISMATCH"
	// CodeSharedBinaryRepinFailed means the co-located Line pins could not be
	// written; the binary may already have moved, so the caller reports
	// partial.
	CodeSharedBinaryRepinFailed = "HUB_SHARED_BINARY_REPIN_FAILED"
)
