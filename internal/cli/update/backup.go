package update

// The Node rollback store (#11c-3, spec §4.1-§4.4, §6) is now a thin layer over
// internal/backup (#11d Task 1). The record schema, its single encoder, the
// per-operation layout and the GC rule live in that neutral package, so the Hub
// Web process can read and write the same record bytes without importing the
// Agent's update executor (spec C17).
//
// Everything below is frozen 11c-3 surface kept for the callers that already
// exist: the type aliases, the state constants and the wrappers that pin the
// per-operation layout and PayloadTree. The Node store's semantics did not
// change — one 0700 directory per operation, one 0600 metadata record, one 0600
// payload copy of the installer snapshot, staged until a confirmed readback
// releases an older generation to the N-1 GC. Staged packages live in the update
// work directory and are never collected here
// (TestBackupGCNeverCollectsStagedPackages).
//
// The record is metadata only: no key, token or subscription URL is ever written
// into it. The payload may contain secrets (Reality keys, the subscription
// credential block, the active sing-box configuration), so it is 0700/0600,
// root-owned and never leaves the host; it is part of the GC set.

import (
	"os"
	"path/filepath"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

const (
	// DefaultBackupRoot is the fixed rollback store of a Node (spec §6). The
	// installer snapshot is promoted from its operation directory to here so
	// it survives the installer's own cleanup and a restart.
	DefaultBackupRoot = versions.AgentUpgradeBackupsDir

	// BackupRecordSchema is the on-disk schema of one rollback record.
	BackupRecordSchema = backup.RecordSchema

	backupRecordName = backup.RecordName
	backupPayloadDir = backup.PayloadDir

	// backupKeepConfirmed is N-1: after a confirmed upgrade the store keeps
	// the single newest confirmed generation, because that is the release a
	// revert must be able to go back to. Failed and staged records are always
	// retained (D1, spec §4.20).
	backupKeepConfirmed = backup.KeepConfirmed
)

// BackupRecord states. The record is written staged and only a confirmed
// readback (Task 3) may release an older generation to GC.
const (
	BackupStateStaged    = backup.StateStaged
	BackupStateConfirmed = backup.StateConfirmed
	BackupStateFailed    = backup.StateFailed
)

// BackupRecord and BackupSpec are the frozen 11c-3 types. The aliases keep the
// JSON bytes, the field names and every caller's struct literal unchanged.
type (
	BackupRecord = backup.Record
	BackupSpec   = backup.Spec
)

// backupRoot resolves the store root. Production leaves Config.BackupRoot
// empty and sets WorkDir to DefaultWorkDir, whose sibling is exactly
// DefaultBackupRoot; tests point either field at a private fixture.
func (cfg Config) backupRoot() string {
	if cfg.BackupRoot != "" {
		return cfg.BackupRoot
	}
	if cfg.WorkDir != "" {
		return filepath.Join(filepath.Dir(cfg.WorkDir), "upgrade-backups")
	}
	return DefaultBackupRoot
}

func backupRootOf(root string) string {
	if root == "" {
		return DefaultBackupRoot
	}
	return root
}

// RequireBackupDir returns the 0700 directory of one operation, creating the
// store and the operation directory when absent.
func RequireBackupDir(root, operationID string) (string, error) {
	return backup.Dir(backupRootOf(root), operationID)
}

// WriteBackupRecord promotes the installer snapshot into the private store and
// writes the metadata record. A retry of the same operation re-verifies the
// existing record instead of overwriting a rollback source. The returned path is
// the record file.
func WriteBackupRecord(root string, spec BackupSpec) (string, error) {
	dir := backupRootOf(root)
	record, err := backup.Write(dir, spec, backup.Payload{
		Kind:        backup.PayloadTree,
		SnapshotDir: spec.SnapshotDir,
	})
	if err != nil {
		return "", err
	}
	recordPath, _ := backup.Paths(filepath.Join(dir, record.OperationID))
	return recordPath, nil
}

// VerifyBackupRecord is the handoff precondition (11c-3 Task 2): the record and
// its payload are read back from disk under the private-mode rules. It never
// mutates anything.
func VerifyBackupRecord(root, operationID, fromVersion string, dbSchema int64, policySchema int) (BackupRecord, error) {
	return backup.Verify(backupRootOf(root), operationID, fromVersion, dbSchema, policySchema, os.Geteuid())
}

// GCBackups collects confirmed generations beyond keep, newest first. Staged
// and failed records are never candidates: a failed upgrade still needs its
// rollback source.
func GCBackups(root string, keep int) ([]string, error) {
	return backup.GC(backupRootOf(root), keep)
}

// readBackupRecord reads the record of one known operation directory, state
// agnostically: a confirmed record is a legitimate explicit rollback target and a
// failed one must stay readable for manual recovery.
func readBackupRecord(opDir, operationID string) (BackupRecord, error) {
	return backup.ReadRecord(opDir, operationID, os.Geteuid())
}

// writeRecordFile replaces the record of one operation directory in place,
// always through the single encoder.
func writeRecordFile(opDir string, record BackupRecord) error {
	return backup.WriteRecord(opDir, record)
}
