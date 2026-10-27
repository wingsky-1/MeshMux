package hubupgrade

// Confirmation of Hub backup generations (#11d Task 3r, spec §5.2.1, §5.5, R2).
//
// backup.Confirm owns the record transition and its payload re-verification. The
// Hub adds the one rule the record layer deliberately does not own: the
// irreversible approval bit is a per-attempt gate, so it is cleared when the
// attempt is confirmed. Leaving it set would make one irreversible upgrade block
// every later backup forever (R2).
//
// GC is the caller's timing (spec C12): ConfirmBackup does not collect, and
// CleanupConfirmed (gc.go) is the explicit entry with the Hub's keep >= 2 policy.

import (
	"path/filepath"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

// ConfirmBackup confirms one staged per-operation record and clears the
// irreversible approval bit it carried.
//
// The clear is a second in-place record write after backup.Confirm succeeded. A
// failure there returns the error: the record is confirmed but still carries the
// bit, which only means the next attempt must be approved again — never that a
// confirmed generation was silently dropped.
func ConfirmBackup(dataDir, operationID, targetVersion, packageSHA256 string, now time.Time) (backup.Record, error) {
	root, err := dataPath(dataDir, DatabaseBackupDir)
	if err != nil {
		return backup.Record{}, err
	}
	record, err := backup.Confirm(root, operationID, targetVersion, packageSHA256, now)
	if err != nil {
		return backup.Record{}, err
	}
	if !record.IrreversibleApproved {
		return record, nil
	}
	// Confirm already proved the operation directory exists under the private
	// rules; the clear is an in-place update of that same record.
	record.IrreversibleApproved = false
	if err := backup.WriteRecord(filepath.Join(root, operationID), record); err != nil {
		return backup.Record{}, err
	}
	return record, nil
}
