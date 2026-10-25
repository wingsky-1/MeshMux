package hubupgrade

// The flat "latest" pointer of #11d (spec §5.2.1, D1). After a per-operation
// record is committed, one byte-identical copy is published at
// <data-dir>/database-backup/record.json.
//
// It exists for exactly one reader: the frozen `schemaTooNew` check of 11c-3
// (internal/web/store_database_gate.go) does an existence-only Lstat of that
// flat path, so an old binary must still be able to point an operator at a
// verified backup record after the store moved to per-operation directories.
// Nothing in 11d reads it: Read/Verify/Confirm/GC/restore/dispatcher/approve all
// work on <op32hex>/record.json. A stale or missing pointer therefore loses a
// diagnostic hint, never a rollback source.
//
// The copy is taken from the committed per-operation record bytes, not
// re-encoded, so the two files cannot disagree about the record they name.

import (
	"os"
	"path/filepath"

	"github.com/wingsky-1/MeshMux/internal/backup"
)

// PointerName is the flat pointer file inside DatabaseBackupDir. It is the path
// the frozen schemaTooNew Lstat names and the only flat path 11d writes.
const PointerName = backup.RecordName

// PublishFlatPointer republishes <root>/<operationID>/record.json as
// <root>/record.json. The order is: read the committed record bytes, clear a
// stale scratch file, write 0600 with O_EXCL, fsync, rename, fsync the store
// root. A failure leaves the previous pointer (or none) in place and never
// touches the per-operation record, the payload or the journal.
func PublishFlatPointer(root, operationID string) error {
	if !filepath.IsAbs(root) {
		return fail("HUB_BACKUP_POINTER_STALE", "the Hub backup root is not absolute")
	}
	if !opIDRE.MatchString(operationID) {
		return fail("HUB_BACKUP_POINTER_STALE", "the operation id is not 32 lowercase hex")
	}
	source := filepath.Join(root, operationID, backup.RecordName)
	body, err := os.ReadFile(source)
	if err != nil || len(body) == 0 {
		return fail("HUB_BACKUP_POINTER_STALE", "the per-operation record could not be read back")
	}
	path := filepath.Join(root, PointerName)
	part := path + ".part"
	// A crash between the write and the rename leaves a scratch file; it is
	// never trusted, only replaced (and a planted symlink is unlinked, not
	// followed).
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return fail("HUB_BACKUP_POINTER_STALE", "the pointer scratch path could not be cleared")
	}
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail("HUB_BACKUP_POINTER_STALE", "the pointer copy could not be written")
	}
	_, writeErr := file.Write(body)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(part)
		return fail("HUB_BACKUP_POINTER_STALE", "the pointer copy could not be written")
	}
	if err := os.Rename(part, path); err != nil {
		_ = os.Remove(part)
		return fail("HUB_BACKUP_POINTER_STALE", "the pointer copy could not be published")
	}
	if err := syncDir(root); err != nil {
		return fail("HUB_BACKUP_POINTER_STALE", "the pointer directory could not be flushed")
	}
	return nil
}
