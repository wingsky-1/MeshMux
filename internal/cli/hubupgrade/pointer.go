package hubupgrade

// The flat "latest" pointer of #11d (spec §5.2.1, D1). After a per-operation
// record is committed, one byte-identical copy is published at
// <data-dir>/database-backup/record.json.
//
// It exists for exactly one reader: the database gate of 11c-3
// (internal/control/store/store_database_gate.go) names the flat path, so a
// binary that meets a database written by a newer release can point the operator
// at a verified backup record after the store moved to per-operation directories.
// The read half now lives in the record layer (backup.ReadFlatPointer), because
// the installer needs the same chain and only that leaf package is importable by
// both. Nothing in the Web upgrade handoff reads it: Read/Verify/Confirm/GC/
// restore/dispatcher/approve all work on <op32hex>/record.json. A stale or
// missing pointer therefore loses a diagnostic hint, never a rollback source.
//
// The copy is taken from the committed per-operation record bytes, not
// re-encoded, so the two files cannot disagree about the record they name. The
// source is read through the record layer's validating read (expected owner =
// this process, as the Web is the only writer), so a symlink, a loose mode, a
// foreign owner, a trailing-data document or a record naming another operation
// is refused before one byte reaches the pointer.

import (
	"os"
	"path/filepath"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

// PointerName is the flat pointer file inside DatabaseBackupDir. It is the path
// the database gate names and the only flat path 11d writes.
const PointerName = backup.RecordName

// Pointer failure codes. Both are non-fatal for the operation (the journal stays
// backed_up and the per-operation record is authoritative); they differ in what
// they say about the pointer on disk, because an operator debugging a downgrade
// must not be told "stale" when the copy was in fact published.
const (
	// codePointerStale means no new pointer was published: the source record was
	// unreadable or the copy could not be written/renamed.
	codePointerStale = "HUB_BACKUP_POINTER_STALE"
	// codePointerUnflushed means the pointer was renamed into place but the
	// store root could not be fsynced, so it may not survive a power loss.
	codePointerUnflushed = "HUB_BACKUP_POINTER_UNFLUSHED"
)

// pointerRootSync is the store-root fsync seam of a published pointer. Production
// syncs the real directory; a test proves a flush failure is reported as
// unflushed rather than stale.
var pointerRootSync = syncDir

// PublishFlatPointer republishes <root>/<operationID>/record.json as
// <root>/record.json. The order is: read the committed record bytes through the
// record layer's private-mode-validating read, clear a stale scratch file, write
// 0600 with O_EXCL, fsync, rename, fsync the store root. A failure leaves the
// previous pointer (or none) in place and never touches the per-operation
// record, the payload or the journal.
//
// The final root fsync is reported as codePointerUnflushed: the rename already
// happened, so the new pointer is visible now and only its durability is in
// doubt.
func PublishFlatPointer(root, operationID string) error {
	if !filepath.IsAbs(root) {
		return fail(codePointerStale, "the Hub backup root is not absolute")
	}
	if !opIDRE.MatchString(operationID) {
		return fail(codePointerStale, "the operation id is not 32 lowercase hex")
	}
	body, err := backup.ReadRecordBytes(filepath.Join(root, operationID), operationID, os.Geteuid())
	if err != nil {
		return fail(codePointerStale, "the per-operation record is not a private, readable record of this operation")
	}
	if len(body) == 0 {
		return fail(codePointerStale, "the per-operation record is empty")
	}
	path := filepath.Join(root, PointerName)
	part := path + ".part"
	// A crash between the write and the rename leaves a scratch file; it is
	// never trusted, only replaced (and a planted symlink is unlinked, not
	// followed).
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return fail(codePointerStale, "the pointer scratch path could not be cleared")
	}
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail(codePointerStale, "the pointer copy could not be written")
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
		return fail(codePointerStale, "the pointer copy could not be written")
	}
	if err := os.Rename(part, path); err != nil {
		_ = os.Remove(part)
		return fail(codePointerStale, "the pointer copy could not be published")
	}
	if err := pointerRootSync(root); err != nil {
		return fail(codePointerUnflushed, "the pointer was published but its directory could not be flushed")
	}
	return nil
}
