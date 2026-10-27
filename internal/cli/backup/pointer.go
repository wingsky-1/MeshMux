package backup

// The flat "latest" pointer of a per-operation store.
//
// One store root may publish one byte-identical copy of its newest committed
// record at <root>/record.json. The Hub is the only producer (the Web upgrade
// handoff, and now the pre-migration snapshot), and it has exactly one reader
// that must not know the operation id in advance: the database gate that refuses
// a file written by a newer binary (SCHEMA_TOO_NEW). That gate has to name a
// backup that really exists, and it must be able to say whether the generation
// belongs to the binary that is asking.
//
// ReadFlatPointer is the one resolver of that chain: <root>/record.json ->
// <root>/<operation_id>/record.json -> <root>/<operation_id>/payload/meshmux.db.
// It reuses the record reader (private 0600 file, strict schema-1 decode) and the
// committed-generation reader, so a hand-edited pointer, a half-overwritten copy
// or a pointer to a collected generation is refused instead of being presented as
// a restore source. The payload digest is not re-hashed here: a restore still
// proves the bytes before it opens them.

import (
	"os"
	"path/filepath"
)

// FlatPointer is the resolved flat pointer of one per-operation store.
type FlatPointer struct {
	// RecordPath is <root>/record.json.
	RecordPath string
	// PayloadPath is the one database copy the generation holds:
	// <root>/<operation_id>/payload/meshmux.db.
	PayloadPath string
	// Record is the committed per-operation record, not the flat copy.
	Record Record
}

// ReadFlatPointer resolves <root>/record.json and the generation it names for the
// account that owns the store. A missing pointer is CodeMissing; a pointer whose
// generation, record identity or payload is not the private verified shape is
// CodeCorrupt.
func ReadFlatPointer(root string, expectedOwner int) (FlatPointer, error) {
	if !filepath.IsAbs(root) {
		return FlatPointer{}, fail(CodeMissing, "the rollback store path must be absolute")
	}
	recordPath := filepath.Join(root, RecordName)
	_, record, err := readRecordFile(recordPath, expectedOwner)
	if err != nil {
		return FlatPointer{}, err
	}
	if !opIDRE.MatchString(record.OperationID) {
		return FlatPointer{}, fail(CodeCorrupt, "the flat pointer names no operation")
	}
	opDir := filepath.Join(root, record.OperationID)
	if filepath.Clean(record.PayloadPath) != filepath.Join(opDir, PayloadDir) {
		return FlatPointer{}, fail(CodeCorrupt, "the flat pointer names another payload path")
	}
	committed, err := ReadRecord(opDir, record.OperationID, expectedOwner)
	if err != nil {
		return FlatPointer{}, fail(CodeCorrupt, "the per-operation record the pointer names is missing or unsafe")
	}
	if !sameGeneration(committed, record) {
		return FlatPointer{}, fail(CodeCorrupt, "the flat pointer and its per-operation record disagree")
	}
	if !committed.IntegrityOK || committed.PayloadFiles != 1 || committed.DBSchema <= 0 {
		return FlatPointer{}, fail(CodeCorrupt, "the backup generation holds no verified database copy")
	}
	payloadPath := filepath.Join(committed.PayloadPath, SingleDBName)
	info, statErr := os.Lstat(payloadPath)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || !ownedBy(expectedOwner, info) || info.Size() <= 0 {
		return FlatPointer{}, fail(CodeCorrupt, "the database copy the pointer names is missing or unsafe")
	}
	return FlatPointer{RecordPath: recordPath, PayloadPath: payloadPath, Record: committed}, nil
}

// sameGeneration reports whether the flat copy and the committed per-operation
// record describe the same bytes. The flat copy is a byte copy, but comparing the
// fields a reader relies on keeps a stale or hand-edited pointer from passing as
// the generation it names.
func sameGeneration(committed, flat Record) bool {
	return committed.OperationID == flat.OperationID &&
		committed.FromVersion == flat.FromVersion &&
		committed.TargetVersion == flat.TargetVersion &&
		committed.DBSchema == flat.DBSchema &&
		committed.PayloadPath == flat.PayloadPath &&
		committed.PayloadSHA256 == flat.PayloadSHA256 &&
		committed.PayloadFiles == flat.PayloadFiles &&
		committed.IntegrityOK == flat.IntegrityOK
}
