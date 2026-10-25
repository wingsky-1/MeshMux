package backup

// The store of both layouts.
//
// The per-operation layout is the 11c-3 Node store: one 0700 directory per
// operation, one 0600 record and one 0700 payload tree. A retry of the same
// operation re-verifies the existing generation instead of overwriting a
// rollback source.
//
// The flat layout is the 11d Hub slot (spec C1): <root>/record.json and
// <root>/payload, one generation, replaced atomically by the next backup. Two
// files cannot be committed by one rename, so the replacement is ordered
// payload-then-record and every crash window is repaired by recoverFlatSlot on
// the next entry. GC never collects a generation that is not confirmed: a
// failed or still-staged record is the rollback source the next restore needs
// (spec C18, B8).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Dir returns the holding directory of one generation, creating the store and
// the operation directory when absent. An existing directory must already be
// 0700 and owned by this process; a loose directory is never adopted, because
// its payload may contain secrets. For LayoutFlat the holding directory is the
// slot root itself, and a per-operation directory inside it is refused instead
// of adopted or migrated.
func Dir(root string, layout Layout, operationID string) (string, error) {
	if !opIDRE.MatchString(operationID) {
		return "", fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	switch layout {
	case LayoutPerOp:
		if !filepath.IsAbs(root) {
			return "", fail(CodeMissing, "the rollback store path must be absolute")
		}
		if err := ensureStoreRoot(root); err != nil {
			return "", err
		}
		dir := filepath.Join(root, operationID)
		if err := ensurePrivateDir(dir); err != nil {
			return "", err
		}
		return dir, nil
	case LayoutFlat:
		dir, err := flatSlot(root, os.Geteuid(), true)
		if err != nil {
			return "", err
		}
		if err := rejectPerOpResidue(dir); err != nil {
			return "", err
		}
		return dir, nil
	default:
		return "", fail(CodeCorrupt, "the rollback layout is unknown")
	}
}

// Write publishes one verified generation. The order is fixed: clear scratch,
// stage the payload, verify it, publish it, then write the record. A failure
// before the record rename leaves the previous generation byte-identical; the
// flat slot additionally retires the previous payload through a trash name
// instead of deleting it, so an interrupted replacement is recoverable.
//
// A single-database payload is staged by the producer (VACUUM INTO
// payload.part/meshmux.db) and verified here. The producer reconciles the slot
// first by calling Dir, which runs the flat crash recovery, and only then
// VACUUMs: a producer that stages into an unreconciled slot is refused with
// UPDATE_BACKUP_CORRUPT and no record.
func Write(root string, spec Spec, layout Layout, payload Payload) (Record, error) {
	if err := spec.validate(); err != nil {
		return Record{}, err
	}
	owner := os.Geteuid()
	dir, err := Dir(root, layout, spec.OperationID)
	if err != nil {
		return Record{}, err
	}
	recordPath, payloadPath := Paths(dir, layout)

	if layout == LayoutPerOp {
		// A retry of the same operation reuses the verified generation; any
		// other identity at the same operation ID is a mismatch, never an
		// overwrite of a rollback source.
		switch info, statErr := os.Lstat(recordPath); {
		case statErr == nil:
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return Record{}, fail(CodeCorrupt, "the rollback record is not a regular file")
			}
			existing, readErr := ReadRecord(dir, spec.OperationID, owner)
			if readErr != nil {
				return Record{}, readErr
			}
			if !existing.sameIdentity(spec) {
				return Record{}, fail(CodeMismatch, "another rollback record already owns this operation")
			}
			if err := verifyPayload(existing, dir, layout, owner); err != nil {
				return Record{}, err
			}
			return existing, nil
		case !os.IsNotExist(statErr):
			return Record{}, fail(CodeCorrupt, "the rollback record could not be inspected")
		}
	}

	part := filepath.Join(dir, PayloadPart)
	switch payload.Kind {
	case PayloadTree:
		// The frozen update.BackupSpec still carries SnapshotDir (it is part of
		// the aliased struct), so a tree payload may name its source through
		// either field. When both are set they must agree: copying one tree and
		// recording another would make the record lie about its payload.
		switch {
		case payload.SnapshotDir == "":
			payload.SnapshotDir = spec.SnapshotDir
		case spec.SnapshotDir != "" && payload.SnapshotDir != spec.SnapshotDir:
			return Record{}, fail(CodeCorrupt, "the payload source and the spec snapshot name different trees")
		}
		// A tree payload is this call's own product: the scratch directory is
		// cleared and the snapshot copied into it.
		if err := os.RemoveAll(part); err != nil {
			return Record{}, fail(CodeMissing, "the rollback payload scratch directory could not be cleared")
		}
	case PayloadSingleDB:
		// A single-database payload is staged by the producer (VACUUM INTO
		// payload.part/meshmux.db). Write verifies and publishes it; clearing it
		// here would throw away the only copy.
		if _, statErr := os.Lstat(part); statErr != nil {
			return Record{}, fail(CodeCorrupt, "the single-database payload was not staged")
		}
	default:
		return Record{}, fail(CodeCorrupt, "the rollback payload kind is unknown")
	}
	digest, files, err := stagePayload(payload, part, owner)
	if err != nil {
		_ = os.RemoveAll(part)
		return Record{}, err
	}
	record := newRecord(spec, payloadPath, digest, files, spec.now())

	switch layout {
	case LayoutPerOp:
		// A payload without a record was never bound to a verified snapshot: it
		// is re-copied, never trusted.
		if _, statErr := os.Lstat(payloadPath); statErr == nil {
			if err := os.RemoveAll(payloadPath); err != nil {
				_ = os.RemoveAll(part)
				return Record{}, fail(CodeCorrupt, "the unrecorded rollback payload could not be replaced")
			}
		}
		if err := os.Rename(part, payloadPath); err != nil {
			_ = os.RemoveAll(part)
			return Record{}, fail(CodeCorrupt, "the rollback payload could not be published")
		}
		if err := WriteRecord(dir, record); err != nil {
			return Record{}, err
		}
		return record, nil
	case LayoutFlat:
		return publishFlatSlot(dir, record, part, payloadPath)
	default:
		_ = os.RemoveAll(part)
		return Record{}, fail(CodeCorrupt, "the rollback layout is unknown")
	}
}

// Crash windows of the flat slot's replacement. They are the points a process
// death leaves a repairable state; tests stop the write exactly there to prove
// recoverFlatSlot reconciles each one.
const (
	flatStagePayloadRetired   = "payload-retired"
	flatStagePayloadPublished = "payload-published"
	flatStageRecordPublished  = "record-published"
)

// flatCrashPoint is the crash seam of publishFlatSlot. Production leaves it nil;
// a test panics at a named window to reproduce a process death without cleanup.
var flatCrashPoint func(stage string)

func reachFlatCrashPoint(stage string) {
	if flatCrashPoint != nil {
		flatCrashPoint(stage)
	}
}

// publishFlatSlot rotates the single generation: retire the current payload,
// publish the staged one, write the record, then delete the retired copy. A
// failure at any step restores the previous generation.
func publishFlatSlot(dir string, record Record, part, payloadPath string) (Record, error) {
	trash := filepath.Join(dir, PayloadTrashPrefix+unixSuffix(record.CreatedAt))
	retired := false
	if _, err := os.Lstat(payloadPath); err == nil {
		if err := os.Rename(payloadPath, trash); err != nil {
			_ = os.RemoveAll(part)
			return Record{}, fail(CodeCorrupt, "the previous rollback payload could not be retired")
		}
		retired = true
	}
	reachFlatCrashPoint(flatStagePayloadRetired)
	if err := os.Rename(part, payloadPath); err != nil {
		_ = os.RemoveAll(part)
		restoreRetiredPayload(trash, payloadPath)
		return Record{}, fail(CodeCorrupt, "the rollback payload could not be published")
	}
	reachFlatCrashPoint(flatStagePayloadPublished)
	if err := WriteRecord(dir, record); err != nil {
		_ = os.RemoveAll(payloadPath)
		restoreRetiredPayload(trash, payloadPath)
		return Record{}, err
	}
	reachFlatCrashPoint(flatStageRecordPublished)
	if retired {
		_ = os.RemoveAll(trash)
	}
	_ = syncDir(dir)
	return record, nil
}

func restoreRetiredPayload(trash, payloadPath string) {
	if _, err := os.Lstat(trash); err != nil {
		return
	}
	_ = os.Rename(trash, payloadPath)
}

// Verify is the handoff and restore precondition: it reads the record and the
// payload back from disk under the private-mode rules and refuses a missing
// store or record with UPDATE_BACKUP_MISSING, a damaged record or payload with
// UPDATE_BACKUP_CORRUPT, and a record for another installed state with
// UPDATE_BACKUP_MISMATCH. It never mutates the record.
func Verify(root, operationID, fromVersion string, dbSchema int64, policySchema int, layout Layout, expectedOwner int) (Record, error) {
	if !opIDRE.MatchString(operationID) {
		return Record{}, fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	if fromVersion == "" {
		return Record{}, fail(CodeMismatch, "no from version was supplied for verification")
	}
	dir, err := holdingDir(root, layout, operationID, expectedOwner)
	if err != nil {
		return Record{}, err
	}
	record, err := ReadRecord(dir, operationID, expectedOwner)
	if err != nil {
		return Record{}, err
	}
	if record.FromVersion != fromVersion || record.DBSchema != dbSchema || record.PolicySchema != policySchema {
		return Record{}, fail(CodeMismatch, "the rollback record names another installed state")
	}
	if err := verifyPayload(record, dir, layout, expectedOwner); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Read returns the record metadata of one generation without re-hashing the
// payload. It is the state-agnostic read: a confirmed record is a legitimate
// explicit rollback target, a failed one must stay readable for manual
// recovery, and the Web approval gate verifies the payload shape it needs
// itself. A reader that needs the bytes proven calls Verify.
func Read(root, operationID string, layout Layout, expectedOwner int) (Record, error) {
	dir, err := holdingDir(root, layout, operationID, expectedOwner)
	if err != nil {
		return Record{}, err
	}
	return ReadRecord(dir, operationID, expectedOwner)
}

// ReadFlat returns the record of the single flat slot without an operation id.
// The producer needs the current generation's irreversible bit before it starts
// a new one, and the flat slot has exactly one generation, so requiring its id
// would force a second reader over the same document.
//
// Like every flat entry this runs recoverFlatSlot and may rename a retired
// payload back into place. The caller must hold the process-wide flat-slot lock
// (internal/hubupgrade.LockFlatSlot) around this call and around any publish
// that must not interleave with it.
func ReadFlat(root string, expectedOwner int) (Record, error) {
	dir, err := flatSlot(root, expectedOwner, false)
	if err != nil {
		return Record{}, err
	}
	if err := rejectPerOpResidue(dir); err != nil {
		return Record{}, err
	}
	return readRecordFile(dir, expectedOwner)
}

// Confirm writes the confirmed state of one staged record. It checks the
// readback anchors before the idempotent confirmed short-circuit, so a stale or
// foreign readback can never re-confirm a record; it re-reads the payload from
// disk before the write; and it does nothing else. GC and the durable-source
// refresh belong to the caller, because their timing is the caller's contract
// (spec C12, 11c-3 Task 3).
func Confirm(root, operationID, targetVersion, packageSHA256 string, layout Layout, now time.Time) (Record, error) {
	if !opIDRE.MatchString(operationID) {
		return Record{}, fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	if !targetRE.MatchString(targetVersion) || !digestRE.MatchString(packageSHA256) {
		return Record{}, fail(CodeMismatch, "the readback anchors are not a release and a digest")
	}
	owner := os.Geteuid()
	dir, err := holdingDir(root, layout, operationID, owner)
	if err != nil {
		return Record{}, err
	}
	record, err := ReadRecord(dir, operationID, owner)
	if err != nil {
		return Record{}, err
	}
	if record.TargetVersion != targetVersion || record.PackageSHA256 != packageSHA256 {
		return Record{}, fail(CodeMismatch, "the readback does not name the record's target release and package")
	}
	if record.State == StateConfirmed {
		// Idempotent success: the caller still refreshes its durable source and
		// collects older generations, so a previously failed attempt is retried
		// by the next accepted readback.
		return record, nil
	}
	if record.State != StateStaged {
		return Record{}, fail(CodeConfirmRefused, "the rollback record is not a confirmable staged source")
	}
	if !record.RollbackComplete() {
		return Record{}, fail(CodeCorrupt, "the rollback record holds nothing to restore")
	}
	// Re-read the payload from disk before confirming it: a tampered copy must
	// never become the N-1 generation.
	if err := verifyPayload(record, dir, layout, owner); err != nil {
		return Record{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	confirmed := now.UTC()
	record.State, record.ConfirmedAt = StateConfirmed, &confirmed
	if err := WriteRecord(dir, record); err != nil {
		return Record{}, err
	}
	return record, nil
}

// GC collects confirmed generations beyond keep, newest first. Staged and failed
// records are never candidates: a failed upgrade still needs its rollback
// source. Records that cannot be read are retained (fail closed), and only
// direct operation directories of the store are ever retired.
//
// The flat slot holds exactly one generation, so GC(keep>=1) is a no-op there:
// the newest confirmed generation is also the only one, and the next backup
// replaces it atomically. An explicit keep<1 cleanup of a confirmed generation
// is supported for completeness; it never touches a staged generation.
func GC(root string, keep int, layout Layout) ([]string, error) {
	if keep < 0 {
		return nil, fail(CodeCorrupt, "the GC keep count is negative")
	}
	switch layout {
	case LayoutPerOp:
		return gcPerOp(root, keep)
	case LayoutFlat:
		return gcFlat(root, keep)
	default:
		return nil, fail(CodeCorrupt, "the rollback layout is unknown")
	}
}

func gcPerOp(root string, keep int) ([]string, error) {
	if !filepath.IsAbs(root) {
		return nil, fail(CodeMissing, "the rollback store path must be absolute")
	}
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fail(CodeMissing, "the rollback store could not be read")
	}
	type candidate struct {
		op      string
		created time.Time
	}
	var confirmed []candidate
	for _, entry := range entries {
		if !entry.IsDir() || !opIDRE.MatchString(entry.Name()) {
			continue
		}
		opDir := filepath.Join(root, entry.Name())
		info, err := os.Lstat(opDir)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		record, err := ReadRecord(opDir, entry.Name(), os.Geteuid())
		if err != nil || record.State != StateConfirmed {
			continue
		}
		confirmed = append(confirmed, candidate{op: entry.Name(), created: record.CreatedAt})
	}
	sort.Slice(confirmed, func(i, j int) bool {
		if confirmed[i].created.Equal(confirmed[j].created) {
			return confirmed[i].op < confirmed[j].op
		}
		return confirmed[i].created.After(confirmed[j].created)
	})
	var removed []string
	for i := keep; i < len(confirmed); i++ {
		path := filepath.Join(root, confirmed[i].op)
		// Retire before deleting: a generation is renamed into .trash-<unix>
		// first, so a failed rename retains it and reports the error instead of
		// leaving a half-collected generation.
		trash := path + ".trash-" + unixSuffix(confirmed[i].created)
		if err := os.Rename(path, trash); err != nil {
			return removed, fail(CodeCorrupt, "a confirmed rollback generation could not be retired")
		}
		if err := os.RemoveAll(trash); err != nil {
			return removed, fail(CodeCorrupt, "a confirmed rollback generation could not be collected")
		}
		removed = append(removed, confirmed[i].op)
	}
	return removed, nil
}

func gcFlat(root string, keep int) ([]string, error) {
	if keep >= KeepConfirmed {
		return nil, nil
	}
	owner := os.Geteuid()
	if _, statErr := os.Lstat(root); os.IsNotExist(statErr) {
		return nil, nil
	}
	// flatSlot already repairs the slot, so the cleanup below starts from a
	// reconciled generation.
	dir, err := flatSlot(root, owner, false)
	if err != nil {
		return nil, err
	}
	recordPath, _ := Paths(dir, LayoutFlat)
	record, err := readRecordFile(dir, owner)
	if err != nil {
		return nil, err
	}
	if record.State != StateConfirmed {
		// A staged or failed generation is the only rollback source the slot
		// has; an explicit cleanup never removes it.
		return nil, nil
	}
	suffix := unixSuffix(record.CreatedAt)
	payloadPath := filepath.Join(dir, PayloadDir)
	payloadTrash := filepath.Join(dir, PayloadTrashPrefix+suffix)
	recordTrash := filepath.Join(dir, RecordTrashPrefix+suffix)
	retiredPayload := false
	if _, statErr := os.Lstat(payloadPath); statErr == nil {
		if err := os.Rename(payloadPath, payloadTrash); err != nil {
			return nil, fail(CodeCorrupt, "the flat rollback payload could not be retired")
		}
		retiredPayload = true
	}
	if err := os.Rename(recordPath, recordTrash); err != nil {
		if retiredPayload {
			_ = os.Rename(payloadTrash, payloadPath)
		}
		return nil, fail(CodeCorrupt, "the flat rollback record could not be retired")
	}
	_ = os.RemoveAll(payloadTrash)
	_ = os.Remove(recordTrash)
	_ = syncDir(dir)
	return []string{record.OperationID}, nil
}

// recoverFlatSlot repairs the two-file slot after an interrupted replacement or
// cleanup. It is called on every entry (Write, Verify, Read, GC) and is a no-op
// while no retired or displaced payload exists, so an ordinary read never
// touches the slot.
//
// Reconciliation is by the record's payload digest, never by file age:
//
//   - the current payload matches the record: the new generation is committed
//     (or the old one was never touched); every trash and orphan is discarded;
//   - a retired payload matches the record: the replacement never committed, so
//     the current payload is displaced to payload.orphan-<unix> and the retired
//     one is restored; the abandoned scratch copy is dropped;
//   - a record retired by an explicit cleanup is present: the cleanup completes,
//     because a record that was deliberately renamed away is not a rollback
//     source;
//   - neither pair matches: the slot holds no generation that agrees with its
//     record, so it is UPDATE_BACKUP_CORRUPT and nothing is deleted.
//
// The producer's payload.part scratch copy is never touched here: it is not a
// generation, it is the staged copy Write is about to verify and publish. A
// crash before publication therefore leaves a retryable slot, and only the
// producer decides when that scratch copy is obsolete.
//
// A record that is present but unreadable is reported as corruption and left
// untouched: the generation's identity is unknown, so nothing may be deleted.
func recoverFlatSlot(dir string, owner int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fail(CodeCorrupt, "the flat backup slot could not be read")
	}
	var retiredPayloads, orphanPayloads, retiredRecords []string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case len(name) > len(PayloadTrashPrefix) && name[:len(PayloadTrashPrefix)] == PayloadTrashPrefix:
			retiredPayloads = append(retiredPayloads, name)
		case len(name) > len(PayloadOrphanPrefix) && name[:len(PayloadOrphanPrefix)] == PayloadOrphanPrefix:
			orphanPayloads = append(orphanPayloads, name)
		case len(name) > len(RecordTrashPrefix) && name[:len(RecordTrashPrefix)] == RecordTrashPrefix:
			retiredRecords = append(retiredRecords, name)
		}
	}
	if len(retiredPayloads) == 0 && len(orphanPayloads) == 0 && len(retiredRecords) == 0 {
		return nil
	}
	discard := func(names []string) {
		for _, name := range names {
			_ = os.RemoveAll(filepath.Join(dir, name))
		}
	}
	recordPath := filepath.Join(dir, RecordName)
	payloadPath := filepath.Join(dir, PayloadDir)
	record, recordErr := readRecordFile(dir, owner)
	if recordErr != nil {
		if _, statErr := os.Lstat(recordPath); statErr == nil {
			return fail(CodeCorrupt, "the flat backup record is not readable while the slot holds retired copies")
		}
		if len(retiredRecords) > 0 {
			// An explicit cleanup was interrupted after it retired the record.
			// Completing it is the only state that agrees with the operator's
			// intent; the payload is already unreachable.
			_ = os.RemoveAll(payloadPath)
			discard(retiredPayloads)
			discard(orphanPayloads)
			discard(retiredRecords)
			_ = syncDir(dir)
			return nil
		}
		return fail(CodeCorrupt, "the flat backup slot holds a retired payload without a record")
	}
	if payloadMatchesRecord(record, payloadPath, owner) {
		discard(retiredPayloads)
		discard(orphanPayloads)
		discard(retiredRecords)
		_ = syncDir(dir)
		return nil
	}
	for _, name := range retiredPayloads {
		if !payloadMatchesRecord(record, filepath.Join(dir, name), owner) {
			continue
		}
		if _, statErr := os.Lstat(payloadPath); statErr == nil {
			orphan := filepath.Join(dir, PayloadOrphanPrefix+unixSuffix(time.Now()))
			if err := os.Rename(payloadPath, orphan); err != nil {
				return fail(CodeCorrupt, "the displaced rollback payload could not be retired")
			}
			orphanPayloads = append(orphanPayloads, filepath.Base(orphan))
		}
		if err := os.Rename(filepath.Join(dir, name), payloadPath); err != nil {
			return fail(CodeCorrupt, "the retired rollback payload could not be restored")
		}
		// The retired copy is the generation again; the copy that replaced it
		// was never committed and is now the orphan.
		discard(retiredPayloads)
		discard(orphanPayloads)
		discard(retiredRecords)
		_ = syncDir(dir)
		return nil
	}
	return fail(CodeCorrupt, "no payload in the flat backup slot matches its record")
}

// holdingDir resolves (and with create, prepares) the directory that holds one
// generation. A reader never creates the store: a missing store is MISSING, not
// a new empty slot.
func holdingDir(root string, layout Layout, operationID string, expectedOwner int) (string, error) {
	if !opIDRE.MatchString(operationID) {
		return "", fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	switch layout {
	case LayoutPerOp:
		if !filepath.IsAbs(root) {
			return "", fail(CodeMissing, "the rollback store path must be absolute")
		}
		dir := filepath.Join(root, operationID)
		info, err := os.Lstat(dir)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fail(CodeMissing, "no verified rollback record exists")
		}
		if info.Mode().Perm() != 0700 || !ownedBy(expectedOwner, info) {
			return "", fail(CodeCorrupt, "the rollback operation directory is not 0700 and owned by the expected account")
		}
		return dir, nil
	case LayoutFlat:
		dir, err := flatSlot(root, expectedOwner, false)
		if err != nil {
			return "", err
		}
		if err := rejectPerOpResidue(dir); err != nil {
			return "", err
		}
		return dir, nil
	default:
		return "", fail(CodeCorrupt, "the rollback layout is unknown")
	}
}

// flatSlot validates the single-generation slot root. It is shared by the
// creator (Write) and the readers (Verify, Read, GC), so both agree on what a
// private slot is: 0700, owned by the expected account, no symlink.
func flatSlot(root string, expectedOwner int, create bool) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fail(CodeMissing, "the rollback store path must be absolute")
	}
	info, err := os.Lstat(root)
	if create && os.IsNotExist(err) {
		if err := ensureStoreRoot(root); err != nil {
			return "", err
		}
		info, err = os.Lstat(root)
	}
	if err != nil {
		return "", fail(CodeMissing, "no verified rollback record exists")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fail(CodeCorrupt, "the rollback store path is not a private directory")
	}
	if !ownedBy(expectedOwner, info) {
		return "", fail(CodeCorrupt, "the rollback store is not owned by the expected account")
	}
	if info.Mode().Perm() != 0700 {
		if !create {
			return "", fail(CodeCorrupt, "the rollback store is not a private 0700 directory")
		}
		if err := os.Chmod(root, 0700); err != nil {
			return "", fail(CodeCorrupt, "the rollback store could not be made private")
		}
	}
	if err := recoverFlatSlot(root, expectedOwner); err != nil {
		return "", err
	}
	return root, nil
}

// rejectPerOpResidue refuses a per-operation directory inside the flat slot: the
// Hub layout is one generation, so a <op32hex>/ tree is residue from another
// layout and is never adopted, migrated or read (spec C1).
func rejectPerOpResidue(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fail(CodeCorrupt, "the rollback store could not be read")
	}
	for _, entry := range entries {
		if entry.IsDir() && opIDRE.MatchString(entry.Name()) {
			return fail(CodeCorrupt, "the flat backup slot holds a per-operation directory")
		}
	}
	return nil
}

// stagePayload produces the verified payload in the scratch directory and
// returns its digest and file count.
func stagePayload(payload Payload, part string, owner int) (string, int, error) {
	switch payload.Kind {
	case PayloadTree:
		sourceDigest, sourceFiles, err := hashPayloadTree(payload.SnapshotDir, false, TreeFileMaxBytes, owner)
		if err != nil {
			return "", 0, fail(CodeCorrupt, "the installer snapshot is not a safe file tree")
		}
		if err := copyPayloadTree(payload.SnapshotDir, part); err != nil {
			return "", 0, fail(CodeCorrupt, "the rollback payload could not be copied")
		}
		digest, files, err := hashPayloadTree(part, true, TreeFileMaxBytes, owner)
		if err != nil || digest != sourceDigest || files != sourceFiles {
			return "", 0, fail(CodeCorrupt, "the rollback payload copy does not match the installer snapshot")
		}
		return digest, files, nil
	case PayloadSingleDB:
		if payload.Check == nil {
			return "", 0, fail(CodeCorrupt, "a single-database payload requires its integrity check")
		}
		digest, files, err := hashSingleDB(part, owner)
		if err != nil {
			return "", 0, fail(CodeCorrupt, "the staged database copy is not a private single-file payload")
		}
		if err := payload.Check(part); err != nil {
			return "", 0, fail(CodeCorrupt, "the staged database copy did not pass its integrity check")
		}
		return digest, files, nil
	default:
		return "", 0, fail(CodeCorrupt, "the rollback payload kind is unknown")
	}
}

// verifyPayload re-reads the payload of a record from disk. The record pins the
// path and the digest; the layout only decides where that path is.
func verifyPayload(record Record, dir string, layout Layout, owner int) error {
	_, payloadPath := Paths(dir, layout)
	if filepath.Clean(record.PayloadPath) != filepath.Clean(payloadPath) {
		return fail(CodeCorrupt, "the rollback record names another payload path")
	}
	if !record.IntegrityOK {
		return fail(CodeCorrupt, "the rollback payload has no integrity readback")
	}
	if !payloadMatchesRecord(record, payloadPath, owner) {
		return fail(CodeCorrupt, "the rollback payload does not match its record")
	}
	return nil
}

// payloadMatchesRecord reports whether the payload directory holds exactly the
// bytes the record names. Two encodings are possible and both bind the exact
// bytes: the raw digest of a single meshmux.db copy (what a restore re-hashes
// before it opens the copy) and the tree digest of a copied snapshot. The single
// file shape is tried first because it rejects a tree payload after one readdir,
// while the tree digest is the one that has to walk a snapshot.
func payloadMatchesRecord(record Record, payloadPath string, owner int) bool {
	if digest, files, err := hashSingleDB(payloadPath, owner); err == nil {
		if digest == record.PayloadSHA256 && files == record.PayloadFiles {
			return true
		}
	}
	digest, files, err := hashPayloadTree(payloadPath, true, TreeFileMaxBytes, owner)
	if err != nil {
		return false
	}
	return digest == record.PayloadSHA256 && files == record.PayloadFiles
}

// ReadRecord reads one record from a known holding directory. It is the
// state-agnostic metadata read: unknown fields and trailing data are refused, the
// private-file rule is enforced, and the record must belong to the operation.
func ReadRecord(dir, operationID string, expectedOwner int) (Record, error) {
	record, err := readRecordFile(dir, expectedOwner)
	if err != nil {
		return Record{}, err
	}
	if record.OperationID != operationID {
		return Record{}, fail(CodeCorrupt, "the rollback record does not belong to this operation")
	}
	return record, nil
}

// readRecordFile parses the record of one holding directory without an operation
// check. It exists for the flat slot's recovery and cleanup, which must read the
// generation before they know its operation ID.
func readRecordFile(dir string, expectedOwner int) (Record, error) {
	path := filepath.Join(dir, RecordName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return Record{}, fail(CodeMissing, "no verified rollback record exists")
	}
	if err != nil {
		return Record{}, fail(CodeMissing, "the rollback record could not be read")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		!ownedBy(expectedOwner, info) || info.Size() > RecordMaxBytes {
		return Record{}, fail(CodeCorrupt, "the rollback record is not a private 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Record{}, fail(CodeCorrupt, "the rollback record could not be read")
	}
	record, err := decodeRecord(data)
	if err != nil {
		return Record{}, err
	}
	if record.Schema != RecordSchema {
		return Record{}, fail(CodeCorrupt, "the rollback record does not carry this schema")
	}
	return record, nil
}

// decodeRecord is the strict decoder of the frozen schema: unknown fields and
// trailing data are corruption, not a newer record to be truncated into today's
// approval semantics.
func decodeRecord(data []byte) (Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fail(CodeCorrupt, "the rollback record is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, fail(CodeCorrupt, "the rollback record carries trailing data")
	}
	return record, nil
}

// WriteRecord replaces the record of one holding directory in place. It is the
// state-update entry (a revert marks the record failed; a readback marks it
// confirmed) and it always goes through the single encoder, so an in-place
// update cannot drift from what Write publishes.
func WriteRecord(dir string, record Record) error {
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0700 || !ownedBy(os.Geteuid(), info) {
		return fail(CodeCorrupt, "the rollback operation directory is not 0700 and owned by this process")
	}
	data, err := encodeRecord(record)
	if err != nil {
		return err
	}
	part := filepath.Join(dir, RecordPart)
	// Remove any stale scratch path first: the open below is O_EXCL, and a
	// planted symlink at the scratch path must be unlinked, not followed.
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return fail(CodeCorrupt, "the rollback record scratch path could not be cleared")
	}
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail(CodeCorrupt, "the rollback record could not be written")
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(part)
		return fail(CodeCorrupt, "the rollback record could not be written")
	}
	if err := os.Rename(part, filepath.Join(dir, RecordName)); err != nil {
		_ = os.Remove(part)
		return fail(CodeCorrupt, "the rollback record could not be published")
	}
	if err := syncDir(dir); err != nil {
		return fail(CodeCorrupt, "the rollback record could not be flushed")
	}
	return nil
}

// ensureStoreRoot prepares a dedicated store root. It creates a missing root
// 0700 and narrows a pre-existing owned root to 0700; it never adopts a symlink
// or a directory owned by someone else. The root holds only generations, so
// tightening it can never break a payload.
func ensureStoreRoot(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fail(CodeMissing, "the rollback store is unavailable")
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fail(CodeMissing, "the rollback store is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail(CodeCorrupt, "the rollback store path is not a private directory")
	}
	if !ownedBy(os.Geteuid(), info) {
		return fail(CodeCorrupt, "the rollback store is not owned by this process")
	}
	if info.Mode().Perm() != 0700 {
		if err := os.Chmod(path, 0700); err != nil {
			return fail(CodeCorrupt, "the rollback store could not be made private")
		}
	}
	return nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fail(CodeMissing, "the rollback store is unavailable")
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fail(CodeMissing, "the rollback store is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail(CodeCorrupt, "the rollback store path is not a private directory")
	}
	if info.Mode().Perm() != 0700 || !ownedBy(os.Geteuid(), info) {
		return fail(CodeCorrupt, "the rollback store directory is not 0700 and owned by this process")
	}
	return nil
}
