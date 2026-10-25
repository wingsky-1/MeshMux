package backup

// The per-operation rollback store (#11d Task 1r).
//
// One 0700 directory per operation under the rollback root holds one 0600
// record and one 0700 payload tree or database copy. A retry of the same
// operation re-verifies the existing generation instead of overwriting a
// rollback source; a new operation never touches another operation's directory.
// GC never collects a generation that is not confirmed: a failed or still-staged
// record is the rollback source the next restore needs (spec C18, B8).

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

// Dir returns the holding directory of one operation, creating the store and
// the operation directory when absent. An existing directory must already be
// 0700 and owned by this process; a loose directory is never adopted, because
// its payload may contain secrets.
func Dir(root, operationID string) (string, error) {
	if !opIDRE.MatchString(operationID) {
		return "", fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
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
}

// Write publishes one verified generation into its operation directory. The
// order is fixed: stage the payload, verify it, publish it, then write the
// record. A failure before the record rename leaves every other generation
// byte-identical and clears the operation's scratch payload.
//
// A single-database payload is staged by the producer (VACUUM INTO
// payload.part/meshmux.db) and verified here. Write only ever touches
// <root>/<operationID>; it never replaces another operation's generation.
func Write(root string, spec Spec, payload Payload) (Record, error) {
	if err := spec.validate(); err != nil {
		return Record{}, err
	}
	owner := os.Geteuid()
	dir, err := Dir(root, spec.OperationID)
	if err != nil {
		return Record{}, err
	}
	recordPath, payloadPath := Paths(dir)

	// A retry of the same operation reuses the verified generation; any other
	// identity at the same operation ID is a mismatch, never an overwrite of a
	// rollback source.
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
		if err := verifyPayload(existing, dir, owner); err != nil {
			return Record{}, err
		}
		return existing, nil
	case !os.IsNotExist(statErr):
		return Record{}, fail(CodeCorrupt, "the rollback record could not be inspected")
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

	// A payload without a record was never bound to a verified snapshot: it is
	// re-copied, never trusted.
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
	// The operation directory's entry is created by Dir; syncing the store root
	// here is what makes the published generation durable across power loss.
	// Without it the journal could claim backed_up while database-backup/<op>/
	// was never durable, which is data loss with no restore source (T1r review
	// carry).
	if err := storeRootSync(root); err != nil {
		return Record{}, fail(CodeCorrupt, "the rollback store directory could not be flushed")
	}
	return record, nil
}

// storeRootSync is the store-root fsync seam of a successful Write. Production
// syncs the real directory; a test replaces it to prove the flush happens after
// the record is published and that a failure is reported rather than swallowed.
var storeRootSync = syncDir

// Verify is the handoff and restore precondition: it reads the record and the
// payload back from disk under the private-mode rules and refuses a missing
// store or record with UPDATE_BACKUP_MISSING, a damaged record or payload with
// UPDATE_BACKUP_CORRUPT, and a record for another installed state with
// UPDATE_BACKUP_MISMATCH. It never mutates the record.
func Verify(root, operationID, fromVersion string, dbSchema int64, policySchema int, expectedOwner int) (Record, error) {
	if !opIDRE.MatchString(operationID) {
		return Record{}, fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	if fromVersion == "" {
		return Record{}, fail(CodeMismatch, "no from version was supplied for verification")
	}
	dir, err := holdingDir(root, operationID, expectedOwner)
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
	if err := verifyPayload(record, dir, expectedOwner); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Read returns the record metadata of one operation without re-hashing the
// payload. It is the state-agnostic read: a confirmed record is a legitimate
// explicit rollback target, a failed one must stay readable for manual
// recovery, and the Web approval gate verifies the payload shape it needs
// itself. A reader that needs the bytes proven calls Verify.
func Read(root, operationID string, expectedOwner int) (Record, error) {
	dir, err := holdingDir(root, operationID, expectedOwner)
	if err != nil {
		return Record{}, err
	}
	return ReadRecord(dir, operationID, expectedOwner)
}

// Confirm writes the confirmed state of one staged record. It checks the
// readback anchors before the idempotent confirmed short-circuit, so a stale or
// foreign readback can never re-confirm a record; it re-reads the payload from
// disk before the write; and it does nothing else. GC and the durable-source
// refresh belong to the caller, because their timing is the caller's contract
// (spec C12, 11c-3 Task 3).
func Confirm(root, operationID, targetVersion, packageSHA256 string, now time.Time) (Record, error) {
	if !opIDRE.MatchString(operationID) {
		return Record{}, fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
	if !targetRE.MatchString(targetVersion) || !digestRE.MatchString(packageSHA256) {
		return Record{}, fail(CodeMismatch, "the readback anchors are not a release and a digest")
	}
	owner := os.Geteuid()
	dir, err := holdingDir(root, operationID, owner)
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
	if err := verifyPayload(record, dir, owner); err != nil {
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

// GC collects confirmed operations beyond keep, newest first. Staged and failed
// records are never candidates: a failed upgrade still needs its rollback
// source. Records that cannot be read are retained (fail closed), and only
// direct operation directories of the store are ever retired. The keep count is
// the caller's policy: the Node passes KeepConfirmed, the Hub passes 2.
func GC(root string, keep int) ([]string, error) {
	if keep < 0 {
		return nil, fail(CodeCorrupt, "the GC keep count is negative")
	}
	return gcPerOp(root, keep)
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

// holdingDir resolves the operation directory that holds one operation's
// record and payload. A reader never creates the store: a missing store is
// MISSING, not a new empty directory.
func holdingDir(root, operationID string, expectedOwner int) (string, error) {
	if !opIDRE.MatchString(operationID) {
		return "", fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	}
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
// operation's payload path and digest.
func verifyPayload(record Record, dir string, owner int) error {
	_, payloadPath := Paths(dir)
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

// readRecordFile parses the record of one holding directory; ReadRecord adds
// the operation-identity check.
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
