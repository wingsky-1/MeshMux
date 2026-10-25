package hubupgrade

// The operation journal of #11d (spec §5.5). It is the authority for an
// operation's state because it survives a data-dir flip and a schema rollback:
// a restore brings back a schema-10 database where the mirror table does not
// exist, but the journal travels with hub-upgrade/. The DB mirror is written by
// Task 5 and is never read by the dispatcher.
//
// Only the Web process writes a journal. Its file is a 0600 document under
// <data-dir>/hub-upgrade/ops/, published with temp+fsync+rename, and every
// reader applies the same owner/private-mode rule.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// State is one frozen journal state. The set is closed: a restore, a readback
// and the mirror all switch on exactly these values.
type State string

// The frozen state set of spec §5.5. partial is entered only after a write has
// already touched the host and the operation cannot complete without a restore.
const (
	StateBackingUp  State = "backing_up"
	StateBackedUp   State = "backed_up"
	StateQueued     State = "queued"
	StateApplying   State = "applying"
	StateRestarting State = "restarting"
	StateVerifying  State = "verifying"
	StatePartial    State = "partial"
	StateConfirmed  State = "confirmed"
	StateReverted   State = "reverted"
	StateFailed     State = "failed"
)

// Stable journal codes. They fall inside the HUB_UPGRADE_* group of spec §5.9;
// the journal never invents a fourth group.
const (
	codeJournalCorrupt    = "HUB_UPGRADE_JOURNAL_CORRUPT"
	codeJournalWrite      = "HUB_UPGRADE_JOURNAL_FAILED"
	codeTransitionInvalid = "HUB_UPGRADE_TRANSITION_INVALID"
)

// journalStateValid reports whether s belongs to the frozen set.
func journalStateValid(s State) bool {
	switch s {
	case StateBackingUp, StateBackedUp, StateQueued, StateApplying, StateRestarting,
		StateVerifying, StatePartial, StateConfirmed, StateReverted, StateFailed:
		return true
	}
	return false
}

// Busy reports whether this state blocks another backup (spec §5.2/C18).
// partial is included: a half-applied operation still owns the single rollback
// source. The terminal states do not block; reverted is sticky and confirmed is
// the successful end.
func (s State) Busy() bool {
	switch s {
	case StateBackingUp, StateBackedUp, StateQueued, StateApplying, StateRestarting,
		StateVerifying, StatePartial:
		return true
	}
	return false
}

// Op is one operation journal document (schema 1). Naming matches the frozen
// spec fields; detail and the mirror-only columns are not part of this file.
type Op struct {
	Schema           int       `json:"schema"`
	OperationID      string    `json:"operation_id"`
	Kind             string    `json:"kind"`
	State            State     `json:"state"`
	TargetVersion    string    `json:"target_version"`
	FromVersion      string    `json:"from_version"`
	ManifestSHA256   string    `json:"manifest_sha256"`
	PackageSHA256    string    `json:"package_sha256"`
	DBSchema         int64     `json:"db_schema"`
	BackupGeneration int64     `json:"backup_generation"`
	ErrorCode        string    `json:"error_code,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ConfirmedBy is the one confirmation predicate (spec §5.5/C21): the running
// version and package digest together, never either half alone.
func (op Op) ConfirmedBy(version, digest string) bool {
	return version != "" && digest != "" && op.TargetVersion == version && op.PackageSHA256 == digest
}

// Advance returns op moved to next. It is forward-only: a terminal state never
// moves, a state may not be skipped through the ordered chain, and partial is
// only reachable once a write may have happened. Rewriting the same state is an
// idempotent no-op so a mirror retry (Task 5) cannot be mistaken for a move.
func Advance(op Op, next State, errorCode string) (Op, error) {
	if !journalStateValid(next) {
		return Op{}, fail(codeTransitionInvalid, "the next state is not in the frozen set")
	}
	if op.State == next {
		op.ErrorCode = errorCode
		return op, nil
	}
	if !transitionAllowed(op.State, next) {
		return Op{}, fail(codeTransitionInvalid, "the operation cannot move from "+string(op.State)+" to "+string(next))
	}
	op.State, op.ErrorCode = next, errorCode
	return op, nil
}

func transitionAllowed(from, to State) bool {
	switch from {
	case StateBackingUp:
		return to == StateBackedUp || to == StateFailed
	case StateBackedUp:
		return to == StateQueued || to == StateFailed
	case StateQueued:
		return to == StateApplying || to == StateRestarting || to == StateFailed
	case StateApplying:
		return to == StateRestarting || to == StateVerifying || to == StateFailed || to == StatePartial
	case StateRestarting:
		return to == StateVerifying || to == StateFailed || to == StatePartial
	case StateVerifying:
		return to == StateConfirmed || to == StateReverted || to == StateFailed || to == StatePartial
	case StatePartial:
		return to == StateReverted
	case StateFailed:
		return to == StateReverted || to == StatePartial
	}
	return false
}

// WriteOp publishes one journal document. The operation id is both the file
// name and the identity; the write is private, fsynced and renamed so a reader
// never sees half a document.
func WriteOp(dataDir string, op Op) error {
	if !opIDRE.MatchString(op.OperationID) {
		return fail(codeJournalCorrupt, "the operation id is not 32 lowercase hex")
	}
	if err := validateOp(op); err != nil {
		return err
	}
	opsDir, err := journalOpsDir(dataDir, true)
	if err != nil {
		return err
	}
	path := filepath.Join(opsDir, op.OperationID+".json")
	part := path + ".part"
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return fail(codeJournalWrite, "the journal scratch path could not be cleared")
	}
	body, err := json.MarshalIndent(op, "", "  ")
	if err != nil {
		return fail(codeJournalCorrupt, "the journal could not be encoded")
	}
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail(codeJournalWrite, "the journal could not be written")
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
		return fail(codeJournalWrite, "the journal could not be written")
	}
	if err := os.Rename(part, path); err != nil {
		_ = os.Remove(part)
		return fail(codeJournalWrite, "the journal could not be published")
	}
	return syncDir(opsDir)
}

func validateOp(op Op) error {
	switch {
	case op.Schema != OpSchema:
		return fail(codeJournalCorrupt, "the journal does not carry this schema")
	case op.Kind != KindUpdate && op.Kind != KindRestore:
		return fail(codeJournalCorrupt, "the journal kind is not update or restore")
	case !journalStateValid(op.State):
		return fail(codeJournalCorrupt, "the journal state is not in the frozen set")
	case !targetRE.MatchString(op.TargetVersion):
		return fail(codeJournalCorrupt, "the journal target is not a SemVer release")
	case op.FromVersion == "" || strings.ContainsAny(op.FromVersion, "\x00\n\r/"):
		return fail(codeJournalCorrupt, "the journal from-version is not a plain release")
	case !digestRE.MatchString(op.ManifestSHA256) || !digestRE.MatchString(op.PackageSHA256):
		return fail(codeJournalCorrupt, "the journal is missing a manifest or package digest")
	case op.DBSchema < 0 || op.BackupGeneration < 0:
		return fail(codeJournalCorrupt, "the journal carries a negative schema or generation")
	case op.UpdatedAt.IsZero():
		return fail(codeJournalCorrupt, "the journal has no update time")
	}
	return nil
}

// ReadOp returns one journal document. A missing operation is (zero, false,
// nil); an unreadable or malformed one is an error, never "not found".
func ReadOp(dataDir, operationID string) (Op, bool, error) {
	if !opIDRE.MatchString(operationID) {
		return Op{}, false, fail(codeJournalCorrupt, "the operation id is not 32 lowercase hex")
	}
	opsDir, err := journalOpsDir(dataDir, false)
	if err != nil {
		if os.IsNotExist(err) {
			return Op{}, false, nil
		}
		return Op{}, false, err
	}
	path := filepath.Join(opsDir, operationID+".json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return Op{}, false, nil
	}
	if err != nil {
		return Op{}, false, fail(codeJournalCorrupt, "the journal could not be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || !ownedBy(os.Geteuid(), info) || info.Size() > JournalMaxBytes {
		return Op{}, false, fail(codeJournalCorrupt, "the journal is not a private 0600 file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Op{}, false, fail(codeJournalCorrupt, "the journal could not be read")
	}
	op, err := decodeOp(body)
	if err != nil {
		return Op{}, false, err
	}
	if op.OperationID != operationID {
		return Op{}, false, fail(codeJournalCorrupt, "the journal does not belong to this operation")
	}
	return op, true, nil
}

// ListOps returns every readable journal document, newest first. A corrupt
// document is an error: a state machine that silently ignores one operation
// could start a second backup over its rollback source.
func ListOps(dataDir string) ([]Op, error) {
	opsDir, err := journalOpsDir(dataDir, false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(opsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fail(codeJournalCorrupt, "the journal directory could not be read")
	}
	var ops []Op
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") ||
			!opIDRE.MatchString(strings.TrimSuffix(name, ".json")) {
			continue
		}
		operationID := strings.TrimSuffix(name, ".json")
		op, ok, err := ReadOp(dataDir, operationID)
		if err != nil {
			return nil, err
		}
		if ok {
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].UpdatedAt.Equal(ops[j].UpdatedAt) {
			return ops[i].OperationID > ops[j].OperationID
		}
		return ops[i].UpdatedAt.After(ops[j].UpdatedAt)
	})
	return ops, nil
}

// Busy returns the newest non-terminal operation. It is the backup single-flight
// predicate; a journal that cannot be read is an error, never "not busy".
func Busy(dataDir string) (Op, bool, error) {
	ops, err := ListOps(dataDir)
	if err != nil {
		return Op{}, false, err
	}
	for _, op := range ops {
		if op.State.Busy() {
			return op, true, nil
		}
	}
	return Op{}, false, nil
}

func journalOpsDir(dataDir string, create bool) (string, error) {
	root, err := dataPath(dataDir, HubUpgradeDir)
	if err != nil {
		return "", err
	}
	if create {
		if err := ensurePrivateDir(root); err != nil {
			return "", err
		}
	}
	opsDir := filepath.Join(root, "ops")
	if create {
		if err := ensurePrivateDir(opsDir); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(opsDir)
	if os.IsNotExist(err) {
		return "", err
	}
	if err != nil {
		return "", fail(codeJournalCorrupt, "the journal directory could not be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 ||
		!ownedBy(os.Geteuid(), info) {
		return "", fail(codeJournalCorrupt, "the journal directory is not a private 0700 directory")
	}
	return opsDir, nil
}

func decodeOp(body []byte) (Op, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var op Op
	if err := decoder.Decode(&op); err != nil {
		return Op{}, fail(codeJournalCorrupt, "the journal is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Op{}, fail(codeJournalCorrupt, "the journal carries trailing data")
	}
	if err := validateOp(op); err != nil {
		return Op{}, err
	}
	return op, nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fail(codeJournalWrite, "the journal directory is unavailable")
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fail(codeJournalWrite, "the journal directory is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0700 || !ownedBy(os.Geteuid(), info) {
		return fail(codeJournalCorrupt, "the journal directory is not 0700 and owned by this process")
	}
	return nil
}

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fail(codeJournalWrite, "the journal directory could not be opened")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fail(codeJournalWrite, "the journal directory could not be flushed")
	}
	return nil
}
