package hubupgrade

// Startup reconciliation and confirmation of Hub upgrade operations (#11d Task
// 5, spec §5.5).
//
// The journal is the authority (D3): there is no mirror table and no schema
// bump, so one pass over the journal files is the whole state machine. A pass
// runs once at startup and then every 30 seconds; the two passes differ in
// exactly one rule:
//
//   - only the startup pass may judge identity. A running old binary is
//     indistinguishable from "the swap did not happen yet", so a ticker that
//     read the `from` version as NOT_APPLIED would fail every upgrade in the
//     seconds between the dispatcher's `restart-accepted` result and the
//     restart itself. The ticker therefore only advances states and applies
//     timeouts;
//   - only the startup pass may confirm (`confirmed` needs a process that
//     started after the swap).
//
// Confirmation itself is the one predicate of Op.ConfirmedBy: running version
// AND running package digest. `from_*` is never compared with the post-upgrade
// running value; the version is only used to recognise "still the old binary".
//
// Every terminal decision writes the journal before it is reported. GC and the
// flat-pointer refresh are the confirmer's job and are both decoupled from the
// confirmation result: a failed pointer refresh logs HUB_BACKUP_POINTER_STALE,
// a failed collection logs HUB_BACKUP_GC_FAILED, and neither turns a confirmed
// record back into a failure (spec §5.2.1).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/buildinfo"
)

// The frozen timeouts of the reconcile table (spec §5.5, oracle carry). They
// are exported because /tasks shows an operator when a backup row will time
// out: silently failing an operation the operator just walked away from is the
// failure mode this row exists to prevent.
const (
	// OrphanTimeout is the pure-age bound of backing_up, backed_up, applying
	// and restarting (C18). A Web process that died never wrote a terminal
	// state; this is the backstop.
	OrphanTimeout = 30 * time.Minute
	// HandoffTimeout is the bound on a queued operation no dispatcher answered.
	HandoffTimeout = 120 * time.Second
)

// Stable terminal/refusal codes of one reconcile pass. They all fall into the
// HUB_BACKUP_* / HUB_UPGRADE_* groups of spec §5.9.
const (
	codeBackupOrphaned  = "HUB_BACKUP_ORPHANED"
	codeUpgradeOrphaned = "HUB_UPGRADE_ORPHANED"
	codeUpgradeNotDone  = "HUB_UPGRADE_NOT_APPLIED"
	codeVerifyMismatch  = "HUB_UPGRADE_VERIFY_MISMATCH"
	codeUpgradeFailed   = "HUB_UPGRADE_FAILED"
	codeConfirmFailed   = "HUB_UPGRADE_CONFIRM_FAILED"
	codeGC              = "HUB_BACKUP_GC_FAILED"
	// codeRepinIncomplete is the R1 terminal: the claim proves the target
	// binary became the running image while the four pins may still be old.
	codeRepinIncomplete = "HUB_SHARED_BINARY_REPIN_INCOMPLETE"
)

// RestoredMarker is the write-once fact that the data directory was restored
// from a backup of operation OperationID (spec §5.7, D2). Restore is lossy:
// every write after the snapshot is gone, so the marker says so and carries the
// snapshot time the operator must see.
type RestoredMarker struct {
	Schema      int       `json:"schema"`
	OperationID string    `json:"operation_id"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	Lossy       bool      `json:"lossy"`
}

// RestoredSchema is the frozen marker schema.
const RestoredSchema = 1

// restoredMarkerName is the marker file inside <data-dir>/hub-upgrade. It
// travels with the journal across a data-dir flip.
const restoredMarkerName = "restored.json"

// ConfirmHooks are the two side effects after a record is confirmed, plus the
// log sink. Nil Publish/Collect mean the production functions; both failures
// are logged and never undo the confirmation.
type ConfirmHooks struct {
	Publish func(root, operationID string) error
	Collect func(dataDir string, keep int) ([]string, error)
	Log     func(code, operationID string)
}

// ConfirmAndCollect confirms one operation's per-operation record, refreshes
// the flat existence-only pointer and then collects confirmed generations.
//
// The order is the spec's: Confirm (which also clears the irreversible bit),
// then publish, then GC unconditionally. The pointer is a diagnostic copy no
// 11d reader consumes, so its failure is logged; GC is confirmed-only and keeps
// the newest two, so a stale pointer to an older generation is not a reason to
// skip it.
//
// Lock obligation (per-operation store, restated for Task 7's docs):
// LockBackupProduce covers exactly the producer's
// Busy → generation → WriteOp(backing_up) check-then-act. The dispatcher, the
// approval, /tasks reads and this confirmation never take it, and there is no
// flat lock. Same-operation safety comes from the atomic rename that publishes
// a per-operation record: the only read-modify-write (the approval bit) is
// idempotent, and Confirm has a staged precondition, so a concurrent confirm
// either wins the rename or is refused.
func ConfirmAndCollect(dataDir, operationID, target, pkg string, now time.Time, hooks ConfirmHooks) (backup.Record, error) {
	record, err := ConfirmBackup(dataDir, operationID, target, pkg, now)
	if err != nil {
		return backup.Record{}, err
	}
	root, err := dataPath(dataDir, DatabaseBackupDir)
	if err != nil {
		return backup.Record{}, err
	}
	publish := hooks.Publish
	if publish == nil {
		publish = PublishFlatPointer
	}
	if err := publish(root, operationID); err != nil {
		if hooks.Log != nil {
			hooks.Log(pointerLogCode(err), operationID)
		}
	}
	collect := hooks.Collect
	if collect == nil {
		collect = CleanupConfirmed
	}
	if _, err := collect(dataDir, minHubKeep); err != nil {
		// A collector failure never un-confirms: the record on disk is the
		// authority and the next confirmation retries the collection.
		if hooks.Log != nil {
			hooks.Log(codeGC, operationID)
		}
	}
	return record, nil
}

// ReconcileConfig is one reconcile pass. The identity and result inputs are
// injected so a fixture never needs /var/lib or a running dispatcher.
type ReconcileConfig struct {
	DataDir string
	// Now is the clock seam. A nil Now means time.Now.
	Now func() time.Time
	// Startup is true for the one pass that runs while the process starts. Only
	// that pass may judge identity and confirm.
	Startup bool
	// Version is the running release. Empty means buildinfo.Version.
	Version string
	// Digest returns the running executable's SHA-256. Nil means
	// buildinfo.Digest.
	Digest func() (string, error)
	// Result reads the root-written progress document of one operation. Nil
	// means the fixed ResultsDir.
	Result func(operationID string) (Result, bool, error)
	// Confirm performs the confirmation side effects. It is required whenever a
	// startup pass reaches a confirmable operation.
	Confirm func(ctx context.Context, operationID, target, pkg string) error
	// RemoveRequest unlinks one timed-out request. Nil means the fixed
	// RequestDir; a fixture replaces it so no pass touches /run.
	RemoveRequest func(operationID string) error
	// Claim reads the root-written crash anchor (Task 6). Nil means the fixed
	// ClaimDir. The Web reads it; only root writes or deletes it (C22), so an
	// inert old-binary claim stays until the next root executor overwrites it.
	Claim func() (Claim, bool, error)
}

// ReconcileChange is one journal transition this pass made. It is the only
// record of the pass; the journal file remains the authority.
type ReconcileChange struct {
	OperationID string
	From        State
	To          State
	Code        string
}

// ReconcileError is one operation this pass could not judge or advance. It is
// reported, never retried silently, and it is not a terminal journal write.
type ReconcileError struct {
	OperationID string
	Code        string
}

// ReconcileReport is one pass's honest result.
type ReconcileReport struct {
	Examined int
	Changes  []ReconcileChange
	Errors   []ReconcileError
}

// Reconcile runs one pass over every journaled operation. A journal that cannot
// be read is an error (never "nothing to do"): a state machine that ignored a
// corrupt document could start a second backup over the same rollback source.
func Reconcile(ctx context.Context, cfg ReconcileConfig) (ReconcileReport, error) {
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		return ReconcileReport{}, fail("HUB_UPGRADE_JOURNAL_FAILED", "the Hub data directory is not absolute")
	}
	now := time.Now().UTC()
	if cfg.Now != nil {
		now = cfg.Now().UTC()
	}
	if cfg.Version == "" {
		cfg.Version = buildinfo.Version
	}
	if cfg.Digest == nil {
		cfg.Digest = buildinfo.Digest
	}
	if cfg.Result == nil {
		cfg.Result = func(operationID string) (Result, bool, error) {
			return ReadResult(ResultsDir, operationID)
		}
	}
	if cfg.RemoveRequest == nil {
		cfg.RemoveRequest = func(operationID string) error {
			return RemoveRequest(RequestDir, operationID)
		}
	}
	if cfg.Claim == nil {
		cfg.Claim = func() (Claim, bool, error) { return ReadClaim(ClaimDir) }
	}
	ops, err := ListOps(cfg.DataDir, os.Geteuid())
	if err != nil {
		return ReconcileReport{}, backupJournalError(err)
	}
	pass := &reconciler{cfg: cfg, now: now, report: ReconcileReport{Examined: len(ops)}}
	for _, op := range ops {
		if err := pass.one(ctx, op); err != nil {
			pass.report.Errors = append(pass.report.Errors, ReconcileError{OperationID: op.OperationID, Code: codeOf(err)})
		}
	}
	pass.clearSupersededMarker(ops)
	return pass.report, nil
}

type reconciler struct {
	cfg    ReconcileConfig
	now    time.Time
	report ReconcileReport

	digestOnce bool
	digest     string
	digestErr  error
}

// one applies the reconcile matrix to a single operation. A result document is
// progress evidence only: it may move a state and it may report a terminal
// state, but it never authorizes a confirmation.
func (p *reconciler) one(ctx context.Context, op Op) error {
	if op.Kind != KindUpdate || op.State == StateConfirmed || op.State == StateReverted {
		// confirmed is the successful end and reverted is sticky (C12): a later
		// startup pass never overwrites either.
		return nil
	}
	if handled, err := p.claimGate(op); handled {
		return err
	}
	result, hasResult, err := p.cfg.Result(op.OperationID)
	if err != nil {
		// A malformed result is not an authorization and not a state input: the
		// operation falls back to its journal state and the pure-age timeouts.
		p.report.Errors = append(p.report.Errors, ReconcileError{OperationID: op.OperationID, Code: codeOf(err)})
		hasResult = false
	}
	if hasResult {
		handled, err := p.terminalResult(op, result)
		if handled {
			return err
		}
	}

	switch op.State {
	case StateBackingUp:
		if p.age(op) <= OrphanTimeout {
			return nil
		}
		p.discardBackupScratch(op.OperationID)
		_, err := p.advance(op, StateFailed, codeBackupOrphaned)
		return err

	case StateBackedUp:
		if p.age(op) <= OrphanTimeout {
			return nil
		}
		_, err := p.advance(op, StateFailed, codeBackupOrphaned)
		return err

	case StateQueued:
		if !hasResult {
			if p.age(op) <= HandoffTimeout {
				return nil
			}
			// Remove first: the path unit only re-arms on an empty directory,
			// and the journal write is what makes the timeout durable.
			if err := p.cfg.RemoveRequest(op.OperationID); err != nil {
				p.report.Errors = append(p.report.Errors, ReconcileError{OperationID: op.OperationID, Code: codeOf(err)})
			}
			_, err := p.advance(op, StateFailed, codeHandoffTimeout)
			return err
		}
		switch result.Phase {
		case ResultAccepted, ResultSwapping:
			_, err := p.advance(op, StateApplying, "")
			return err
		case ResultRestarting, ResultRestartAccepted:
			return p.restarting(ctx, op)
		}
		return nil

	case StateApplying:
		if hasResult {
			switch result.Phase {
			case ResultRestarting, ResultRestartAccepted:
				return p.restarting(ctx, op)
			}
		}
		// C18 is pure age: the dispatcher wrote a result and then stopped.
		if p.age(op) <= OrphanTimeout {
			return nil
		}
		_, err := p.advance(op, StateFailed, codeUpgradeOrphaned)
		return err

	case StateRestarting:
		return p.restarting(ctx, op)

	case StateVerifying:
		return p.verifying(ctx, op)
	}
	return nil
}

// claimGate applies the R1 crash-claim rule before any result/state logic. A
// claim is evidence, not an authorization: it can only move the operation it
// names to the honest REPIN_INCOMPLETE terminal. A claim whose running identity
// is still the old binary is inert and keeps the ordinary timeout/NOT_APPLIED
// decision.
func (p *reconciler) claimGate(op Op) (bool, error) {
	if op.State == StateFailed || op.State == StatePartial || op.State == StateConfirmed || op.State == StateReverted {
		return false, nil
	}
	claim, found, err := p.cfg.Claim()
	if err != nil {
		// A malformed claim is reported and retried; it must never be read as
		// "no claim" and it must never authorize a write itself.
		return false, err
	}
	if !found || claim.OperationID != op.OperationID {
		return false, nil
	}
	if claim.Phase == ClaimPhaseRepinned {
		// Every pin moved; only the unlink did not. Inert.
		return false, nil
	}
	if p.cfg.Version == claim.FromVersion {
		// The old binary still runs: the swap never became this image. Normal
		// timeout / NOT_APPLIED logic decides; the claim adds nothing. The Web
		// cannot unlink a root-owned file in the root-only upgrade tree (C22),
		// and leaving this inert anchor is harmless: the next root executor
		// overwrites it atomically.
		return false, nil
	}
	if p.cfg.Version != claim.TargetVersion {
		return false, nil
	}
	digest, err := p.runningDigest()
	if err != nil {
		return false, err
	}
	if digest != claim.NewSHA256 {
		return false, nil
	}
	// Running target bytes + a swapping claim: the crash landed after the
	// rename and before the four-pin write finished (or before its claim
	// update). Restore must not wait out 30 minutes.
	_, err = p.advance(op, StateFailed, codeRepinIncomplete)
	return true, err
}

// terminalResult applies a terminal result document (failed, partial or
// restored). It reports whether the result was terminal.
func (p *reconciler) terminalResult(op Op, result Result) (bool, error) {
	switch result.Phase {
	case ResultFailed:
		return true, p.terminal(op, StateFailed, result.ErrorCode)
	case ResultPartial:
		return true, p.terminal(op, StatePartial, result.ErrorCode)
	case ResultRestored:
		return true, p.restored(op)
	}
	return false, nil
}

func (p *reconciler) terminal(op Op, next State, code string) error {
	if code == "" {
		code = codeUpgradeFailed
	}
	// partial is strictly "a write may already have touched the host": it never
	// moves back to failed, because the operator's next step is a restore.
	if op.State == StatePartial && next == StateFailed {
		return nil
	}
	_, err := p.advance(op, next, code)
	return err
}

// restored records the restore fact and moves the journal to reverted. The
// marker is written even when the transition is refused: the database really
// was restored, and losing that fact would hide a lossy state from the
// operator.
func (p *reconciler) restored(op Op) error {
	marker := RestoredMarker{
		Schema: RestoredSchema, OperationID: op.OperationID,
		SnapshotAt: p.snapshotAt(op), Lossy: true,
	}
	if err := writeRestoredMarker(p.cfg.DataDir, marker); err != nil {
		return err
	}
	_, err := p.advance(op, StateReverted, "")
	return err
}

// snapshotAt is the time the restored database copy was taken: the per-op
// record's created_at. When that record is gone the pass falls back to its own
// clock and stays lossy, rather than claiming a precision it does not have.
func (p *reconciler) snapshotAt(op Op) time.Time {
	root, err := dataPath(p.cfg.DataDir, DatabaseBackupDir)
	if err == nil {
		if record, readErr := backup.Read(root, op.OperationID, os.Geteuid()); readErr == nil && !record.CreatedAt.IsZero() {
			return record.CreatedAt.UTC()
		}
	}
	return p.now
}

// restarting advances an operation (from queued/applying) into restarting and
// then applies the identity rule. The old process cannot distinguish "not
// swapped yet" from "swapped and failed", so only a startup pass may call a
// `from` identity NOT_APPLIED; the ticker just keeps the state and lets the age
// timeout be the backstop.
func (p *reconciler) restarting(ctx context.Context, op Op) error {
	if op.State != StateRestarting {
		next, err := p.advance(op, StateRestarting, "")
		if err != nil {
			return err
		}
		op = next
	}
	class, err := p.classify(op)
	if err != nil {
		// No identity decision without a running digest; the pass reports the
		// environment failure (HUB_DIGEST_UNAVAILABLE) and retries later.
		return err
	}
	switch class {
	case identityTarget:
		next, err := p.advance(op, StateVerifying, "")
		if err != nil {
			return err
		}
		// The ticker only advances: a confirmation must come from a process that
		// started after the swap (spec §5.5, plan TestReconcileConfirmOnlyOnStartupPass).
		if !p.cfg.Startup {
			return nil
		}
		return p.confirm(ctx, next)
	case identityFrom:
		if p.cfg.Startup {
			_, err := p.advance(op, StateFailed, codeUpgradeNotDone)
			return err
		}
		// The ticker cannot distinguish "not swapped yet" from "swapped and
		// failed", so it never writes NOT_APPLIED; the age bound below is its
		// only terminal decision here.
	}
	if p.age(op) <= OrphanTimeout {
		return nil
	}
	_, err = p.advance(op, StateFailed, codeUpgradeOrphaned)
	return err
}

// verifying judges a verifying operation. Identity is a startup-only decision:
// see the package comment.
func (p *reconciler) verifying(ctx context.Context, op Op) error {
	if !p.cfg.Startup {
		return nil
	}
	class, err := p.classify(op)
	if err != nil {
		// An unreadable running digest is retryable, never a terminal mismatch.
		return err
	}
	switch class {
	case identityTarget:
		return p.confirm(ctx, op)
	case identityFrom:
		_, err := p.advance(op, StateFailed, codeUpgradeNotDone)
		return err
	default:
		_, err := p.advance(op, StateFailed, codeVerifyMismatch)
		return err
	}
}

// confirm performs the confirmation side effects and then publishes
// `confirmed`. A side-effect failure leaves the journal at verifying, so the
// next startup pass retries the idempotent confirm instead of losing the
// operation.
func (p *reconciler) confirm(ctx context.Context, op Op) error {
	if p.cfg.Confirm == nil {
		return fail(codeConfirmFailed, "no confirmation handler is wired")
	}
	if err := p.cfg.Confirm(ctx, op.OperationID, op.TargetVersion, op.PackageSHA256); err != nil {
		return err
	}
	_, err := p.advance(op, StateConfirmed, "")
	return err
}

type identityClass int

const (
	identityOther identityClass = iota
	identityTarget
	identityFrom
)

// classify compares the running identity with the operation. Only a version and
// package digest together prove the target; the from version is a version-only
// hint that the swap did not happen (spec §5.5 rejects comparing from_* with
// the post-upgrade running value).
//
// A failing digest read is returned as an error, never folded into
// identityOther: an unreadable executable is an environment failure
// (HUB_DIGEST_UNAVAILABLE), and treating it as "another identity" would write a
// terminal VERIFY_MISMATCH for an upgrade that is in fact fine. The caller
// reports it and retries on the next pass.
func (p *reconciler) classify(op Op) (identityClass, error) {
	if p.cfg.Version != "" && p.cfg.Version == op.TargetVersion {
		digest, err := p.runningDigest()
		if err != nil {
			return identityOther, err
		}
		if op.PackageSHA256 == digest {
			return identityTarget, nil
		}
		return identityOther, nil
	}
	if p.cfg.Version != "" && p.cfg.Version == op.FromVersion {
		return identityFrom, nil
	}
	return identityOther, nil
}

func (p *reconciler) runningDigest() (string, error) {
	if !p.digestOnce {
		p.digestOnce = true
		p.digest, p.digestErr = p.cfg.Digest()
	}
	return p.digest, p.digestErr
}

func (p *reconciler) age(op Op) time.Duration { return p.now.Sub(op.UpdatedAt) }

// advance publishes one forward transition and reports it. Rewriting the state
// and code an operation already carries is a no-op: a ticker must not refresh
// updated_at (and therefore the age timeout) of nothing.
func (p *reconciler) advance(op Op, next State, code string) (Op, error) {
	moved, err := Advance(op, next, code)
	if err != nil {
		return Op{}, err
	}
	if moved.State == op.State && moved.ErrorCode == op.ErrorCode {
		return op, nil
	}
	moved.UpdatedAt = p.now
	if err := WriteOp(p.cfg.DataDir, moved); err != nil {
		return Op{}, err
	}
	p.report.Changes = append(p.report.Changes, ReconcileChange{
		OperationID: op.OperationID, From: op.State, To: moved.State, Code: code,
	})
	return moved, nil
}

// discardBackupScratch clears a backing_up orphan's scratch copy. A committed
// record is never removed (it is a valid restore source even when the journal
// transition did not happen); a directory that holds no record is not a
// generation and is dropped whole.
func (p *reconciler) discardBackupScratch(operationID string) {
	root, err := dataPath(p.cfg.DataDir, DatabaseBackupDir)
	if err != nil {
		return
	}
	opDir := filepath.Join(root, operationID)
	_ = os.RemoveAll(filepath.Join(opDir, backup.PayloadPart))
	discardUncommittedOperation(opDir)
}

// clearSupersededMarker removes the restored marker once a new backup has been
// committed. The marker describes the data directory the restore produced; the
// first *committed* backup of the next generation supersedes it, and keeping it
// would label the current record with an older operation's snapshot time.
//
// "Committed" means the journal is backed_up and this operation's per-operation
// record reads back: a backup attempt that only reached backing_up and then
// failed (or was orphaned) never produced a generation, so it must not erase the
// lossy fact. The record may already be confirmed by the time this pass runs
// (reconcile was down through the whole upgrade), so both committed states count.
func (p *reconciler) clearSupersededMarker(ops []Op) {
	marker, ok, err := ReadRestoredMarker(p.cfg.DataDir)
	if err != nil || !ok {
		return
	}
	root, err := dataPath(p.cfg.DataDir, DatabaseBackupDir)
	if err != nil {
		return
	}
	for _, op := range ops {
		if op.Kind != KindUpdate || op.OperationID == marker.OperationID || op.State != StateBackedUp {
			continue
		}
		record, err := backup.Read(root, op.OperationID, os.Geteuid())
		if err != nil || (record.State != backup.StateStaged && record.State != backup.StateConfirmed) {
			continue
		}
		if err := removeRestoredMarker(p.cfg.DataDir); err != nil {
			p.report.Errors = append(p.report.Errors, ReconcileError{OperationID: marker.OperationID, Code: codeOf(err)})
		}
		return
	}
}

// ReadRestoredMarker returns the restore fact of this data directory. A missing
// marker is (zero, false, nil); a malformed, loose or symlinked one is an error
// (a lossy state must never be plausible-but-unreadable).
func ReadRestoredMarker(dataDir string) (RestoredMarker, bool, error) {
	var marker RestoredMarker
	root, err := dataPath(dataDir, HubUpgradeDir)
	if err != nil {
		return marker, false, err
	}
	path := filepath.Join(root, restoredMarkerName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return marker, false, nil
	}
	if err != nil {
		return marker, false, fail("HUB_RESTORE_MARKER_INVALID", "the restored marker could not be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || !ownedBy(os.Geteuid(), info) || info.Size() > JournalMaxBytes {
		return marker, false, fail("HUB_RESTORE_MARKER_INVALID", "the restored marker is not a private 0600 file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return marker, false, fail("HUB_RESTORE_MARKER_INVALID", "the restored marker could not be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return marker, false, fail("HUB_RESTORE_MARKER_INVALID", "the restored marker is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return marker, false, fail("HUB_RESTORE_MARKER_INVALID", "the restored marker carries trailing data")
	}
	if marker.Schema != RestoredSchema || !opIDRE.MatchString(marker.OperationID) ||
		marker.SnapshotAt.IsZero() || !marker.Lossy {
		return marker, false, fail("HUB_RESTORE_MARKER_INVALID", "the restored marker does not carry this schema, an operation, a snapshot time and the lossy flag")
	}
	return marker, true, nil
}

func writeRestoredMarker(dataDir string, marker RestoredMarker) error {
	root, err := dataPath(dataDir, HubUpgradeDir)
	if err != nil {
		return err
	}
	if err := ensurePrivateDir(root); err != nil {
		return err
	}
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker could not be encoded")
	}
	path := filepath.Join(root, restoredMarkerName)
	part := path + ".part"
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker scratch path could not be cleared")
	}
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker could not be written")
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
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker could not be written")
	}
	if err := os.Rename(part, path); err != nil {
		_ = os.Remove(part)
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker could not be published")
	}
	if err := syncDir(root); err != nil {
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker directory could not be flushed")
	}
	return nil
}

func removeRestoredMarker(dataDir string) error {
	root, err := dataPath(dataDir, HubUpgradeDir)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(root, restoredMarkerName)); err != nil && !os.IsNotExist(err) {
		return fail("HUB_RESTORE_MARKER_FAILED", "the restored marker could not be removed")
	}
	return syncDir(root)
}
