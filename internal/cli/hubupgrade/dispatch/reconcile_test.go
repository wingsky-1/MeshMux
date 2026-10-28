package dispatch

// Tests for the #11d Task 5 reconcile pass (spec §5.5).
//
// The review gates are the startup/ticker split (only a startup pass may judge
// identity and confirm), the orphan timeouts (a Web that died must not leave a
// non-terminal operation blocking every later backup), the restored marker with
// its lossy snapshot time, and the confirmation side effects: pointer refresh
// first, then an unconditional confirmed-only GC that can never undo the
// confirmation.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

const reconcileDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type reconcileHarness struct {
	dataDir    string
	now        time.Time
	version    string
	digest     string
	digestErr  error
	results    map[string]Result
	resultErrs map[string]error
	confirmed  []string
	confirmErr error
	removed    []string
	claim      *Claim
	claimErr   error
}

func newReconcileHarness(t *testing.T) *reconcileHarness {
	t.Helper()
	return &reconcileHarness{
		dataDir: t.TempDir(), now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
		version: "1.0.0-dev", digest: reconcileDigest,
		results: map[string]Result{}, resultErrs: map[string]error{},
	}
}

func (h *reconcileHarness) config(startup bool) ReconcileConfig {
	return ReconcileConfig{
		DataDir: h.dataDir, Startup: startup,
		Now:     func() time.Time { return h.now },
		Version: h.version,
		Digest:  func() (string, error) { return h.digest, h.digestErr },
		Result: func(operationID string) (Result, bool, error) {
			if err, ok := h.resultErrs[operationID]; ok {
				return Result{}, false, err
			}
			result, ok := h.results[operationID]
			return result, ok, nil
		},
		Confirm: func(_ context.Context, operationID, target, pkg string) error {
			h.confirmed = append(h.confirmed, operationID)
			return h.confirmErr
		},
		RemoveRequest: func(operationID string) error {
			h.removed = append(h.removed, operationID)
			return nil
		},
		Claim: func() (Claim, bool, error) {
			if h.claimErr != nil {
				return Claim{}, false, h.claimErr
			}
			if h.claim == nil {
				return Claim{}, false, nil
			}
			return *h.claim, true, nil
		},
	}
}

func (h *reconcileHarness) run(t *testing.T, startup bool) ReconcileReport {
	t.Helper()
	report, err := Reconcile(context.Background(), h.config(startup))
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return report
}

func (h *reconcileHarness) op(t *testing.T, operationID string) Op {
	t.Helper()
	op, ok, err := ReadOp(h.dataDir, operationID, os.Geteuid())
	if err != nil || !ok {
		t.Fatalf("journal: ok=%v err=%v", ok, err)
	}
	return op
}

func (h *reconcileHarness) requireState(t *testing.T, operationID string, state State, code string) Op {
	t.Helper()
	op := h.op(t, operationID)
	if op.State != state || op.ErrorCode != code {
		t.Fatalf("journal state = %s/%q, want %s/%q", op.State, op.ErrorCode, state, code)
	}
	return op
}

// operation builds one journal document with the fields the state machine reads.
func operation(operationID string, state State, updated time.Time, generation int64) Op {
	return Op{
		Schema: OpSchema, OperationID: operationID, Kind: KindUpdate, State: state,
		TargetVersion: handoffTarget, FromVersion: handoffFrom,
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("c", 64),
		DBSchema: 10, BackupGeneration: generation, UpdatedAt: updated,
	}
}

// TestReconcileQueuedTimeout pins the 120s handoff timeout and that the request
// file is removed (the .path unit only re-arms on an empty directory).
func TestReconcileQueuedTimeout(t *testing.T) {
	t.Run("timed out", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("1", 32)
		writeJournal(t, h.dataDir, operation(id, StateQueued, h.now.Add(-HandoffTimeout-time.Second), 1))
		h.run(t, false)
		h.requireState(t, id, StateFailed, codeHandoffTimeout)
		if len(h.removed) != 1 || h.removed[0] != id {
			t.Fatalf("removed requests = %v, want [%s]", h.removed, id)
		}
	})

	t.Run("still waiting", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("2", 32)
		writeJournal(t, h.dataDir, operation(id, StateQueued, h.now.Add(-HandoffTimeout+time.Second), 1))
		h.run(t, false)
		h.requireState(t, id, StateQueued, "")
		if len(h.removed) != 0 {
			t.Fatalf("removed requests = %v, want none", h.removed)
		}
	})

	t.Run("answered request does not time out", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("3", 32)
		writeJournal(t, h.dataDir, operation(id, StateQueued, h.now.Add(-HandoffTimeout-time.Second), 1))
		h.results[id] = Result{Schema: ResultSchema, OperationID: id, Phase: ResultAccepted, UpdatedAt: h.now}
		h.run(t, false)
		h.requireState(t, id, StateApplying, "")
		if len(h.removed) != 0 {
			t.Fatalf("removed requests = %v, want none", h.removed)
		}
	})
}

// TestReconcileOrphan30Min pins the pure-age bound of an applying operation: the
// dispatcher wrote a progress result and then stopped.
func TestReconcileOrphan30Min(t *testing.T) {
	t.Run("just under the bound", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("1", 32)
		writeJournal(t, h.dataDir, operation(id, StateApplying, h.now.Add(-OrphanTimeout+time.Minute), 1))
		h.results[id] = Result{Schema: ResultSchema, OperationID: id, Phase: ResultAccepted, UpdatedAt: h.now}
		h.run(t, false)
		h.requireState(t, id, StateApplying, "")
	})

	t.Run("past the bound", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("2", 32)
		writeJournal(t, h.dataDir, operation(id, StateApplying, h.now.Add(-OrphanTimeout-time.Minute), 1))
		h.results[id] = Result{Schema: ResultSchema, OperationID: id, Phase: ResultSwapping, UpdatedAt: h.now}
		h.run(t, false)
		h.requireState(t, id, StateFailed, codeUpgradeOrphaned)
	})
}

// TestReconcileBackingUpOrphan pins the backing_up row: fail with
// HUB_BACKUP_ORPHANED, delete this operation's payload.part, and leave no
// record behind.
func TestReconcileBackingUpOrphan(t *testing.T) {
	h := newReconcileHarness(t)
	id := strings.Repeat("4", 32)
	root := filepath.Join(h.dataDir, DatabaseBackupDir)
	opDir, err := backup.Dir(root, id)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("half a copy"), 0600); err != nil {
		t.Fatal(err)
	}
	writeJournal(t, h.dataDir, operation(id, StateBackingUp, h.now.Add(-OrphanTimeout-time.Minute), 1))
	h.run(t, false)
	h.requireState(t, id, StateFailed, codeBackupOrphaned)
	if _, err := os.Lstat(part); !os.IsNotExist(err) {
		t.Fatalf("the scratch payload survived: %v", err)
	}
	if _, err := os.Lstat(opDir); !os.IsNotExist(err) {
		t.Fatalf("a recordless operation directory survived: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(opDir, backup.RecordName)); !os.IsNotExist(err) {
		t.Fatalf("a record was created by the reconcile pass: %v", err)
	}
}

// TestReconcileBackedUpOrphan pins the backed_up row: it fails, but the record
// and payload are the rollback source and stay readable.
func TestReconcileBackedUpOrphan(t *testing.T) {
	h := newReconcileHarness(t)
	id := strings.Repeat("5", 32)
	record := plantRecord(t, h.dataDir, id, h.now.Add(-time.Hour))
	writeJournal(t, h.dataDir, operation(id, StateBackedUp, h.now.Add(-OrphanTimeout-time.Minute), 1))
	h.run(t, false)
	h.requireState(t, id, StateFailed, codeBackupOrphaned)
	stored, err := backup.Read(filepath.Join(h.dataDir, DatabaseBackupDir), id, os.Geteuid())
	if err != nil {
		t.Fatalf("the orphan timeout removed the rollback source: %v", err)
	}
	if stored.PayloadSHA256 != record.PayloadSHA256 {
		t.Fatalf("the record changed: %+v", stored)
	}
}

// TestReconcileRestartingOrphan pins the restarting row the oracle added: a
// restart that never produced a new identity is an orphan, not an endless wait.
// The fixture runs the old binary (version == from), so the ticker's only
// terminal decision here is the pure age bound.
func TestReconcileRestartingOrphan(t *testing.T) {
	h := newReconcileHarness(t)
	if h.version != handoffFrom {
		t.Fatalf("fixture version = %q, want the from version", h.version)
	}
	id := strings.Repeat("6", 32)
	writeJournal(t, h.dataDir, operation(id, StateRestarting, h.now.Add(-OrphanTimeout-time.Minute), 1))
	h.run(t, false)
	h.requireState(t, id, StateFailed, codeUpgradeOrphaned)
}

// TestReconcileRestartingNotApplied pins both halves of the restart identity
// rule: a startup pass that still runs the from version concludes NOT_APPLIED,
// while a ticker pass never makes that call (the old process cannot tell "not
// swapped yet" from "swapped and failed").
func TestReconcileRestartingNotApplied(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("7", 32)
		writeJournal(t, h.dataDir, operation(id, StateRestarting, h.now.Add(-time.Minute), 1))
		h.run(t, true)
		h.requireState(t, id, StateFailed, codeUpgradeNotDone)
	})

	t.Run("ticker does not judge", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("8", 32)
		writeJournal(t, h.dataDir, operation(id, StateRestarting, h.now.Add(-time.Minute), 1))
		h.run(t, false)
		h.requireState(t, id, StateRestarting, "")
	})
}

// TestReconcileConfirmNeedsVersionAndDigest pins the one confirmation predicate:
// the running version AND the package digest must name the operation. A `from`
// version is only a hint that the swap did not happen, and a digest-only match
// is never a release.
func TestReconcileConfirmNeedsVersionAndDigest(t *testing.T) {
	id := strings.Repeat("9", 32)
	cases := []struct {
		name         string
		version      string
		digest       string
		wantState    State
		wantCode     string
		wantConfirms int
	}{
		{"target and digest", handoffTarget, strings.Repeat("c", 64), StateConfirmed, "", 1},
		{"target but another digest", handoffTarget, strings.Repeat("e", 64), StateFailed, codeVerifyMismatch, 0},
		{"from version", handoffFrom, strings.Repeat("c", 64), StateFailed, codeUpgradeNotDone, 0},
		{"neither", "2.0.0", strings.Repeat("e", 64), StateFailed, codeVerifyMismatch, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newReconcileHarness(t)
			h.version, h.digest = tc.version, tc.digest
			writeJournal(t, h.dataDir, operation(id, StateVerifying, h.now.Add(-time.Minute), 1))
			h.run(t, true)
			h.requireState(t, id, tc.wantState, tc.wantCode)
			if len(h.confirmed) != tc.wantConfirms {
				t.Fatalf("confirmed %v, want %d call(s)", h.confirmed, tc.wantConfirms)
			}
		})
	}
}

// TestReconcileConfirmOnlyOnStartupPass pins spec §5.5's "判定只在启动对账执行":
// the ticker advances a restarting operation whose identity already matches the
// target into verifying, and only the next startup pass confirms it.
func TestReconcileConfirmOnlyOnStartupPass(t *testing.T) {
	h := newReconcileHarness(t)
	h.version, h.digest = handoffTarget, strings.Repeat("c", 64)
	id := strings.Repeat("a", 32)
	writeJournal(t, h.dataDir, operation(id, StateRestarting, h.now.Add(-time.Minute), 1))

	h.run(t, false)
	h.requireState(t, id, StateVerifying, "")
	if len(h.confirmed) != 0 {
		t.Fatalf("the ticker confirmed an operation: %v", h.confirmed)
	}

	h.run(t, true)
	h.requireState(t, id, StateConfirmed, "")
	if len(h.confirmed) != 1 || h.confirmed[0] != id {
		t.Fatalf("startup confirms = %v, want [%s]", h.confirmed, id)
	}
}

// TestReconcileVerifyMismatch pins a verifying operation whose running binary is
// neither the target nor the from version: it cannot be confirmed and must not
// linger as a non-terminal operation.
func TestReconcileVerifyMismatch(t *testing.T) {
	h := newReconcileHarness(t)
	h.version, h.digest = "2.0.0", strings.Repeat("f", 64)
	id := strings.Repeat("b", 32)
	writeJournal(t, h.dataDir, operation(id, StateVerifying, h.now.Add(-time.Minute), 1))
	h.run(t, true)
	h.requireState(t, id, StateFailed, codeVerifyMismatch)
	if len(h.confirmed) != 0 {
		t.Fatalf("a mismatching readback confirmed: %v", h.confirmed)
	}
}

// TestReconcileConfirmFailureKeepsVerifying pins that a side-effect failure does
// not lose the operation: the journal stays verifying so the next startup pass
// retries the idempotent confirmation.
func TestReconcileConfirmFailureKeepsVerifying(t *testing.T) {
	h := newReconcileHarness(t)
	h.version, h.digest = handoffTarget, strings.Repeat("c", 64)
	h.confirmErr = errors.New("UPDATE_BACKUP_CORRUPT: the record does not verify")
	id := strings.Repeat("c", 32)
	writeJournal(t, h.dataDir, operation(id, StateVerifying, h.now.Add(-time.Minute), 1))
	report := h.run(t, true)
	h.requireState(t, id, StateVerifying, "")
	if len(report.Errors) != 1 || report.Errors[0].Code != "UPDATE_BACKUP_CORRUPT" {
		t.Fatalf("report errors = %+v", report.Errors)
	}
}

// TestReconcileRevertedSticky pins C12: a reverted operation is never rewritten,
// not even by a later startup pass that sees a stale terminal result.
func TestReconcileRevertedSticky(t *testing.T) {
	h := newReconcileHarness(t)
	id := strings.Repeat("d", 32)
	writeJournal(t, h.dataDir, operation(id, StateReverted, h.now.Add(-time.Hour), 1))
	before, err := os.ReadFile(filepath.Join(h.dataDir, OpsDir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	h.results[id] = Result{Schema: ResultSchema, OperationID: id, Phase: ResultFailed, ErrorCode: "HUB_UPGRADE_FAILED", UpdatedAt: h.now}
	h.run(t, true)
	after, err := os.ReadFile(filepath.Join(h.dataDir, OpsDir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a startup pass rewrote a reverted operation")
	}
}

// TestReconcileRestoredMarker pins the restore fact: a restored result writes
// restored.json with the snapshot time and the lossy flag, moves the journal to
// reverted, and only a *committed* backup of a later generation clears the
// marker. A failed attempt (backing_up that never committed a record) must not
// erase the lossy fact. The reverted journal stays reverted.
func TestReconcileRestoredMarker(t *testing.T) {
	h := newReconcileHarness(t)
	id := strings.Repeat("e", 32)
	record := plantRecord(t, h.dataDir, id, h.now.Add(-time.Hour))
	writeJournal(t, h.dataDir, operation(id, StateVerifying, h.now.Add(-time.Minute), 1))
	h.results[id] = Result{Schema: ResultSchema, OperationID: id, Phase: ResultRestored, UpdatedAt: h.now}
	h.run(t, true)

	h.requireState(t, id, StateReverted, "")
	marker, ok, err := ReadRestoredMarker(h.dataDir)
	if err != nil || !ok {
		t.Fatalf("restored marker: ok=%v err=%v", ok, err)
	}
	if marker.Schema != RestoredSchema || marker.OperationID != id || !marker.Lossy ||
		!marker.SnapshotAt.Equal(record.CreatedAt) {
		t.Fatalf("restored marker = %+v, want snapshot %v", marker, record.CreatedAt)
	}

	// A repeated startup pass with the same stale result must not recreate or
	// rewrite anything: reverted is sticky.
	h.run(t, true)
	h.requireState(t, id, StateReverted, "")

	// A failed backup attempt never committed a record, so it does not supersede
	// the marker: the attempt only reached backing_up and is orphaned.
	attempt := strings.Repeat("a", 32)
	writeJournal(t, h.dataDir, operation(attempt, StateBackingUp, h.now.Add(-OrphanTimeout-time.Minute), 2))
	h.run(t, true)
	h.requireState(t, attempt, StateFailed, codeBackupOrphaned)
	if _, ok, err := ReadRestoredMarker(h.dataDir); err != nil || !ok {
		t.Fatalf("marker after a failed backup attempt: ok=%v err=%v", ok, err)
	}

	// A committed per-operation record with the journal backed_up is the first
	// generation that replaces the restored data directory.
	committed := strings.Repeat("b", 32)
	plantRecord(t, h.dataDir, committed, h.now)
	writeJournal(t, h.dataDir, operation(committed, StateBackedUp, h.now, 3))
	h.run(t, true)
	if _, ok, err := ReadRestoredMarker(h.dataDir); err != nil || ok {
		t.Fatalf("marker after a committed backup: ok=%v err=%v", ok, err)
	}
	h.requireState(t, id, StateReverted, "")
	h.requireState(t, committed, StateBackedUp, "")
}

// TestConfirmCollectsConfirmedBeyondTwo pins the Hub's keep=2 policy at the
// confirm call site: three confirmed generations become two, the newest staged
// record is never a candidate.
func TestConfirmCollectsConfirmedBeyondTwo(t *testing.T) {
	h := newReconcileHarness(t)
	root := filepath.Join(h.dataDir, DatabaseBackupDir)
	ids := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)}
	for i, id := range ids {
		record := plantRecord(t, h.dataDir, id, h.now.Add(time.Duration(i)*time.Minute))
		if _, err := backup.Confirm(root, id, record.TargetVersion, record.PackageSHA256, h.now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	staged := plantRecord(t, h.dataDir, strings.Repeat("4", 32), h.now.Add(time.Hour))

	record, err := ConfirmAndCollect(h.dataDir, ids[2], handoffTarget, strings.Repeat("c", 64), h.now, ConfirmHooks{})
	if err != nil {
		t.Fatalf("ConfirmAndCollect: %v", err)
	}
	if record.State != backup.StateConfirmed {
		t.Fatalf("record state = %q", record.State)
	}
	if _, err := backup.Read(root, ids[0], os.Geteuid()); err == nil {
		t.Fatal("the oldest confirmed generation was not collected")
	}
	for _, id := range ids[1:] {
		stored, err := backup.Read(root, id, os.Geteuid())
		if err != nil || stored.State != backup.StateConfirmed {
			t.Fatalf("generation %s: %v %+v", id, err, stored)
		}
	}
	if _, err := backup.Read(root, staged.OperationID, os.Geteuid()); err != nil {
		t.Fatalf("the newest staged record was collected: %v", err)
	}
}

// TestConfirmPointerFailureStillCollects pins spec §5.2.1: a pointer refresh
// failure is only logged (HUB_BACKUP_POINTER_STALE) and GC still runs with
// keep=2, because the pointer is a diagnostic copy and the record is the
// authority.
func TestConfirmPointerFailureStillCollects(t *testing.T) {
	h := newReconcileHarness(t)
	root := filepath.Join(h.dataDir, DatabaseBackupDir)
	ids := []string{strings.Repeat("5", 32), strings.Repeat("6", 32), strings.Repeat("7", 32)}
	for i, id := range ids {
		record := plantRecord(t, h.dataDir, id, h.now.Add(time.Duration(i)*time.Minute))
		if _, err := backup.Confirm(root, id, record.TargetVersion, record.PackageSHA256, h.now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	var keep int
	var logged []string
	record, err := ConfirmAndCollect(h.dataDir, ids[2], handoffTarget, strings.Repeat("c", 64), h.now, ConfirmHooks{
		Publish: func(string, string) error {
			return fail(codePointerStale, "injected pointer failure")
		},
		Collect: func(dataDir string, requested int) ([]string, error) {
			keep = requested
			return CleanupConfirmed(dataDir, requested)
		},
		Log: func(code, _ string) { logged = append(logged, code) },
	})
	if err != nil {
		t.Fatalf("a pointer failure failed the confirmation: %v", err)
	}
	if record.State != backup.StateConfirmed {
		t.Fatalf("record state = %q", record.State)
	}
	if keep != minHubKeep {
		t.Fatalf("collector keep = %d, want %d", keep, minHubKeep)
	}
	if len(logged) != 1 || logged[0] != codePointerStale {
		t.Fatalf("logged codes = %v, want [%s]", logged, codePointerStale)
	}
	if _, err := backup.Read(root, ids[0], os.Geteuid()); err == nil {
		t.Fatal("GC did not run after a pointer failure")
	}
}

// TestApproveAndConfirmDoNotTakeProduceLock pins the lock obligation of the
// per-operation store: the producer mutex covers only the producer's
// check-then-act triple, so the approval read-modify-write and a confirmation
// both complete while it is held.
func TestApproveAndConfirmDoNotTakeProduceLock(t *testing.T) {
	h := newReconcileHarness(t)
	root := filepath.Join(h.dataDir, DatabaseBackupDir)
	confirmID := strings.Repeat("8", 32)
	record := plantRecord(t, h.dataDir, confirmID, h.now.Add(-time.Hour))
	approveID := strings.Repeat("9", 32)
	plantRecord(t, h.dataDir, approveID, h.now)

	unlock := LockBackupProduce()
	defer unlock()

	done := make(chan error, 1)
	go func() {
		_, err := ConfirmAndCollect(h.dataDir, confirmID, record.TargetVersion, record.PackageSHA256, h.now, ConfirmHooks{})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("confirm: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the confirmation waited for the producer mutex")
	}

	approved, err := backup.Read(root, approveID, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	approved.IrreversibleApproved = true
	if err := backup.WriteRecord(filepath.Join(root, approveID), approved); err != nil {
		t.Fatalf("the approval read-modify-write waited for the producer mutex: %v", err)
	}
	if stored, err := backup.Read(root, approveID, os.Geteuid()); err != nil || !stored.IrreversibleApproved {
		t.Fatalf("stored approval: %v %+v", err, stored)
	}
}

// TestConfirmAndCollectNeedsTheReadbackAnchors pins the confirmation binding:
// the side effects (pointer refresh, collection) run only for an accepted
// readback that names the record's own target release and package digest. The
// anchors are checked before the idempotent confirmed short-circuit, so a stale
// readback can never re-confirm an already confirmed generation.
func TestConfirmAndCollectNeedsTheReadbackAnchors(t *testing.T) {
	h := newReconcileHarness(t)
	root := filepath.Join(h.dataDir, DatabaseBackupDir)
	id := strings.Repeat("a", 32)
	plantRecord(t, h.dataDir, id, h.now)
	publishes := 0
	hooks := ConfirmHooks{Publish: func(string, string) error {
		publishes++
		return nil
	}}

	// Another package digest: the record stays staged and nothing is published.
	_, err := ConfirmAndCollect(h.dataDir, id, handoffTarget, strings.Repeat("d", 64), h.now, hooks)
	if codeOf(err) != "UPDATE_BACKUP_MISMATCH" {
		t.Fatalf("stale readback error = %v, want UPDATE_BACKUP_MISMATCH", err)
	}
	if publishes != 0 {
		t.Fatal("a stale readback published the pointer")
	}
	stored, err := backup.Read(root, id, os.Geteuid())
	if err != nil || stored.State != backup.StateStaged {
		t.Fatalf("record after a stale readback: %v %+v", err, stored)
	}

	// The accepted readback confirms and publishes.
	if _, err := ConfirmAndCollect(h.dataDir, id, handoffTarget, strings.Repeat("c", 64), h.now, hooks); err != nil {
		t.Fatalf("accepted readback: %v", err)
	}
	stored, err = backup.Read(root, id, os.Geteuid())
	if err != nil || stored.State != backup.StateConfirmed {
		t.Fatalf("record after the accepted readback: %v %+v", err, stored)
	}
	if publishes != 1 {
		t.Fatalf("pointer publishes = %d, want 1", publishes)
	}

	// Another release can never re-confirm the same record, even though the
	// record is already confirmed (the anchor check precedes the short-circuit).
	_, err = ConfirmAndCollect(h.dataDir, id, "1.0.2", strings.Repeat("c", 64), h.now, hooks)
	if codeOf(err) != "UPDATE_BACKUP_MISMATCH" {
		t.Fatalf("stale re-confirm error = %v, want UPDATE_BACKUP_MISMATCH", err)
	}
	if publishes != 1 {
		t.Fatal("a stale re-confirm published the pointer")
	}

	// The same accepted readback stays idempotent, so a retried startup pass
	// completes instead of failing forever.
	if _, err := ConfirmAndCollect(h.dataDir, id, handoffTarget, strings.Repeat("c", 64), h.now, hooks); err != nil {
		t.Fatalf("idempotent readback: %v", err)
	}
	if publishes != 2 {
		t.Fatalf("pointer publishes = %d, want 2", publishes)
	}
}

// TestReconcileDigestFailureIsRetryable pins the digest rule of this fix round:
// an unreadable running digest is an environment failure, not an identity. It
// must never be folded into identityOther, because that would write a terminal
// VERIFY_MISMATCH (or NOT_APPLIED) for an operation that is in fact fine. The
// pass reports HUB_DIGEST_UNAVAILABLE and leaves the journal untouched so the
// next pass retries.
func TestReconcileDigestFailureIsRetryable(t *testing.T) {
	digestErr := errors.New("HUB_DIGEST_UNAVAILABLE: the running executable could not be opened")
	for _, state := range []State{StateVerifying, StateRestarting} {
		t.Run(string(state), func(t *testing.T) {
			h := newReconcileHarness(t)
			h.version, h.digestErr = handoffTarget, digestErr
			id := strings.Repeat("a", 32)
			writeJournal(t, h.dataDir, operation(id, state, h.now.Add(-time.Minute), 1))
			report := h.run(t, true)
			h.requireState(t, id, state, "")
			if len(report.Errors) != 1 || report.Errors[0].Code != "HUB_DIGEST_UNAVAILABLE" {
				t.Fatalf("report errors = %+v, want one HUB_DIGEST_UNAVAILABLE", report.Errors)
			}
			if len(h.confirmed) != 0 {
				t.Fatalf("a digest failure confirmed: %v", h.confirmed)
			}
			if len(report.Changes) != 0 {
				t.Fatalf("a digest failure wrote the journal: %+v", report.Changes)
			}
		})
	}
}

// claimFor builds the R1 anchor of one operation. The old pin set is complete
// so the strict claim reader would accept it.
func claimFor(operationID string, phase string, op Op) Claim {
	return Claim{
		Schema: ClaimSchema, Phase: phase, OperationID: operationID,
		TargetVersion: op.TargetVersion, FromVersion: op.FromVersion,
		NewSHA256: op.PackageSHA256,
		OldPins: Pins{
			HubSharedSHA: strings.Repeat("a", 64), HubManagedSHA: strings.Repeat("a", 64),
		},
		CreatedAt: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	}
}

// TestReconcileClaimSwappingNewBinary pins the R1 terminal: the claim says the
// swap section began, and the running identity is already the target. The four
// pins may still be old, so restore must become legal immediately instead of
// waiting out the 30 minute orphan bound.
func TestReconcileClaimSwappingNewBinary(t *testing.T) {
	h := newReconcileHarness(t)
	h.version = handoffTarget
	id := strings.Repeat("a", 32)
	op := operation(id, StateApplying, h.now.Add(-time.Minute), 1)
	writeJournal(t, h.dataDir, op)
	h.claim = &Claim{}
	claim := claimFor(id, ClaimPhaseSwapping, op)
	h.claim = &claim
	h.digest = op.PackageSHA256
	h.run(t, true)
	h.requireState(t, id, StateFailed, codeRepinIncomplete)
}

// TestReconcileClaimOldBinaryInert pins the safe half: the old binary still
// runs, so the swap never became this image. The claim adds no terminal; the
// ordinary NOT_APPLIED / timeout logic decides. The Web cannot unlink a
// root-owned claim (C22), so the inert file simply stays.
func TestReconcileClaimOldBinaryInert(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		h := newReconcileHarness(t)
		if h.version != handoffFrom {
			t.Fatalf("fixture version = %q", h.version)
		}
		id := strings.Repeat("b", 32)
		op := operation(id, StateRestarting, h.now.Add(-time.Minute), 1)
		writeJournal(t, h.dataDir, op)
		claim := claimFor(id, ClaimPhaseSwapping, op)
		h.claim = &claim
		h.run(t, true)
		h.requireState(t, id, StateFailed, codeUpgradeNotDone)
	})

	t.Run("ticker keeps it", func(t *testing.T) {
		h := newReconcileHarness(t)
		id := strings.Repeat("c", 32)
		op := operation(id, StateRestarting, h.now.Add(-time.Minute), 1)
		writeJournal(t, h.dataDir, op)
		claim := claimFor(id, ClaimPhaseSwapping, op)
		h.claim = &claim
		h.run(t, false)
		h.requireState(t, id, StateRestarting, "")
	})
}

// TestReconcileRepinnedClaimInert: every pin moved; only the unlink did not.
// The claim must not stop the ordinary startup confirmation.
func TestReconcileRepinnedClaimInert(t *testing.T) {
	h := newReconcileHarness(t)
	h.version = handoffTarget
	id := strings.Repeat("d", 32)
	op := operation(id, StateRestarting, h.now.Add(-time.Minute), 1)
	writeJournal(t, h.dataDir, op)
	claim := claimFor(id, ClaimPhaseRepinned, op)
	h.claim = &claim
	h.digest = op.PackageSHA256
	h.run(t, true)
	h.requireState(t, id, StateConfirmed, "")
}
