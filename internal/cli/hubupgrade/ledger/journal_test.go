package ledger

// Journal tests of #11d Task 3 (spec §5.5): one frozen state set, one
// forward-only Advance, and one Busy predicate the backup producer and the
// dispatcher both read. The journal is the authority across schema and data-dir
// changes, so a backward or skipped transition must be refused before it can
// overwrite a better fact.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func journalOperationID(t *testing.T, fill string) string {
	t.Helper()
	return strings.Repeat(fill, 32)
}

func journalOp(t *testing.T, operationID string, state State) Op {
	t.Helper()
	return Op{
		Schema: 1, OperationID: operationID, Kind: KindUpdate, State: state,
		TargetVersion: "1.0.1", FromVersion: "1.0.0",
		ManifestSHA256:   strings.Repeat("a", 64),
		PackageSHA256:    strings.Repeat("b", 64),
		DBSchema:         10,
		BackupGeneration: 1,
		UpdatedAt:        time.Unix(1700000000, 0).UTC(),
	}
}

func TestJournalForwardOnly(t *testing.T) {
	dataDir := t.TempDir()
	op := journalOp(t, journalOperationID(t, "a"), StateBackingUp)
	if err := WriteOp(dataDir, op); err != nil {
		t.Fatalf("write backing_up: %v", err)
	}
	path := filepath.Join(dataDir, OpsDir, op.OperationID+".json")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("journal mode %v want 0600", info.Mode().Perm())
	}
	got, ok, err := ReadOp(dataDir, op.OperationID, os.Geteuid())
	if err != nil || !ok {
		t.Fatalf("read backing_up: ok=%v err=%v", ok, err)
	}
	if got.State != StateBackingUp || got.TargetVersion != "1.0.1" || got.DBSchema != 10 {
		t.Fatalf("journal round trip: %+v", got)
	}

	next, err := Advance(got, StateBackedUp, "")
	if err != nil {
		t.Fatalf("backing_up -> backed_up: %v", err)
	}
	if next.State != StateBackedUp {
		t.Fatalf("advance did not move: %+v", next)
	}
	next, err = Advance(next, StateQueued, "")
	if err != nil {
		t.Fatalf("backed_up -> queued: %v", err)
	}
	next, err = Advance(next, StateApplying, "")
	if err != nil {
		t.Fatalf("queued -> applying: %v", err)
	}
	next, err = Advance(next, StateRestarting, "")
	if err != nil {
		t.Fatalf("applying -> restarting: %v", err)
	}
	next, err = Advance(next, StateVerifying, "")
	if err != nil {
		t.Fatalf("restarting -> verifying: %v", err)
	}
	next, err = Advance(next, StateConfirmed, "")
	if err != nil {
		t.Fatalf("verifying -> confirmed: %v", err)
	}
	if err := WriteOp(dataDir, next); err != nil {
		t.Fatalf("write confirmed: %v", err)
	}

	for _, backward := range []State{StateVerifying, StateApplying, StateBackedUp, StateBackingUp} {
		if _, err := Advance(next, backward, ""); err == nil {
			t.Fatalf("confirmed moved back to %s", backward)
		}
	}
	if _, err := Advance(journalOp(t, journalOperationID(t, "b"), StateBackingUp), StateQueued, ""); err == nil {
		t.Fatal("backing_up skipped backed_up")
	}
	if _, err := Advance(journalOp(t, journalOperationID(t, "c"), StateBackingUp), State("unknown"), ""); err == nil {
		t.Fatal("an unknown state was accepted")
	}

	// A failed operation is terminal for confirmation but may still be restored,
	// which is the one backward-looking transition the spec allows.
	failed, err := Advance(journalOp(t, journalOperationID(t, "d"), StateBackingUp), StateFailed, "HUB_BACKUP_VACUUM_FAILED")
	if err != nil {
		t.Fatalf("backing_up -> failed: %v", err)
	}
	if failed.ErrorCode != "HUB_BACKUP_VACUUM_FAILED" {
		t.Fatalf("error code not carried: %+v", failed)
	}
	if _, err := Advance(failed, StateConfirmed, ""); err == nil {
		t.Fatal("failed operation was confirmed")
	}
	if _, err := Advance(failed, StateReverted, ""); err != nil {
		t.Fatalf("failed operation must accept restore: %v", err)
	}

	// The dispatcher may report failed/partial before the Web ever leaves
	// queued (spec §5.5); the Web applies that terminal result without a
	// synthetic applying/restarting step.
	queued, err := Advance(journalOp(t, journalOperationID(t, "e"), StateBackedUp), StateQueued, "")
	if err != nil {
		t.Fatalf("backed_up -> queued: %v", err)
	}
	if _, err := Advance(queued, StatePartial, "HUB_HANDOFF_WRITE_FAILED"); err != nil {
		t.Fatalf("queued -> partial: %v", err)
	}
}

func TestJournalReadsAreOwnerAware(t *testing.T) {
	dataDir := t.TempDir()
	op := journalOp(t, journalOperationID(t, "a"), StateBackedUp)
	if err := WriteOp(dataDir, op); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadOp(dataDir, op.OperationID, os.Geteuid()); err != nil || !ok {
		t.Fatalf("owner read: ok=%v err=%v", ok, err)
	}
	if _, _, err := ReadOp(dataDir, op.OperationID, os.Geteuid()+1); err == nil {
		t.Fatal("ReadOp adopted a journal owned by another account")
	}
	if _, err := ListOps(dataDir, os.Geteuid()+1); err == nil {
		t.Fatal("ListOps adopted a journal owned by another account")
	}
	if _, _, err := Busy(dataDir, os.Geteuid()+1); err == nil {
		t.Fatal("Busy adopted a journal owned by another account")
	}
	if ops, err := ListOps(dataDir, os.Geteuid()); err != nil || len(ops) != 1 {
		t.Fatalf("owner list = %d ops, %v", len(ops), err)
	}
	if _, busy, err := Busy(dataDir, os.Geteuid()); err != nil || !busy {
		t.Fatalf("owner busy = %v, %v", busy, err)
	}
}

func TestJournalBusyOnlyNonTerminal(t *testing.T) {
	for _, tc := range []struct {
		state State
		busy  bool
	}{
		{StateBackingUp, true},
		{StateBackedUp, true},
		{StateQueued, true},
		{StateApplying, true},
		{StateRestarting, true},
		{StateVerifying, true},
		{StatePartial, true},
		{StateConfirmed, false},
		{StateReverted, false},
		{StateFailed, false},
	} {
		dataDir := t.TempDir()
		if err := WriteOp(dataDir, journalOp(t, journalOperationID(t, "a"), tc.state)); err != nil {
			t.Fatalf("write %s: %v", tc.state, err)
		}
		op, busy, err := Busy(dataDir, os.Geteuid())
		if err != nil {
			t.Fatalf("busy %s: %v", tc.state, err)
		}
		if busy != tc.busy {
			t.Fatalf("state %s busy=%v want %v (op %+v)", tc.state, busy, tc.busy, op)
		}
	}

	dataDir := t.TempDir()
	if _, busy, err := Busy(dataDir, os.Geteuid()); err != nil || busy {
		t.Fatalf("empty journal busy=%v err=%v", busy, err)
	}
}

func TestJournalConfirmedByNeedsBothHalves(t *testing.T) {
	op := journalOp(t, journalOperationID(t, "a"), StateVerifying)
	if !op.ConfirmedBy("1.0.1", strings.Repeat("b", 64)) {
		t.Fatal("matching version and digest did not confirm")
	}
	if op.ConfirmedBy("1.0.1", "") || op.ConfirmedBy("", strings.Repeat("b", 64)) {
		t.Fatal("half of the identity confirmed")
	}
	if op.ConfirmedBy("1.0.2", strings.Repeat("b", 64)) {
		t.Fatal("another version confirmed")
	}
}

func TestJournalRejectsUnknownFieldAndTrailingData(t *testing.T) {
	dataDir := t.TempDir()
	op := journalOp(t, journalOperationID(t, "a"), StateBackingUp)
	if err := WriteOp(dataDir, op); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, OpsDir, op.OperationID+".json")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field": strings.Replace(string(valid), "{", `{"future":true,`, 1),
		"trailing":      string(valid) + "{}",
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadOp(dataDir, op.OperationID, os.Geteuid()); err == nil {
			t.Fatalf("%s journal was accepted", name)
		}
	}
}
