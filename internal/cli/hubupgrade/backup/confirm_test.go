package backup

// Confirmation tests of #11d Task 3r (spec §5.2.1, R2): confirming an
// irreversible attempt clears the per-attempt approval bit so it can never latch
// the producer shut.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

// TestApproveConfirmRebackup is the R2 regression: an approved staged record
// confirms, the confirmation clears the approval bit, and a new backup then
// succeeds instead of being locked out forever.
func TestApproveConfirmRebackup(t *testing.T) {
	f := newHubBackupFixture(t)
	oldOp := strings.Repeat("5", 32)
	seedBackup(t, f.dataDir, oldOp, false)
	root := f.root()
	record, err := backup.Read(root, oldOp, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	record.IrreversibleApproved = true
	if err := backup.WriteRecord(filepath.Join(root, oldOp), record); err != nil {
		t.Fatal(err)
	}

	confirmed, err := ConfirmBackup(f.dataDir, oldOp, record.TargetVersion, record.PackageSHA256, time.Now())
	if err != nil {
		t.Fatalf("ConfirmBackup: %v", err)
	}
	if confirmed.State != backup.StateConfirmed {
		t.Fatalf("confirmed state = %q", confirmed.State)
	}
	if confirmed.IrreversibleApproved {
		t.Fatal("Confirm did not clear the irreversible approval bit")
	}
	stored, err := backup.Read(root, oldOp, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != backup.StateConfirmed || stored.IrreversibleApproved {
		t.Fatalf("stored record after confirm = %+v", stored)
	}
	// R2: a confirmed attempt releases the next backup.
	if _, err := CreateBackup(context.Background(), f.config()); err != nil {
		t.Fatalf("backup after a confirmed irreversible attempt: %v", err)
	}
}

// TestConfirmBackupKeepsAnUnapprovedBitAlone pins that ConfirmBackup writes
// nothing extra when the record never carried the bit.
func TestConfirmBackupKeepsAnUnapprovedBitAlone(t *testing.T) {
	f := newHubBackupFixture(t)
	op := strings.Repeat("4", 32)
	recordPath, _ := seedBackup(t, f.dataDir, op, false)
	record, err := backup.Read(f.root(), op, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ConfirmBackup(f.dataDir, op, record.TargetVersion, record.PackageSHA256, time.Now()); err != nil {
		t.Fatalf("ConfirmBackup: %v", err)
	}
	body, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "irreversible_approved") {
		t.Fatalf("an unapproved record gained the approval field:\n%s", body)
	}
}
