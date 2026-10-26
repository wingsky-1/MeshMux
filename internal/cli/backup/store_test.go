package backup

// The store tests pin the per-operation store (#11d Task 1r): one 0700
// directory per operation holding one 0600 record and one 0700 payload, a retry
// that re-verifies instead of overwriting, confirmed-only GC, and the cross-uid
// ownership rule of the read path (spec C1/C18, §5.9, §6.2-3, §6.15).

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// testPolicySchema is a stand-in for upgrade.PolicySchema: the backup package
// imports only the standard library, so the number is not imported here.
const testPolicySchema = 8

// noCheck is the trivial integrity callback of a fixture database copy.
func noCheck(string) error { return nil }

func testSpec(operationID string) Spec {
	return Spec{
		OperationID:       operationID,
		FromVersion:       "1.0.0",
		TargetVersion:     "1.0.1",
		DBSchema:          10,
		PolicySchema:      testPolicySchema,
		ManifestSHA256:    strings.Repeat("b", 64),
		PackageSHA256:     strings.Repeat("c", 64),
		FromPackageSHA256: strings.Repeat("d", 64),
		FromAgentSHA256:   strings.Repeat("e", 64),
	}
}

func codeOf(err error) string {
	if err == nil {
		return ""
	}
	code, _, _ := strings.Cut(err.Error(), ": ")
	return code
}

// writeTree writes one per-operation record whose payload is a copied snapshot
// tree, exactly as the Node rollback store does.
func writeTree(t *testing.T, root string, spec Spec) Record {
	t.Helper()
	source := filepath.Join(t.TempDir(), "snapshot")
	for _, f := range []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"usr/local/libexec/meshmuxd", "fixture old agent\n", 0755},
		{"etc/meshmux/agent.json", `{"node_id":"fixture"}`, 0600},
	} {
		path := filepath.Join(source, f.name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(f.data), f.mode); err != nil {
			t.Fatal(err)
		}
	}
	record, err := Write(root, spec, Payload{Kind: PayloadTree, SnapshotDir: source})
	if err != nil {
		t.Fatalf("write per-op record: %v", err)
	}
	return record
}

// stagePerOpDB puts the database copy a producer VACUUMed into the operation's
// scratch payload, which Write verifies and publishes.
func stagePerOpDB(t *testing.T, root, operationID string, data []byte) {
	t.Helper()
	part := filepath.Join(root, operationID, PayloadPart)
	if err := os.MkdirAll(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, SingleDBName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// writePerOpDB stages one database copy and publishes it as a per-operation
// single-database generation.
func writePerOpDB(t *testing.T, root string, spec Spec, data []byte) Record {
	t.Helper()
	stagePerOpDB(t, root, spec.OperationID, data)
	record, err := Write(root, spec, Payload{Kind: PayloadSingleDB, Check: noCheck})
	if err != nil {
		t.Fatalf("write per-op database record: %v", err)
	}
	return record
}

// TestPerOpSingleDBRequiresCheck pins the fail-closed rule for a payload the
// store cannot verify by itself: the producer's integrity callback is required,
// and a refusal writes no record and leaves no scratch payload behind.
func TestPerOpSingleDBRequiresCheck(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	stagePerOpDB(t, root, op, []byte("fixture database\n"))
	_, err := Write(root, testSpec(op), Payload{Kind: PayloadSingleDB})
	if codeOf(err) != CodeCorrupt {
		t.Fatalf("write without check = %v, want %s", err, CodeCorrupt)
	}
	opDir := filepath.Join(root, op)
	for _, name := range []string{RecordName, PayloadDir, PayloadPart} {
		if _, statErr := os.Lstat(filepath.Join(opDir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("a refused write left %q behind: %v", name, statErr)
		}
	}
}

// TestPerOpSingleDBIntegrityFailureKeepsOldGeneration is the B8 property: a copy
// that fails its integrity check never touches another operation's generation,
// and the scratch copy is cleaned up.
func TestPerOpSingleDBIntegrityFailureKeepsOldGeneration(t *testing.T) {
	root := t.TempDir()
	oldOp := strings.Repeat("a", 32)
	old := writeTree(t, root, testSpec(oldOp))
	oldRecordPath := filepath.Join(root, oldOp, RecordName)
	oldPayloadFile := filepath.Join(old.PayloadPath, "usr/local/libexec/meshmuxd")
	recordBefore, err := os.ReadFile(oldRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadBefore, err := os.ReadFile(oldPayloadFile)
	if err != nil {
		t.Fatal(err)
	}

	newOp := strings.Repeat("b", 32)
	stagePerOpDB(t, root, newOp, []byte("generation B\n"))
	_, err = Write(root, testSpec(newOp), Payload{
		Kind:  PayloadSingleDB,
		Check: func(string) error { return errors.New("integrity_check: not ok") },
	})
	if codeOf(err) != CodeCorrupt {
		t.Fatalf("integrity failure = %v, want %s", err, CodeCorrupt)
	}
	recordAfter, err := os.ReadFile(oldRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recordBefore, recordAfter) {
		t.Fatalf("a failed backup changed the old record:\nbefore:\n%s\nafter:\n%s", recordBefore, recordAfter)
	}
	payloadAfter, err := os.ReadFile(oldPayloadFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payloadBefore, payloadAfter) {
		t.Fatal("a failed backup changed the retained payload")
	}
	if _, err := Verify(root, old.OperationID, old.FromVersion, old.DBSchema, old.PolicySchema, os.Geteuid()); err != nil {
		t.Fatalf("the retained generation stopped verifying: %v", err)
	}
	newDir := filepath.Join(root, newOp)
	for _, name := range []string{RecordName, PayloadDir, PayloadPart} {
		if _, statErr := os.Lstat(filepath.Join(newDir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("the failed operation left %q behind: %v", name, statErr)
		}
	}
}

// TestExpectedOwnerEnforced pins the cross-uid read rule (spec §5.9): a root
// dispatcher reads a meshmux-owned record by naming the expected owner, and a
// caller that names another account is refused even though the bytes are
// readable. Ownership is part of the read contract, never a side effect of being
// able to open the file.
func TestExpectedOwnerEnforced(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	writeTree(t, root, testSpec(op))

	if _, err := Read(root, op, os.Geteuid()+1); codeOf(err) != CodeCorrupt {
		t.Fatalf("read with a foreign owner = %v, want %s", err, CodeCorrupt)
	}
	if _, err := Verify(root, op, "1.0.0", 10, testPolicySchema, os.Geteuid()+1); codeOf(err) != CodeCorrupt {
		t.Fatalf("verify with a foreign owner = %v, want %s", err, CodeCorrupt)
	}
	// The owner the writer used is the one that passes.
	if _, err := Read(root, op, os.Geteuid()); err != nil {
		t.Fatalf("read as the owning account: %v", err)
	}
	if _, err := Verify(root, op, "1.0.0", 10, testPolicySchema, os.Geteuid()); err != nil {
		t.Fatalf("verify as the owning account: %v", err)
	}
}

// TestGCOnlyConfirmedGenerations pins the B8 candidate set: only confirmed
// generations beyond keep are collected, so a failed or still-staged record and
// its payload always survive as a rollback source.
func TestGCOnlyConfirmedGenerations(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ops := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32), strings.Repeat("5", 32)}
	states := []string{StateConfirmed, StateConfirmed, StateConfirmed, StateStaged, StateFailed}
	for i, op := range ops {
		spec := testSpec(op)
		spec.Now = func() time.Time { return base.Add(time.Duration(i) * time.Hour) }
		record := writeTree(t, root, spec)
		switch states[i] {
		case StateStaged:
		case StateFailed:
			record.State = StateFailed
			if err := WriteRecord(filepath.Join(root, op), record); err != nil {
				t.Fatal(err)
			}
		case StateConfirmed:
			if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, record.CreatedAt); err != nil {
				t.Fatalf("confirm %s: %v", op, err)
			}
		}
	}

	removed, err := GC(root, KeepConfirmed)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	sort.Strings(removed)
	if len(removed) != 2 || removed[0] != ops[0] || removed[1] != ops[1] {
		t.Fatalf("removed = %q, want the two oldest confirmed generations %q", removed, ops[:2])
	}
	for i, op := range ops {
		_, statErr := os.Lstat(filepath.Join(root, op))
		if i < 2 && !os.IsNotExist(statErr) {
			t.Fatalf("old confirmed %s survived: %v", op, statErr)
		}
		if i >= 2 && statErr != nil {
			t.Fatalf("retained %s missing: %v", op, statErr)
		}
	}
	// Staged and failed records keep their payloads: they are still restore
	// sources.
	for _, op := range ops[3:] {
		record, err := Read(root, op, os.Geteuid())
		if err != nil {
			t.Fatalf("retained %s unreadable: %v", op, err)
		}
		if _, err := Verify(root, op, record.FromVersion, record.DBSchema, record.PolicySchema, os.Geteuid()); err != nil {
			t.Fatalf("retained %s payload damaged: %v", op, err)
		}
	}
	// A second GC is a no-op.
	if again, err := GC(root, KeepConfirmed); err != nil || len(again) != 0 {
		t.Fatalf("second gc = %q, %v; want none", again, err)
	}
}

// TestGCKeepTwoConfirmed pins the Hub keep count: four confirmed generations,
// keep=2, only the two oldest are collected.
func TestGCKeepTwoConfirmed(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ops := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32)}
	for i, op := range ops {
		spec := testSpec(op)
		spec.Now = func() time.Time { return base.Add(time.Duration(i) * time.Hour) }
		record := writeTree(t, root, spec)
		if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, record.CreatedAt); err != nil {
			t.Fatalf("confirm %s: %v", op, err)
		}
	}

	removed, err := GC(root, 2)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	sort.Strings(removed)
	if len(removed) != 2 || removed[0] != ops[0] || removed[1] != ops[1] {
		t.Fatalf("removed = %q, want the two oldest confirmed generations %q", removed, ops[:2])
	}
	for i, op := range ops {
		_, statErr := os.Lstat(filepath.Join(root, op))
		if i < 2 && !os.IsNotExist(statErr) {
			t.Fatalf("old confirmed %s survived: %v", op, statErr)
		}
		if i >= 2 && statErr != nil {
			t.Fatalf("retained confirmed %s missing: %v", op, statErr)
		}
	}
}

// TestGCNeverCollectsNewestOrStaged pins the two exclusions of the Hub GC: the
// newest two confirmed generations are never candidates, and a staged or failed
// generation is never collected even when it is the newest record.
func TestGCNeverCollectsNewestOrStaged(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ops := []string{
		strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32),
		strings.Repeat("4", 32), strings.Repeat("5", 32),
	}
	for i, op := range ops {
		spec := testSpec(op)
		spec.Now = func() time.Time { return base.Add(time.Duration(i) * time.Hour) }
		record := writeTree(t, root, spec)
		switch i {
		case 0, 1, 2:
			if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, record.CreatedAt); err != nil {
				t.Fatalf("confirm %s: %v", op, err)
			}
		case 3:
			// Still staged and the newest record.
		case 4:
			record.State = StateFailed
			if err := WriteRecord(filepath.Join(root, op), record); err != nil {
				t.Fatal(err)
			}
		}
	}

	removed, err := GC(root, 2)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(removed) != 1 || removed[0] != ops[0] {
		t.Fatalf("removed = %q, want only the oldest confirmed generation %q", removed, ops[0])
	}
	if _, statErr := os.Lstat(filepath.Join(root, ops[0])); !os.IsNotExist(statErr) {
		t.Fatalf("oldest confirmed %s survived: %v", ops[0], statErr)
	}
	for _, op := range ops[1:] {
		if _, statErr := os.Lstat(filepath.Join(root, op)); statErr != nil {
			t.Fatalf("retained %s missing: %v", op, statErr)
		}
		record, err := Read(root, op, os.Geteuid())
		if err != nil {
			t.Fatalf("retained %s unreadable: %v", op, err)
		}
		if _, err := Verify(root, op, record.FromVersion, record.DBSchema, record.PolicySchema, os.Geteuid()); err != nil {
			t.Fatalf("retained %s payload damaged: %v", op, err)
		}
	}
}

// TestGCTrashRenameFailureRetains pins the last line of the collection order: a
// generation is renamed into .trash-<unix> before it is deleted, so a failed
// rename retains it and reports the error instead of removing anything.
func TestGCTrashRenameFailureRetains(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	created := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	spec := testSpec(op)
	spec.Now = func() time.Time { return created }
	record := writeTree(t, root, spec)
	if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, created); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// A non-empty directory at the trash path makes the rename fail.
	trash := filepath.Join(root, op+".trash-"+unixSuffix(created))
	if err := os.MkdirAll(trash, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trash, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	removed, err := GC(root, 0)
	if err == nil {
		t.Fatal("gc reported success although the generation could not be retired")
	}
	if len(removed) != 0 {
		t.Fatalf("gc reported removed generations %q despite the failure", removed)
	}
	if _, statErr := os.Lstat(filepath.Join(root, op)); statErr != nil {
		t.Fatalf("the generation was not retained: %v", statErr)
	}
	if _, err := Read(root, op, os.Geteuid()); err != nil {
		t.Fatalf("the retained generation is unreadable: %v", err)
	}
}

// TestWriteSyncsStoreRoot is the Task 1r review carry: a published generation
// must be durable, so Write fsyncs the store root after the record rename. The
// journal of the Hub producer is written after this call; without the root sync a
// power loss could leave a backed_up journal next to no database-backup/<op>/ at
// all, which is data loss with no restore source.
func TestWriteSyncsStoreRoot(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	stagePerOpDB(t, root, op, []byte("fixture database copy\n"))

	var synced []string
	old := storeRootSync
	storeRootSync = func(dir string) error {
		synced = append(synced, dir)
		// The record must already be published when the root is flushed.
		if _, err := os.Lstat(filepath.Join(root, op, RecordName)); err != nil {
			t.Errorf("store root synced before the record was published: %v", err)
		}
		return nil
	}
	defer func() { storeRootSync = old }()

	if _, err := Write(root, testSpec(op), Payload{Kind: PayloadSingleDB, Check: noCheck}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(synced) != 1 || filepath.Clean(synced[0]) != filepath.Clean(root) {
		t.Fatalf("store root syncs = %v, want exactly %q", synced, root)
	}
}

// TestWriteReportsStoreRootSyncFailure pins that the flush is not best-effort: a
// store root that cannot be flushed is reported, because a generation the kernel
// may drop is not a rollback source.
func TestWriteReportsStoreRootSyncFailure(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("b", 32)
	stagePerOpDB(t, root, op, []byte("fixture database copy\n"))

	old := storeRootSync
	storeRootSync = func(string) error { return errors.New("sync failed") }
	defer func() { storeRootSync = old }()

	if _, err := Write(root, testSpec(op), Payload{Kind: PayloadSingleDB, Check: noCheck}); err == nil {
		t.Fatal("a failed store root sync was swallowed")
	} else if codeOf(err) != CodeCorrupt {
		t.Fatalf("sync failure code = %s, want %s", codeOf(err), CodeCorrupt)
	}
}
