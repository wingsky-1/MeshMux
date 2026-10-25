package backup

// The store tests pin the two layouts apart: the per-operation store keeps the
// 11c-3 directory semantics, while the flat Hub slot is a single generation that
// a new backup replaces atomically. The flat slot has two files and no atomic
// multi-file commit, so every crash window is tested explicitly
// (recoverFlatSlot) and GC is a no-op unless the caller asks for keep<1
// (spec C1/C18, §5.2, §6.2-3, §6.15).

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

var errSimulatedCrash = errors.New("simulated crash")

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

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
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
	record, err := Write(root, spec, LayoutPerOp, Payload{Kind: PayloadTree, SnapshotDir: source})
	if err != nil {
		t.Fatalf("write per-op record: %v", err)
	}
	return record
}

// stageDB puts the database copy a producer VACUUMed into the flat scratch slot
// the store promotes from.
func stageDB(t *testing.T, root string, data []byte) {
	t.Helper()
	part := filepath.Join(root, PayloadPart)
	if err := os.MkdirAll(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, SingleDBName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// writeDB stages one database copy and publishes it through the flat layout.
func writeDB(t *testing.T, root string, spec Spec, data []byte) Record {
	t.Helper()
	stageDB(t, root, data)
	record, err := Write(root, spec, LayoutFlat, Payload{Kind: PayloadSingleDB, Check: noCheck})
	if err != nil {
		t.Fatalf("write flat record: %v", err)
	}
	return record
}

// crashWrite runs one flat write and dies at the named publication step, so the
// slot is left exactly as a process crash would leave it: no cleanup ran.
func crashWrite(t *testing.T, root string, spec Spec, stage string) {
	t.Helper()
	previous := flatCrashPoint
	flatCrashPoint = func(reached string) {
		if reached == stage {
			panic(errSimulatedCrash)
		}
	}
	defer func() { flatCrashPoint = previous }()
	func() {
		defer func() {
			switch recovered := recover(); recovered {
			case errSimulatedCrash:
				return
			case nil:
				t.Fatalf("write finished without reaching the %q crash point", stage)
			default:
				t.Fatalf("write failed before the %q crash point: %v", stage, recovered)
			}
		}()
		if _, err := Write(root, spec, LayoutFlat, Payload{Kind: PayloadSingleDB, Check: noCheck}); err != nil {
			panic(err)
		}
	}()
}

// TestSingleDBPayloadRequiresCheck pins the fail-closed rule for a payload the
// store cannot verify by itself: the producer's integrity callback is required,
// and a refusal writes no record and leaves no scratch payload behind.
func TestSingleDBPayloadRequiresCheck(t *testing.T) {
	root := t.TempDir()
	stageDB(t, root, []byte("fixture database\n"))
	_, err := Write(root, testSpec(strings.Repeat("a", 32)), LayoutFlat, Payload{Kind: PayloadSingleDB})
	if codeOf(err) != CodeCorrupt {
		t.Fatalf("write without check = %v, want %s", err, CodeCorrupt)
	}
	for _, name := range []string{RecordName, PayloadDir, PayloadPart} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(statErr) {
			t.Fatalf("a refused write left %q behind: %v", name, statErr)
		}
	}
}

// TestSingleDBIntegrityFailureKeepsOldGeneration is the B8 property on the Hub
// slot: a copy that fails its integrity check never replaces the generation that
// is already there, and the scratch copy is cleaned up.
func TestSingleDBIntegrityFailureKeepsOldGeneration(t *testing.T) {
	root := t.TempDir()
	old := writeDB(t, root, testSpec(strings.Repeat("a", 32)), []byte("generation A\n"))
	recordPath := filepath.Join(root, RecordName)
	payloadPath := filepath.Join(old.PayloadPath, SingleDBName)
	recordBefore, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadBefore, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}

	stageDB(t, root, []byte("generation B\n"))
	_, err = Write(root, testSpec(strings.Repeat("b", 32)), LayoutFlat, Payload{
		Kind:  PayloadSingleDB,
		Check: func(string) error { return errors.New("integrity_check: not ok") },
	})
	if codeOf(err) != CodeCorrupt {
		t.Fatalf("integrity failure = %v, want %s", err, CodeCorrupt)
	}
	recordAfter, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recordBefore, recordAfter) {
		t.Fatalf("a failed backup changed the record:\nbefore:\n%s\nafter:\n%s", recordBefore, recordAfter)
	}
	payloadAfter, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payloadBefore, payloadAfter) {
		t.Fatal("a failed backup changed the retained payload")
	}
	if _, statErr := os.Lstat(filepath.Join(root, PayloadPart)); !os.IsNotExist(statErr) {
		t.Fatalf("the failed copy's scratch payload survived: %v", statErr)
	}
	if _, err := Verify(root, old.OperationID, old.FromVersion, old.DBSchema, old.PolicySchema, LayoutFlat, os.Geteuid()); err != nil {
		t.Fatalf("the retained generation stopped verifying: %v", err)
	}
}

// TestFlatWriteCrashWindowsRecover pins the crash recovery of the two-file slot.
// A crash between the payload renames, one before the record rename, and one
// after it must all resolve to a generation whose record and payload agree: the
// old one while the new record is not committed, the new one once it is. A slot
// where neither pair agrees is corrupt, never guessed.
func TestFlatWriteCrashWindowsRecover(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stage  string
		wantOp string
		wantDB string
	}{
		{"between the payload renames", flatStagePayloadRetired, strings.Repeat("a", 32), "generation A\n"},
		{"before the record rename", flatStagePayloadPublished, strings.Repeat("a", 32), "generation A\n"},
		{"after the record rename", flatStageRecordPublished, strings.Repeat("b", 32), "generation B\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			old := writeDB(t, root, testSpec(strings.Repeat("a", 32)), []byte("generation A\n"))
			stageDB(t, root, []byte("generation B\n"))
			crashWrite(t, root, testSpec(strings.Repeat("b", 32)), tc.stage)

			// Recovery happens on the next entry, not in the crashed write.
			record, err := Read(root, tc.wantOp, LayoutFlat, os.Geteuid())
			if err != nil {
				t.Fatalf("read after the %q crash: %v", tc.stage, err)
			}
			if record.OperationID != tc.wantOp {
				t.Fatalf("recovered record = %s, want %s", record.OperationID, tc.wantOp)
			}
			if _, err := Verify(root, record.OperationID, record.FromVersion, record.DBSchema, record.PolicySchema, LayoutFlat, os.Geteuid()); err != nil {
				t.Fatalf("recovered record does not verify: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(root, PayloadDir, SingleDBName))
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tc.wantDB {
				t.Fatalf("recovered payload = %q, want %q", data, tc.wantDB)
			}
			if tc.wantOp == old.OperationID && record.PayloadSHA256 != old.PayloadSHA256 {
				t.Fatalf("rollback changed the retained digest: %+v", record)
			}
			assertNoSlotLeftovers(t, root)
		})
	}

	t.Run("neither pair agrees", func(t *testing.T) {
		root := t.TempDir()
		record := writeDB(t, root, testSpec(strings.Repeat("a", 32)), []byte("generation A\n"))
		if err := os.WriteFile(filepath.Join(root, PayloadDir, SingleDBName), []byte("tampered\n"), 0600); err != nil {
			t.Fatal(err)
		}
		trash := filepath.Join(root, PayloadTrashPrefix+"1")
		if err := os.MkdirAll(trash, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(trash, SingleDBName), []byte("also tampered\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(root, record.OperationID, LayoutFlat, os.Geteuid()); codeOf(err) != CodeCorrupt {
			t.Fatalf("read of an unrecoverable slot = %v, want %s", err, CodeCorrupt)
		}
		if data, err := os.ReadFile(filepath.Join(root, PayloadDir, SingleDBName)); err != nil || string(data) != "tampered\n" {
			t.Fatalf("an unrecoverable slot was rewritten: %q, %v", data, err)
		}
	})
}

func assertNoSlotLeftovers(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		// payload.part is the producer's staged copy, not a slot leftover.
		if name == RecordName || name == PayloadDir || name == PayloadPart {
			continue
		}
		t.Fatalf("the recovered slot still holds %q", name)
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
	flatRoot := filepath.Join(root, "flat")
	writeDB(t, flatRoot, testSpec(op), []byte("fixture database\n"))

	if _, err := Read(root, op, LayoutPerOp, os.Geteuid()+1); codeOf(err) != CodeCorrupt {
		t.Fatalf("per-op read with a foreign owner = %v, want %s", err, CodeCorrupt)
	}
	if _, err := Read(flatRoot, op, LayoutFlat, os.Geteuid()+1); codeOf(err) != CodeCorrupt {
		t.Fatalf("flat read with a foreign owner = %v, want %s", err, CodeCorrupt)
	}
	if _, err := Verify(root, op, "1.0.0", 10, testPolicySchema, LayoutPerOp, os.Geteuid()+1); codeOf(err) != CodeCorrupt {
		t.Fatalf("per-op verify with a foreign owner = %v, want %s", err, CodeCorrupt)
	}
	// The owner the writer used is the one that passes.
	if _, err := Read(root, op, LayoutPerOp, os.Geteuid()); err != nil {
		t.Fatalf("read as the owning account: %v", err)
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
			if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, LayoutPerOp, record.CreatedAt); err != nil {
				t.Fatalf("confirm %s: %v", op, err)
			}
		}
	}

	removed, err := GC(root, KeepConfirmed, LayoutPerOp)
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
		record, err := Read(root, op, LayoutPerOp, os.Geteuid())
		if err != nil {
			t.Fatalf("retained %s unreadable: %v", op, err)
		}
		if _, err := Verify(root, op, record.FromVersion, record.DBSchema, record.PolicySchema, LayoutPerOp, os.Geteuid()); err != nil {
			t.Fatalf("retained %s payload damaged: %v", op, err)
		}
	}
	// A second GC is a no-op.
	if again, err := GC(root, KeepConfirmed, LayoutPerOp); err != nil || len(again) != 0 {
		t.Fatalf("second gc = %q, %v; want none", again, err)
	}
}

// TestGCFlatKeepsOneGeneration pins the Hub slot rule: the flat layout holds one
// generation, so GC(keep>=1) is a no-op and only an explicit keep<1 cleanup of a
// confirmed generation removes it. A staged generation is never collected.
func TestGCFlatKeepsOneGeneration(t *testing.T) {
	root := t.TempDir()
	record := writeDB(t, root, testSpec(strings.Repeat("a", 32)), []byte("generation A\n"))
	recordPath := filepath.Join(root, RecordName)
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadBefore, err := os.ReadFile(filepath.Join(root, PayloadDir, SingleDBName))
	if err != nil {
		t.Fatal(err)
	}

	for _, keep := range []int{KeepConfirmed, 2, 100} {
		removed, err := GC(root, keep, LayoutFlat)
		if err != nil || len(removed) != 0 {
			t.Fatalf("flat gc(keep=%d) = %q, %v; want a no-op", keep, removed, err)
		}
	}
	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("flat gc(keep=1) changed the record")
	}
	if payloadAfter, err := os.ReadFile(filepath.Join(root, PayloadDir, SingleDBName)); err != nil || !bytes.Equal(payloadBefore, payloadAfter) {
		t.Fatalf("flat gc(keep=1) changed the payload: %q, %v", payloadAfter, err)
	}

	// An explicit keep<1 still refuses a staged generation: it is the only
	// rollback source this slot has.
	if removed, err := GC(root, 0, LayoutFlat); err != nil || len(removed) != 0 {
		t.Fatalf("flat gc(keep=0) on a staged generation = %q, %v; want retained", removed, err)
	}
	if _, err := Read(root, record.OperationID, LayoutFlat, os.Geteuid()); err != nil {
		t.Fatalf("staged generation was collected: %v", err)
	}

	// After confirmation an explicit cleanup removes the generation.
	if _, err := Confirm(root, record.OperationID, record.TargetVersion, record.PackageSHA256, LayoutFlat, time.Now().UTC()); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	removed, err := GC(root, 0, LayoutFlat)
	if err != nil || len(removed) != 1 || removed[0] != record.OperationID {
		t.Fatalf("flat gc(keep=0) after confirm = %q, %v; want %q", removed, err, record.OperationID)
	}
	if _, err := Read(root, record.OperationID, LayoutFlat, os.Geteuid()); codeOf(err) != CodeMissing {
		t.Fatalf("collected generation is still readable: %v", err)
	}
	assertNoSlotLeftovers(t, root)
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
	if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, LayoutPerOp, created); err != nil {
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
	removed, err := GC(root, 0, LayoutPerOp)
	if err == nil {
		t.Fatal("gc reported success although the generation could not be retired")
	}
	if len(removed) != 0 {
		t.Fatalf("gc reported removed generations %q despite the failure", removed)
	}
	if _, statErr := os.Lstat(filepath.Join(root, op)); statErr != nil {
		t.Fatalf("the generation was not retained: %v", statErr)
	}
	if _, err := Read(root, op, LayoutPerOp, os.Geteuid()); err != nil {
		t.Fatalf("the retained generation is unreadable: %v", err)
	}
}

// TestConfirmFlatLayoutReadsRootRecord pins N5/§6.17: the flat finalize parses
// <root>/record.json and never <root>/<op32hex>/record.json, while the per-op
// layout keeps working. The per-operation tree is residue that is neither
// adopted nor migrated, so a slot that holds one is refused; the root record is
// still the only generation that can ever be confirmed.
func TestConfirmFlatLayoutReadsRootRecord(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	record := writeDB(t, root, testSpec(op), []byte("fixture database\n"))

	// A decoy per-operation record naming another target: reading it would
	// refuse the readback below.
	decoyDir := filepath.Join(root, op)
	if err := os.MkdirAll(filepath.Join(decoyDir, PayloadDir), 0700); err != nil {
		t.Fatal(err)
	}
	decoy := record
	decoy.TargetVersion = "9.9.9"
	decoy.PayloadPath = filepath.Join(decoyDir, PayloadDir)
	if err := WriteRecord(decoyDir, decoy); err != nil {
		t.Fatal(err)
	}
	if _, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, LayoutFlat, time.Now().UTC()); codeOf(err) != CodeCorrupt {
		t.Fatalf("flat confirm with per-op residue = %v, want %s", err, CodeCorrupt)
	}
	if stored, err := ReadRecord(decoyDir, op, os.Geteuid()); err != nil || stored.State != StateStaged {
		t.Fatalf("the per-op residue was confirmed: %+v, %v", stored, err)
	}
	if err := os.RemoveAll(decoyDir); err != nil {
		t.Fatal(err)
	}

	confirmed, err := Confirm(root, op, record.TargetVersion, record.PackageSHA256, LayoutFlat, time.Now().UTC())
	if err != nil {
		t.Fatalf("flat confirm: %v", err)
	}
	if confirmed.State != StateConfirmed || confirmed.ConfirmedAt == nil {
		t.Fatalf("confirmed record = %+v", confirmed)
	}
	if confirmed.PayloadPath != filepath.Join(root, PayloadDir) {
		t.Fatalf("confirmed payload_path = %q, want the slot payload", confirmed.PayloadPath)
	}
	stored, err := Read(root, op, LayoutFlat, os.Geteuid())
	if err != nil || stored.State != StateConfirmed {
		t.Fatalf("stored flat record = %+v, %v", stored, err)
	}

	// The per-operation layout still confirms through the same read path.
	perOpRoot := t.TempDir()
	perOp := writeTree(t, perOpRoot, testSpec(strings.Repeat("c", 32)))
	if _, err := Confirm(perOpRoot, perOp.OperationID, perOp.TargetVersion, perOp.PackageSHA256, LayoutPerOp, time.Now().UTC()); err != nil {
		t.Fatalf("per-op confirm: %v", err)
	}
	storedPerOp, err := Read(perOpRoot, perOp.OperationID, LayoutPerOp, os.Geteuid())
	if err != nil || storedPerOp.State != StateConfirmed {
		t.Fatalf("stored per-op record = %+v, %v", storedPerOp, err)
	}
}
