package hubupgrade

// Producer tests of #11d Task 3r (spec §5.2, §5.9, C4/C6/C18): the fixed order
// manifest gate -> running-binary stage -> VACUUM -> integrity -> per-operation
// record -> backed_up journal -> flat pointer, one producer mutex over the
// check-then-act only, journal-only single flight (R2), and no GC before
// confirmation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

const hubBackupTestTarget = "1.0.1"

type hubBackupFixture struct {
	dataDir       string
	manifestDir   string
	manifestOwner int
	// mu guards the recorded callback order, the space counter and the logs:
	// TestBackupProduceSerialized runs concurrent producers against one
	// fixture, and the race detector must stay clean.
	mu         sync.Mutex
	calls      []string
	spaceCalls int
	vacuumHook func(dst string) error
	intCheck   func(path string) error
	spaceHook  func(path string, need uint64, call int) error
	publish    func(root, operationID string) error
	logs       []string
}

// record appends one callback name to the ordered trace.
func (f *hubBackupFixture) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

// nextSpaceCall counts a space check and returns its 1-based index.
func (f *hubBackupFixture) nextSpaceCall() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spaceCalls++
	return f.spaceCalls
}

func (f *hubBackupFixture) trace() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *hubBackupFixture) logged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.logs...)
}

func newHubBackupFixture(t *testing.T) *hubBackupFixture {
	t.Helper()
	base := t.TempDir()
	f := &hubBackupFixture{
		dataDir:       filepath.Join(base, "data"),
		manifestDir:   filepath.Join(base, "installer-upgrade"),
		manifestOwner: os.Geteuid(),
	}
	if err := os.Mkdir(f.dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeHubManifest(t, f.manifestDir, hubBackupTestTarget, nil)
	return f
}

func (f *hubBackupFixture) root() string { return filepath.Join(f.dataDir, DatabaseBackupDir) }

func (f *hubBackupFixture) pointerPath() string { return filepath.Join(f.root(), PointerName) }

func (f *hubBackupFixture) config() BackupConfig {
	return BackupConfig{
		DataDir:       f.dataDir,
		Target:        hubBackupTestTarget,
		ManifestDir:   f.manifestDir,
		manifestOwner: f.manifestOwner,
		Vacuum: func(_ context.Context, dst string) error {
			f.record("vacuum")
			if f.vacuumHook != nil {
				return f.vacuumHook(dst)
			}
			return os.WriteFile(dst, []byte("fixture database copy"), 0600)
		},
		Integrity: func(_ context.Context, path string) error {
			f.record("integrity")
			if f.intCheck != nil {
				return f.intCheck(path)
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				return errors.New("fixture copy is not a private file")
			}
			return nil
		},
		Schema: func(context.Context) (int64, error) {
			f.record("schema")
			return 10, nil
		},
		Space: func(path string, need uint64) error {
			call := f.nextSpaceCall()
			f.record("space")
			if f.spaceHook != nil {
				return f.spaceHook(path, need, call)
			}
			return nil
		},
		PublishPointer: f.publish,
		Log: func(code, operationID string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.logs = append(f.logs, code+" "+operationID)
		},
	}
}

func (f *hubBackupFixture) run(t *testing.T) (BackupReceipt, backup.Record) {
	t.Helper()
	receipt, err := CreateBackup(context.Background(), f.config())
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	record, err := backup.Read(f.root(), receipt.OperationID, os.Geteuid())
	if err != nil {
		t.Fatalf("read staged record: %v", err)
	}
	return receipt, record
}

// seedBackup writes one verified per-operation generation directly through the
// record layer, so a test can start with a rollback source without running the
// producer.
func seedBackup(t *testing.T, dataDir, operationID string, confirmed bool) (string, []byte) {
	t.Helper()
	root := filepath.Join(dataDir, DatabaseBackupDir)
	opDir, err := backup.Dir(root, operationID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("old fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := backup.Spec{
		OperationID: operationID, FromVersion: "1.0.0", TargetVersion: hubBackupTestTarget,
		DBSchema: 10, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("1", 64), PackageSHA256: strings.Repeat("2", 64),
		FromPackageSHA256: strings.Repeat("3", 64), FromAgentSHA256: strings.Repeat("4", 64),
	}
	if _, err := backup.Write(root, spec, backup.Payload{
		Kind: backup.PayloadSingleDB, Check: func(string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if confirmed {
		if _, err := backup.Confirm(root, operationID, hubBackupTestTarget, strings.Repeat("2", 64), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	recordPath := filepath.Join(opDir, backup.RecordName)
	body, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	return recordPath, body
}

func lastJournalOp(t *testing.T, dataDir string) Op {
	t.Helper()
	ops, err := ListOps(dataDir, os.Geteuid())
	if err != nil || len(ops) == 0 {
		t.Fatalf("journal: %v (%d ops)", err, len(ops))
	}
	return ops[0]
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// TestBackupOrderVacuumIntegrityRecord pins the producer order on one
// operation's scratch copy and the honest staged receipt.
func TestBackupOrderVacuumIntegrityRecord(t *testing.T) {
	f := newHubBackupFixture(t)
	var opDir string
	f.vacuumHook = func(dst string) error {
		opDir = filepath.Dir(filepath.Dir(dst))
		if filepath.Base(opDir) == DatabaseBackupDir || filepath.Dir(opDir) != f.root() {
			t.Errorf("VACUUM destination %q is not inside one operation directory of %s", dst, f.root())
		}
		if want := backup.SingleDBName; filepath.Base(dst) != want {
			t.Errorf("VACUUM destination name %q want %q", filepath.Base(dst), want)
		}
		if filepath.Base(filepath.Dir(dst)) != backup.PayloadPart {
			t.Errorf("VACUUM destination %q is not inside %s", dst, backup.PayloadPart)
		}
		if info, err := os.Lstat(opDir); err != nil || info.Mode().Perm() != 0700 {
			t.Errorf("operation directory %q is not 0700: %v", opDir, err)
		}
		if _, err := os.Lstat(filepath.Join(opDir, backup.RecordName)); err == nil {
			t.Error("a record existed before VACUUM INTO")
		}
		if _, err := os.Lstat(filepath.Join(f.root(), PointerName)); err == nil {
			t.Error("a pointer existed before VACUUM INTO")
		}
		return os.WriteFile(dst, []byte("fixture database copy"), 0600)
	}
	f.intCheck = func(path string) error {
		if filepath.Dir(filepath.Dir(path)) != opDir {
			t.Errorf("integrity check ran on %q, not on the VACUUMed copy", path)
		}
		if _, err := os.Lstat(filepath.Join(opDir, backup.RecordName)); err == nil {
			t.Error("a record existed before the copy integrity check")
		}
		return nil
	}
	receipt, record := f.run(t)
	if got, want := f.trace(), []string{"space", "vacuum", "space", "schema", "integrity"}; !equalStrings(got, want) {
		t.Fatalf("callback order %v want %v", got, want)
	}
	if opDir != filepath.Join(f.root(), receipt.OperationID) {
		t.Fatalf("VACUUM ran in %q, want the operation directory of %q", opDir, receipt.OperationID)
	}
	if receipt.Status != "staged" || receipt.OperationID != record.OperationID ||
		receipt.FromVersion != buildinfo.Version || receipt.DBSchema != 10 || !receipt.IntegrityOK {
		t.Fatalf("receipt: %+v", receipt)
	}
	if record.State != backup.StateStaged || !record.IntegrityOK || record.PayloadFiles != 1 ||
		record.DBSchema != 10 || record.PolicySchema != upgrade.PolicySchema ||
		record.TargetVersion != hubBackupTestTarget || record.FromAgentSHA256 != record.FromPackageSHA256 {
		t.Fatalf("staged record: %+v", record)
	}
	if want := filepath.Join(f.root(), record.OperationID, backup.PayloadDir); record.PayloadPath != want {
		t.Fatalf("payload path %q want %q", record.PayloadPath, want)
	}
	if op := lastJournalOp(t, f.dataDir); op.State != StateBackedUp || op.ErrorCode != "" ||
		op.DBSchema != 10 || op.BackupGeneration != 1 || op.OperationID != receipt.OperationID {
		t.Fatalf("backed_up journal: %+v", op)
	}
}

// TestBackupIntegrityFailureKeepsOldGeneration is the B8 property on a per-op
// store: a failed integrity check touches no other operation's generation, clears
// this operation's scratch copy and reports the stable code.
func TestBackupIntegrityFailureKeepsOldGeneration(t *testing.T) {
	f := newHubBackupFixture(t)
	oldOp := strings.Repeat("9", 32)
	recordPath, before := seedBackup(t, f.dataDir, oldOp, true)
	oldPayload := filepath.Join(f.root(), oldOp, backup.PayloadDir, backup.SingleDBName)
	payloadBefore, err := os.ReadFile(oldPayload)
	if err != nil {
		t.Fatal(err)
	}
	f.intCheck = func(string) error { return errors.New("integrity_check returned not ok") }

	if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_BACKUP_INTEGRITY_FAILED" {
		t.Fatalf("integrity failure = %v", err)
	}
	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a failed integrity check rewrote the previous record")
	}
	payloadAfter, err := os.ReadFile(oldPayload)
	if err != nil || string(payloadBefore) != string(payloadAfter) {
		t.Fatal("a failed integrity check changed the previous payload")
	}
	op := lastJournalOp(t, f.dataDir)
	if op.State != StateFailed || op.ErrorCode != "HUB_BACKUP_INTEGRITY_FAILED" {
		t.Fatalf("failed journal: %+v", op)
	}
	// The failed operation's own directory holds no record and no scratch copy.
	for _, name := range []string{backup.RecordName, backup.PayloadDir, backup.PayloadPart} {
		if _, statErr := os.Lstat(filepath.Join(f.root(), op.OperationID, name)); !os.IsNotExist(statErr) {
			t.Fatalf("the failed operation left %q behind: %v", name, statErr)
		}
	}
	if _, statErr := os.Lstat(filepath.Join(f.root(), PointerName)); !os.IsNotExist(statErr) {
		t.Fatal("a failed backup published the flat pointer")
	}
}

// TestBackupPublishesPerOpThenPointer pins the publication order of spec §5.2.1:
// the per-operation record and payload are committed and the journal is
// backed_up before the pointer is written, and the pointer bytes are exactly the
// per-operation record bytes at 0600.
func TestBackupPublishesPerOpThenPointer(t *testing.T) {
	f := newHubBackupFixture(t)
	var seenPointerAt string
	f.publish = func(root, operationID string) error {
		seenPointerAt = operationID
		opDir := filepath.Join(root, operationID)
		if _, err := os.Lstat(filepath.Join(opDir, backup.RecordName)); err != nil {
			t.Errorf("the per-operation record was not committed before the pointer: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(opDir, backup.PayloadDir)); err != nil {
			t.Errorf("the per-operation payload was not committed before the pointer: %v", err)
		}
		journal, ok, err := ReadOp(f.dataDir, operationID, os.Geteuid())
		if err != nil || !ok {
			t.Fatalf("journal at pointer time: ok=%v err=%v", ok, err)
		}
		if journal.State != StateBackedUp {
			t.Errorf("journal state at pointer time = %s want backed_up", journal.State)
		}
		return PublishFlatPointer(root, operationID)
	}
	receipt, record := f.run(t)
	if seenPointerAt != receipt.OperationID {
		t.Fatalf("pointer published for %q want %q", seenPointerAt, receipt.OperationID)
	}
	opRecord, err := os.ReadFile(filepath.Join(f.root(), receipt.OperationID, backup.RecordName))
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := os.ReadFile(f.pointerPath())
	if err != nil {
		t.Fatalf("flat pointer: %v", err)
	}
	if string(pointer) != string(opRecord) {
		t.Fatal("the flat pointer is not a byte copy of the per-operation record")
	}
	info, err := os.Lstat(f.pointerPath())
	if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("pointer mode %v, %v; want a 0600 regular file", info, err)
	}
	if !strings.Contains(string(pointer), record.OperationID) {
		t.Fatal("the pointer does not name the operation it was copied from")
	}
}

// TestBackupPointerFailureKeepsBackedUp pins the decoupling of spec §5.2.1: a
// pointer refresh failure is HUB_BACKUP_POINTER_STALE only. The receipt is still
// staged, the journal stays backed_up, the per-operation record is readable and
// no pointer exists.
func TestBackupPointerFailureKeepsBackedUp(t *testing.T) {
	f := newHubBackupFixture(t)
	f.publish = func(string, string) error { return errors.New("HUB_BACKUP_POINTER_STALE: injected") }
	receipt, record := f.run(t)
	if receipt.Status != "staged" || !receipt.IntegrityOK {
		t.Fatalf("receipt after a pointer failure: %+v", receipt)
	}
	if record.State != backup.StateStaged {
		t.Fatalf("record state %q after a pointer failure", record.State)
	}
	if op := lastJournalOp(t, f.dataDir); op.State != StateBackedUp || op.ErrorCode != "" {
		t.Fatalf("a pointer failure changed the journal: %+v", op)
	}
	if _, err := os.Lstat(f.pointerPath()); !os.IsNotExist(err) {
		t.Fatalf("a failed pointer refresh left a pointer: %v", err)
	}
	if logs := f.logged(); len(logs) != 1 || !strings.HasPrefix(logs[0], "HUB_BACKUP_POINTER_STALE "+receipt.OperationID) {
		t.Fatalf("pointer failure log = %v", logs)
	}
}

// TestBackupStagesRunningBinary pins the restore source: the running binary is
// copied to the fixed old-package name, 0755, digest-equal to from_agent_sha256.
func TestBackupStagesRunningBinary(t *testing.T) {
	f := newHubBackupFixture(t)
	_, record := f.run(t)
	path := filepath.Join(f.dataDir, UpgradeDir, "meshmuxd-"+record.FromVersion+"-"+runtime.GOARCH)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("staged old package: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0755 {
		t.Fatalf("staged old package mode %v", info.Mode())
	}
	if got := fileDigest(t, path); got != record.FromAgentSHA256 {
		t.Fatalf("staged old package digest %s want %s", got, record.FromAgentSHA256)
	}
	// Re-running the stage is idempotent: the same bytes are reused.
	if again, err := stageRunningBinary(f.dataDir, record.FromVersion, record.FromAgentSHA256); err != nil || again != path {
		t.Fatalf("second stage = %q, %v", again, err)
	}
	// A non-file at the fixed name cannot be replaced by a rename.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := stageRunningBinary(f.dataDir, record.FromVersion, record.FromAgentSHA256); err == nil || codeOf(err) != "HUB_BACKUP_BINARY_STAGE_FAILED" {
		t.Fatalf("blocked stage = %v", err)
	}
	if _, err := os.Lstat(path + ".part"); !os.IsNotExist(err) {
		t.Fatal("stage scratch file survived a failure")
	}
}

// TestBackupBothDigestsFromWebIdentity pins C6: the Web has no ledger read, so
// both from-* digests come from the running binary identity.
func TestBackupBothDigestsFromWebIdentity(t *testing.T) {
	f := newHubBackupFixture(t)
	_, record := f.run(t)
	digest, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if record.FromPackageSHA256 != digest || record.FromAgentSHA256 != digest {
		t.Fatalf("from digests = %q/%q want %s", record.FromPackageSHA256, record.FromAgentSHA256, digest)
	}
}

// TestProducerHasNoInstallerLedgerDependency pins the module boundary: the Web
// producer cannot read the installer ledger (C6/C19).
func TestProducerHasNoInstallerLedgerDependency(t *testing.T) {
	for _, dir := range []string{".", filepath.Join("..", "..", "web")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			installImport := `"github.com/wingsky-1/MeshMux/internal/` + `install"`
			ledgerRead := `install.` + `ReadState`
			if strings.Contains(string(body), installImport) || strings.Contains(string(body), ledgerRead) {
				t.Fatalf("%s imports the installer ledger", filepath.Join(dir, name))
			}
		}
	}
}

// TestBackupSingleFlight pins R2: the criterion is journal non-terminal only. A
// per-operation record that still carries the irreversible approval bit but has
// no live journal operation does not block a backup.
func TestBackupSingleFlight(t *testing.T) {
	for _, state := range []State{StateBackingUp, StateBackedUp, StateQueued, StateApplying, StateRestarting, StateVerifying, StatePartial} {
		t.Run(string(state), func(t *testing.T) {
			f := newHubBackupFixture(t)
			op := journalOp(t, strings.Repeat("8", 32), state)
			if err := WriteOp(f.dataDir, op); err != nil {
				t.Fatal(err)
			}
			if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_UPGRADE_BUSY" {
				t.Fatalf("busy state %s = %v", state, err)
			}
			if _, err := os.Lstat(f.pointerPath()); !os.IsNotExist(err) {
				t.Fatal("a busy backup published a pointer")
			}
			if _, err := os.Lstat(filepath.Join(f.root(), op.OperationID)); !os.IsNotExist(err) {
				t.Fatal("a busy backup wrote an operation directory")
			}
		})
	}

	t.Run("approved record without a live op", func(t *testing.T) {
		f := newHubBackupFixture(t)
		oldOp := strings.Repeat("7", 32)
		recordPath, _ := seedBackup(t, f.dataDir, oldOp, false)
		record, err := backup.Read(f.root(), oldOp, os.Geteuid())
		if err != nil {
			t.Fatal(err)
		}
		record.IrreversibleApproved = true
		if err := backup.WriteRecord(filepath.Join(f.root(), oldOp), record); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		// R2: the bit is a per-attempt gate, never a busy signal. The journal
		// holds no operation, so the backup proceeds.
		if _, err := CreateBackup(context.Background(), f.config()); err != nil {
			t.Fatalf("approved record blocked a backup: %v", err)
		}
		after, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("a new backup changed the previously approved record")
		}
	})

	t.Run("backed_up blocks a second backup", func(t *testing.T) {
		f := newHubBackupFixture(t)
		f.run(t)
		if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_UPGRADE_BUSY" {
			t.Fatalf("second backup = %v", err)
		}
	})
}

// TestBackupProduceSerialized pins the producer mutex: it covers the
// Busy → generation → backing_up check-then-act, so concurrent requests can
// never both pass the single-flight read or share a generation.
func TestBackupProduceSerialized(t *testing.T) {
	t.Run("concurrent requests", func(t *testing.T) {
		f := newHubBackupFixture(t)
		const requests = 4
		var wg sync.WaitGroup
		results := make([]error, requests)
		for i := 0; i < requests; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				_, results[index] = CreateBackup(context.Background(), f.config())
			}(i)
		}
		wg.Wait()
		successes := 0
		for _, err := range results {
			if err == nil {
				successes++
				continue
			}
			if codeOf(err) != "HUB_UPGRADE_BUSY" {
				t.Fatalf("concurrent backup = %v, want success or HUB_UPGRADE_BUSY", err)
			}
		}
		if successes != 1 {
			t.Fatalf("%d concurrent backups succeeded, want exactly 1", successes)
		}
		ops, err := ListOps(f.dataDir, os.Geteuid())
		if err != nil || len(ops) != 1 {
			t.Fatalf("journal ops = %d, %v; want exactly one", len(ops), err)
		}
		if ops[0].BackupGeneration != 1 {
			t.Fatalf("generation %d want 1", ops[0].BackupGeneration)
		}
	})

	t.Run("check-then-act is inside the mutex", func(t *testing.T) {
		f := newHubBackupFixture(t)
		unlock := LockBackupProduce()
		done := make(chan error, 1)
		go func() {
			_, err := CreateBackup(context.Background(), f.config())
			done <- err
		}()
		select {
		case err := <-done:
			unlock()
			t.Fatalf("CreateBackup ran without the producer mutex: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		unlock()
		if err := <-done; err != nil {
			t.Fatalf("CreateBackup after unlock: %v", err)
		}
	})
}

// TestBackupNeverCollectsBeforeConfirm pins B8: the producer collects nothing, so
// the previous confirmed generation is still a restore source after a new staged
// backup.
func TestBackupNeverCollectsBeforeConfirm(t *testing.T) {
	f := newHubBackupFixture(t)
	oldOp := strings.Repeat("6", 32)
	recordPath, _ := seedBackup(t, f.dataDir, oldOp, true)
	oldPayload := filepath.Join(f.root(), oldOp, backup.PayloadDir, backup.SingleDBName)
	oldBody, err := os.ReadFile(oldPayload)
	if err != nil {
		t.Fatal(err)
	}
	seenOld := func(when string) {
		if _, err := os.Lstat(recordPath); err != nil {
			t.Errorf("%s: the confirmed rollback record was collected before confirmation", when)
		}
		body, err := os.ReadFile(oldPayload)
		if err != nil || string(body) != string(oldBody) {
			t.Errorf("%s: the confirmed rollback payload was collected", when)
		}
	}
	f.vacuumHook = func(dst string) error {
		seenOld("vacuum")
		return os.WriteFile(dst, []byte("new fixture database copy"), 0600)
	}
	f.intCheck = func(string) error { seenOld("integrity"); return nil }

	// The producer must not call the collector at all. The seam is the check: a
	// source grep would pass on a renamed helper or a copy of the call.
	calls := 0
	old := collectGenerations
	collectGenerations = func(root string, keep int) ([]string, error) {
		calls++
		return old(root, keep)
	}
	defer func() { collectGenerations = old }()

	_, record := f.run(t)
	if record.OperationID == oldOp || record.State != backup.StateStaged {
		t.Fatalf("new record: %+v", record)
	}
	seenOld("after the backup")
	if calls != 0 {
		t.Fatalf("the producer called the collector %d times", calls)
	}
}

// TestBackupSpaceInsufficient pins the two space gates: before the binary stage
// and with the real copy size, both leaving the previous generation untouched.
func TestBackupSpaceInsufficient(t *testing.T) {
	t.Run("before the running-binary stage", func(t *testing.T) {
		f := newHubBackupFixture(t)
		oldOp := strings.Repeat("4", 32)
		recordPath, before := seedBackup(t, f.dataDir, oldOp, false)
		f.spaceHook = func(string, uint64, int) error { return errors.New("no free space") }
		if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_SPACE_INSUFFICIENT" {
			t.Fatalf("space failure = %v", err)
		}
		after, err := os.ReadFile(recordPath)
		if err != nil || string(before) != string(after) {
			t.Fatal("space refusal changed the previous record")
		}
		if op := lastJournalOp(t, f.dataDir); op.State != StateFailed || op.ErrorCode != "HUB_SPACE_INSUFFICIENT" {
			t.Fatalf("failed journal: %+v", op)
		}
		if _, err := os.Lstat(filepath.Join(f.dataDir, UpgradeDir)); !os.IsNotExist(err) {
			t.Fatal("a space refusal staged a binary")
		}
	})

	t.Run("after the copy exists", func(t *testing.T) {
		f := newHubBackupFixture(t)
		oldOp := strings.Repeat("3", 32)
		recordPath, before := seedBackup(t, f.dataDir, oldOp, false)
		f.spaceHook = func(_ string, _ uint64, call int) error {
			if call == 2 {
				return errors.New("no free space for the copy")
			}
			return nil
		}
		if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_SPACE_INSUFFICIENT" {
			t.Fatalf("space failure = %v", err)
		}
		after, err := os.ReadFile(recordPath)
		if err != nil || string(before) != string(after) {
			t.Fatal("space refusal changed the previous record")
		}
		op := lastJournalOp(t, f.dataDir)
		if _, err := os.Lstat(filepath.Join(f.root(), op.OperationID, backup.PayloadPart)); !os.IsNotExist(err) {
			t.Fatal("payload.part survived a space refusal")
		}
	})
}

// TestBackupManifestUnavailableZeroChanges pins the gate order: the manifest is
// checked before anything is written.
func TestBackupManifestUnavailableZeroChanges(t *testing.T) {
	f := newHubBackupFixture(t)
	if err := os.Remove(filepath.Join(f.manifestDir, "manifest-"+hubBackupTestTarget+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "MANIFEST_UNAVAILABLE" {
		t.Fatalf("missing manifest = %v", err)
	}
	for _, path := range []string{
		filepath.Join(f.dataDir, HubUpgradeDir),
		filepath.Join(f.dataDir, UpgradeDir),
		f.root(),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("a manifest refusal wrote %s", path)
		}
	}
}

// TestBackupJournalGenerationIncrements pins generation allocation: max over all
// journal ops + 1, never recycled.
func TestBackupJournalGenerationIncrements(t *testing.T) {
	f := newHubBackupFixture(t)
	previous := journalOp(t, strings.Repeat("2", 32), StateFailed)
	previous.BackupGeneration = 4
	if err := WriteOp(f.dataDir, previous); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	if op := lastJournalOp(t, f.dataDir); op.BackupGeneration != 5 {
		t.Fatalf("backup generation %d want 5", op.BackupGeneration)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBackupStalePayloadPartCleared pins the retry rule of spec §5.2 step 3: a
// previous attempt that died after creating its scratch copy must not make every
// retry of the operation fail closed, because VACUUM INTO refuses an existing
// destination. Only payload.part is cleared; a committed payload and record of
// the same operation are never touched.
func TestBackupStalePayloadPartCleared(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	opDir, err := backup.Dir(root, op)
	if err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join(opDir, backup.PayloadDir)
	if err := os.Mkdir(committed, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(committed, backup.SingleDBName), []byte("committed"), 0600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, backup.SingleDBName), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	partDir, err := preparePayloadScratch(opDir)
	if err != nil {
		t.Fatalf("preparePayloadScratch: %v", err)
	}
	if partDir != stale {
		t.Fatalf("scratch dir %q want %q", partDir, stale)
	}
	entries, err := os.ReadDir(partDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("stale scratch contents survived: %v", entries)
	}
	if _, err := os.Lstat(filepath.Join(partDir, backup.SingleDBName)); !os.IsNotExist(err) {
		t.Fatal("the VACUUM destination already exists after the scratch reset")
	}
	body, err := os.ReadFile(filepath.Join(committed, backup.SingleDBName))
	if err != nil || string(body) != "committed" {
		t.Fatalf("the committed payload was touched: %q, %v", body, err)
	}
}

// TestBackupUnreadableJournalFailsClosed pins spec §5.2's fail-closed rule: a
// journal that cannot be read is HUB_BACKUP_JOURNAL_FAILED and starts no backup,
// because the producer cannot know whether an operation is in flight.
func TestBackupUnreadableJournalFailsClosed(t *testing.T) {
	f := newHubBackupFixture(t)
	op := journalOp(t, strings.Repeat("3", 32), StateBackedUp)
	if err := WriteOp(f.dataDir, op); err != nil {
		t.Fatal(err)
	}
	// A loose journal directory is not the private shape a reader accepts.
	if err := os.Chmod(filepath.Join(f.dataDir, OpsDir), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_BACKUP_JOURNAL_FAILED" {
		t.Fatalf("unreadable journal = %v, want HUB_BACKUP_JOURNAL_FAILED", err)
	}
	if _, err := os.Lstat(f.root()); !os.IsNotExist(err) {
		t.Fatal("a failed journal read still created the backup store")
	}
	if _, err := os.Lstat(filepath.Join(f.dataDir, UpgradeDir)); !os.IsNotExist(err) {
		t.Fatal("a failed journal read staged a binary")
	}
}

// TestBackupPostLockJournalFailureFailsTerminal pins the fix for a non-terminal
// leak: the backing_up document is published, so a journal read that fails right
// after the lock must still leave a terminal entry. Otherwise every later backup
// is HUB_UPGRADE_BUSY until Task 5's 30-minute orphan timeout.
func TestBackupPostLockJournalFailureFailsTerminal(t *testing.T) {
	f := newHubBackupFixture(t)
	old := readJournalOp
	failNext := true
	readJournalOp = func(dataDir, operationID string, expectedOwner int) (Op, bool, error) {
		if failNext {
			failNext = false
			return Op{}, false, fail("HUB_UPGRADE_JOURNAL_CORRUPT", "injected unreadable journal")
		}
		return old(dataDir, operationID, expectedOwner)
	}
	defer func() { readJournalOp = old }()

	if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_BACKUP_JOURNAL_FAILED" {
		t.Fatalf("post-lock journal failure = %v, want HUB_BACKUP_JOURNAL_FAILED", err)
	}
	// The journal must not be left non-terminal: a later backup has to proceed.
	ops, err := ListOps(f.dataDir, os.Geteuid())
	if err != nil || len(ops) != 1 {
		t.Fatalf("journal ops = %d, %v; want exactly one", len(ops), err)
	}
	if ops[0].State != StateFailed || ops[0].ErrorCode != "HUB_BACKUP_JOURNAL_FAILED" {
		t.Fatalf("journal entry after the failure = %+v; want failed/HUB_BACKUP_JOURNAL_FAILED", ops[0])
	}
	if _, busy, err := Busy(f.dataDir, os.Geteuid()); err != nil || busy {
		t.Fatalf("a failed backup still blocks: busy=%v err=%v", busy, err)
	}
}

// TestBackupStageFailureLeavesNoEmptyUpgradeDir pins the second nit: a failed
// stage drops the package directory only when it is empty, so a failed first
// backup leaves no stray upgrade/, while a directory that already holds a staged
// package is always left alone (that copy is a restore source).
func TestBackupStageFailureLeavesNoEmptyUpgradeDir(t *testing.T) {
	t.Run("empty directory is removed", func(t *testing.T) {
		f := newHubBackupFixture(t)
		// A previous crash left an empty package directory behind. The stage
		// refuses it (not private), so the failure path must not keep it.
		upgradeDir := filepath.Join(f.dataDir, UpgradeDir)
		if err := os.Mkdir(upgradeDir, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_BACKUP_BINARY_STAGE_FAILED" {
			t.Fatalf("blocked stage = %v", err)
		}
		if _, err := os.Lstat(upgradeDir); !os.IsNotExist(err) {
			t.Fatalf("an empty upgrade directory survived a failed stage: %v", err)
		}
	})

	t.Run("staged package is retained", func(t *testing.T) {
		f := newHubBackupFixture(t)
		digest, err := buildinfo.Digest()
		if err != nil {
			t.Fatal(err)
		}
		staged, err := stageRunningBinary(f.dataDir, buildinfo.Version, digest)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		// A later failure of this attempt must never remove the restore source.
		f.intCheck = func(string) error { return errors.New("integrity_check: not ok") }
		if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_BACKUP_INTEGRITY_FAILED" {
			t.Fatalf("integrity failure = %v", err)
		}
		if _, err := os.Lstat(staged); err != nil {
			t.Fatalf("the staged restore source was removed: %v", err)
		}
	})
}

// TestBackupPointerUnflushedLogsItsOwnCode pins the fix for the misleading log: a
// pointer that was renamed into place but not fsynced is reported as
// HUB_BACKUP_POINTER_UNFLUSHED, not as if nothing had been published. The
// operation still stays backed_up and the receipt stays staged.
func TestBackupPointerUnflushedLogsItsOwnCode(t *testing.T) {
	f := newHubBackupFixture(t)
	f.publish = func(root, operationID string) error {
		old := pointerRootSync
		pointerRootSync = func(string) error { return errors.New("sync failed") }
		defer func() { pointerRootSync = old }()
		return PublishFlatPointer(root, operationID)
	}
	receipt, record := f.run(t)
	if receipt.Status != "staged" || record.State != backup.StateStaged {
		t.Fatalf("receipt/record after an unflushed pointer: %+v / %+v", receipt, record)
	}
	if op := lastJournalOp(t, f.dataDir); op.State != StateBackedUp || op.ErrorCode != "" {
		t.Fatalf("an unflushed pointer changed the journal: %+v", op)
	}
	// The pointer itself was published: only its durability is in doubt.
	if _, err := os.Lstat(f.pointerPath()); err != nil {
		t.Fatalf("the published pointer is missing: %v", err)
	}
	if logs := f.logged(); len(logs) != 1 || !strings.HasPrefix(logs[0], "HUB_BACKUP_POINTER_UNFLUSHED "+receipt.OperationID) {
		t.Fatalf("unflushed pointer log = %v", logs)
	}
}
