package hubupgrade

// Producer tests of #11d Task 3 (spec §5.2, §5.9, C4/C6/C18): the fixed order
// manifest gate -> running-binary stage -> VACUUM -> integrity -> flat record ->
// backed_up journal, one in-process flat-slot lock, no GC before confirmation,
// and the two Task-1 carries (stale payload.part, serialized flat access).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const hubBackupTestTarget = "1.0.1"

type hubBackupFixture struct {
	dataDir       string
	manifestDir   string
	manifestOwner int
	calls         []string
	spaceCalls    int
	vacuumHook    func(dst string) error
	intCheck      func(path string) error
	spaceHook     func(path string, need uint64) error
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

func (f *hubBackupFixture) flatRoot() string { return filepath.Join(f.dataDir, DatabaseBackupDir) }

func (f *hubBackupFixture) config() BackupConfig {
	return BackupConfig{
		DataDir:       f.dataDir,
		Target:        hubBackupTestTarget,
		ManifestDir:   f.manifestDir,
		manifestOwner: f.manifestOwner,
		Vacuum: func(_ context.Context, dst string) error {
			f.calls = append(f.calls, "vacuum")
			if f.vacuumHook != nil {
				return f.vacuumHook(dst)
			}
			return os.WriteFile(dst, []byte("fixture database copy"), 0600)
		},
		Integrity: func(_ context.Context, path string) error {
			f.calls = append(f.calls, "integrity")
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
			f.calls = append(f.calls, "schema")
			return 10, nil
		},
		Space: func(path string, need uint64) error {
			f.calls = append(f.calls, "space")
			f.spaceCalls++
			if f.spaceHook != nil {
				return f.spaceHook(path, need)
			}
			return nil
		},
	}
}

func (f *hubBackupFixture) run(t *testing.T) (BackupReceipt, backup.Record) {
	t.Helper()
	receipt, err := CreateBackup(context.Background(), f.config())
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	record, err := backup.Read(f.flatRoot(), receipt.OperationID, backup.LayoutFlat, os.Geteuid())
	if err != nil {
		t.Fatalf("read staged record: %v", err)
	}
	return receipt, record
}

// seedHubSlot writes one verified generation directly through the record layer,
// so a test can start with a rollback source without running the producer.
func seedHubSlot(t *testing.T, dataDir, operationID string, confirmed bool) (string, []byte) {
	t.Helper()
	root := filepath.Join(dataDir, DatabaseBackupDir)
	slot, err := backup.Dir(root, backup.LayoutFlat, operationID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(slot, backup.PayloadPart)
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
	if _, err := backup.Write(root, spec, backup.LayoutFlat, backup.Payload{
		Kind: backup.PayloadSingleDB, Check: func(string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if confirmed {
		if _, err := backup.Confirm(root, operationID, hubBackupTestTarget, strings.Repeat("2", 64), backup.LayoutFlat, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, backup.RecordName)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, body
}

func lastJournalOp(t *testing.T, dataDir string) Op {
	t.Helper()
	ops, err := ListOps(dataDir)
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

func TestBackupOrderVacuumIntegrityRecord(t *testing.T) {
	f := newHubBackupFixture(t)
	recordPath := filepath.Join(f.flatRoot(), backup.RecordName)
	f.vacuumHook = func(dst string) error {
		if _, err := os.Lstat(recordPath); err == nil {
			t.Error("a record existed before VACUUM INTO")
		}
		return os.WriteFile(dst, []byte("fixture database copy"), 0600)
	}
	f.intCheck = func(path string) error {
		if _, err := os.Lstat(recordPath); err == nil {
			t.Error("a record existed before the copy integrity check")
		}
		return nil
	}
	receipt, record := f.run(t)
	if got, want := f.calls, []string{"space", "vacuum", "space", "schema", "integrity"}; !equalStrings(got, want) {
		t.Fatalf("callback order %v want %v", got, want)
	}
	if receipt.Status != "staged" || receipt.OperationID != record.OperationID ||
		receipt.FromVersion != buildinfo.Version || receipt.DBSchema != 10 || !receipt.IntegrityOK {
		t.Fatalf("receipt: %+v", receipt)
	}
	if record.State != backup.StateStaged || !record.IntegrityOK || record.PayloadFiles != 1 ||
		record.DBSchema != 10 || record.PolicySchema != upgrade.PolicySchema ||
		record.TargetVersion != hubBackupTestTarget {
		t.Fatalf("staged record: %+v", record)
	}
	if op := lastJournalOp(t, f.dataDir); op.State != StateBackedUp || op.ErrorCode != "" ||
		op.DBSchema != 10 || op.BackupGeneration != 1 || op.OperationID != receipt.OperationID {
		t.Fatalf("backed_up journal: %+v", op)
	}
}

func TestBackupIntegrityFailureKeepsOldGeneration(t *testing.T) {
	f := newHubBackupFixture(t)
	oldOp := strings.Repeat("9", 32)
	recordPath, before := seedHubSlot(t, f.dataDir, oldOp, true)
	oldPayload := filepath.Join(f.flatRoot(), backup.PayloadDir, backup.SingleDBName)
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
	if err != nil {
		t.Fatal(err)
	}
	if string(payloadBefore) != string(payloadAfter) {
		t.Fatal("a failed integrity check changed the previous payload")
	}
	if _, err := os.Lstat(filepath.Join(f.flatRoot(), backup.PayloadPart)); !os.IsNotExist(err) {
		t.Fatalf("payload.part survived a failed integrity check: %v", err)
	}
	if op := lastJournalOp(t, f.dataDir); op.State != StateFailed || op.ErrorCode != "HUB_BACKUP_INTEGRITY_FAILED" {
		t.Fatalf("failed journal: %+v", op)
	}
}

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
	// Re-running the stage is idempotent: the same bytes are reused, not
	// rewritten with a different identity.
	if again, err := stageRunningBinary(f.dataDir, record.FromVersion, record.FromAgentSHA256); err != nil || again != path {
		t.Fatalf("second stage = %q, %v", again, err)
	}

	// A non-file at the fixed name cannot be replaced by a rename; the producer
	// reports the stable stage failure instead of claiming a rollback source.
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

func TestProducerHasNoInstallerLedgerDependency(t *testing.T) {
	// The Web process has no ledger read right (spec C6/C19). The producer must
	// therefore not reach install.ReadState through any direct import; the root
	// dispatcher (Task 4) is the only ledger reader.
	for _, dir := range []string{".", filepath.Join("..", "web")} {
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
			if _, err := os.Lstat(filepath.Join(f.flatRoot(), backup.RecordName)); !os.IsNotExist(err) {
				t.Fatal("a busy backup published a record")
			}
		})
	}

	t.Run("irreversible record", func(t *testing.T) {
		f := newHubBackupFixture(t)
		oldOp := strings.Repeat("7", 32)
		recordPath, _ := seedHubSlot(t, f.dataDir, oldOp, false)
		record, err := backup.Read(f.flatRoot(), oldOp, backup.LayoutFlat, os.Geteuid())
		if err != nil {
			t.Fatal(err)
		}
		record.IrreversibleApproved = true
		if err := backup.WriteRecord(f.flatRoot(), record); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "HUB_UPGRADE_BUSY" {
			t.Fatalf("irreversible record = %v", err)
		}
		after, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("a busy backup changed the approved record")
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

func TestBackupNeverCollectsBeforeConfirm(t *testing.T) {
	f := newHubBackupFixture(t)
	oldOp := strings.Repeat("6", 32)
	recordPath, _ := seedHubSlot(t, f.dataDir, oldOp, true)
	oldPayload := filepath.Join(f.flatRoot(), backup.PayloadDir, backup.SingleDBName)
	oldBody, err := os.ReadFile(oldPayload)
	if err != nil {
		t.Fatal(err)
	}
	seenOld := func(when string) {
		if _, err := os.Lstat(recordPath); err != nil {
			t.Errorf("%s: the confirmed rollback record was collected before the new backup", when)
		}
		body, err := os.ReadFile(oldPayload)
		if err != nil || string(body) != string(oldBody) {
			t.Errorf("%s: the confirmed rollback payload was collected before confirmation", when)
		}
	}
	f.vacuumHook = func(dst string) error {
		seenOld("vacuum")
		return os.WriteFile(dst, []byte("new fixture database copy"), 0600)
	}
	f.intCheck = func(string) error { seenOld("integrity"); return nil }

	receipt, record := f.run(t)
	if record.OperationID == oldOp || record.State != backup.StateStaged {
		t.Fatalf("new record: %+v", record)
	}
	if _, err := backup.Read(f.flatRoot(), oldOp, backup.LayoutFlat, os.Geteuid()); err == nil {
		t.Fatal("the old record is still current after the atomic replacement")
	}
	_ = receipt
	entries, err := os.ReadDir(f.flatRoot())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), backup.PayloadTrashPrefix) ||
			strings.HasPrefix(entry.Name(), backup.RecordTrashPrefix) ||
			strings.HasPrefix(entry.Name(), backup.PayloadOrphanPrefix) {
			t.Fatalf("backup left a retired generation %q", entry.Name())
		}
	}
	// GC must not be called by the producer at all: the flat slot replaces, it
	// never collects before confirmation (plan ruling 3 / B8).
	source, err := os.ReadFile("backup.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "backup.GC(") {
		t.Fatal("the backup producer calls backup.GC")
	}
	if removed, err := backup.GC(f.flatRoot(), backup.KeepConfirmed, backup.LayoutFlat); err != nil || len(removed) != 0 {
		t.Fatalf("flat GC after a staged backup = %v, %v", removed, err)
	}
}

func TestBackupStalePayloadPartRemovedAfterReconcile(t *testing.T) {
	f := newHubBackupFixture(t)
	oldOp := strings.Repeat("5", 32)
	seedHubSlot(t, f.dataDir, oldOp, false)
	// A previous VACUUM died after creating its destination. VACUUM INTO refuses
	// an existing target, so the producer must reconcile the slot first and only
	// then remove the stale scratch copy; otherwise every retry fails forever.
	stale := filepath.Join(f.flatRoot(), backup.PayloadPart)
	if err := os.Mkdir(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, backup.SingleDBName), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	f.vacuumHook = func(dst string) error {
		if _, err := os.Lstat(dst); err == nil {
			return errors.New("VACUUM INTO target already exists")
		}
		return os.WriteFile(dst, []byte("new fixture database copy"), 0600)
	}
	if _, record := f.run(t); record.OperationID == oldOp {
		t.Fatal("stale scratch copy blocked a retry")
	}
}

func TestBackupSpaceInsufficient(t *testing.T) {
	t.Run("before the running-binary stage", func(t *testing.T) {
		f := newHubBackupFixture(t)
		oldOp := strings.Repeat("4", 32)
		recordPath, before := seedHubSlot(t, f.dataDir, oldOp, false)
		f.spaceHook = func(string, uint64) error { return errors.New("no free space") }
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
	})

	t.Run("after the copy exists", func(t *testing.T) {
		f := newHubBackupFixture(t)
		oldOp := strings.Repeat("3", 32)
		recordPath, before := seedHubSlot(t, f.dataDir, oldOp, false)
		f.spaceHook = func(string, uint64) error {
			if f.spaceCalls == 2 {
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
		if _, err := os.Lstat(filepath.Join(f.flatRoot(), backup.PayloadPart)); !os.IsNotExist(err) {
			t.Fatal("payload.part survived a space refusal")
		}
	})
}

func TestBackupManifestUnavailableZeroChanges(t *testing.T) {
	f := newHubBackupFixture(t)
	if err := os.Remove(filepath.Join(f.manifestDir, "manifest-"+hubBackupTestTarget+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBackup(context.Background(), f.config()); err == nil || codeOf(err) != "MANIFEST_UNAVAILABLE" {
		t.Fatalf("missing manifest = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.dataDir, HubUpgradeDir)); !os.IsNotExist(err) {
		t.Fatal("a manifest refusal wrote the journal directory")
	}
	if _, err := os.Lstat(filepath.Join(f.dataDir, UpgradeDir)); !os.IsNotExist(err) {
		t.Fatal("a manifest refusal staged a binary")
	}
	if _, err := os.Lstat(filepath.Join(f.flatRoot(), backup.RecordName)); !os.IsNotExist(err) {
		t.Fatal("a manifest refusal published a record")
	}
}

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

func TestFlatRecordAccessSerialized(t *testing.T) {
	f := newHubBackupFixture(t)
	unlock := LockFlatSlot()
	done := make(chan error, 1)
	go func() {
		_, err := CreateBackup(context.Background(), f.config())
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("CreateBackup ran without the flat-slot lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("CreateBackup after unlock: %v", err)
	}
}

func TestReadFlatReturnsTheSlotWithoutAnOperationID(t *testing.T) {
	f := newHubBackupFixture(t)
	operationID := strings.Repeat("1", 32)
	seedHubSlot(t, f.dataDir, operationID, false)
	record, err := backup.ReadFlat(f.flatRoot(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if record.OperationID != operationID {
		t.Fatalf("ReadFlat returned %q want %q", record.OperationID, operationID)
	}
	if _, err := backup.ReadFlat(f.flatRoot(), os.Geteuid()+1); err == nil {
		t.Fatal("ReadFlat adopted a foreign-owned slot")
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
