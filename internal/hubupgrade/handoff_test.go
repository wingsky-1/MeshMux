package hubupgrade

// Tests for the #11d Task 5 handoff (spec §5.2, §5.5, §5.8).
//
// The review gates are TestHandoffOrder (verify → stage → queued → request, and
// a stage failure changes nothing) and TestHandoffIrreversibleGate (the bit is
// read from exactly this operation's record, and any refusal writes nothing).
// A real per-operation record and a real root-shaped manifest are used; only
// the package source is injected, so no root privilege and no network is
// needed.

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
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const (
	handoffTarget = "1.0.1"
	handoffFrom   = "1.0.0-dev"
)

// plantRecord writes one readable per-operation generation. created pins the
// record's created_at so GC ordering is deterministic.
func plantRecord(t *testing.T, dataDir, operationID string, created time.Time) backup.Record {
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
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("fixture database copy "+operationID), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := backup.Write(root, backup.Spec{
		OperationID: operationID, FromVersion: handoffFrom, TargetVersion: handoffTarget,
		DBSchema: 10, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("c", 64),
		Now: func() time.Time { return created },
	}, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// plantOperation writes a per-operation record and its journal entry whose
// digests name the given manifest, so a handoff can verify the whole chain.
func plantOperation(t *testing.T, dataDir, operationID string, manifest TargetManifest, state State, updated time.Time) backup.Record {
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
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := backup.Write(root, backup.Spec{
		OperationID: operationID, FromVersion: handoffFrom, TargetVersion: handoffTarget,
		DBSchema: 10, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: manifest.SHA256, PackageSHA256: manifest.Package.SHA256,
	}, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	writeJournal(t, dataDir, Op{
		Schema: OpSchema, OperationID: operationID, Kind: KindUpdate, State: state,
		TargetVersion: handoffTarget, FromVersion: handoffFrom,
		ManifestSHA256: manifest.SHA256, PackageSHA256: manifest.Package.SHA256,
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: updated,
	})
	return record
}

func writeJournal(t *testing.T, dataDir string, op Op) {
	t.Helper()
	if op.UpdatedAt.IsZero() {
		op.UpdatedAt = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	}
	if err := WriteOp(dataDir, op); err != nil {
		t.Fatal(err)
	}
}

// handoffFixture is one backed_up operation with its authenticated manifest.
type handoffFixture struct {
	dataDir     string
	manifestDir string
	requestDir  string
	operationID string
	manifest    TargetManifest
	record      backup.Record
	now         time.Time
	// spaceNeed records the requirement the handoff passed to Space, so a test
	// can pin the 1 GiB floor instead of trusting the call.
	spaceNeed  uint64
	spaceCalls int
	spaceErr   error
}

func newHandoffFixture(t *testing.T, mutate func(*upgrade.Manifest)) *handoffFixture {
	t.Helper()
	dataDir := t.TempDir()
	manifestDir := filepath.Join(t.TempDir(), "manifests")
	if err := os.Mkdir(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeHubManifest(t, manifestDir, handoffTarget, mutate)
	manifest, err := readRootManifest(manifestDir, handoffTarget, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("a", 32)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	record := plantOperation(t, dataDir, operationID, manifest, StateBackedUp, now.Add(-time.Minute))
	return &handoffFixture{
		dataDir: dataDir, manifestDir: manifestDir,
		requestDir:  filepath.Join(t.TempDir(), "requests"),
		operationID: operationID, manifest: manifest, record: record, now: now,
	}
}

func (fx *handoffFixture) config(fetch func(context.Context, string, string) (string, error)) HandoffConfig {
	return HandoffConfig{
		DataDir: fx.dataDir, OperationID: fx.operationID,
		ManifestDir: fx.manifestDir, ManifestOwner: os.Geteuid(),
		RequestDir: fx.requestDir,
		Now:        func() time.Time { return fx.now },
		Space: func(_ string, need uint64) error {
			fx.spaceCalls++
			fx.spaceNeed = need
			return fx.spaceErr
		},
		Fetch: fetch,
	}
}

func (fx *handoffFixture) journalBytes(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(fx.dataDir, OpsDir, fx.operationID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (fx *handoffFixture) requireJournal(t *testing.T, state State, code string) {
	t.Helper()
	op, ok, err := ReadOp(fx.dataDir, fx.operationID, os.Geteuid())
	if err != nil || !ok {
		t.Fatalf("journal: ok=%v err=%v", ok, err)
	}
	if op.State != state || op.ErrorCode != code {
		t.Fatalf("journal state = %s/%q, want %s/%q", op.State, op.ErrorCode, state, code)
	}
}

func (fx *handoffFixture) requireNoRequest(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(fx.requestDir, fx.operationID+".json")); !os.IsNotExist(err) {
		t.Fatalf("a request file exists although nothing was handed off: %v", err)
	}
}

// TestHandoffOrder pins the fixed order and its two visible effects: the target
// is staged while the journal is still backed_up and no request exists yet, and
// only afterwards do queued and the request appear.
func TestHandoffOrder(t *testing.T) {
	fx := newHandoffFixture(t, nil)
	staged := filepath.Join(t.TempDir(), "staged-target")
	calls := 0
	fetch := func(_ context.Context, dataDir, target string) (string, error) {
		calls++
		if dataDir != fx.dataDir || target != handoffTarget {
			t.Fatalf("fetch(%q, %q), want the fixture data dir and %q", dataDir, target, handoffTarget)
		}
		fx.requireJournal(t, StateBackedUp, "")
		fx.requireNoRequest(t)
		if err := os.WriteFile(staged, []byte("target package"), 0755); err != nil {
			t.Fatal(err)
		}
		return staged, nil
	}
	receipt, err := Handoff(context.Background(), fx.config(fetch))
	if err != nil {
		t.Fatalf("Handoff: %v", err)
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1", calls)
	}
	if receipt.Status != "queued" || receipt.OperationID != fx.operationID ||
		receipt.TargetVersion != handoffTarget || receipt.PackageSHA256 != fx.manifest.Package.SHA256 {
		t.Fatalf("receipt: %+v", receipt)
	}
	fx.requireJournal(t, StateQueued, "")
	request, err := ReadRequest(filepath.Join(fx.requestDir, fx.operationID+".json"), os.Geteuid())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if request.Kind != KindUpdate || request.OperationID != fx.operationID || request.DataDir != fx.dataDir {
		t.Fatalf("request: %+v", request)
	}
}

// TestHandoffStageFailureChangesNothing pins the plan's stage row: a failed
// stage reports HUB_BACKUP_STAGE_FAILED and leaves the journal byte-identical,
// so the verified rollback source is still available for a retry.
func TestHandoffStageFailureChangesNothing(t *testing.T) {
	fx := newHandoffFixture(t, nil)
	before := fx.journalBytes(t)
	fetch := func(context.Context, string, string) (string, error) {
		return "", errors.New("UPDATE_DIGEST_MISMATCH: the package does not match")
	}
	_, err := Handoff(context.Background(), fx.config(fetch))
	if codeOf(err) != codeHandoffStage {
		t.Fatalf("error = %v, want %s", err, codeHandoffStage)
	}
	if after := fx.journalBytes(t); string(after) != string(before) {
		t.Fatal("a failed stage changed the journal")
	}
	fx.requireNoRequest(t)
}

// TestHandoffIrreversibleGate pins spec §5.8's destructive gate: without the
// bit on exactly this operation's record nothing is staged or queued; with the
// bit the handoff proceeds; and a bit cannot outlive the payload it approved.
func TestHandoffIrreversibleGate(t *testing.T) {
	irreversible := func(m *upgrade.Manifest) { m.DatabaseMigration = MigrationIrreversible }
	fetch := func(context.Context, string, string) (string, error) {
		return filepath.Join(t.TempDir(), "staged"), nil
	}

	t.Run("no bit", func(t *testing.T) {
		fx := newHandoffFixture(t, irreversible)
		before := fx.journalBytes(t)
		called := false
		_, err := Handoff(context.Background(), fx.config(func(ctx context.Context, dataDir, target string) (string, error) {
			called = true
			return fetch(ctx, dataDir, target)
		}))
		if codeOf(err) != "IRREVERSIBLE_CONFIRM_REQUIRED" {
			t.Fatalf("error = %v, want IRREVERSIBLE_CONFIRM_REQUIRED", err)
		}
		if called {
			t.Fatal("the target was staged without the irreversible bit")
		}
		if after := fx.journalBytes(t); string(after) != string(before) {
			t.Fatal("a refused handoff changed the journal")
		}
		fx.requireNoRequest(t)
	})

	t.Run("bit set", func(t *testing.T) {
		fx := newHandoffFixture(t, irreversible)
		setIrreversibleBit(t, fx)
		if _, err := Handoff(context.Background(), fx.config(fetch)); err != nil {
			t.Fatalf("approved handoff: %v", err)
		}
		fx.requireJournal(t, StateQueued, "")
	})

	t.Run("bit set but payload gone", func(t *testing.T) {
		fx := newHandoffFixture(t, irreversible)
		setIrreversibleBit(t, fx)
		if err := os.RemoveAll(fx.record.PayloadPath); err != nil {
			t.Fatal(err)
		}
		before := fx.journalBytes(t)
		_, err := Handoff(context.Background(), fx.config(fetch))
		if codeOf(err) != "UPDATE_BACKUP_CORRUPT" {
			t.Fatalf("error = %v, want UPDATE_BACKUP_CORRUPT", err)
		}
		if after := fx.journalBytes(t); string(after) != string(before) {
			t.Fatal("a refused handoff changed the journal")
		}
		fx.requireNoRequest(t)
	})
}

func setIrreversibleBit(t *testing.T, fx *handoffFixture) {
	t.Helper()
	root := filepath.Join(fx.dataDir, DatabaseBackupDir)
	record, err := backup.Read(root, fx.operationID, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	record.IrreversibleApproved = true
	if err := backup.WriteRecord(filepath.Join(root, fx.operationID), record); err != nil {
		t.Fatal(err)
	}
}

// TestHandoffTargetStageIdempotent runs the production fetch twice with the same
// digest: the staged package is the verified source bytes both times, and no
// scratch file survives.
func TestHandoffTargetStageIdempotent(t *testing.T) {
	source := filepath.Join(t.TempDir(), "meshmuxd-dev")
	body := []byte("signed fixture package bytes")
	if err := os.WriteFile(source, body, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	fx := newHandoffFixture(t, func(m *upgrade.Manifest) {
		m.Components[0].Source = "file://" + source
		m.Components[0].SHA256 = digest
	})
	fx.manifest, _ = readRootManifest(fx.manifestDir, handoffTarget, os.Geteuid())
	// Re-plant so the record names the manifest that pins the real bytes.
	fx.record = plantOperation(t, fx.dataDir, fx.operationID, fx.manifest, StateBackedUp, fx.now.Add(-time.Minute))

	name, err := PackageName(handoffTarget, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(fx.dataDir, UpgradeDir, name)
	run := func() {
		t.Helper()
		receipt, err := Handoff(context.Background(), fx.config(nil))
		if err != nil {
			t.Fatalf("Handoff: %v", err)
		}
		if receipt.Status != "queued" {
			t.Fatalf("receipt: %+v", receipt)
		}
		got, err := os.ReadFile(staged)
		if err != nil || string(got) != string(body) {
			t.Fatalf("staged package: %v (%d bytes)", err, len(got))
		}
		entries, err := os.ReadDir(filepath.Join(fx.dataDir, UpgradeDir))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".part") {
				t.Fatalf("a scratch file survived the stage: %s", entry.Name())
			}
		}
	}
	run()
	// A retried handoff of the same operation sees the same digest and replaces
	// identical bytes (the journal is re-armed by the test, not by the Web).
	fx.requireJournal(t, StateQueued, "")
	writeJournal(t, fx.dataDir, Op{
		Schema: OpSchema, OperationID: fx.operationID, Kind: KindUpdate, State: StateBackedUp,
		TargetVersion: handoffTarget, FromVersion: handoffFrom,
		ManifestSHA256: fx.manifest.SHA256, PackageSHA256: fx.manifest.Package.SHA256,
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: fx.now,
	})
	run()
}

// TestHandoffPreconditions pins the refusals that must happen before any write:
// an unknown or non-backed_up operation, a manifest that no longer names the
// frozen package, and a missing record.
func TestHandoffPreconditions(t *testing.T) {
	fetch := func(context.Context, string, string) (string, error) {
		return filepath.Join(t.TempDir(), "staged"), nil
	}

	t.Run("unknown operation", func(t *testing.T) {
		fx := newHandoffFixture(t, nil)
		cfg := fx.config(fetch)
		cfg.OperationID = strings.Repeat("b", 32)
		if _, err := Handoff(context.Background(), cfg); codeOf(err) != codeHandoffInvalidState {
			t.Fatalf("error = %v, want %s", err, codeHandoffInvalidState)
		}
		fx.requireNoRequest(t)
	})

	t.Run("wrong state", func(t *testing.T) {
		fx := newHandoffFixture(t, nil)
		writeJournal(t, fx.dataDir, Op{
			Schema: OpSchema, OperationID: fx.operationID, Kind: KindUpdate, State: StateQueued,
			TargetVersion: handoffTarget, FromVersion: handoffFrom,
			ManifestSHA256: fx.manifest.SHA256, PackageSHA256: fx.manifest.Package.SHA256,
			DBSchema: 10, BackupGeneration: 1, UpdatedAt: fx.now,
		})
		if _, err := Handoff(context.Background(), fx.config(fetch)); codeOf(err) != codeHandoffInvalidState {
			t.Fatalf("error = %v, want %s", err, codeHandoffInvalidState)
		}
		fx.requireNoRequest(t)
	})

	t.Run("manifest no longer names the package", func(t *testing.T) {
		fx := newHandoffFixture(t, nil)
		writeHubManifest(t, fx.manifestDir, handoffTarget, func(m *upgrade.Manifest) {
			m.Components[0].SHA256 = strings.Repeat("d", 64)
		})
		before := fx.journalBytes(t)
		_, err := Handoff(context.Background(), fx.config(fetch))
		if codeOf(err) != "HUB_MANIFEST_PACKAGE_MISMATCH" {
			t.Fatalf("error = %v, want HUB_MANIFEST_PACKAGE_MISMATCH", err)
		}
		if after := fx.journalBytes(t); string(after) != string(before) {
			t.Fatal("a refused handoff changed the journal")
		}
		fx.requireNoRequest(t)
	})

	t.Run("missing record", func(t *testing.T) {
		fx := newHandoffFixture(t, nil)
		if err := os.RemoveAll(filepath.Join(fx.dataDir, DatabaseBackupDir, fx.operationID)); err != nil {
			t.Fatal(err)
		}
		if _, err := Handoff(context.Background(), fx.config(fetch)); codeOf(err) != "UPDATE_BACKUP_MISSING" {
			t.Fatalf("error = %v, want UPDATE_BACKUP_MISSING", err)
		}
		fx.requireNoRequest(t)
	})
}

// TestHandoffSpaceFloor pins the requirement the handoff passes to Space: the
// installer's 1 GiB preflight floor, not the bare formula. The target stage may
// never be allowed with less free space than a fresh backup already required
// (T3r's producer uses Floor at both of its space checks).
func TestHandoffSpaceFloor(t *testing.T) {
	fx := newHandoffFixture(t, nil)
	info, err := os.Lstat(filepath.Join(fx.record.PayloadPath, backup.SingleDBName))
	if err != nil {
		t.Fatal(err)
	}
	size := uint64(info.Size())
	// The floor only matters because this small fixture's bare formula is below
	// it; otherwise the assertion would pass for the wrong reason.
	if RequiredSpace(size) >= spaceFloor {
		t.Fatalf("fixture payload is too large for the floor assertion: %d", size)
	}
	staged := filepath.Join(t.TempDir(), "staged-target")
	fetch := func(context.Context, string, string) (string, error) {
		return staged, os.WriteFile(staged, []byte("target package"), 0755)
	}
	if _, err := Handoff(context.Background(), fx.config(fetch)); err != nil {
		t.Fatalf("Handoff: %v", err)
	}
	if fx.spaceCalls != 1 {
		t.Fatalf("space checks = %d, want 1", fx.spaceCalls)
	}
	want := Floor(size)
	if fx.spaceNeed != want {
		t.Fatalf("space need = %d, want Floor(%d) = %d", fx.spaceNeed, size, want)
	}
	if fx.spaceNeed < spaceFloor {
		t.Fatalf("space need = %d, below the 1 GiB floor %d", fx.spaceNeed, spaceFloor)
	}
	if fx.spaceNeed != RequiredSpace(size) && fx.spaceNeed != spaceFloor {
		t.Fatalf("space need = %d, want max(%d, %d)", fx.spaceNeed, RequiredSpace(size), spaceFloor)
	}
}

// TestHandoffDoesNotClobberAConcurrentFailure pins the post-stage journal
// re-read: the reconcile ticker can fail a backed_up orphan while a slow stage
// runs, and the forward-only queued write must never overwrite that fact (nor
// queue a second request for an operation someone else already moved).
func TestHandoffDoesNotClobberAConcurrentFailure(t *testing.T) {
	fx := newHandoffFixture(t, nil)
	fetch := func(context.Context, string, string) (string, error) {
		op, ok, err := ReadOp(fx.dataDir, fx.operationID, os.Geteuid())
		if err != nil || !ok {
			t.Fatalf("journal: ok=%v err=%v", ok, err)
		}
		failed, err := Advance(op, StateFailed, codeBackupOrphaned)
		if err != nil {
			t.Fatal(err)
		}
		failed.UpdatedAt = fx.now
		if err := WriteOp(fx.dataDir, failed); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(t.TempDir(), "staged"), nil
	}
	_, err := Handoff(context.Background(), fx.config(fetch))
	if codeOf(err) != codeHandoffInvalidState {
		t.Fatalf("error = %v, want %s", err, codeHandoffInvalidState)
	}
	fx.requireJournal(t, StateFailed, codeBackupOrphaned)
	fx.requireNoRequest(t)
}
