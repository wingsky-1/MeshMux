package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
)

// fixtureBackupSource is the installer-provided snapshot shape: the installed
// binaries (0755), the private Agent files (0600) and the LKG pair in a tree.
// The store normalizes every copy to 0600 and keeps the whole tree 0700.
func fixtureBackupSource(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "snapshot")
	files := []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"usr/local/libexec/meshmuxd", "fixture old agent\n", 0755},
		{"usr/local/libexec/meshmux-sing-box", "fixture old kernel\n", 0755},
		{"etc/meshmux/agent.json", `{"node_id":"fixture","agent_sha256":"` + strings.Repeat("e", 64) + `"}`, 0600},
		{"var/lib/meshmux-agent/lkg.json", `{"revision":7}`, 0600},
	}
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(f.data), f.mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func fixtureBackupSpec(t *testing.T) BackupSpec {
	t.Helper()
	return BackupSpec{
		OperationID:       strings.Repeat("a", 32),
		FromVersion:       "1.0.0",
		TargetVersion:     "1.0.1",
		DBSchema:          0,
		PolicySchema:      upgrade.PolicySchema,
		ManifestSHA256:    strings.Repeat("b", 64),
		PackageSHA256:     strings.Repeat("c", 64),
		FromPackageSHA256: strings.Repeat("d", 64),
		FromAgentSHA256:   strings.Repeat("e", 64),
		SnapshotDir:       fixtureBackupSource(t),
	}
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

// TestBackupRecordRoundTrip is the record property: one upgrade operation gets
// one 0700 directory holding a 0600 metadata record and a 0600 payload copy,
// and Verify reads back the same identity tuple from exactly those bytes.
func TestBackupRecordRoundTrip(t *testing.T) {
	root := t.TempDir()
	spec := fixtureBackupSpec(t)
	recordPath, err := WriteBackupRecord(root, spec)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	opDir := filepath.Join(root, spec.OperationID)
	if recordPath != filepath.Join(opDir, backupRecordName) {
		t.Fatalf("record path = %q, want %q", recordPath, filepath.Join(opDir, backupRecordName))
	}
	requireMode(t, opDir, 0700)
	requireMode(t, recordPath, 0600)
	payload := filepath.Join(opDir, backupPayloadDir)
	requireMode(t, payload, 0700)

	// Every copied file is private, including the binaries that were 0755 in
	// the installer snapshot; restore re-applies the recorded mode, not this
	// copy's mode.
	if walkErr := filepath.WalkDir(payload, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == payload {
			return nil
		}
		if d.IsDir() {
			requireMode(t, path, 0700)
			return nil
		}
		requireMode(t, path, 0600)
		return nil
	}); walkErr != nil {
		t.Fatalf("payload walk: %v", walkErr)
	}

	record, err := VerifyBackupRecord(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if record.Schema != BackupRecordSchema || record.State != BackupStateStaged || !record.IntegrityOK {
		t.Fatalf("record = %+v", record)
	}
	if record.OperationID != spec.OperationID || record.FromVersion != spec.FromVersion ||
		record.TargetVersion != spec.TargetVersion || record.DBSchema != spec.DBSchema ||
		record.PolicySchema != spec.PolicySchema || record.ManifestSHA256 != spec.ManifestSHA256 ||
		record.PackageSHA256 != spec.PackageSHA256 || record.FromPackageSHA256 != spec.FromPackageSHA256 ||
		record.FromAgentSHA256 != spec.FromAgentSHA256 {
		t.Fatalf("identity tuple = %+v, want %+v", record, spec)
	}
	if record.PayloadPath != payload || record.PayloadSHA256 == "" || record.PayloadFiles != 4 {
		t.Fatalf("payload binding = %+v", record)
	}
	if record.CreatedAt.IsZero() {
		t.Fatalf("record has no creation time: %+v", record)
	}
	if !record.RollbackComplete() {
		t.Fatalf("a copied snapshot is not a complete rollback source: %+v", record)
	}

	// A retry of the same operation reuses the verified record; it never
	// overwrites a rollback source with a second copy.
	again, err := WriteBackupRecord(root, spec)
	if err != nil || again != recordPath {
		t.Fatalf("idempotent write = %q, %v; want %q", again, err, recordPath)
	}

	// The same operation ID with another identity is a mismatch, not an
	// overwrite.
	conflict := spec
	conflict.FromVersion = "0.9.0"
	if _, err := WriteBackupRecord(root, conflict); codeOf(err) != "UPDATE_BACKUP_MISMATCH" {
		t.Fatalf("conflicting write code = %q, want UPDATE_BACKUP_MISMATCH (err %v)", codeOf(err), err)
	}
}

// TestBackupVerifyRefusesCorruptRecord pins the corrupt branch: a damaged
// record, a loose mode, an unknown record field, a tampered payload, a
// symlinked payload entry, an unverified integrity flag or a vanished payload
// tree is CORRUPT, while a vanished record is MISSING.
func TestBackupVerifyRefusesCorruptRecord(t *testing.T) {
	rewriteRecord := func(t *testing.T, recordPath string, mutate func(*BackupRecord)) {
		t.Helper()
		data, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		var record BackupRecord
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		mutate(&record)
		data, err = json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recordPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name   string
		code   string
		mutate func(t *testing.T, root string, spec BackupSpec)
	}{
		{"tampered payload", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			payload := filepath.Join(root, spec.OperationID, backupPayloadDir)
			path := filepath.Join(payload, "usr/local/libexec/meshmuxd")
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.WriteString("tampered\n"); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing record", "UPDATE_BACKUP_MISSING", func(t *testing.T, root string, spec BackupSpec) {
			if err := os.Remove(filepath.Join(root, spec.OperationID, backupRecordName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing payload", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			if err := os.RemoveAll(filepath.Join(root, spec.OperationID, backupPayloadDir)); err != nil {
				t.Fatal(err)
			}
		}},
		{"loose record mode", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			recordPath := filepath.Join(root, spec.OperationID, backupRecordName)
			if err := os.Chmod(recordPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"loose operation directory", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			if err := os.Chmod(filepath.Join(root, spec.OperationID), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"loose payload mode", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			path := filepath.Join(root, spec.OperationID, backupPayloadDir, "etc/meshmux/agent.json")
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown record field", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			recordPath := filepath.Join(root, spec.OperationID, backupRecordName)
			data, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			fields["caller_selected"] = true
			data, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, data, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"integrity not established", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			rewriteRecord(t, filepath.Join(root, spec.OperationID, backupRecordName), func(record *BackupRecord) {
				record.IntegrityOK = false
			})
		}},
		{"symlinked payload entry", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			path := filepath.Join(root, spec.OperationID, backupPayloadDir, "etc/meshmux/agent.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(spec.SnapshotDir, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign schema", "UPDATE_BACKUP_CORRUPT", func(t *testing.T, root string, spec BackupSpec) {
			rewriteRecord(t, filepath.Join(root, spec.OperationID, backupRecordName), func(record *BackupRecord) {
				record.Schema = BackupRecordSchema + 1
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			spec := fixtureBackupSpec(t)
			if _, err := WriteBackupRecord(root, spec); err != nil {
				t.Fatalf("fixture write: %v", err)
			}
			tc.mutate(t, root, spec)
			_, err := VerifyBackupRecord(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema)
			if code := codeOf(err); code != tc.code {
				t.Fatalf("code = %q, want %q (err %v)", code, tc.code, err)
			}
		})
	}
}

// TestBackupVerifyRefusesMismatch is the identity tuple rule: a record that
// exists but names another (from_version, db_schema, policy_schema) never
// satisfies the precondition, and a record under another operation ID is
// simply absent.
func TestBackupVerifyRefusesMismatch(t *testing.T) {
	root := t.TempDir()
	spec := fixtureBackupSpec(t)
	if _, err := WriteBackupRecord(root, spec); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, tc := range []struct {
		name         string
		op           string
		from         string
		dbSchema     int64
		policySchema int
		code         string
	}{
		{"other from version", spec.OperationID, "1.0.1", spec.DBSchema, spec.PolicySchema, "UPDATE_BACKUP_MISMATCH"},
		{"other db schema", spec.OperationID, spec.FromVersion, spec.DBSchema + 1, spec.PolicySchema, "UPDATE_BACKUP_MISMATCH"},
		{"other policy schema", spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema + 1, "UPDATE_BACKUP_MISMATCH"},
		{"other operation", strings.Repeat("f", 32), spec.FromVersion, spec.DBSchema, spec.PolicySchema, "UPDATE_BACKUP_MISSING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyBackupRecord(root, tc.op, tc.from, tc.dbSchema, tc.policySchema)
			if code := codeOf(err); code != tc.code {
				t.Fatalf("code = %q, want %q (err %v)", code, tc.code, err)
			}
		})
	}
}

// craftBackupRecord writes one syntactically valid record without a payload
// digest check; GC reads only the metadata.
func craftBackupRecord(t *testing.T, root, op, from, state string, created time.Time) {
	t.Helper()
	opDir, err := RequireBackupDir(root, op)
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(opDir, backupPayloadDir)
	if err := os.MkdirAll(payload, 0700); err != nil {
		t.Fatal(err)
	}
	record := BackupRecord{Schema: BackupRecordSchema, OperationID: op, FromVersion: from,
		TargetVersion: "1.0.1", DBSchema: 0, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: strings.Repeat("c", 64),
		PayloadPath: payload, PayloadSHA256: strings.Repeat("f", 64), IntegrityOK: true,
		State: state, CreatedAt: created.UTC()}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opDir, backupRecordName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestBackupGCKeepsNMinusOne is the retention rule: after a confirmed upgrade
// GC keeps the single newest confirmed generation (N-1) and always keeps
// records of failed or still-staged operations, because those are the ones a
// revert still needs.
func TestBackupGCKeepsNMinusOne(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ops := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32)}
	states := []string{BackupStateConfirmed, BackupStateConfirmed, BackupStateConfirmed, BackupStateFailed}
	for i, op := range ops {
		craftBackupRecord(t, root, op, "1.0.0", states[i], base.Add(time.Duration(i)*time.Hour))
	}

	removed, err := GCBackups(root, backupKeepConfirmed)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	sort.Strings(removed)
	if len(removed) != 2 || removed[0] != ops[0] || removed[1] != ops[1] {
		t.Fatalf("removed = %q, want %q", removed, ops[:2])
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
	// A second GC is a no-op: the kept generation is the newest confirmed one
	// and the failed record is never a collection candidate.
	again, err := GCBackups(root, backupKeepConfirmed)
	if err != nil || len(again) != 0 {
		t.Fatalf("second gc = %q, %v; want none", again, err)
	}
}

// TestBackupGCNeverCollectsStagedPackages pins the directory split: GC only
// ever walks the rollback store, so staged packages in the update work
// directory and anything else outside it survive untouched.
func TestBackupGCNeverCollectsStagedPackages(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "upgrade-backups")
	staging := filepath.Join(parent, "update")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(staging, "meshmuxd-1.0.1-"+runtime.GOARCH)
	if err := os.WriteFile(staged, []byte("staged package bytes\n"), 0700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(root, "operator-note.txt")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("do not collect\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ops := []string{strings.Repeat("1", 32), strings.Repeat("2", 32)}
	for i, op := range ops {
		craftBackupRecord(t, root, op, "1.0.0", BackupStateConfirmed, base.Add(time.Duration(i)*time.Hour))
	}

	removed, err := GCBackups(root, backupKeepConfirmed)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(removed) != 1 || removed[0] != ops[0] {
		t.Fatalf("removed = %q, want only %q", removed, ops[0])
	}
	if data, err := os.ReadFile(staged); err != nil || string(data) != "staged package bytes\n" {
		t.Fatalf("staged package modified: %q, %v", data, err)
	}
	if data, err := os.ReadFile(stray); err != nil || string(data) != "do not collect\n" {
		t.Fatalf("stray file modified: %q, %v", data, err)
	}
}

// TestBackupLayoutAndDirectoryRules pins the fixed layout and the private
// directory rules: the store is a sibling of the production work directory
// (spec §6), operation IDs are validated before they become path segments, and
// a pre-existing world-readable directory is refused rather than adopted.
func TestBackupLayoutAndDirectoryRules(t *testing.T) {
	if DefaultBackupRoot != "/var/lib/meshmux-agent/upgrade-backups" {
		t.Fatalf("DefaultBackupRoot = %q", DefaultBackupRoot)
	}
	if got := (Config{WorkDir: DefaultWorkDir}).backupRoot(); got != DefaultBackupRoot {
		t.Fatalf("production backup root = %q, want %q", got, DefaultBackupRoot)
	}
	work := t.TempDir()
	if got := (Config{WorkDir: work}).backupRoot(); got != filepath.Join(filepath.Dir(work), "upgrade-backups") {
		t.Fatalf("derived backup root = %q", got)
	}

	root := t.TempDir()
	for _, op := range []string{"", "not-hex", "../escape", strings.Repeat("a", 31), strings.Repeat("A", 32)} {
		if _, err := RequireBackupDir(root, op); codeOf(err) != "OPERATION_ID_INVALID" {
			t.Fatalf("op %q code = %q, want OPERATION_ID_INVALID (err %v)", op, codeOf(err), err)
		}
	}
	opDir, err := RequireBackupDir(root, strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("require: %v", err)
	}
	requireMode(t, opDir, 0700)
	if again, err := RequireBackupDir(root, strings.Repeat("a", 32)); err != nil || again != opDir {
		t.Fatalf("second require = %q, %v", again, err)
	}

	loose := t.TempDir()
	if err := os.Mkdir(filepath.Join(loose, strings.Repeat("b", 32)), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := RequireBackupDir(loose, strings.Repeat("b", 32)); codeOf(err) != "UPDATE_BACKUP_CORRUPT" {
		t.Fatalf("loose directory code = %q, want UPDATE_BACKUP_CORRUPT (err %v)", codeOf(err), err)
	}
}

// TestBackupRecordWithoutSnapshotIsNotRestorable pins the fail-closed gap
// between this task and Task 4: a record written before the installer snapshot
// is retained still verifies (it is a real record of a real operation) but
// RollbackComplete is false, so the Task 2 gate must refuse it rather than
// claim a revert source exists.
func TestBackupRecordWithoutSnapshotIsNotRestorable(t *testing.T) {
	root := t.TempDir()
	spec := fixtureBackupSpec(t)
	spec.SnapshotDir = ""
	recordPath, err := WriteBackupRecord(root, spec)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	requireMode(t, filepath.Dir(recordPath), 0700)
	requireMode(t, recordPath, 0600)
	record, err := VerifyBackupRecord(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if record.PayloadFiles != 0 || record.RollbackComplete() {
		t.Fatalf("empty payload reported as restorable: %+v", record)
	}
	// GC never collects it: only confirmed generations are candidates.
	if removed, err := GCBackups(root, 0); err != nil || len(removed) != 0 {
		t.Fatalf("gc = %q, %v; want none", removed, err)
	}
}

// TestSpaceFloorDerivation pins the re-derived floor from spec §4.14. The
// constant is the sum of every copy that shares the root filesystem at the
// moment of an upgrade: the staged package, the installer snapshot, its
// promoted copy, the N-1 retained generation and headroom.
func TestSpaceFloorDerivation(t *testing.T) {
	want := packageSpace + 3*snapshotSpace + spaceHeadroom
	if requiredSpace != want {
		t.Fatalf("requiredSpace = %d, want %d", requiredSpace, want)
	}
	// Re-deriving must never quietly lower the 11c-1 floor below the
	// installer's own preflight minimum (1 GiB).
	if requiredSpace < 1<<30 {
		t.Fatalf("requiredSpace = %d, below the installer preflight floor", requiredSpace)
	}
	// The snapshot holds the Agent binary and the co-located kernel; each is
	// bounded by the package cap, so the snapshot bound must cover both.
	if snapshotSpace < 2*updatePackageMaxBytes {
		t.Fatalf("snapshotSpace = %d, cannot hold two package-sized binaries", snapshotSpace)
	}
	if packageSpace < updatePackageMaxBytes {
		t.Fatalf("packageSpace = %d, below the fetch bound %d", packageSpace, updatePackageMaxBytes)
	}
	if backupKeepConfirmed != 1 {
		t.Fatalf("backupKeepConfirmed = %d, want N-1 = 1", backupKeepConfirmed)
	}
}

// TestBackupHandoffWritesAndVerifiesRecord is the ordering property: the
// record and its payload are copied and re-read before the transient unit is
// started, and the result names the verified record. The zero-change refusals
// below additionally prove the package is not even staged when the backup
// cannot be produced.
func TestBackupHandoffWritesAndVerifiesRecord(t *testing.T) {
	pkg := []byte("fixture package\n")
	manifest := fixtureManifest(t, pkg, shaOf(pkg))
	cfg := fixtureConfig(t, manifest)
	cfg.BackupRoot = t.TempDir()
	cfg.BackupSource = func() (string, error) { return fixtureBackupSource(t), nil }
	runner := &handoffRunner{}
	checked := false
	runner.atExec = func() {
		if checked {
			return
		}
		checked = true
		record, err := VerifyBackupRecord(cfg.BackupRoot, cfg.OperationID, cfg.CurrentVersion, nodeDBSchema, upgrade.PolicySchema)
		if err != nil {
			t.Fatalf("record not verified before the transient unit: %v", err)
		}
		if record.PayloadFiles == 0 {
			t.Fatalf("record was written without a rollback payload: %+v", record)
		}
	}
	result, err := Run(context.Background(), cfg, runner)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !checked {
		t.Fatal("handoff never ran")
	}
	if want := filepath.Join(cfg.BackupRoot, cfg.OperationID, backupRecordName); result.BackupPointer != want {
		t.Fatalf("backup pointer = %q, want %q", result.BackupPointer, want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("handoff calls = %q, want one", runner.calls)
	}
}

// TestBackupHandoffRefusesWithZeroSystemChange covers the three stable refusal
// codes through Run: no fetch, no unit start and no file in the update work
// directory when the rollback source cannot be written or verified.
func TestBackupHandoffRefusesWithZeroSystemChange(t *testing.T) {
	pkg := []byte("fixture package\n")
	manifest := fixtureManifest(t, pkg, shaOf(pkg))

	t.Run("store unavailable", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		file := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.BackupRoot = filepath.Join(file, "upgrade-backups")
		cfg.BackupSource = func() (string, error) { return fixtureBackupSource(t), nil }
		assertBackupRefusal(t, cfg, "UPDATE_BACKUP_MISSING")
	})

	t.Run("unsafe snapshot", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		cfg.BackupRoot = t.TempDir()
		source := t.TempDir()
		if err := os.WriteFile(filepath.Join(source, "agent.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(source, "agent.json"), filepath.Join(source, "identity.json")); err != nil {
			t.Fatal(err)
		}
		cfg.BackupSource = func() (string, error) { return source, nil }
		assertBackupRefusal(t, cfg, "UPDATE_BACKUP_CORRUPT")
	})

	t.Run("conflicting record", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		cfg.BackupRoot = t.TempDir()
		cfg.BackupSource = func() (string, error) { return fixtureBackupSource(t), nil }
		spec := fixtureBackupSpec(t)
		spec.OperationID = cfg.OperationID
		if _, err := WriteBackupRecord(cfg.BackupRoot, spec); err != nil {
			t.Fatalf("fixture record: %v", err)
		}
		recordPath := filepath.Join(cfg.BackupRoot, cfg.OperationID, backupRecordName)
		data, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		var record BackupRecord
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		record.FromVersion = "0.9.0"
		data, err = json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recordPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		assertBackupRefusal(t, cfg, "UPDATE_BACKUP_MISMATCH")
	})
}

func assertBackupRefusal(t *testing.T, cfg Config, want string) {
	t.Helper()
	runner := &fixtureRunner{}
	result, err := Run(context.Background(), cfg, runner)
	if code := codeOf(err); code != want {
		t.Fatalf("code = %q, want %q (err %v)", code, want, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused handoff executed %v", runner.calls)
	}
	if result.BackupPointer != "" || result.VerifiedPath != "" {
		t.Fatalf("refused handoff reported progress: %+v", result)
	}
	// An empty staging directory is the zero-change proof on the host side:
	// the package is not fetched before the rollback source is verified.
	if entries, readErr := os.ReadDir(cfg.WorkDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("refused handoff staged a package: %v", entries)
	}
}
