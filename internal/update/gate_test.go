package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// gateBackup prepares one verified rollback record for the precondition tests.
func gateBackup(t *testing.T, spec BackupSpec) string {
	t.Helper()
	root := t.TempDir()
	if _, err := WriteBackupRecord(root, spec); err != nil {
		t.Fatalf("fixture rollback record: %v", err)
	}
	return root
}

// rewriteGateRecord changes a written record the way another writer (a revert
// or a recovery step) legitimately could, without touching its payload.
func rewriteGateRecord(t *testing.T, root, operationID string, mutate func(*BackupRecord)) {
	t.Helper()
	path := filepath.Join(root, operationID, backupRecordName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture record: %v", err)
	}
	var record BackupRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode fixture record: %v", err)
	}
	mutate(&record)
	data, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("encode fixture record: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("rewrite fixture record: %v", err)
	}
}

// TestCompatGateRequiresBackup pins the 11c-3 handoff precondition (spec §4.4,
// §6): the handoff may proceed only when the record this operation just wrote
// is staged, integrity-checked and actually holds files to restore. The stable
// codes keep their meanings: a missing store/record, a damaged record or one
// that holds nothing (UPDATE_BACKUP_CORRUPT), and another installed state
// (UPDATE_BACKUP_MISMATCH).
func TestCompatGateRequiresBackup(t *testing.T) {
	t.Run("verified staged record passes", func(t *testing.T) {
		spec := fixtureBackupSpec(t)
		root := gateBackup(t, spec)
		if err := requireVerifiedBackup(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema); err != nil {
			t.Fatalf("gate refused a verified staged record: %v", err)
		}
	})

	t.Run("missing record", func(t *testing.T) {
		spec := fixtureBackupSpec(t)
		code := codeOf(requireVerifiedBackup(t.TempDir(), spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema))
		if code != "UPDATE_BACKUP_MISSING" {
			t.Fatalf("code = %q, want UPDATE_BACKUP_MISSING", code)
		}
	})

	t.Run("corrupt payload", func(t *testing.T) {
		spec := fixtureBackupSpec(t)
		root := gateBackup(t, spec)
		late := filepath.Join(root, spec.OperationID, backupPayloadDir, "late")
		if err := os.WriteFile(late, []byte("late byte\n"), 0600); err != nil {
			t.Fatal(err)
		}
		code := codeOf(requireVerifiedBackup(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema))
		if code != "UPDATE_BACKUP_CORRUPT" {
			t.Fatalf("code = %q, want UPDATE_BACKUP_CORRUPT", code)
		}
	})

	t.Run("record without a payload", func(t *testing.T) {
		spec := fixtureBackupSpec(t)
		spec.SnapshotDir = ""
		root := gateBackup(t, spec)
		code := codeOf(requireVerifiedBackup(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema))
		if code != "UPDATE_BACKUP_CORRUPT" {
			t.Fatalf("code = %q, want UPDATE_BACKUP_CORRUPT", code)
		}
	})

	// A record left over by a failed or confirmed attempt of the same
	// operation is present but is not the staged source this handoff wrote.
	for _, state := range []string{BackupStateFailed, BackupStateConfirmed, "unknown"} {
		t.Run("record state "+state, func(t *testing.T) {
			spec := fixtureBackupSpec(t)
			root := gateBackup(t, spec)
			rewriteGateRecord(t, root, spec.OperationID, func(record *BackupRecord) { record.State = state })
			code := codeOf(requireVerifiedBackup(root, spec.OperationID, spec.FromVersion, spec.DBSchema, spec.PolicySchema))
			if code != "UPDATE_BACKUP_CORRUPT" {
				t.Fatalf("code = %q, want UPDATE_BACKUP_CORRUPT", code)
			}
		})
	}

	t.Run("mismatched record", func(t *testing.T) {
		spec := fixtureBackupSpec(t)
		root := gateBackup(t, spec)
		for _, tc := range []struct {
			name   string
			from   string
			db     int64
			policy int
		}{
			{"from version", "0.9.0", spec.DBSchema, spec.PolicySchema},
			{"database schema", spec.FromVersion, spec.DBSchema + 1, spec.PolicySchema},
			{"policy schema", spec.FromVersion, spec.DBSchema, spec.PolicySchema + 1},
		} {
			if code := codeOf(requireVerifiedBackup(root, spec.OperationID, tc.from, tc.db, tc.policy)); code != "UPDATE_BACKUP_MISMATCH" {
				t.Fatalf("%s: code = %q, want UPDATE_BACKUP_MISMATCH", tc.name, code)
			}
		}
	})
}

// TestCompatGateRequiresBackupAtRun is the end-to-end half: Run itself refuses
// a handoff without a restorable backup, before the package fetch, the staging
// write or the transient unit. Writer-level tests alone cannot catch a gate
// that exists but is never called.
func TestCompatGateRequiresBackupAtRun(t *testing.T) {
	pkg := []byte("fixture package\n")
	manifest := fixtureManifest(t, pkg, shaOf(pkg))

	assertRefusedWithoutMutation := func(t *testing.T, cfg Config, want string) {
		t.Helper()
		runner := &fixtureRunner{}
		result, err := Run(context.Background(), cfg, runner)
		if code := codeOf(err); code != want {
			t.Fatalf("code = %q, want %q (err %v)", code, want, err)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatalf("refusal reported progress: %+v", result)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("refusal executed %v", runner.calls)
		}
		if entries, readErr := os.ReadDir(cfg.WorkDir); readErr == nil && len(entries) != 0 {
			t.Fatalf("refusal fetched or staged a package: %v", entries)
		}
	}

	// The binding case: no installer snapshot at all. The refusal must happen
	// before the record write, so no vacuous record can stand in for a backup.
	t.Run("no backup source", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		cfg.BackupSource = nil
		cfg.BackupRoot = filepath.Join(t.TempDir(), "upgrade-backups")
		assertRefusedWithoutMutation(t, cfg, "UPDATE_BACKUP_MISSING")
		if _, statErr := os.Lstat(cfg.BackupRoot); !os.IsNotExist(statErr) {
			t.Fatalf("refusal manufactured a rollback record: %v", statErr)
		}
	})

	t.Run("record without a payload", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		cfg.BackupRoot = t.TempDir()
		if _, err := WriteBackupRecord(cfg.BackupRoot, BackupSpec{
			OperationID: cfg.OperationID, FromVersion: cfg.CurrentVersion, TargetVersion: cfg.Target,
			DBSchema: nodeDBSchema, PolicySchema: upgrade.PolicySchema,
			ManifestSHA256: cfg.ManifestSHA256, PackageSHA256: shaOf(pkg),
		}); err != nil {
			t.Fatalf("fixture record: %v", err)
		}
		assertRefusedWithoutMutation(t, cfg, "UPDATE_BACKUP_CORRUPT")
	})

	t.Run("mismatched record", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		cfg.BackupRoot = t.TempDir()
		spec := fixtureBackupSpec(t)
		spec.OperationID = cfg.OperationID
		spec.FromVersion = "0.9.0"
		if _, err := WriteBackupRecord(cfg.BackupRoot, spec); err != nil {
			t.Fatalf("fixture record: %v", err)
		}
		assertRefusedWithoutMutation(t, cfg, "UPDATE_BACKUP_MISMATCH")
	})

	t.Run("verified backup passes through", func(t *testing.T) {
		cfg := fixtureConfig(t, manifest)
		runner := &fixtureRunner{}
		result, err := Run(context.Background(), cfg, runner)
		if err != nil {
			t.Fatalf("handoff: %v", err)
		}
		record, err := VerifyBackupRecord(cfg.backupRoot(), cfg.OperationID, cfg.CurrentVersion, nodeDBSchema, upgrade.PolicySchema)
		if err != nil || record.State != BackupStateStaged || !record.RollbackComplete() {
			t.Fatalf("record = %+v, err %v", record, err)
		}
		if len(runner.calls) != 1 || result.BackupPointer == "" {
			t.Fatalf("calls = %q, result = %+v", runner.calls, result)
		}
	})
}

// TestRunStagesChangedMeshmuxdTable is the regression test for the target gate:
// a genuine target manifest differs from the running build's pinned table (new
// meshmuxd version and digest), and it must reach staged bytes through the real
// gate. Running-build table equality would refuse it here.
func TestRunStagesChangedMeshmuxdTable(t *testing.T) {
	pkg := []byte("new meshmuxd build\n")
	m := fixtureManifest(t, pkg, shaOf(pkg))
	// The target ships a newer executor build than the running one; the
	// running build's canonical table can never match this.
	m.Components[0].Version = "dev-20261024"
	if err := m.Validate(); codeOf(err) != "MANIFEST_COMPONENT_INVALID" {
		t.Fatalf("running-build self-check accepted a target table: %v", err)
	}
	cfg := fixtureConfig(t, m)

	result, err := Run(context.Background(), cfg, &fixtureRunner{})
	if err != nil {
		t.Fatalf("handoff: %v", err)
	}
	if staged, readErr := os.ReadFile(result.VerifiedPath); readErr != nil || string(staged) != string(pkg) {
		t.Fatalf("staged bytes = %q, err %v", staged, readErr)
	}
	if result.Manifest.Components[0].Version != "dev-20261024" {
		t.Fatalf("result carries the running build's component: %+v", result.Manifest.Components[0])
	}
}

// TestRunRefusesForeignPolicySchema keeps the stored-policy gate: a target that
// names another stored policy schema cannot be applied by this binary, and the
// refusal is the handoff's own compat code.
func TestRunRefusesForeignPolicySchema(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	m.PolicySchema = upgrade.PolicySchema + 1
	cfg := fixtureConfig(t, m)
	if code := runCode(t, cfg); code != "UPDATE_SCHEMA_INCOMPATIBLE" {
		t.Fatalf("code = %q, want UPDATE_SCHEMA_INCOMPATIBLE", code)
	}
}

// TestRunRefusesUntrustedComponentSource pins the source-class rule restored in
// the target gate: a digest alone never makes an arbitrary URL executable.
func TestRunRefusesUntrustedComponentSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*upgrade.Component)
	}{
		{"dev build from a plain http source", func(c *upgrade.Component) { c.Source = "http://example.invalid/meshmuxd" }},
		{"dev build without the dev- prefix", func(c *upgrade.Component) { c.Version = "1.0.1" }},
		{"release build from a file source", func(c *upgrade.Component) { c.Dev, c.Source = false, "file:///tmp/meshmuxd" }},
		{"release build from a foreign host", func(c *upgrade.Component) { c.Dev, c.Source = false, "https://example.invalid/meshmuxd" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
			tc.mutate(&m.Components[0])
			if code := runCode(t, fixtureConfig(t, m)); code != "MANIFEST_COMPONENT_INVALID" {
				t.Fatalf("code = %q, want MANIFEST_COMPONENT_INVALID", code)
			}
		})
	}
}

// TestRunRefusesManifestForAnotherTarget keeps the version binding: the pinned
// manifest must describe exactly the approved target.
func TestRunRefusesManifestForAnotherTarget(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	m.Version = "1.0.2"
	if code := runCode(t, fixtureConfig(t, m)); code != "UPDATE_TARGET_INVALID" {
		t.Fatalf("code = %q, want UPDATE_TARGET_INVALID", code)
	}
}

// TestRunRefusesForeignKeySetSchema keeps the set-envelope gate: a bare
// single-arch manifest (the pre-6b shape) or a foreign set schema is refused
// before any projection, package fetch or host action.
func TestRunRefusesForeignKeySetSchema(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	bare, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	foreign := fixtureSet(m)
	foreign.Schema = upgrade.SetSchema + "-v2"
	foreignBody, err := json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"bare single-arch manifest", bare},
		{"foreign set schema", foreignBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fixtureConfig(t, m)
			cfg.FetchManifest = func(context.Context) ([]byte, error) { return tc.body, nil }
			runner := &fixtureRunner{}
			if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "MANIFEST_SCHEMA_INVALID" {
				t.Fatalf("code = %q, want MANIFEST_SCHEMA_INVALID (err %v)", codeOf(err), err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("foreign set schema executed %v", runner.calls)
			}
		})
	}
}

func runCode(t *testing.T, cfg Config) string {
	t.Helper()
	_, err := Run(context.Background(), cfg, &fixtureRunner{})
	if err == nil {
		return ""
	}
	return codeOf(err)
}

// TestReadAgentFileRefusesUnsafeFiles pins the ownership/mode half of finding
// #3: the update path applies the same 0600 + owner rule as the Agent, and
// names the failing file in its code.
func TestReadAgentFileRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"node_id":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := readAgentFile(good, &v, "AGENT_CONFIG_UNAVAILABLE"); err != nil || v["node_id"] != "x" {
		t.Fatalf("valid file: err %v, value %v", err, v)
	}

	loose := filepath.Join(dir, "loose.json")
	if err := os.WriteFile(loose, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := readAgentFile(loose, &v, "AGENT_IDENTITY_UNAVAILABLE"); err == nil || err.Error() != "AGENT_IDENTITY_UNAVAILABLE" {
		t.Fatalf("world-readable file: err %v, want AGENT_IDENTITY_UNAVAILABLE", err)
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := readAgentFile(broken, &v, "AGENT_CONFIG_UNAVAILABLE"); err == nil || err.Error() != "AGENT_CONFIG_UNAVAILABLE" {
		t.Fatalf("invalid JSON: err %v, want AGENT_CONFIG_UNAVAILABLE", err)
	}
}
