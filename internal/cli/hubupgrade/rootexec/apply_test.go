package rootexec

// Tests for the #11d Task 6 update executor (spec §5.6).
//
// The gates pinned here are the ones that decide whether a host can still be
// recovered: every check before the claim makes zero writes; the claim exists
// before the binary rename; the four Line pins and both managed_files move
// together; a failed re-pin restores every old pin; the result says restarting
// before systemctl does; and the exec copy is gone after success.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/node"
)

type updateFixture struct {
	root        string
	dataDir     string
	claimDir    string
	resultsDir  string
	execRoot    string
	manifestDir string
	binaryPath  string
	agentPath   string

	opID        string
	target      string
	from        string
	oldSHA      string
	newSHA      string
	manifestSHA string
	record      backup.Record
	op          hubupgrade.Op
	nodeCfg     node.Config
	now         time.Time

	hubLedgerPath  string
	lineLedgerPath string

	payloadDBVersion int
	corruptPayload   bool
}

func newUpdateFixture(t *testing.T) *updateFixture {
	t.Helper()
	return newUpdateFixturePayload(t, 10, false)
}

// newUpdateFixturePayload builds the same fixture with a chosen copy schema or
// corrupt copy while the frozen record still claims db_schema 10. The record's
// payload digest/integrity readback are honest for those bytes, so the failure
// happens in the pre-flight trial, not in the identity gate.
func newUpdateFixturePayload(t *testing.T, dbVersion int, corrupt bool) *updateFixture {
	t.Helper()
	root := t.TempDir()
	f := &updateFixture{
		root:             root,
		dataDir:          filepath.Join(root, "var/lib/meshmux"),
		claimDir:         filepath.Join(root, "var/lib/meshmux-installer/upgrade"),
		resultsDir:       filepath.Join(root, "var/lib/meshmux-installer/hub-upgrade/results"),
		execRoot:         filepath.Join(root, "var/lib/meshmux-installer/upgrade"),
		manifestDir:      filepath.Join(root, "var/lib/meshmux-installer/upgrade"),
		binaryPath:       filepath.Join(root, "usr/local/libexec/meshmuxd"),
		agentPath:        filepath.Join(root, "etc/meshmux/agent.json"),
		opID:             strings.Repeat("a", 32),
		target:           "2.0.0",
		from:             buildinfo.Version,
		now:              time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
		hubLedgerPath:    filepath.Join(root, "var/lib/meshmux-installer/state.json"),
		lineLedgerPath:   filepath.Join(root, "var/lib/meshmux-installer/local-line/state.json"),
		payloadDBVersion: dbVersion,
		corruptPayload:   corrupt,
	}
	for _, dir := range []string{
		f.dataDir, f.claimDir, f.resultsDir, f.execRoot, f.manifestDir,
		filepath.Dir(f.binaryPath), filepath.Dir(f.agentPath),
		filepath.Dir(f.lineLedgerPath),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	oldBytes := []byte("#!/bin/sh\necho old\n")
	f.oldSHA = sha256Of(oldBytes)
	if err := os.WriteFile(f.binaryPath, oldBytes, 0755); err != nil {
		t.Fatal(err)
	}
	newSHA, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.newSHA = newSHA

	upgradeDir := filepath.Join(f.dataDir, hubupgrade.UpgradeDir)
	if err := os.MkdirAll(upgradeDir, 0700); err != nil {
		t.Fatal(err)
	}
	oldName, err := hubupgrade.OldPackageName(f.from, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upgradeDir, oldName), oldBytes, 0755); err != nil {
		t.Fatal(err)
	}

	manifest := upgrade.Manifest{
		Schema: upgrade.Schema, Version: f.target, Architecture: runtime.GOARCH,
		PolicySchema: upgrade.PolicySchema,
		Components: []upgrade.Component{{
			Name: "meshmuxd", Version: f.target, Architecture: runtime.GOARCH,
			Source: "https://github.com/wingsky-1/MeshMux/releases/download/v2.0.0/meshmuxd",
			SHA256: f.newSHA,
		}},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(f.manifestDir, "manifest-"+f.target+".json")
	if err := os.WriteFile(manifestPath, body, 0644); err != nil {
		t.Fatal(err)
	}
	f.manifestSHA = sha256Of(body)

	f.nodeCfg = node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("c", 32),
		Role: node.RoleEdge, VLESSPort: 443, SSHPort: 2222,
		AgentVersion: f.from, AgentSHA256: f.oldSHA,
	}
	agentBody, err := install.RenderNodeAgentConfig(f.nodeCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.agentPath, agentBody, 0600); err != nil {
		t.Fatal(err)
	}

	hub := install.InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed",
		ManagedFiles: map[string]string{node.AgentBinaryPath: f.oldSHA},
		SharedBinaries: map[string]install.SharedBinary{
			sharedAgentKey: {Path: node.AgentBinaryPath, SHA256: f.oldSHA},
		},
	}
	f.writeLedger(t, f.hubLedgerPath, hub)
	lineCfg := f.nodeCfg
	line := install.InstallState{
		Schema: 1, OperationID: strings.Repeat("2", 32), Status: "installed",
		Node: &lineCfg,
		ManagedFiles: map[string]string{
			node.AgentConfigPath: sha256Of(agentBody),
		},
		SharedBinaries: map[string]install.SharedBinary{
			sharedAgentKey: {Path: node.AgentBinaryPath, SHA256: f.oldSHA},
		},
	}
	f.writeLedger(t, f.lineLedgerPath, line)

	f.record = f.writeRecord(t)
	f.op = hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: f.opID, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateQueued, TargetVersion: f.target, FromVersion: f.from,
		ManifestSHA256: f.manifestSHA, PackageSHA256: f.newSHA,
		DBSchema: f.record.DBSchema, BackupGeneration: 1, UpdatedAt: f.now.Add(-time.Minute),
	}
	if err := hubupgrade.WriteOp(f.dataDir, f.op); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *updateFixture) writeLedger(t *testing.T, path string, state install.InstallState) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	body, err := install.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *updateFixture) writeRecord(t *testing.T) backup.Record {
	t.Helper()
	root := filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir)
	dir, err := backup.Dir(root, f.opID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(dir, backup.PayloadPart)
	if err := os.MkdirAll(part, 0700); err != nil {
		t.Fatal(err)
	}
	if f.corruptPayload {
		if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("this is not sqlite"), 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		createSQLite(t, filepath.Join(part, backup.SingleDBName), f.payloadDBVersion)
	}
	record, err := backup.Write(root, backup.Spec{
		OperationID: f.opID, FromVersion: f.from, TargetVersion: f.target,
		DBSchema: 10, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: f.manifestSHA, PackageSHA256: f.newSHA,
		FromPackageSHA256: f.oldSHA, FromAgentSHA256: f.oldSHA,
		Now: func() time.Time { return f.now },
	}, backup.Payload{
		Kind:  backup.PayloadSingleDB,
		Check: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (f *updateFixture) config() UpdateConfig {
	return UpdateConfig{
		Target: f.target, ExpectedSHA256: f.newSHA, OperationID: f.opID,
		DataDir: f.dataDir, FromVersion: f.from, Root: f.root,
		ClaimDir: f.claimDir, ResultsDir: f.resultsDir, ExecRoot: f.execRoot,
		ManifestDir:  f.manifestDir,
		Now:          func() time.Time { return f.now },
		CheckVersion: func() string { return f.target },
		Owner:        os.Geteuid(),
		RootOwner:    os.Geteuid(),
	}
}

func (f *updateFixture) snapshotPins(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, path := range []string{f.hubLedgerPath, f.lineLedgerPath, f.agentPath} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[path] = body
	}
	return out
}

func (f *updateFixture) requirePinsUnchanged(t *testing.T, before map[string][]byte) {
	t.Helper()
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s changed:\n%s\nwant:\n%s", path, got, want)
		}
	}
}

func (f *updateFixture) requireBinary(t *testing.T, digest string) {
	t.Helper()
	got, err := digestBinaryFile(f.binaryPath)
	if err != nil || got != digest {
		t.Fatalf("installed binary digest = %q, %v; want %q", got, err, digest)
	}
}

func (f *updateFixture) requireNoClaim(t *testing.T) {
	t.Helper()
	if _, ok, err := hubupgrade.ReadClaim(f.claimDir); ok || err != nil {
		t.Fatalf("claim still present: ok=%v err=%v", ok, err)
	}
}

func (f *updateFixture) result(t *testing.T) hubupgrade.Result {
	t.Helper()
	result, ok, err := hubupgrade.ReadResult(f.resultsDir, f.opID)
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	return result
}

func (f *updateFixture) requireZeroWrites(t *testing.T, before map[string][]byte) {
	t.Helper()
	f.requireBinary(t, f.oldSHA)
	f.requirePinsUnchanged(t, before)
	f.requireNoClaim(t)
	if _, ok, err := hubupgrade.ReadResult(f.resultsDir, f.opID); ok || err != nil {
		t.Fatalf("a result was written before any system write: ok=%v err=%v", ok, err)
	}
}

type recordingRunner struct {
	lineActive   bool
	calls        []string
	onWebRestart func()
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name != "systemctl" {
		return nil, errors.New("unexpected command")
	}
	switch args[0] {
	case "is-active":
		if r.lineActive {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), errors.New("inactive")
	case "restart":
		if len(args) > 1 && args[1] == webUnit && r.onWebRestart != nil {
			r.onWebRestart()
		}
		return nil, nil
	}
	return nil, errors.New("unexpected systemctl verb")
}

// failPinRenameAt injects one rename-time failure at the nth pin publication.
// It is user-independent (unlike a read-only directory, which root ignores).
func failPinRenameAt(t *testing.T, nth int) {
	t.Helper()
	original := renamePinFile
	calls := 0
	renamePinFile = func(oldPath, newPath string) error {
		calls++
		if calls == nth {
			return errors.New("injected pin rename failure")
		}
		return original(oldPath, newPath)
	}
	t.Cleanup(func() { renamePinFile = original })
}

func (r *recordingRunner) restarted(unit string) bool {
	for _, call := range r.calls {
		if call == "systemctl restart "+unit {
			return true
		}
	}
	return false
}

func TestApplySelfDigestMismatchZeroWrites(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	cfg := f.config()
	cfg.ExpectedSHA256 = strings.Repeat("e", 64)
	err := RunUpdate(context.Background(), cfg, &recordingRunner{})
	if codeOfError(err) != codeDigestMismatch {
		t.Fatalf("error = %v, want %s", err, codeDigestMismatch)
	}
	f.requireZeroWrites(t, before)
}

func TestApplyRefusesNonQueuedJournal(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	op := f.op
	op.State = hubupgrade.StateBackedUp
	if err := hubupgrade.WriteOp(f.dataDir, op); err != nil {
		t.Fatal(err)
	}
	err := RunUpdate(context.Background(), f.config(), &recordingRunner{})
	if codeOfError(err) != codeUpdateState {
		t.Fatalf("error = %v, want %s", err, codeUpdateState)
	}
	f.requireZeroWrites(t, before)
}

func TestApplyRefusesStaleManifest(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	op := f.op
	op.ManifestSHA256 = strings.Repeat("f", 64)
	if err := hubupgrade.WriteOp(f.dataDir, op); err != nil {
		t.Fatal(err)
	}
	err := RunUpdate(context.Background(), f.config(), &recordingRunner{})
	if codeOfError(err) != codeManifestMismatch {
		t.Fatalf("error = %v, want %s", err, codeManifestMismatch)
	}
	f.requireZeroWrites(t, before)
}

func TestUpdateVersionMismatchZeroWrite(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	cfg := f.config()
	cfg.CheckVersion = func() string { return "9.9.9" }
	err := RunUpdate(context.Background(), cfg, &recordingRunner{})
	if codeOfError(err) != codeUpdateVersion {
		t.Fatalf("error = %v, want %s", err, codeUpdateVersion)
	}
	f.requireZeroWrites(t, before)
}

func TestUpdatePreflightTrial(t *testing.T) {
	for name, f := range map[string]*updateFixture{
		"wrong user_version": newUpdateFixturePayload(t, 11, false),
		"corrupt copy":       newUpdateFixturePayload(t, 10, true),
	} {
		t.Run(name, func(t *testing.T) {
			before := f.snapshotPins(t)
			err := RunUpdate(context.Background(), f.config(), &recordingRunner{})
			if codeOfError(err) != codePreflight {
				t.Fatalf("error = %v, want %s", err, codePreflight)
			}
			f.requireZeroWrites(t, before)
		})
	}
}

func TestApplyPrecheckNeedsFourPins(t *testing.T) {
	cases := map[string]func(t *testing.T, f *updateFixture){
		"hub shared": func(t *testing.T, f *updateFixture) {
			state, _, err := install.ReadState(f.root)
			if err != nil {
				t.Fatal(err)
			}
			pin := state.SharedBinaries[sharedAgentKey]
			pin.SHA256 = strings.Repeat("f", 64)
			state.SharedBinaries[sharedAgentKey] = pin
			f.writeLedger(t, f.hubLedgerPath, state)
		},
		"hub managed": func(t *testing.T, f *updateFixture) {
			state, _, err := install.ReadState(f.root)
			if err != nil {
				t.Fatal(err)
			}
			state.ManagedFiles[node.AgentBinaryPath] = strings.Repeat("f", 64)
			f.writeLedger(t, f.hubLedgerPath, state)
		},
		"line shared": func(t *testing.T, f *updateFixture) {
			state, _, err := install.ReadLocalLineState(f.root)
			if err != nil {
				t.Fatal(err)
			}
			pin := state.SharedBinaries[sharedAgentKey]
			pin.SHA256 = strings.Repeat("f", 64)
			state.SharedBinaries[sharedAgentKey] = pin
			f.writeLedger(t, f.lineLedgerPath, state)
		},
		"line state.Node": func(t *testing.T, f *updateFixture) {
			state, _, err := install.ReadLocalLineState(f.root)
			if err != nil {
				t.Fatal(err)
			}
			state.Node.AgentSHA256 = strings.Repeat("f", 64)
			f.writeLedger(t, f.lineLedgerPath, state)
		},
		"agent.json": func(t *testing.T, f *updateFixture) {
			cfg := f.nodeCfg
			cfg.AgentSHA256 = strings.Repeat("f", 64)
			body, err := install.RenderNodeAgentConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.agentPath, body, 0600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newUpdateFixture(t)
			mutate(t, f)
			before := f.snapshotPins(t)
			err := RunUpdate(context.Background(), f.config(), &recordingRunner{})
			if codeOfError(err) != codePrecheck {
				t.Fatalf("error = %v, want %s", err, codePrecheck)
			}
			f.requireZeroWrites(t, before)
		})
	}
}

func TestLineRepinAllFour(t *testing.T) {
	f := newUpdateFixture(t)
	runner := &recordingRunner{lineActive: true}
	if err := RunUpdate(context.Background(), f.config(), runner); err != nil {
		t.Fatal(err)
	}
	f.requireBinary(t, f.newSHA)
	hub, _, err := install.ReadState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if got := hub.SharedBinaries[sharedAgentKey].SHA256; got != f.newSHA {
		t.Fatalf("Hub shared pin = %q", got)
	}
	if got := hub.ManagedFiles[node.AgentBinaryPath]; got != f.newSHA {
		t.Fatalf("Hub managed pin = %q", got)
	}
	line, _, err := install.ReadLocalLineState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if got := line.SharedBinaries[sharedAgentKey].SHA256; got != f.newSHA {
		t.Fatalf("Line shared pin = %q", got)
	}
	if line.Node.AgentVersion != f.target || line.Node.AgentSHA256 != f.newSHA {
		t.Fatalf("Line state.Node = %s/%s", line.Node.AgentVersion, line.Node.AgentSHA256)
	}
	agentBody, err := os.ReadFile(f.agentPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := line.ManagedFiles[node.AgentConfigPath]; got != sha256Of(agentBody) {
		t.Fatalf("Line managed agent.json pin = %q", got)
	}
	var agentCfg node.Config
	if err := json.Unmarshal(agentBody, &agentCfg); err != nil {
		t.Fatal(err)
	}
	if agentCfg.AgentVersion != f.target || agentCfg.AgentSHA256 != f.newSHA {
		t.Fatalf("agent.json = %s/%s", agentCfg.AgentVersion, agentCfg.AgentSHA256)
	}
	if !runner.restarted(lineUnit) || !runner.restarted(webUnit) {
		t.Fatalf("systemctl calls = %v", runner.calls)
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultRestartAccepted {
		t.Fatalf("result phase = %s", got.Phase)
	}
	f.requireNoClaim(t)
}

func TestLineRepinOnlyWhenLineActive(t *testing.T) {
	f := newUpdateFixture(t)
	runner := &recordingRunner{lineActive: false}
	if err := RunUpdate(context.Background(), f.config(), runner); err != nil {
		t.Fatal(err)
	}
	if runner.restarted(lineUnit) {
		t.Fatalf("restarted an inactive Line: %v", runner.calls)
	}
	if !runner.restarted(webUnit) {
		t.Fatalf("Web was not restarted: %v", runner.calls)
	}
}

func TestLineRepinAllOrNothing(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	agentDir := filepath.Dir(f.agentPath)
	if err := os.Chmod(agentDir, 0500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(agentDir, 0755) }()
	runner := &recordingRunner{lineActive: true}
	err := RunUpdate(context.Background(), f.config(), runner)
	if codeOfError(err) != codeRepinFailed {
		t.Fatalf("error = %v, want %s", err, codeRepinFailed)
	}
	f.requireBinary(t, f.oldSHA)
	f.requirePinsUnchanged(t, before)
	f.requireNoClaim(t)
	if runner.restarted(webUnit) {
		t.Fatal("Web was restarted after a failed re-pin")
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultFailed || got.ErrorCode != codeRepinFailed {
		t.Fatalf("result = %s/%s", got.Phase, got.ErrorCode)
	}
}

func TestClaimWrittenBeforeSwap(t *testing.T) {
	f := newUpdateFixture(t)
	var claimAtSwap *hubupgrade.Claim
	cfg := f.config()
	cfg.BeforeSwap = func() {
		claim, ok, err := hubupgrade.ReadClaim(f.claimDir)
		if err != nil || !ok {
			t.Fatalf("claim missing before swap: ok=%v err=%v", ok, err)
		}
		claimAtSwap = &claim
		result := f.result(t)
		if result.Phase != hubupgrade.ResultSwapping {
			t.Fatalf("result before swap = %s", result.Phase)
		}
	}
	if err := RunUpdate(context.Background(), cfg, &recordingRunner{}); err != nil {
		t.Fatal(err)
	}
	if claimAtSwap == nil {
		t.Fatal("the swap hook did not run")
	}
	if claimAtSwap.Phase != hubupgrade.ClaimPhaseSwapping || claimAtSwap.NewSHA256 != f.newSHA ||
		claimAtSwap.OldPins.HubSharedSHA != f.oldSHA || claimAtSwap.OldPins.LineAgentSHA != f.oldSHA {
		t.Fatalf("claim at swap = %+v", claimAtSwap)
	}
}

func TestClaimDeletedAfterRepin(t *testing.T) {
	f := newUpdateFixture(t)
	if err := RunUpdate(context.Background(), f.config(), &recordingRunner{}); err != nil {
		t.Fatal(err)
	}
	f.requireNoClaim(t)
}

func TestApplyResultBeforeRestart(t *testing.T) {
	f := newUpdateFixture(t)
	var phase hubupgrade.ResultPhase
	runner := &recordingRunner{onWebRestart: func() {
		phase = f.result(t).Phase
	}}
	if err := RunUpdate(context.Background(), f.config(), runner); err != nil {
		t.Fatal(err)
	}
	if phase != hubupgrade.ResultRestarting {
		t.Fatalf("result at restart = %q, want restarting", phase)
	}
}

func TestApplyDeletesExecCopyOnSuccess(t *testing.T) {
	f := newUpdateFixture(t)
	execPath := filepath.Join(f.execRoot, "exec-"+f.opID)
	if err := os.WriteFile(execPath, []byte("copy"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := RunUpdate(context.Background(), f.config(), &recordingRunner{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(execPath); !os.IsNotExist(err) {
		t.Fatalf("exec copy survived success: %v", err)
	}
}

// createSQLite writes a tiny valid SQLite database so the real pre-flight can
// prove integrity and user_version without a fixture callback.
func createSQLite(t *testing.T, path string, userVersion int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=" + strconv.Itoa(userVersion)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestLineRepinRenameFailureRestoresOldBytes extends the all-or-nothing gate to
// a failure after the Hub and Line ledgers were already renamed: the captured
// pre-write bytes must be restored exactly, not re-rendered.
func TestLineRepinRenameFailureRestoresOldBytes(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	failPinRenameAt(t, 3) // hub, line renamed; agent rename fails
	runner := &recordingRunner{}
	err := RunUpdate(context.Background(), f.config(), runner)
	if codeOfError(err) != codeRepinFailed {
		t.Fatalf("error = %v, want %s", err, codeRepinFailed)
	}
	f.requireBinary(t, f.oldSHA)
	f.requirePinsUnchanged(t, before)
	f.requireNoClaim(t)
	if runner.restarted(webUnit) {
		t.Fatal("Web was restarted after a failed re-pin")
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultFailed || got.ErrorCode != codeRepinFailed {
		t.Fatalf("result = %s/%s", got.Phase, got.ErrorCode)
	}
}

// TestApplyRollbackFailureKeepsClaimAndPartial: the pin write fails after the
// swap, and the old package is gone so the binary rollback cannot finish. The
// swapping claim must stay as the boot anchor and the receipt must be partial.
func TestApplyRollbackFailureKeepsClaimAndPartial(t *testing.T) {
	f := newUpdateFixture(t)
	before := f.snapshotPins(t)
	oldName, err := hubupgrade.OldPackageName(f.from, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.dataDir, hubupgrade.UpgradeDir, oldName)); err != nil {
		t.Fatal(err)
	}
	failPinRenameAt(t, 1) // restore is exact; only the missing binary blocks rollback
	err = RunUpdate(context.Background(), f.config(), &recordingRunner{})
	if codeOfError(err) != codeRepinFailed {
		t.Fatalf("error = %v, want %s", err, codeRepinFailed)
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultPartial {
		t.Fatalf("result phase = %s, want partial", got.Phase)
	}
	claim, ok, err := hubupgrade.ReadClaim(f.claimDir)
	if err != nil || !ok {
		t.Fatalf("claim retained? ok=%v err=%v", ok, err)
	}
	if claim.Phase != hubupgrade.ClaimPhaseSwapping || claim.OldPins.HubSharedSHA != f.oldSHA {
		t.Fatalf("claim = %+v", claim)
	}
	f.requirePinsUnchanged(t, before)
	f.requireBinary(t, f.newSHA)
}
