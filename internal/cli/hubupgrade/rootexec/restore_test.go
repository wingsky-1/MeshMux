package rootexec

// Tests for the #11d Task 7 restore executor (spec §5.7, D2).
//
// The gates pinned here decide whether a failed Hub upgrade is recoverable at
// all: every refusal must happen before the Web stops, staged is a legal source
// and confirmed is not required, a carried record after a restore is not a
// source, and a successful restore flips the binary, all four pins, the drop-in
// and the carried journal together while leaving the old data directory alone.

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
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

type restoreFixture struct {
	root        string
	dataDir     string
	restoreDir  string
	requestDir  string
	resultsDir  string
	claimDir    string
	binaryPath  string
	agentPath   string
	webUnit     string
	webUnitPath string
	hubLedger   string
	lineLedger  string
	from        string
	target      string
	opID        string
	oldSHA      string
	newSHA      string
	record      backup.Record
	op          hubupgrade.Op
	now         time.Time
	payloadPath string
	oldPackage  string
	dbVersion   int
	recordVer   int64
	lastErr     error
}

func newRestoreFixture(t *testing.T) *restoreFixture {
	t.Helper()
	return newRestoreFixtureSchema(t, 10, 10)
}

// newRestoreFixtureSchema builds the same fixture with a chosen copy schema and
// a chosen record schema. The record's payload digest and integrity readback are
// honest for the copy, so the mismatch is detected by the identity check rather
// than by the digest gate.
func newRestoreFixtureSchema(t *testing.T, dbVersion int, recordVersion int64) *restoreFixture {
	t.Helper()
	root := t.TempDir()
	f := &restoreFixture{
		root:        root,
		dataDir:     filepath.Join(root, "var/lib/meshmux"),
		requestDir:  filepath.Join(root, "run/meshmux-hub/requests"),
		resultsDir:  filepath.Join(root, "var/lib/meshmux-installer/hub-upgrade/results"),
		claimDir:    filepath.Join(root, "var/lib/meshmux-installer/upgrade"),
		binaryPath:  filepath.Join(root, "usr/local/libexec/meshmuxd"),
		agentPath:   filepath.Join(root, "etc/meshmux/agent.json"),
		webUnit:     DefaultWebUnit,
		webUnitPath: filepath.Join(root, "etc/systemd/system/meshmux-web.service"),
		hubLedger:   filepath.Join(root, "var/lib/meshmux-installer/state.json"),
		lineLedger:  filepath.Join(root, "var/lib/meshmux-installer/local-line/state.json"),
		from:        "1.0.0",
		target:      "2.0.0",
		opID:        strings.Repeat("a", 32),
		now:         time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
		dbVersion:   dbVersion,
		recordVer:   recordVersion,
	}
	f.restoreDir = filepath.Join(f.dataDir, "restore-"+f.opID+"-"+strconv.FormatInt(f.now.Unix(), 10))
	for _, dir := range []string{
		f.dataDir, f.requestDir, f.resultsDir, f.claimDir,
		filepath.Dir(f.binaryPath), filepath.Dir(f.agentPath), filepath.Dir(f.webUnitPath),
		filepath.Dir(f.lineLedger),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// The installed binary is the failed upgrade's TARGET; the staged old
	// package is a copy of this test executable, which is the only way a B-level
	// fixture can satisfy both the record's from_agent digest and the executor's
	// own /proc/self/exe self-check.
	newBytes := []byte("#!/bin/sh\necho new target\n")
	f.newSHA = sha256Of(newBytes)
	if err := os.WriteFile(f.binaryPath, newBytes, 0755); err != nil {
		t.Fatal(err)
	}
	oldSHA, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.oldSHA = oldSHA
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.dataDir, hubupgrade.UpgradeDir), 0700); err != nil {
		t.Fatal(err)
	}
	name, err := hubupgrade.OldPackageName(f.from, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	f.oldPackage = filepath.Join(f.dataDir, hubupgrade.UpgradeDir, name)
	if err := copyRegularFile(executable, f.oldPackage, 0755); err != nil {
		t.Fatal(err)
	}

	unit := "[Unit]\nDescription=MeshMux Hub Web\n\n[Service]\nType=simple\nUser=meshmux\n" +
		"ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:19080 --origin https://admin.example.invalid --data-dir " +
		f.dataDir + "\n"
	if err := os.WriteFile(f.webUnitPath, []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}

	// Current pins are the failed upgrade's target set.
	nodeCfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("c", 32),
		Role: node.RoleEdge, VLESSPort: 443, SSHPort: 2222,
		AgentVersion: f.target, AgentSHA256: f.newSHA,
	}
	agentBody, err := install.RenderNodeAgentConfig(nodeCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.agentPath, agentBody, 0600); err != nil {
		t.Fatal(err)
	}
	f.writeLedger(t, f.hubLedger, install.InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed",
		ManagedFiles: map[string]string{node.AgentBinaryPath: f.newSHA},
		SharedBinaries: map[string]install.SharedBinary{
			sharedAgentKey: {Path: node.AgentBinaryPath, SHA256: f.newSHA},
		},
	})
	f.writeLedger(t, f.lineLedger, install.InstallState{
		Schema: 1, OperationID: strings.Repeat("2", 32), Status: "installed",
		Node:         &nodeCfg,
		ManagedFiles: map[string]string{node.AgentConfigPath: sha256Of(agentBody)},
		SharedBinaries: map[string]install.SharedBinary{
			sharedAgentKey: {Path: node.AgentBinaryPath, SHA256: f.newSHA},
		},
	})

	f.payloadPath = f.writePayload(t)
	claim := hubupgrade.Claim{
		Schema: hubupgrade.ClaimSchema, Phase: hubupgrade.ClaimPhaseSwapping,
		OperationID: f.opID, TargetVersion: f.target, FromVersion: f.from,
		NewSHA256: f.newSHA,
		OldPins: hubupgrade.Pins{
			HubSharedSHA: f.oldSHA, HubManagedSHA: f.oldSHA,
			LineSharedSHA: f.oldSHA, LineAgentVersion: f.from, LineAgentSHA: f.oldSHA,
			LineAgentManagedSHA: strings.Repeat("e", 64),
			AgentJSONVersion:    f.from, AgentJSONSHA: f.oldSHA,
		},
		CreatedAt: f.now.Add(-time.Minute),
	}
	if err := hubupgrade.WriteClaim(f.claimDir, claim); err != nil {
		t.Fatal(err)
	}
	f.op = hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: f.opID, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateFailed, TargetVersion: f.target, FromVersion: f.from,
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: f.newSHA,
		DBSchema: f.record.DBSchema, BackupGeneration: 1,
		ErrorCode: "HUB_SHARED_BINARY_REPIN_FAILED", UpdatedAt: f.now.Add(-time.Minute),
	}
	if err := hubupgrade.WriteOp(f.dataDir, f.op); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *restoreFixture) writeLedger(t *testing.T, path string, state install.InstallState) {
	t.Helper()
	body, err := install.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *restoreFixture) writePayload(t *testing.T) string {
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
	copyPath := filepath.Join(part, backup.SingleDBName)
	createRestoreSQLite(t, copyPath, f.dbVersion, f.from, f.recordVer)
	f.record, err = backup.Write(root, backup.Spec{
		OperationID: f.opID, FromVersion: f.from, TargetVersion: f.target,
		DBSchema: f.recordVer, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: f.newSHA,
		FromPackageSHA256: f.oldSHA, FromAgentSHA256: f.oldSHA,
		Now: func() time.Time { return f.now },
	}, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, backup.PayloadDir, backup.SingleDBName)
}

func createRestoreSQLite(t *testing.T, path string, userVersion int, lastGood string, rowSchema int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE database_versions (
 id INTEGER PRIMARY KEY CHECK(id=1),
 last_good_version TEXT NOT NULL DEFAULT '',
 last_good_schema INTEGER NOT NULL,
 confirmed_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO database_versions(id, last_good_version, last_good_schema, confirmed_at) VALUES(1,?,?,0)`,
		lastGood, rowSchema); err != nil {
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

func (f *restoreFixture) config() RestoreConfig {
	return RestoreConfig{
		OperationID: f.opID, DataDir: f.dataDir, RestoreDir: f.restoreDir,
		ExpectedSHA256: f.oldSHA, Root: f.root, ClaimDir: f.claimDir,
		ResultsDir: f.resultsDir, RequestDir: f.requestDir, WebUnit: f.webUnit,
		Now:          func() time.Time { return f.now },
		Probe:        func(context.Context) error { return nil },
		Space:        func(string, uint64) error { return nil },
		Owner:        os.Geteuid(),
		RootOwner:    os.Geteuid(),
		ProbeTimeout: 50 * time.Millisecond,
	}
}

type restoreRunner struct {
	calls    []string
	failStop bool
}

func (r *restoreRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name != "systemctl" {
		return nil, errors.New("unexpected command")
	}
	switch args[0] {
	case "stop":
		if r.failStop {
			return nil, errors.New("injected stop failure")
		}
		return nil, nil
	case "is-active":
		return []byte("active\n"), nil
	case "restart", "start", "daemon-reload", "enable", "disable":
		return nil, nil
	}
	return nil, errors.New("unexpected systemctl verb")
}

func (r *restoreRunner) called(prefix string) bool {
	for _, call := range r.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

func (f *restoreFixture) result(t *testing.T) hubupgrade.Result {
	t.Helper()
	result, ok, err := hubupgrade.ReadResult(f.resultsDir, f.opID)
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	return result
}

func (f *restoreFixture) requirePrestopRefusal(t *testing.T, runner *restoreRunner, code string) {
	t.Helper()
	if got := codeOfError(f.lastErr); got != code {
		t.Fatalf("error = %v, want %s", f.lastErr, code)
	}
	if runner.called("systemctl stop") {
		t.Fatalf("the Web was stopped on a pre-stop refusal: %v", runner.calls)
	}
	if got, err := digestBinaryFile(f.binaryPath); err != nil || got != f.newSHA {
		t.Fatalf("installed binary changed: %q %v", got, err)
	}
	if _, err := os.Lstat(f.restoreDir); !os.IsNotExist(err) {
		t.Fatalf("restore directory was left behind: %v", err)
	}
	if _, err := os.Lstat(f.webUnitPath + ".d"); !os.IsNotExist(err) {
		t.Fatalf("drop-in directory was written before the stop")
	}
	if _, ok, err := hubupgrade.ReadResult(f.resultsDir, f.opID); ok || err != nil {
		t.Fatalf("a result was written on a pre-stop refusal: ok=%v err=%v", ok, err)
	}
}

// lastErr records the RunRestore return for requirePrestopRefusal.
func (f *restoreFixture) run(t *testing.T, runner *restoreRunner) error {
	t.Helper()
	err := RunRestore(context.Background(), f.config(), runner)
	f.lastErr = err
	return err
}

func TestRestoreHappyPath(t *testing.T) {
	f := newRestoreFixture(t)
	recordBefore, err := os.ReadFile(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, f.opID, backup.RecordName))
	if err != nil {
		t.Fatal(err)
	}
	runner := &restoreRunner{}
	if err := RunRestore(context.Background(), f.config(), runner); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// The binary is the old staged package again.
	if got, err := digestBinaryFile(f.binaryPath); err != nil || got != f.oldSHA {
		t.Fatalf("installed binary = %q, %v; want %q", got, err, f.oldSHA)
	}
	// The four pins and agent.json are back on from_*.
	hub, _, err := install.ReadState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if hub.SharedBinaries[sharedAgentKey].SHA256 != f.oldSHA || hub.ManagedFiles[node.AgentBinaryPath] != f.oldSHA {
		t.Fatalf("Hub pins not restored: %+v", hub)
	}
	line, hasLine, err := install.ReadLocalLineState(f.root)
	if err != nil || !hasLine || line.Node == nil {
		t.Fatalf("Line ledger: has=%v err=%v", hasLine, err)
	}
	if line.Node.AgentVersion != f.from || line.Node.AgentSHA256 != f.oldSHA ||
		line.SharedBinaries[sharedAgentKey].SHA256 != f.oldSHA {
		t.Fatalf("Line pins not restored: %+v", line)
	}
	agentCfg, agentBody, err := readAgentConfig(f.agentPath, os.Geteuid())
	if err != nil || agentCfg.AgentVersion != f.from || agentCfg.AgentSHA256 != f.oldSHA {
		t.Fatalf("agent.json not restored: %+v %v", agentCfg, err)
	}
	if line.ManagedFiles[node.AgentConfigPath] != sha256Of(agentBody) {
		t.Fatal("Line managed_files[agent.json] does not match the restored bytes")
	}
	if _, ok, err := hubupgrade.ReadClaim(f.claimDir); ok || err != nil {
		t.Fatalf("claim still present: ok=%v err=%v", ok, err)
	}

	// The drop-in is the only data-dir flip and points at the new directory.
	dropIn, err := os.ReadFile(filepath.Join(f.webUnitPath+".d", restoreDataDirDropInName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ExecStart=\n", "--data-dir " + f.restoreDir} {
		if !strings.Contains(string(dropIn), want) {
			t.Fatalf("drop-in missing %q:\n%s", want, dropIn)
		}
	}
	if !runner.called("systemctl restart meshmux-agent.service") {
		t.Fatalf("Line was not restarted: %v", runner.calls)
	}
	if !runner.called("systemctl daemon-reload") || !runner.called("systemctl start meshmux-web.service") {
		t.Fatalf("unit reload/start missing: %v", runner.calls)
	}

	// The restored database is the frozen identity and the carried journal is
	// still readable for the next boot reconcile.
	identity, err := readDatabaseIdentity(filepath.Join(f.restoreDir, backup.SingleDBName))
	if err != nil || identity.UserVersion != f.record.DBSchema ||
		!identity.HasVersionRow || identity.LastGoodVersion != f.from || identity.LastGoodSchema != f.record.DBSchema {
		t.Fatalf("restored identity = %+v, %v", identity, err)
	}
	if op, ok, err := hubupgrade.ReadOp(f.restoreDir, f.opID, os.Geteuid()); err != nil || !ok || op.State != hubupgrade.StateFailed {
		t.Fatalf("carried journal = %+v ok=%v err=%v", op, ok, err)
	}
	if _, err := os.Stat(filepath.Join(f.restoreDir, hubupgrade.DatabaseBackupDir, f.opID, backup.RecordName)); err != nil {
		t.Fatalf("carried per-op record is missing: %v", err)
	}
	info, err := os.Lstat(f.restoreDir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("restore directory mode = %v, %v; want 0700", info.Mode().Perm(), err)
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultRestored || got.OperationID != f.opID {
		t.Fatalf("result = %+v", got)
	}
	// The original data directory was not rewritten.
	recordAfter, err := os.ReadFile(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, f.opID, backup.RecordName))
	if err != nil || string(recordBefore) != string(recordAfter) {
		t.Fatalf("source data directory changed: %v", err)
	}
}

func TestRestoreAcceptsStagedSource(t *testing.T) {
	f := newRestoreFixture(t)
	if f.record.State != backup.StateStaged {
		t.Fatalf("fixture record state = %q, want staged", f.record.State)
	}
	if err := RunRestore(context.Background(), f.config(), &restoreRunner{}); err != nil {
		t.Fatalf("a staged source was refused: %v", err)
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultRestored {
		t.Fatalf("result = %+v", got)
	}
}

func TestRestoreRefusesPayloadDigestMismatch(t *testing.T) {
	f := newRestoreFixture(t)
	if err := os.WriteFile(f.payloadPath, []byte("swapped after the record"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &restoreRunner{}
	f.run(t, runner)
	f.requirePrestopRefusal(t, runner, codeRestorePayload)
}

func TestRestoreRefusesForeignSchemaCopy(t *testing.T) {
	f := newRestoreFixtureSchema(t, 11, 10)
	runner := &restoreRunner{}
	f.run(t, runner)
	f.requirePrestopRefusal(t, runner, codeRestoreConfig)
}

func TestRestoreMissingOldPackage(t *testing.T) {
	f := newRestoreFixture(t)
	if err := os.Remove(f.oldPackage); err != nil {
		t.Fatal(err)
	}
	runner := &restoreRunner{}
	f.run(t, runner)
	f.requirePrestopRefusal(t, runner, codeRestoreBinMissing)
}

func writeRestoreMarker(t *testing.T, dataDir, operationID string, at time.Time) {
	t.Helper()
	marker := hubupgrade.RestoredMarker{
		Schema: hubupgrade.RestoredSchema, OperationID: operationID,
		SnapshotAt: at, Lossy: true,
	}
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(dataDir, hubupgrade.HubUpgradeDir, "restored.json")
	if err := os.MkdirAll(filepath.Dir(markerPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreRefusesCarriedRecordAsSource(t *testing.T) {
	f := newRestoreFixture(t)
	writeRestoreMarker(t, f.dataDir, f.opID, f.now.Add(-time.Hour))
	runner := &restoreRunner{}
	f.run(t, runner)
	f.requirePrestopRefusal(t, runner, codeRestoreCarried)
}

// TestRestoreMarkerForAnotherOperationProceeds pins the op-scoped marker rule:
// a fresh operation in a data directory that was restored earlier must remain
// recoverable while the Web is down (the reconcile pass that clears the marker
// never runs). The marker for the *same* operation is still a refusal, covered
// by TestRestoreRefusesCarriedRecordAsSource.
func TestRestoreMarkerForAnotherOperationProceeds(t *testing.T) {
	f := newRestoreFixture(t)
	writeRestoreMarker(t, f.dataDir, strings.Repeat("b", 32), f.now.Add(-time.Hour))
	runner := &restoreRunner{}
	if err := RunRestore(context.Background(), f.config(), runner); err != nil {
		t.Fatalf("a marker for another operation blocked a fresh restore: %v", err)
	}
	if got := f.result(t); got.Phase != hubupgrade.ResultRestored {
		t.Fatalf("result = %+v", got)
	}
}

func TestRestoreUnitShapeInvalid(t *testing.T) {
	f := newRestoreFixture(t)
	body, err := os.ReadFile(f.webUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("ExecStart=/usr/local/libexec/meshmuxd __internal-web --data-dir "+f.dataDir+"\n")...)
	if err := os.WriteFile(f.webUnitPath, body, 0644); err != nil {
		t.Fatal(err)
	}
	runner := &restoreRunner{}
	f.run(t, runner)
	f.requirePrestopRefusal(t, runner, "HUB_RESTORE_UNIT_SHAPE_INVALID")
}

func TestRestoreSecondRequestBusy(t *testing.T) {
	f := newRestoreFixture(t)
	if err := os.MkdirAll(f.requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.requestDir, strings.Repeat("b", 32)+".json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &restoreRunner{}
	f.run(t, runner)
	f.requirePrestopRefusal(t, runner, codeRestoreBusy)
}

func TestRestoreSpaceCheck(t *testing.T) {
	f := newRestoreFixture(t)
	cfg := f.config()
	var gotNeed uint64
	cfg.Space = func(_ string, need uint64) error {
		gotNeed = need
		return errors.New("HUB_SPACE_INSUFFICIENT: injected")
	}
	runner := &restoreRunner{}
	if err := RunRestore(context.Background(), cfg, runner); codeOfError(err) != "HUB_SPACE_INSUFFICIENT" {
		t.Fatalf("error = %v, want HUB_SPACE_INSUFFICIENT", err)
	}
	info, err := os.Stat(f.payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := hubupgrade.Floor(uint64(info.Size())); gotNeed != want {
		t.Fatalf("space need = %d, want Floor(dbSize) = %d", gotNeed, want)
	}
	if runner.called("systemctl stop") {
		t.Fatal("the Web was stopped without the space check passing")
	}
	if _, err := os.Lstat(f.restoreDir); !os.IsNotExist(err) {
		t.Fatal("restore directory exists after a space refusal")
	}
}
