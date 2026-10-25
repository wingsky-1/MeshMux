package rootexec

// R-SURFACE tests of the #11d Task 4 dispatcher (spec §5.1). Every refusal must
// happen before exec and leave a stable-code result; the executed file is the
// root-only copy whose bytes were hashed while copying, never the Web-writable
// staged path.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const (
	fixtureTarget = "2.0.0"
	fixtureOp     = "0123456789abcdef0123456789abcdef"
)

type dispatchFixture struct {
	root        string
	dataDir     string
	manifestDir string
	requestDir  string
	doneDir     string
	execRoot    string
	resultsDir  string
	webUnit     string
	now         time.Time

	op          hubupgrade.Op
	record      backup.Record
	ledger      install.InstallState
	pkgBytes    []byte
	oldBytes    []byte
	pkgSHA      string
	oldSHA      string
	manifestSHA string
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	root := t.TempDir()
	f := &dispatchFixture{
		root:        root,
		dataDir:     filepath.Join(root, "var/lib/meshmux"),
		manifestDir: filepath.Join(root, "var/lib/meshmux-installer/upgrade"),
		requestDir:  filepath.Join(root, "run/meshmux-hub/requests"),
		doneDir:     filepath.Join(root, "run/meshmux-hub/requests.done"),
		execRoot:    filepath.Join(root, "var/lib/meshmux-installer/upgrade"),
		resultsDir:  filepath.Join(root, "var/lib/meshmux-installer/hub-upgrade/results"),
		webUnit:     filepath.Join(root, "etc/systemd/system/meshmux-web.service"),
		now:         time.Unix(1700000000, 0).UTC(),
		pkgBytes:    []byte("#!/bin/sh\nexit 0\n"),
		oldBytes:    []byte("#!/bin/sh\necho old\n"),
	}
	for _, dir := range []string{f.dataDir, f.manifestDir, f.doneDir, f.execRoot, f.resultsDir, filepath.Dir(f.webUnit)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// The watched request directory is the production shape: 0730, owned by
	// the dispatcher account, group-writable so the Web can publish.
	if err := os.MkdirAll(f.requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	f.pkgSHA = sha256Hex(f.pkgBytes)
	f.oldSHA = sha256Hex(f.oldBytes)

	// The producer stages both the old and the target package in <data-dir>/upgrade.
	upgradeDir := filepath.Join(f.dataDir, hubupgrade.UpgradeDir)
	if err := os.MkdirAll(upgradeDir, 0700); err != nil {
		t.Fatal(err)
	}
	oldName, err := hubupgrade.OldPackageName(buildinfo.Version, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upgradeDir, oldName), f.oldBytes, 0755); err != nil {
		t.Fatal(err)
	}
	targetName, err := hubupgrade.PackageName(fixtureTarget, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upgradeDir, targetName), f.pkgBytes, 0755); err != nil {
		t.Fatal(err)
	}

	// Root-preset target manifest, pinned by its exact bytes.
	manifest := upgrade.Manifest{
		Schema:       upgrade.Schema,
		Version:      fixtureTarget,
		Architecture: runtime.GOARCH,
		PolicySchema: upgrade.PolicySchema,
		Components: []upgrade.Component{{
			Name: "meshmuxd", Version: "2.0.0", Architecture: runtime.GOARCH,
			Source: "https://github.com/wingsky-1/MeshMux/releases/download/v2.0.0/meshmuxd",
			SHA256: f.pkgSHA,
		}},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(f.manifestDir, "manifest-"+fixtureTarget+".json")
	if err := os.WriteFile(manifestPath, body, 0644); err != nil {
		t.Fatal(err)
	}
	f.manifestSHA = sha256Hex(body)

	// Per-operation record of the backup the Web queued.
	f.record = f.writeBackup(t, fixtureOp)

	f.op = hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: fixtureOp, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateQueued, TargetVersion: fixtureTarget, FromVersion: buildinfo.Version,
		ManifestSHA256: f.manifestSHA, PackageSHA256: f.pkgSHA,
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: f.now,
	}
	f.writeOp(t, nil)

	f.ledger = install.InstallState{
		Schema: 1, OperationID: fixtureOp, Status: "installed",
		ManagedFiles: map[string]string{
			"/usr/local/libexec/meshmuxd": f.oldSHA,
		},
		SharedBinaries: map[string]install.SharedBinary{
			"meshmuxd": {Path: "/usr/local/libexec/meshmuxd", SHA256: f.oldSHA},
		},
	}
	f.writeWebUnit(t, `[Unit]
Description=MeshMux Hub Web

[Service]
Type=simple
User=meshmux
ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:9080 --data-dir `+f.dataDir+`

[Install]
WantedBy=multi-user.target
`)
	return f
}

// writeBackup stages one single-database payload and publishes its per-operation
// record (<root>/<operationID>/record.json). It mirrors the producer of Task 3r:
// the database copy exists inside payload.part before backup.Write verifies and
// publishes it.
func (f *dispatchFixture) writeBackup(t *testing.T, operationID string) backup.Record {
	t.Helper()
	root := filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir)
	dir, err := backup.Dir(root, operationID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(dir, backup.PayloadPart)
	if err := os.MkdirAll(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("database-copy"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := backup.Write(root, backup.Spec{
		OperationID:       operationID,
		FromVersion:       buildinfo.Version,
		TargetVersion:     fixtureTarget,
		DBSchema:          10,
		PolicySchema:      upgrade.PolicySchema,
		ManifestSHA256:    f.manifestSHA,
		PackageSHA256:     f.pkgSHA,
		FromPackageSHA256: f.oldSHA,
		FromAgentSHA256:   f.oldSHA,
		Now:               func() time.Time { return f.now },
	}, backup.Payload{
		Kind:  backup.PayloadSingleDB,
		Check: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (f *dispatchFixture) writeOp(t *testing.T, mutate func(*hubupgrade.Op)) {
	t.Helper()
	op := f.op
	if mutate != nil {
		mutate(&op)
	}
	if err := hubupgrade.WriteOp(f.dataDir, op); err != nil {
		t.Fatal(err)
	}
	f.op = op
}

func (f *dispatchFixture) writeWebUnit(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(f.webUnit, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func (f *dispatchFixture) writeRequest(t *testing.T, req hubupgrade.Request) {
	t.Helper()
	if _, err := hubupgrade.WriteRequest(f.requestDir, req); err != nil {
		t.Fatal(err)
	}
}

func (f *dispatchFixture) config(exec func(string, []string, []string) error) DispatchConfig {
	owner := os.Geteuid()
	return DispatchConfig{
		DataDir:       f.dataDir,
		ManifestDir:   f.manifestDir,
		RequestDir:    f.requestDir,
		DoneDir:       f.doneDir,
		ExecRoot:      f.execRoot,
		ResultsDir:    f.resultsDir,
		WebUnit:       f.webUnit,
		Now:           func() time.Time { return f.now },
		Exec:          exec,
		Owner:         owner,
		RecordOwner:   owner,
		ManifestOwner: owner,
		RootOwner:     owner,
		ReadLedger: func() (install.InstallState, bool, error) {
			return f.ledger, true, nil
		},
	}
}

func (f *dispatchFixture) updateRequest() hubupgrade.Request {
	return hubupgrade.Request{
		Schema: hubupgrade.RequestSchema, Kind: hubupgrade.KindUpdate,
		OperationID: fixtureOp, DataDir: f.dataDir,
	}
}

func (f *dispatchFixture) restoreRequest() hubupgrade.Request {
	return hubupgrade.Request{
		Schema: hubupgrade.RequestSchema, Kind: hubupgrade.KindRestore,
		OperationID: fixtureOp, DataDir: f.dataDir,
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if i := strings.IndexByte(text, ':'); i > 0 {
		return text[:i]
	}
	return text
}

func readDispatchResult(t *testing.T, dir, operationID string) hubupgrade.Result {
	t.Helper()
	result, ok, err := hubupgrade.ReadResult(dir, operationID)
	if err != nil || !ok {
		t.Fatalf("result %s = ok %v err %v", operationID, ok, err)
	}
	return result
}

func TestDispatchArgvPinned(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		f := newDispatchFixture(t)
		f.writeRequest(t, f.updateRequest())
		var gotPath string
		var gotArgv, gotEnv []string
		exec := func(path string, argv, env []string) error {
			gotPath, gotArgv, gotEnv = path, argv, env
			return nil
		}
		if err := RunDispatch(context.Background(), f.config(exec), node.ExecRunner{}); err != nil {
			t.Fatal(err)
		}
		execPath := filepath.Join(f.execRoot, "exec-"+fixtureOp)
		want := []string{execPath, "__internal-hub-update", "--target", fixtureTarget,
			"--expected-sha256", f.pkgSHA, "--operation-id", fixtureOp,
			"--data-dir", f.dataDir, "--from-version", buildinfo.Version}
		if gotPath != execPath {
			t.Fatalf("exec path = %q, want %q", gotPath, execPath)
		}
		if strings.Join(gotArgv, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("argv = %#v\nwant %#v", gotArgv, want)
		}
		if len(gotEnv) == 0 {
			t.Fatal("exec environment is empty")
		}
	})
	t.Run("restore", func(t *testing.T) {
		f := newDispatchFixture(t)
		f.writeOp(t, func(op *hubupgrade.Op) {
			op.Kind = hubupgrade.KindRestore
			op.State = hubupgrade.StateFailed
		})
		f.writeRequest(t, f.restoreRequest())
		var gotPath string
		var gotArgv []string
		exec := func(path string, argv, env []string) error {
			gotPath, gotArgv = path, argv
			return nil
		}
		if err := RunDispatch(context.Background(), f.config(exec), node.ExecRunner{}); err != nil {
			t.Fatal(err)
		}
		execPath := filepath.Join(f.execRoot, "exec-"+fixtureOp)
		restoreDir := filepath.Join(f.dataDir, "restore-"+fixtureOp+"-"+strconv.FormatInt(f.now.Unix(), 10))
		want := []string{execPath, "__internal-hub-restore", "--expected-sha256", f.oldSHA,
			"--operation-id", fixtureOp, "--data-dir", f.dataDir, "--restore-dir", restoreDir}
		if gotPath != execPath || strings.Join(gotArgv, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("restore exec = %q %#v\nwant %q %#v", gotPath, gotArgv, execPath, want)
		}
	})
}

func TestDispatchRejectsSymlinkRequest(t *testing.T) {
	f := newDispatchFixture(t)
	realPath := filepath.Join(t.TempDir(), "real.json")
	body, err := json.Marshal(f.updateRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.requestDir, fixtureOp+".json")
	if err := os.Symlink(realPath, link); err != nil {
		t.Fatal(err)
	}
	executed := false
	err = RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
		executed = true
		return nil
	}), node.ExecRunner{})
	if err == nil || executed {
		t.Fatalf("symlinked request: err=%v executed=%v", err, executed)
	}
	if code := readDispatchResult(t, f.resultsDir, fixtureOp).ErrorCode; code != codeRequestInvalid {
		t.Fatalf("result code = %q, want %q", code, codeRequestInvalid)
	}
	entries, err := os.ReadDir(f.requestDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("request directory after rejection = %v, %v", entries, err)
	}
}

// TestDispatchRejectsUnsafeRequestDir is the blocker-2 regression. requests/ is
// group-writable by the Web, so its identity is part of the boundary: a
// symlinked, Web-readable or foreign-owned watched directory must never be
// traversed, because the Web could otherwise rename the real directory away and
// substitute one it controls.
func TestDispatchRejectsUnsafeRequestDir(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		f := newDispatchFixture(t)
		realDir := filepath.Join(f.root, "run/meshmux-hub/real-requests")
		if err := os.Mkdir(realDir, 0730); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(realDir, 0730); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(f.requestDir); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDir, f.requestDir); err != nil {
			t.Fatal(err)
		}
		if _, err := hubupgrade.WriteRequest(realDir, f.updateRequest()); err != nil {
			t.Fatal(err)
		}
		executed := false
		err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
			executed = true
			return nil
		}), node.ExecRunner{})
		if err == nil || executed {
			t.Fatalf("symlinked request directory: err=%v executed=%v", err, executed)
		}
		if code := errorCode(err); code != codeRequestInvalid {
			t.Fatalf("code = %q, want %q", code, codeRequestInvalid)
		}
	})
	t.Run("web-readable mode", func(t *testing.T) {
		f := newDispatchFixture(t)
		if err := os.Chmod(f.requestDir, 0770); err != nil {
			t.Fatal(err)
		}
		f.writeRequest(t, f.updateRequest())
		executed := false
		err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
			executed = true
			return nil
		}), node.ExecRunner{})
		if err == nil || executed {
			t.Fatalf("0770 request directory: err=%v executed=%v", err, executed)
		}
	})
	t.Run("foreign owner", func(t *testing.T) {
		f := newDispatchFixture(t)
		f.writeRequest(t, f.updateRequest())
		cfg := f.config(func(string, []string, []string) error {
			t.Error("exec ran with a foreign request-directory owner")
			return nil
		})
		cfg.RootOwner = os.Geteuid() + 1
		if err := RunDispatch(context.Background(), cfg, node.ExecRunner{}); err == nil {
			t.Fatal("a request directory owned by another account was accepted")
		}
	})
}

// TestDispatchIgnoresUnstagedResidue proves the removed scratch-drain branch:
// only a completed <op>.json is a request. A name the writer never publishes
// (scratch residue) is left alone, so the dispatcher cannot consume a document
// that is still being written; a real request beside it is still executed.
func TestDispatchIgnoresUnstagedResidue(t *testing.T) {
	t.Run("residue alone is a no-op", func(t *testing.T) {
		f := newDispatchFixture(t)
		residue := filepath.Join(f.requestDir, "."+fixtureOp+".json.part-123")
		if err := os.WriteFile(residue, []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
		executed := false
		if err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
			executed = true
			return nil
		}), node.ExecRunner{}); err != nil {
			t.Fatal(err)
		}
		if executed {
			t.Fatal("scratch residue was executed")
		}
		if _, err := os.Lstat(residue); err != nil {
			t.Fatalf("dispatcher consumed a non-request entry: %v", err)
		}
		if _, ok, err := hubupgrade.ReadResult(f.resultsDir, fixtureOp); err != nil || ok {
			t.Fatalf("a result was written for a non-request: ok=%v err=%v", ok, err)
		}
	})
	t.Run("residue does not block a completed request", func(t *testing.T) {
		f := newDispatchFixture(t)
		if err := os.WriteFile(filepath.Join(f.requestDir, "."+fixtureOp+".json.part-9"), []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
		f.writeRequest(t, f.updateRequest())
		if err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error { return nil }), node.ExecRunner{}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(f.requestDir, fixtureOp+".json")); !os.IsNotExist(err) {
			t.Fatalf("the consumed request is still in the watched directory: %v", err)
		}
	})
}

func TestDispatchRejectsForeignDataDir(t *testing.T) {
	f := newDispatchFixture(t)
	req := f.updateRequest()
	req.DataDir = filepath.Join(t.TempDir(), "other")
	f.writeRequest(t, req)
	executed := false
	err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
		executed = true
		return nil
	}), node.ExecRunner{})
	if err == nil || executed {
		t.Fatalf("foreign data_dir: err=%v executed=%v", err, executed)
	}
	if code := readDispatchResult(t, f.resultsDir, fixtureOp).ErrorCode; code != codeDataDirMismatch {
		t.Fatalf("result code = %q, want %q", code, codeDataDirMismatch)
	}
}

func TestDispatchRejectsMoreThanOneRequest(t *testing.T) {
	f := newDispatchFixture(t)
	second := strings.Repeat("b", 32)
	f.writeRequest(t, f.updateRequest())
	f.writeRequest(t, hubupgrade.Request{
		Schema: hubupgrade.RequestSchema, Kind: hubupgrade.KindUpdate,
		OperationID: second, DataDir: f.dataDir,
	})
	executed := false
	err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
		executed = true
		return nil
	}), node.ExecRunner{})
	if err == nil || !strings.Contains(err.Error(), "HUB_HANDOFF_BUSY") || executed {
		t.Fatalf("two requests: err=%v executed=%v", err, executed)
	}
	entries, err := os.ReadDir(f.requestDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("request directory not drained: %v, %v", entries, err)
	}
	done, err := os.ReadDir(f.doneDir)
	if err != nil || len(done) != 2 {
		t.Fatalf("done directory = %v, %v", done, err)
	}
	for _, op := range []string{fixtureOp, second} {
		if code := readDispatchResult(t, f.resultsDir, op).ErrorCode; code != "HUB_HANDOFF_BUSY" {
			t.Fatalf("result %s code = %q, want HUB_HANDOFF_BUSY", op, code)
		}
	}
}

func TestDispatchUnknownTargetNoExec(t *testing.T) {
	f := newDispatchFixture(t)
	if err := os.Remove(filepath.Join(f.manifestDir, "manifest-"+fixtureTarget+".json")); err != nil {
		t.Fatal(err)
	}
	f.writeRequest(t, f.updateRequest())
	executed := false
	err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
		executed = true
		return nil
	}), node.ExecRunner{})
	if err == nil || executed || errorCode(err) != "MANIFEST_UNAVAILABLE" {
		t.Fatalf("missing manifest: err=%v executed=%v", err, executed)
	}
	if code := readDispatchResult(t, f.resultsDir, fixtureOp).ErrorCode; code != "MANIFEST_UNAVAILABLE" {
		t.Fatalf("result code = %q", code)
	}
}

func TestDispatchStagedDigestMismatchNoExec(t *testing.T) {
	f := newDispatchFixture(t)
	name, err := hubupgrade.PackageName(fixtureTarget, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(f.dataDir, hubupgrade.UpgradeDir, name)
	if err := os.WriteFile(staged, []byte("tampered package"), 0755); err != nil {
		t.Fatal(err)
	}
	f.writeRequest(t, f.updateRequest())
	executed := false
	err = RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
		executed = true
		return nil
	}), node.ExecRunner{})
	if err == nil || executed || errorCode(err) != codeDigestMismatch {
		t.Fatalf("staged digest mismatch: err=%v executed=%v", err, executed)
	}
	if code := readDispatchResult(t, f.resultsDir, fixtureOp).ErrorCode; code != codeDigestMismatch {
		t.Fatalf("result code = %q, want %q", code, codeDigestMismatch)
	}
}

func TestDispatchExecsVerifiedCopy(t *testing.T) {
	f := newDispatchFixture(t)
	f.writeRequest(t, f.updateRequest())
	name, err := hubupgrade.PackageName(fixtureTarget, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(f.dataDir, hubupgrade.UpgradeDir, name)
	execPath := filepath.Join(f.execRoot, "exec-"+fixtureOp)
	var executedBytes []byte
	exec := func(path string, argv, env []string) error {
		if path != execPath {
			t.Errorf("exec path = %q, want the root-only copy", path)
		}
		executedBytes, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		// The TOCTOU attempt happens after the dispatcher validated and copied
		// the staged bytes: the executed copy must not follow it.
		return os.WriteFile(staged, []byte("replaced after validation"), 0755)
	}
	if err := RunDispatch(context.Background(), f.config(exec), node.ExecRunner{}); err != nil {
		t.Fatal(err)
	}
	if string(executedBytes) != string(f.pkgBytes) {
		t.Fatalf("executed bytes = %q, want the verified package bytes", executedBytes)
	}
	info, err := os.Lstat(execPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("exec copy mode = %o, want 0700", info.Mode().Perm())
	}
	stagedBytes, err := os.ReadFile(staged)
	if err != nil || string(stagedBytes) != "replaced after validation" {
		t.Fatalf("staged replacement did not happen: %q, %v", stagedBytes, err)
	}
}

func TestDispatchLedgerIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*install.InstallState)
		code   string
	}{
		{name: "missing ledger", mutate: func(*install.InstallState) {}, code: "HUB_BACKUP_IDENTITY_MISSING"},
		{name: "missing managed file", mutate: func(state *install.InstallState) {
			delete(state.ManagedFiles, "/usr/local/libexec/meshmuxd")
		}, code: "HUB_BACKUP_IDENTITY_MISSING"},
		{name: "managed digest mismatch", mutate: func(state *install.InstallState) {
			state.ManagedFiles["/usr/local/libexec/meshmuxd"] = strings.Repeat("c", 64)
		}, code: "UPDATE_BACKUP_MISMATCH"},
		{name: "shared bin drift", mutate: func(state *install.InstallState) {
			state.SharedBinaries["meshmuxd"] = install.SharedBinary{Path: "/usr/local/libexec/meshmuxd", SHA256: strings.Repeat("d", 64)}
		}, code: "HUB_BACKUP_IDENTITY_MISSING"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			f.writeRequest(t, f.updateRequest())
			state := f.ledger
			state.ManagedFiles = map[string]string{}
			for key, value := range f.ledger.ManagedFiles {
				state.ManagedFiles[key] = value
			}
			state.SharedBinaries = map[string]install.SharedBinary{}
			for key, value := range f.ledger.SharedBinaries {
				state.SharedBinaries[key] = value
			}
			if tc.name == "missing ledger" {
				state = install.InstallState{}
			} else {
				tc.mutate(&state)
			}
			cfg := f.config(func(string, []string, []string) error {
				t.Error("exec ran despite a ledger identity refusal")
				return nil
			})
			if tc.name == "missing ledger" {
				cfg.ReadLedger = func() (install.InstallState, bool, error) { return install.InstallState{}, false, nil }
			} else {
				cfg.ReadLedger = func() (install.InstallState, bool, error) { return state, true, nil }
			}
			err := RunDispatch(context.Background(), cfg, node.ExecRunner{})
			if err == nil || errorCode(err) != tc.code {
				t.Fatalf("err = %v, want code %s", err, tc.code)
			}
			if code := readDispatchResult(t, f.resultsDir, fixtureOp).ErrorCode; code != tc.code {
				t.Fatalf("result code = %q, want %s", code, tc.code)
			}
		})
	}
}

func TestDispatchReadsMeshmuxOwnedRecord(t *testing.T) {
	t.Run("expected owner reads the record", func(t *testing.T) {
		f := newDispatchFixture(t)
		f.writeRequest(t, f.updateRequest())
		if err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error { return nil }), node.ExecRunner{}); err != nil {
			t.Fatal(err)
		}
		// The read is <root>/<op>/record.json. A flat pointer copy is never
		// consulted, and this fixture planted none.
		if _, err := os.Lstat(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, fixtureOp, backup.RecordName)); err != nil {
			t.Fatalf("the per-operation record was not read: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, backup.RecordName)); !os.IsNotExist(err) {
			t.Fatalf("the dispatcher looked at a flat pointer record: %v", err)
		}
	})
	t.Run("a foreign expected owner is refused", func(t *testing.T) {
		f := newDispatchFixture(t)
		f.writeRequest(t, f.updateRequest())
		cfg := f.config(func(string, []string, []string) error {
			t.Error("exec ran with a foreign record owner")
			return nil
		})
		cfg.RecordOwner = os.Geteuid() + 1
		err := RunDispatch(context.Background(), cfg, node.ExecRunner{})
		if err == nil {
			t.Fatal("a record owned by another account was accepted")
		}
		if got := errorCode(err); got != backup.CodeCorrupt {
			t.Fatalf("code = %q, want %q", got, backup.CodeCorrupt)
		}
	})
}

func TestDispatchReadsRequestedOperation(t *testing.T) {
	f := newDispatchFixture(t)
	// A newer operation exists: a higher generation in the journal and a
	// directory whose mtime is fresher than the requested one. The dispatcher
	// reads exactly request.operation_id, never "the latest".
	newer := strings.Repeat("a", 32)
	f.writeBackup(t, newer)
	newerOp := f.op
	newerOp.OperationID = newer
	newerOp.BackupGeneration = 2
	newerOp.UpdatedAt = f.now.Add(time.Hour)
	if err := hubupgrade.WriteOp(f.dataDir, newerOp); err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, newer), later, later); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, newer, backup.RecordName), later, later); err != nil {
		t.Fatal(err)
	}
	// A damaged flat pointer copy sits beside the per-operation tree; the
	// dispatcher must never consult it.
	if err := os.WriteFile(filepath.Join(f.dataDir, hubupgrade.DatabaseBackupDir, backup.RecordName), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}

	f.writeRequest(t, f.updateRequest())
	var gotPath string
	var gotArgv []string
	exec := func(path string, argv, env []string) error {
		gotPath, gotArgv = path, argv
		return nil
	}
	if err := RunDispatch(context.Background(), f.config(exec), node.ExecRunner{}); err != nil {
		t.Fatal(err)
	}
	execPath := filepath.Join(f.execRoot, "exec-"+fixtureOp)
	if gotPath != execPath {
		t.Fatalf("exec path = %q, want %q", gotPath, execPath)
	}
	if argvOperationID(t, gotArgv) != fixtureOp {
		t.Fatalf("executed operation = %q, want the requested %q", argvOperationID(t, gotArgv), fixtureOp)
	}
	if _, err := os.Lstat(filepath.Join(f.execRoot, "exec-"+newer)); !os.IsNotExist(err) {
		t.Fatalf("the dispatcher copied an operation that was not requested: %v", err)
	}
}

func argvOperationID(t *testing.T, argv []string) string {
	t.Helper()
	for i, arg := range argv {
		if arg == "--operation-id" && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	t.Fatalf("argv carries no --operation-id: %#v", argv)
	return ""
}

// TestDispatchReadDoesNotWriteDataDir pins the per-operation read: it runs no
// recovery, so the Web-owned tree is byte-identical before and after a dispatch
// and gains no trash/orphan/scratch entry.
func TestDispatchReadDoesNotWriteDataDir(t *testing.T) {
	f := newDispatchFixture(t)
	before := snapshotTree(t, f.dataDir)
	f.writeRequest(t, f.updateRequest())
	if err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error { return nil }), node.ExecRunner{}); err != nil {
		t.Fatal(err)
	}
	after := snapshotTree(t, f.dataDir)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("the dispatcher modified the data directory:\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	for _, line := range after {
		for _, marker := range []string{".trash-", ".orphan-", "record.json.part"} {
			if strings.Contains(line, marker) {
				t.Fatalf("the per-operation read produced %q: %s", marker, line)
			}
		}
	}
}

func snapshotTree(t *testing.T, root string) []string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest := "-"
		if info.Mode().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest = sha256Hex(body)
		}
		lines = append(lines, fmt.Sprintf("%s %s %d %s", rel, info.Mode(), info.Size(), digest))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return lines
}

// TestDispatchNeverTakesProduceLock proves the read path is lock-free: the
// producer mutex only covers the Web's check-then-write triple, and holding it
// must not block a dispatch.
func TestDispatchNeverTakesProduceLock(t *testing.T) {
	f := newDispatchFixture(t)
	f.writeRequest(t, f.updateRequest())
	unlock := hubupgrade.LockBackupProduce()
	defer unlock()
	done := make(chan error, 1)
	go func() {
		done <- RunDispatch(context.Background(), f.config(func(string, []string, []string) error { return nil }), node.ExecRunner{})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dispatcher blocked on LockBackupProduce; it must not share the producer mutex")
	}
}

func TestDispatchRefusesNonQueuedJournal(t *testing.T) {
	for _, state := range []hubupgrade.State{
		hubupgrade.StateApplying, hubupgrade.StateRestarting, hubupgrade.StateConfirmed,
	} {
		t.Run(string(state), func(t *testing.T) {
			f := newDispatchFixture(t)
			f.writeOp(t, func(op *hubupgrade.Op) { op.State = state })
			f.writeRequest(t, f.updateRequest())
			executed := false
			err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error {
				executed = true
				return nil
			}), node.ExecRunner{})
			if err == nil || executed || errorCode(err) != codeStateInvalid {
				t.Fatalf("non-queued journal %s: err=%v executed=%v", state, err, executed)
			}
		})
	}
}

func TestDispatchAcceptsDropInDataDir(t *testing.T) {
	f := newDispatchFixture(t)
	// The base unit still names the pre-restore data directory; the root-written
	// drop-in resets and names the current one, exactly as Task 7 will.
	f.writeWebUnit(t, `[Service]
ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:9080 --data-dir `+filepath.Join(f.root, "old")+`
`)
	dropDir := f.webUnit + ".d"
	if err := os.MkdirAll(dropDir, 0755); err != nil {
		t.Fatal(err)
	}
	dropIn := `[Service]
ExecStart=
ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:9080 --data-dir ` + f.dataDir + `
`
	if err := os.WriteFile(filepath.Join(dropDir, "10-data-dir.conf"), []byte(dropIn), 0644); err != nil {
		t.Fatal(err)
	}
	f.writeRequest(t, f.updateRequest())
	if err := RunDispatch(context.Background(), f.config(func(string, []string, []string) error { return nil }), node.ExecRunner{}); err != nil {
		t.Fatal(err)
	}
}
