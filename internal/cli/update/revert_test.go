package update

// Graded revert and the LKG republish chain (#11c-3 Task 4, spec §4.7/§4.11/
// §4.12/§4.17).
//
// The revert executor is a NEW transient argv family: the Agent stages the
// verified old package out of the rollback payload and starts it as one
// transient unit with a fixed argv (systemd-run --wait is only a convenience;
// the verdict file plus done=false is the guarantee). The unit
// restores the recorded change set through the installer's rollbackNodeFiles
// path (binary-only only when the Agent binary is the whole observed change and
// the kernel still matches), reconciles the ledger/agent.json disagreement that
// a failed upgrade may leave behind, restarts the restored services and writes
// <op>.revert.json. The Agent only reports after that file exists.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type revertFile struct {
	target string
	body   string
	mode   os.FileMode
}

// writeRevertSnapshot writes a manifest-backed payload tree the way the
// installer's durable snapshot does.
func writeRevertSnapshot(t *testing.T, dir string, files []revertFile) {
	t.Helper()
	payload := filepath.Join(dir, "payload")
	if err := os.MkdirAll(payload, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := struct {
		Schema int `json:"schema"`
		Files  []struct {
			Target  string `json:"target"`
			Payload string `json:"payload"`
			Exists  bool   `json:"exists"`
			Mode    uint32 `json:"mode"`
			UID     int    `json:"uid"`
			GID     int    `json:"gid"`
			SHA256  string `json:"sha256"`
		} `json:"files"`
	}{Schema: 1}
	for _, file := range files {
		relative := strings.TrimPrefix(file.target, "/")
		path := filepath.Join(payload, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.body), 0600); err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, struct {
			Target  string `json:"target"`
			Payload string `json:"payload"`
			Exists  bool   `json:"exists"`
			Mode    uint32 `json:"mode"`
			UID     int    `json:"uid"`
			GID     int    `json:"gid"`
			SHA256  string `json:"sha256"`
		}{Target: file.target, Payload: filepath.ToSlash(filepath.Join("payload", relative)),
			Exists: true, Mode: uint32(file.mode.Perm()), UID: os.Geteuid(), GID: os.Getegid(),
			SHA256: digestOf(file.body)})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, install.SnapshotManifestName), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

type revertFixture struct {
	root     string // backup store
	work     string
	host     string // scratch installed-system root
	op       string
	oldVer   string
	newVer   string
	oldCfg   node.Config
	files    []revertFile
	agentSH  string
	selfBody string
	pkgSH    string
	runner   *revertRunner
}

func newRevertFixture(t *testing.T) *revertFixture {
	t.Helper()
	op := strings.Repeat("c", 32)
	oldCfg := node.Config{HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: node.CurrentAgentVersion(), AgentSHA256: digestOf("old agent\n"),
		KernelSHA256: digestOf("old kernel\n")}
	oldConfigJSON, err := json.Marshal(oldCfg)
	if err != nil {
		t.Fatal(err)
	}
	files := []revertFile{
		{target: node.AgentBinaryPath, body: "old agent\n", mode: 0755},
		{target: node.SingBoxBinaryPath, body: "old kernel\n", mode: 0755},
		{target: node.AgentConfigPath, body: string(oldConfigJSON) + "\n", mode: 0600},
		{target: "/etc/systemd/system/" + node.AgentUnit, body: "[Unit]\nDescription=old\n", mode: 0644},
		{target: node.ActiveCandidatePath, body: `{"schema":"meshmux-node/v1","old":true}` + "\n", mode: 0600},
		{target: node.ActiveConfigPath, body: `{"old":true}` + "\n", mode: 0640},
		{target: node.RuntimeStatePath, body: `{"lkg":"b2xk"}` + "\n", mode: 0600},
	}
	return &revertFixture{
		root: t.TempDir(), work: t.TempDir(), host: t.TempDir(), op: op,
		oldVer: "1.0.0", newVer: "1.0.1", oldCfg: oldCfg, files: files,
		agentSH: digestOf("old agent\n"), selfBody: "old agent\n", pkgSH: digestOf("new package\n"),
		runner: &revertRunner{},
	}
}

// seedUpgradeFailure leaves the host in the shape a failed upgrade produces:
// the new files on disk and a ledger/agent.json pair that no longer agree with
// each other or with the restored release.
func (f *revertFixture) seedUpgradeFailure(t *testing.T) {
	t.Helper()
	seed := []revertFile{
		{target: node.AgentBinaryPath, body: "new agent\n", mode: 0755},
		{target: node.SingBoxBinaryPath, body: "new kernel\n", mode: 0755},
		{target: node.AgentConfigPath, body: `{"node_id":"new"}` + "\n", mode: 0600},
		{target: "/etc/systemd/system/" + node.AgentUnit, body: "[Unit]\nDescription=new\n", mode: 0644},
	}
	for _, file := range seed {
		path := rootedHost(f.host, file.target)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.body), file.mode.Perm()); err != nil {
			t.Fatal(err)
		}
	}
	ledger := map[string]any{
		"schema": 1, "operation_id": f.op, "status": "installing", "stage": "apply",
		"created_at": time.Now().Add(-time.Hour).UTC(), "updated_at": time.Now().UTC(),
		"managed_files": map[string]string{}, "artifacts": map[string]string{},
		"config": map[string]any{}, "architecture": "amd64",
		"node": map[string]any{
			"hub_url": f.oldCfg.HubURL, "node_id": f.oldCfg.NodeID, "role": string(f.oldCfg.Role),
			"vless_port": f.oldCfg.VLESSPort, "ssh_port": f.oldCfg.SSHPort,
			"agent_version": "1.0.1", "agent_sha256": digestOf("new agent\n"),
			"kernel_sha256": digestOf("new kernel\n"),
		},
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := rootedHost(f.host, "/var/lib/meshmux-installer/state.json")
	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func rootedHost(root, target string) string {
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(target), "/"))
}

// writeRecord promotes the old snapshot into the store and returns the record.
func (f *revertFixture) writeRecord(t *testing.T, state string) BackupRecord {
	t.Helper()
	source := filepath.Join(t.TempDir(), "snapshot")
	writeRevertSnapshot(t, source, f.files)
	spec := BackupSpec{
		OperationID: f.op, FromVersion: f.oldVer, TargetVersion: f.newVer,
		DBSchema: 0, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: digestOf("manifest"), PackageSHA256: f.pkgSH,
		FromPackageSHA256: f.agentSH, FromAgentSHA256: f.agentSH, SnapshotDir: source,
	}
	if _, err := WriteBackupRecord(f.root, spec); err != nil {
		t.Fatalf("write record: %v", err)
	}
	record, err := readBackupRecord(filepath.Join(f.root, f.op), f.op)
	if err != nil {
		t.Fatal(err)
	}
	if state != "" {
		record.State = state
		if state == BackupStateConfirmed {
			now := time.Now().UTC()
			record.ConfirmedAt = &now
		}
		if err := writeRecordFile(filepath.Join(f.root, f.op), record); err != nil {
			t.Fatal(err)
		}
	}
	return record
}

func (f *revertFixture) run(t *testing.T, cfg Config, self string) (RevertResult, error) {
	t.Helper()
	if cfg.WorkDir == "" {
		cfg.WorkDir = f.work
	}
	cfg.OperationID = f.op
	cfg.FromAgentSHA256 = f.agentSH
	cfg.BackupRoot = f.root
	cfg.Root = f.host
	cfg.SelfExecutable = self
	return RunRevert(context.Background(), cfg, f.runner)
}

// revertRunner is the fixed-argv boundary of the revert command. It answers the
// systemctl calls the restore/start sequence makes.
type revertRunner struct {
	calls    [][]string
	failCall string
}

func (r *revertRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if r.failCall != "" && strings.Contains(name+" "+strings.Join(args, " "), r.failCall) {
		return nil, errors.New("fixture fault")
	}
	return nil, nil
}

func (r *revertRunner) restarted() []string {
	var units []string
	for _, call := range r.calls {
		if len(call) == 3 && call[0] == "systemctl" && call[1] == "restart" {
			units = append(units, call[2])
		}
	}
	return units
}

// TestRevertArgvFixedShape pins the new fixed argv family: one systemd-run
// unit, the staged old package, one hidden subcommand, two fixed values. The
// --wait is a best-effort convenience; the ordering guarantee is the verdict
// file plus done=false (the unit restarts the Agent and may kill this client).
func TestRevertArgvFixedShape(t *testing.T) {
	cfg := Config{OperationID: strings.Repeat("a", 32), WorkDir: "/var/lib/meshmux-agent/update",
		FromAgentSHA256: strings.Repeat("b", 64)}
	argv, err := BuildRevertArgv(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/usr/bin/systemd-run",
		"--unit=meshmux-revert-" + cfg.OperationID,
		"--collect",
		"--wait",
		"--property=Type=oneshot",
		"--property=Restart=no",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=" + revertRWPaths,
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=RestrictAddressFamilies=" + revertAddressFamilies,
		"--property=CapabilityBoundingSet=" + revertCaps,
		filepath.Join(cfg.WorkDir, cfg.OperationID+revertExecSuffix),
		"__internal-update-revert",
		"--operation-id", cfg.OperationID,
		"--expected-sha256", cfg.FromAgentSHA256,
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv = %q\nwant     %q", argv, want)
	}
	for _, bad := range []Config{
		{OperationID: "", WorkDir: cfg.WorkDir, FromAgentSHA256: cfg.FromAgentSHA256},
		{OperationID: cfg.OperationID, WorkDir: "relative", FromAgentSHA256: cfg.FromAgentSHA256},
		{OperationID: cfg.OperationID, WorkDir: cfg.WorkDir, FromAgentSHA256: "not-a-digest"},
	} {
		if _, err := BuildRevertArgv(bad); err == nil {
			t.Fatalf("invalid revert config accepted: %+v", bad)
		}
	}
}

// TestRevertSelectsFullSetOrBinaryOnly is the graded restore through the real
// executor: a binary-only change restores just the Agent; a kernel or config
// change restores the whole recorded file set.
func TestRevertSelectsFullSetOrBinaryOnly(t *testing.T) {
	t.Run("binary only", func(t *testing.T) {
		f := newRevertFixture(t)
		f.writeRecord(t, "")
		f.seedUpgradeFailure(t)
		// Only the Agent binary differs from the recorded release.
		for _, file := range f.files {
			if file.target == node.AgentBinaryPath {
				continue
			}
			path := rootedHost(f.host, file.target)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(file.body), file.mode.Perm()); err != nil {
				t.Fatal(err)
			}
		}
		// The live config is byte-identical to the snapshot (so it is not part
		// of the change set); its distinctive mtime proves the fast path did
		// not rewrite it.
		configPath := rootedHost(f.host, node.AgentConfigPath)
		stamp := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(configPath, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		result, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody))
		if err != nil {
			t.Fatalf("revert: %v", err)
		}
		if result.Outcome != RevertOutcomeRolledBack || result.FromVersion != f.oldVer ||
			result.TargetVersion != f.newVer || result.ExitCode != 0 {
			t.Fatalf("result = %+v", result)
		}
		if got, _ := os.ReadFile(rootedHost(f.host, node.AgentBinaryPath)); string(got) != "old agent\n" {
			t.Fatalf("agent = %q, want the old package", got)
		}
		if info, statErr := os.Lstat(configPath); statErr != nil || !info.ModTime().Equal(stamp) {
			t.Fatalf("binary-only revert rewrote the config: %v", statErr)
		}
	})
	t.Run("kernel mismatch restores the whole change set", func(t *testing.T) {
		f := newRevertFixture(t)
		f.writeRecord(t, "")
		f.seedUpgradeFailure(t)
		// Every recorded file is the new release: a kernel change must not be
		// hidden by a binary-only fast path.
		for _, file := range f.files {
			path := rootedHost(f.host, file.target)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(file.body), file.mode.Perm()); err != nil {
				t.Fatal(err)
			}
		}
		rand := []byte("live kernel must be replaced\n")
		if err := os.WriteFile(rootedHost(f.host, node.SingBoxBinaryPath), rand, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody)); err != nil {
			t.Fatalf("revert: %v", err)
		}
		if got, _ := os.ReadFile(rootedHost(f.host, node.SingBoxBinaryPath)); string(got) != "old kernel\n" {
			t.Fatalf("kernel = %q, want the recorded kernel", got)
		}
		if got, _ := os.ReadFile(rootedHost(f.host, node.AgentConfigPath)); !strings.Contains(string(got), `"node_id":"`+f.oldCfg.NodeID+`"`) {
			t.Fatalf("config = %q, want the recorded agent.json", got)
		}
	})
}

// TestRevertRestoresFullChangeSet is the review-focus regression: a kernel SHA
// mismatch must restore the whole change set, never a binary-only fast path.
func TestRevertRestoresFullChangeSet(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	f.seedUpgradeFailure(t)
	for _, file := range f.files {
		path := rootedHost(f.host, file.target)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.body), file.mode.Perm()); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(rootedHost(f.host, node.SingBoxBinaryPath), []byte("mismatched kernel\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody)); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if got, _ := os.ReadFile(rootedHost(f.host, node.SingBoxBinaryPath)); string(got) != "old kernel\n" {
		t.Fatalf("kernel = %q, want the recorded kernel", got)
	}
	if got, _ := os.ReadFile(rootedHost(f.host, node.AgentConfigPath)); !strings.Contains(string(got), f.oldCfg.NodeID) {
		t.Fatalf("config = %q, want the full recorded set", got)
	}
}

// TestRevertConfigConflictDeliberate is the §4.17 deliberate path: the ledger
// and agent.json disagree after a failed upgrade, and the revert reconciles them
// instead of failing the host with CONFIG_CONFLICT.
func TestRevertConfigConflictDeliberate(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	f.seedUpgradeFailure(t)
	result, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody))
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if result.Outcome != RevertOutcomeRolledBack {
		t.Fatalf("result = %+v", result)
	}
	ledgerBytes, err := os.ReadFile(rootedHost(f.host, "/var/lib/meshmux-installer/state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ledger struct {
		Status string `json:"status"`
		Stage  string `json:"stage"`
		Node   *struct {
			AgentVersion string `json:"agent_version"`
			AgentSHA256  string `json:"agent_sha256"`
			KernelSHA256 string `json:"kernel_sha256"`
		} `json:"node"`
	}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil {
		t.Fatal(err)
	}
	if ledger.Status != "installed" || ledger.Node == nil ||
		ledger.Node.AgentVersion != f.oldCfg.AgentVersion ||
		ledger.Node.AgentSHA256 != f.oldCfg.AgentSHA256 ||
		ledger.Node.KernelSHA256 != f.oldCfg.KernelSHA256 {
		t.Fatalf("ledger after revert = %+v", ledger)
	}
	if got, _ := os.ReadFile(rootedHost(f.host, node.AgentConfigPath)); !strings.Contains(string(got), f.oldCfg.NodeID) {
		t.Fatalf("agent.json = %q, want the restored config", got)
	}
	// The restored services are restarted, never merely "started": the failed
	// new release may still be running. Kernel first, Agent last.
	want := []string{node.SingBoxUnit, node.AgentUnit}
	if got := f.runner.restarted(); !slices.Equal(got, want) {
		t.Fatalf("restarted units = %v, want %v", got, want)
	}
}

// TestRevertReadsConfirmedRecord is the binding carry: the revert reads the
// record through the state-agnostic reader, while the handoff gate keeps
// refusing a confirmed record as a *new* handoff source.
func TestRevertReadsConfirmedRecord(t *testing.T) {
	f := newRevertFixture(t)
	record := f.writeRecord(t, BackupStateConfirmed)
	if err := requireVerifiedBackup(f.root, f.op, f.oldVer, 0, upgrade.PolicySchema); codeOf(err) != "UPDATE_BACKUP_CORRUPT" {
		t.Fatalf("handoff gate accepted a confirmed record: %v", err)
	}
	f.seedUpgradeFailure(t)
	result, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody))
	if err != nil {
		t.Fatalf("revert of a confirmed record: %v", err)
	}
	if result.Outcome != RevertOutcomeRolledBack || result.FromVersion != record.FromVersion {
		t.Fatalf("result = %+v", result)
	}
}

// TestConfirmVersionRefreshesTheDurableSource pins the post-confirm refresh
// seam: the next upgrade's rollback source is re-recorded from the live host,
// and a source that already names the running Agent is not rewritten again.
func TestConfirmVersionRefreshesTheDurableSource(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	f.seedUpgradeFailure(t)
	// A live Agent has bootstrapped its runtime state (the LKG pair).
	statePath := rootedHost(f.host, node.RuntimeStatePath)
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(`{"lkg":"bGl2ZQ=="}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := &RollbackStore{BackupRoot: f.root, WorkDir: f.work, Root: f.host}
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	digest, ok := install.UpgradeSourceAgentSHA(f.host)
	if !ok || digest != digestOf("new agent\n") {
		t.Fatalf("durable source agent = %s (ok %v), want the live confirmed release", digest, ok)
	}
	// A source already naming the running release is left alone: only a stale
	// snapshot is rewritten (the confirmer runs on every accepted readback).
	before, err := os.Lstat(filepath.Join(f.host, install.UpgradeSourceDir))
	if err != nil {
		t.Fatal(err)
	}
	store.refreshSource(digest)
	after, err := os.Lstat(filepath.Join(f.host, install.UpgradeSourceDir))
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("a current durable source was rewritten")
	}
}

// TestRevertAnchorMismatchWritesFailedResult pins the old-package anchor: the
// payload's Agent bytes must be exactly from_agent_sha256. A mismatch is a
// terminal failed revert with that stable code, never a guessed restore.
func TestRevertAnchorMismatchWritesFailedResult(t *testing.T) {
	f := newRevertFixture(t)
	f.agentSH, f.selfBody = digestOf("another package\n"), "another package\n"
	f.writeRecord(t, "")
	f.seedUpgradeFailure(t)
	result, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody))
	if code := codeOf(err); code != "UPDATE_BACKUP_MISMATCH" {
		t.Fatalf("code = %q, want UPDATE_BACKUP_MISMATCH (err %v)", code, err)
	}
	if result.Outcome != RevertOutcomeFailed || result.ErrorCode != "UPDATE_BACKUP_MISMATCH" || result.ExitCode == 0 {
		t.Fatalf("result = %+v", result)
	}
	if got, _ := os.ReadFile(rootedHost(f.host, node.AgentBinaryPath)); string(got) != "new agent\n" {
		t.Fatalf("a refused revert changed the Agent: %q", got)
	}
	if len(f.runner.calls) != 0 {
		t.Fatalf("a refused revert touched services: %v", f.runner.calls)
	}
}

// TestRevertClearsStaleInstallResult is the confirmer-anchor carry: after a
// successful revert the failed attempt's 11c-2 <op>.result.json is gone, so a
// later readback cannot confirm the operation that was just undone.
func TestRevertClearsStaleInstallResult(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	f.seedUpgradeFailure(t)
	stale := ResultPath(f.work, f.op)
	if err := WriteResult(stale, UpdateResult{OperationID: f.op, Phase: ResultPhaseInstalledAwaitingRestart,
		ExitCode: 0, Digest: digestOf("new agent\n"), Target: f.newVer, Timestamp: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, Config{}, fixtureSelf(t, f.selfBody)); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale install result survived the revert: %v", err)
	}
	if _, err := os.Lstat(RevertResultPath(f.work, f.op)); err != nil {
		t.Fatalf("revert result missing: %v", err)
	}
}

func TestConfirmVersionMarksConfirmedAndGCs(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	store := &RollbackStore{BackupRoot: f.root, WorkDir: f.work}
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	record, err := readBackupRecord(filepath.Join(f.root, f.op), f.op)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != BackupStateConfirmed || record.ConfirmedAt == nil {
		t.Fatalf("record = %+v, want confirmed with a timestamp", record)
	}
	// Idempotent: confirming again is a no-op, not a failure.
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); err != nil {
		t.Fatalf("idempotent confirm: %v", err)
	}
}

// TestConfirmVersionChecksAnchorsBeforeConfirmedShortCircuit pins the ordering:
// once a record is confirmed, a readback that names another release or another
// package is still refused. A stale or foreign readback can therefore never
// re-confirm the record and release older generations to GC.
func TestConfirmVersionChecksAnchorsBeforeConfirmedShortCircuit(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	store := &RollbackStore{BackupRoot: f.root, WorkDir: f.work}
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	for _, tc := range []struct {
		name   string
		target string
		sha    string
	}{
		{"another target", "9.9.8", f.pkgSH},
		{"another package", f.newVer, strings.Repeat("0", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.ConfirmVersion(context.Background(), f.op, tc.target, tc.sha); codeOf(err) != "UPDATE_BACKUP_MISMATCH" {
				t.Fatalf("confirmed record with %s anchors = %v, want UPDATE_BACKUP_MISMATCH", tc.name, err)
			}
		})
	}
	// The matching anchors still take the idempotent success path.
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); err != nil {
		t.Fatalf("matching re-confirm: %v", err)
	}
}

// TestConfirmVersionGCRunsAfterConfirm is the N-1 rule after a confirmed
// generation: the oldest confirmed record is released, while staged and failed
// records are retained.
func TestConfirmVersionGCRunsAfterConfirm(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, "")
	// Two older confirmed generations plus the staged record under test.
	older := []string{strings.Repeat("d", 32), strings.Repeat("e", 32)}
	for i, op := range older {
		copyFixtureRecord(t, f, op)
		record, err := readBackupRecord(filepath.Join(f.root, op), op)
		if err != nil {
			t.Fatal(err)
		}
		record.State = BackupStateConfirmed
		stamp := time.Date(2020+i, 1, 1, 0, 0, 0, 0, time.UTC)
		record.CreatedAt, record.ConfirmedAt = stamp, &stamp
		if err := writeRecordFile(filepath.Join(f.root, op), record); err != nil {
			t.Fatal(err)
		}
	}
	store := &RollbackStore{BackupRoot: f.root, WorkDir: f.work}
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// keep N-1 = 1: only the newest confirmed record (the one just confirmed)
	// remains; both older confirmed generations are collected.
	for _, op := range older {
		if _, err := os.Lstat(filepath.Join(f.root, op)); !os.IsNotExist(err) {
			t.Fatalf("confirmed record %s was not collected", op)
		}
	}
	if _, err := readBackupRecord(filepath.Join(f.root, f.op), f.op); err != nil {
		t.Fatalf("the confirmed record was collected: %v", err)
	}
}

// copyFixtureRecord writes a second record with the same payload under another
// operation ID, for the GC ordering test.
func copyFixtureRecord(t *testing.T, f *revertFixture, operationID string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "snapshot")
	writeRevertSnapshot(t, source, f.files)
	spec := BackupSpec{
		OperationID: operationID, FromVersion: f.oldVer, TargetVersion: f.newVer,
		DBSchema: 0, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: digestOf("manifest"), PackageSHA256: f.pkgSH,
		FromPackageSHA256: f.agentSH, FromAgentSHA256: f.agentSH, SnapshotDir: source,
	}
	if _, err := WriteBackupRecord(f.root, spec); err != nil {
		t.Fatalf("write second record: %v", err)
	}
}

func TestConfirmVersionRefusesFailedRecord(t *testing.T) {
	f := newRevertFixture(t)
	f.writeRecord(t, BackupStateFailed)
	store := &RollbackStore{BackupRoot: f.root, WorkDir: f.work}
	if err := store.ConfirmVersion(context.Background(), f.op, f.newVer, f.pkgSH); codeOf(err) != "UPDATE_CONFIRM_REFUSED" {
		t.Fatalf("failed record confirm = %v, want UPDATE_CONFIRM_REFUSED", err)
	}
	record, err := readBackupRecord(filepath.Join(f.root, f.op), f.op)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != BackupStateFailed {
		t.Fatalf("a refused confirm rewrote the record: %+v", record)
	}
}

func TestConfirmVersionRefusesMismatchedAnchors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		sha    string
		code   string
	}{
		{"target", "9.9.9", "", "UPDATE_BACKUP_MISMATCH"},
		{"digest", "", strings.Repeat("0", 64), "UPDATE_BACKUP_MISMATCH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRevertFixture(t)
			f.writeRecord(t, "")
			target, sha := f.newVer, f.pkgSH
			if tc.target != "" {
				target = tc.target
			}
			if tc.sha != "" {
				sha = tc.sha
			}
			store := &RollbackStore{BackupRoot: f.root, WorkDir: f.work}
			if err := store.ConfirmVersion(context.Background(), f.op, target, sha); codeOf(err) != tc.code {
				t.Fatalf("code = %q, want %q (err %v)", codeOf(err), tc.code, err)
			}
			record, _ := readBackupRecord(filepath.Join(f.root, f.op), f.op)
			if record.State != BackupStateStaged {
				t.Fatalf("refused confirm changed the record: %+v", record)
			}
		})
	}
}

// TestReverterAwaitsTheUnit pins the spawn-and-await contract: when the client
// can observe the unit, the reverter returns only after the transient unit
// wrote its verdict; a still-active unit (or a killed helper that cannot prove
// completion) is reported as not finished and is never cached as failed.
func TestReverterAwaitsTheUnit(t *testing.T) {
	t.Run("unit finished and wrote the verdict", func(t *testing.T) {
		f := newRevertFixture(t)
		f.writeRecord(t, "")
		runner := &reverterRunner{onRun: func() {
			writeRevertResultFileForTest(t, f.work, f.op, f.newVer, f.oldVer, RevertOutcomeRolledBack, "", 0)
		}}
		reverter := &Reverter{BackupRoot: f.root, WorkDir: f.work, Runner: runner}
		done, err := reverter.RevertOperation(context.Background(), f.op)
		if err != nil || !done {
			t.Fatalf("revert operation = done %v, err %v", done, err)
		}
		if len(runner.calls) != 1 || runner.calls[0][0] != systemdRunPath ||
			!slices.Contains(runner.calls[0], "--wait") {
			t.Fatalf("calls = %q, want one awaited systemd-run", runner.calls)
		}
		if _, err := ReadRevertResult(RevertResultPath(f.work, f.op)); err != nil {
			t.Fatalf("verdict not readable after await: %v", err)
		}
	})
	t.Run("still active is not a verdict", func(t *testing.T) {
		f := newRevertFixture(t)
		f.writeRecord(t, "")
		runner := &reverterRunner{runErr: errors.New("context deadline"), active: true}
		reverter := &Reverter{BackupRoot: f.root, WorkDir: f.work, Runner: runner}
		done, err := reverter.RevertOperation(context.Background(), f.op)
		if err == nil || done {
			t.Fatalf("active unit = done %v, err %v; want not finished", done, err)
		}
		if _, statErr := os.Lstat(RevertResultPath(f.work, f.op)); !os.IsNotExist(statErr) {
			t.Fatalf("an unfinished revert wrote a verdict: %v", statErr)
		}
	})
	t.Run("finished without a verdict is terminal and honest", func(t *testing.T) {
		f := newRevertFixture(t)
		f.writeRecord(t, "")
		runner := &reverterRunner{runErr: errors.New("exit status 1")}
		reverter := &Reverter{BackupRoot: f.root, WorkDir: f.work, Runner: runner}
		done, err := reverter.RevertOperation(context.Background(), f.op)
		if !done {
			t.Fatalf("finished unit = done %v, err %v; want a terminal verdict", done, err)
		}
		result, readErr := ReadRevertResult(RevertResultPath(f.work, f.op))
		if readErr != nil || result.Outcome != RevertOutcomeFailed ||
			result.ErrorCode != "UPDATE_REVERT_UNIT_FAILED" {
			t.Fatalf("result = %+v, %v", result, readErr)
		}
	})
}

// reverterRunner is the Agent-side command boundary of the reverter. systemctl
// show answers the liveness query; all other calls are the awaited unit start.
type reverterRunner struct {
	calls  [][]string
	onRun  func()
	runErr error
	active bool
}

func (r *reverterRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if name == systemctlPath && len(args) >= 2 && args[0] == "show" {
		if r.active {
			return []byte("ActiveState=active\nExecMainStatus=0\n"), nil
		}
		return []byte("ActiveState=inactive\nExecMainStatus=1\n"), nil
	}
	if r.onRun != nil {
		r.onRun()
	}
	return nil, r.runErr
}

func writeRevertResultFileForTest(t *testing.T, dir, op, target, from, outcome, code string, exitCode int) {
	t.Helper()
	result := RevertResult{Schema: RevertSchema, OperationID: op, TargetVersion: target,
		FromVersion: from, Outcome: outcome, ExitCode: exitCode, ErrorCode: code,
		Timestamp: time.Now().Unix()}
	if err := WriteRevertResult(RevertResultPath(dir, op), result); err != nil {
		t.Fatal(err)
	}
}

// fixtureSelf returns a self executable whose bytes hash to the fixture's
// from_agent digest (the staged old package self-check).
func fixtureSelf(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "old-meshmuxd")
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}
