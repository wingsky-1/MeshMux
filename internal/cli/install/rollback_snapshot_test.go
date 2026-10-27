package install

// Self-describing rollback payloads (#11c-3 Task 4, spec §4.1/§4.7/§4.18).
//
// The installer keeps a durable snapshot of the release it just verified so the
// NEXT upgrade can promote it as its rollback source. The snapshot carries a
// manifest of target path, existence, mode, owner and digest, so the revert
// executor can rebuild the exact file set `rollbackNodeFiles` restores instead
// of guessing paths from a flat copy. These tests pin the manifest, the graded
// restore selection (binary-only vs full set), and the review-focus property:
// the payload restores a runnable host.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

type snapshotFileFixture struct {
	target string
	body   string
	mode   os.FileMode
}

// writeSnapshotTree builds one manifest-backed snapshot directory. Payload
// names are root-relative, exactly as the installer's durable snapshot writes
// them.
func writeSnapshotTree(t *testing.T, dir string, files []snapshotFileFixture) SnapshotManifest {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(dir, "payload")
	if err := os.MkdirAll(payload, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := SnapshotManifest{Schema: SnapshotSchema}
	for _, file := range files {
		relative := strings.TrimPrefix(file.target, "/")
		target := filepath.Join(payload, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(file.body), 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(file.body))
		manifest.Files = append(manifest.Files, SnapshotEntry{
			Target: file.target, Payload: filepath.ToSlash(filepath.Join("payload", relative)),
			Exists: true, Mode: uint32(file.mode.Perm()), UID: os.Geteuid(), GID: os.Getegid(),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	if err := WriteSnapshotManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func seedScratchTargets(t *testing.T, root string, files []snapshotFileFixture) {
	t.Helper()
	for _, file := range files {
		path := rooted(root, file.target)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.body), file.mode.Perm()); err != nil {
			t.Fatal(err)
		}
	}
}

func readScratch(t *testing.T, root, target string) string {
	t.Helper()
	data, err := os.ReadFile(rooted(root, target))
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	return string(data)
}

// TestBackupRestoresRunnableHost is the review-focus property: a successful
// install leaves a durable, manifest-backed snapshot, and restoring that
// snapshot into a scratch directory reproduces the installed file set byte for
// byte, with its executable mode, and the restored Agent still runs.
func TestBackupRestoresRunnableHost(t *testing.T) {
	script := "#!/bin/sh\nexit 0\n"
	executable := filepath.Join(t.TempDir(), "meshmux")
	if err := os.WriteFile(executable, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	f := makeNodeFixture(t, node.RoleEdge)
	f.opts.Executable = executable
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("install: %v", err)
	}

	source := rooted(f.root, UpgradeSourceDir)
	manifest, err := ReadSnapshotManifest(source)
	if err != nil {
		t.Fatalf("snapshot manifest: %v", err)
	}
	if len(manifest.Files) == 0 {
		t.Fatal("the install left an empty rollback source")
	}
	requireInstallMode(t, source, 0700)
	requireInstallMode(t, filepath.Join(source, SnapshotManifestName), 0600)

	var binary *SnapshotEntry
	for i := range manifest.Files {
		entry := &manifest.Files[i]
		if entry.Target == node.AgentBinaryPath {
			binary = entry
		}
		if !validDigest.MatchString(entry.SHA256) || !entry.Exists || entry.Mode == 0 {
			t.Fatalf("entry is not self-describing: %+v", entry)
		}
	}
	if binary == nil || binary.Mode != 0755 {
		t.Fatalf("the snapshot does not describe the Agent binary: %+v", manifest.Files)
	}

	scratch := t.TempDir()
	opts := NodeApplyOptions{Root: scratch, Runner: &fakeNodeRunner{users: map[string]bool{}}}
	report, err := RestoreNodeSnapshot(context.Background(), opts, source, RestoreAnchors{
		FromAgentSHA256: binary.SHA256, FromPackageSHA256: binary.SHA256,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if report.Mode != RestoreModeFull {
		t.Fatalf("restore mode = %q, want the full change set", report.Mode)
	}
	for _, entry := range manifest.Files {
		restored := rooted(scratch, entry.Target)
		info, statErr := os.Lstat(restored)
		if statErr != nil {
			t.Fatalf("restored %s: %v", entry.Target, statErr)
		}
		if info.Mode().Perm() != os.FileMode(entry.Mode) {
			t.Fatalf("%s mode = %04o, want %04o", entry.Target, info.Mode().Perm(), entry.Mode)
		}
		if digest := fileSHA256ForTest(t, restored); digest != entry.SHA256 {
			t.Fatalf("%s digest = %s, want %s", entry.Target, digest, entry.SHA256)
		}
	}
	// File-set equality: the scratch tree holds exactly the manifest's files,
	// with no extra or missing managed path.
	want := map[string]bool{}
	for _, entry := range manifest.Files {
		want[filepath.Clean(entry.Target)] = true
	}
	var extra []string
	if walkErr := filepath.WalkDir(scratch, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(scratch, path)
		if relErr != nil {
			return relErr
		}
		logical := filepath.Clean("/" + filepath.ToSlash(relative))
		if !want[logical] {
			extra = append(extra, logical)
		}
		return nil
	}); walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(extra) != 0 {
		t.Fatalf("restore produced files outside the recorded set: %v", extra)
	}

	// The restored Agent binary is executable and still answers.
	restoredAgent := rooted(scratch, node.AgentBinaryPath)
	if err := os.Chmod(restoredAgent, 0755); err != nil {
		t.Fatal(err)
	}
	if out, runErr := exec.Command(restoredAgent).CombinedOutput(); runErr != nil {
		t.Fatalf("restored Agent is not runnable: %v (%s)", runErr, out)
	}
}

// TestSnapshotRestoreSelection pins the graded revert: restore only what the
// upgrade actually changed. The binary-only fast path is allowed only when the
// Agent binary is the whole observed change set AND the kernel still matches
// its recorded snapshot digest.
func TestSnapshotRestoreSelection(t *testing.T) {
	files := []snapshotFileFixture{
		{target: node.AgentBinaryPath, body: "old agent\n", mode: 0755},
		{target: node.SingBoxBinaryPath, body: "old kernel\n", mode: 0755},
		{target: node.AgentConfigPath, body: "old config\n", mode: 0600},
	}
	agentSHA := shaOfString("old agent\n")

	cases := []struct {
		name    string
		seed    []snapshotFileFixture
		mode    RestoreMode
		wantRun bool
	}{
		{
			name:    "binary only",
			seed:    []snapshotFileFixture{{target: node.AgentBinaryPath, body: "new agent\n", mode: 0755}},
			mode:    RestoreModeBinaryOnly,
			wantRun: true,
		},
		{
			name: "config changed forces full set",
			seed: []snapshotFileFixture{
				{target: node.AgentBinaryPath, body: "new agent\n", mode: 0755},
				{target: node.AgentConfigPath, body: "new config\n", mode: 0600},
			},
			mode:    RestoreModeFull,
			wantRun: true,
		},
		{
			name: "kernel mismatch forces full set",
			seed: []snapshotFileFixture{
				{target: node.AgentBinaryPath, body: "new agent\n", mode: 0755},
				{target: node.SingBoxBinaryPath, body: "new kernel\n", mode: 0755},
			},
			mode:    RestoreModeFull,
			wantRun: true,
		},
		{
			name:    "everything unchanged is a no-op",
			seed:    nil,
			mode:    RestoreModeNone,
			wantRun: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := t.TempDir()
			writeSnapshotTree(t, source, files)
			scratch := t.TempDir()
			runner := &fakeNodeRunner{users: map[string]bool{}}
			opts := NodeApplyOptions{Root: scratch, Runner: runner}
			// The live host starts exactly at the snapshot baseline; the case
			// then overwrites the files the failed upgrade touched.
			seedScratchTargets(t, scratch, files)
			for _, file := range tc.seed {
				path := rooted(scratch, file.target)
				if err := os.WriteFile(path, []byte(file.body), file.mode.Perm()); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, file.mode.Perm()); err != nil {
					t.Fatal(err)
				}
			}
			report, err := RestoreNodeSnapshot(context.Background(), opts, source, RestoreAnchors{
				FromAgentSHA256: agentSHA, FromPackageSHA256: agentSHA,
			})
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if report.Mode != tc.mode {
				t.Fatalf("mode = %q, want %q", report.Mode, tc.mode)
			}
			if got := len(runner.calls) != 0; got != tc.wantRun {
				t.Fatalf("restore touched services = %v (calls %v), want run=%v", got, runner.calls, tc.wantRun)
			}
			if !tc.wantRun {
				if got := readScratch(t, scratch, node.AgentBinaryPath); got != "old agent\n" {
					t.Fatalf("no-op restore rewrote the Agent: %q", got)
				}
				return
			}
			if got := readScratch(t, scratch, node.AgentBinaryPath); got != "old agent\n" {
				t.Fatalf("Agent = %q, want the restored bytes", got)
			}
			// The unchanged config must survive the binary-only fast path; a
			// full restore rewrites it to the snapshot bytes.
			if tc.mode == RestoreModeBinaryOnly {
				if got := readScratch(t, scratch, node.AgentConfigPath); got != "old config\n" {
					t.Fatalf("binary-only restore rewrote the config: %q", got)
				}
			} else {
				if got := readScratch(t, scratch, node.AgentConfigPath); got != "old config\n" {
					t.Fatalf("full restore config = %q", got)
				}
				if got := readScratch(t, scratch, node.SingBoxBinaryPath); got != "old kernel\n" {
					t.Fatalf("full restore kernel = %q", got)
				}
			}
		})
	}
}

// TestSnapshotRestoreRemovesRecordedAbsentTarget proves the manifest's
// existence half: a target recorded as absent is removed by a full restore.
func TestSnapshotRestoreRemovesRecordedAbsentTarget(t *testing.T) {
	dir := t.TempDir()
	writeSnapshotTree(t, dir, []snapshotFileFixture{{target: node.AgentBinaryPath, body: "agent\n", mode: 0755}})
	manifest, err := ReadSnapshotManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	retired := "/etc/meshmux/retired.conf"
	manifest.Files = append(manifest.Files, SnapshotEntry{Target: retired, Payload: "payload/absent", Exists: false})
	if err := WriteSnapshotManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	seedScratchTargets(t, scratch, []snapshotFileFixture{
		{target: node.AgentBinaryPath, body: "agent\n", mode: 0755},
		{target: retired, body: "created by the failed upgrade\n", mode: 0644},
	})
	opts := NodeApplyOptions{Root: scratch, Runner: &fakeNodeRunner{users: map[string]bool{}}}
	report, err := RestoreNodeSnapshot(context.Background(), opts, dir, RestoreAnchors{FromAgentSHA256: shaOfString("agent\n")})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if report.Mode != RestoreModeFull {
		t.Fatalf("mode = %q, want the full set for an absent recorded target", report.Mode)
	}
	if _, err := os.Lstat(rooted(scratch, retired)); !os.IsNotExist(err) {
		t.Fatalf("recorded-absent target survived: %v", err)
	}
}

// TestSnapshotRestoreRefusesUnsafePayload pins the manifest as foreign input:
// a revert never follows a payload path outside its own snapshot, never adopts
// a symlink and never accepts a manifest/bytes disagreement.
func TestSnapshotRestoreRefusesUnsafePayload(t *testing.T) {
	valid := []snapshotFileFixture{{target: node.AgentBinaryPath, body: "agent\n", mode: 0755}}
	agentSHA := shaOfString("agent\n")

	cases := []struct {
		name   string
		code   string
		mutate func(*testing.T, string, *SnapshotManifest)
	}{
		{"absolute payload", "ROLLBACK_SNAPSHOT_INVALID", func(_ *testing.T, _ string, m *SnapshotManifest) {
			m.Files[0].Payload = "/etc/passwd"
		}},
		{"parent payload", "ROLLBACK_SNAPSHOT_INVALID", func(_ *testing.T, _ string, m *SnapshotManifest) {
			m.Files[0].Payload = "payload/../../etc/passwd"
		}},
		{"relative target", "ROLLBACK_SNAPSHOT_INVALID", func(_ *testing.T, _ string, m *SnapshotManifest) {
			m.Files[0].Target = "usr/local/libexec/meshmuxd"
		}},
		{"digest disagreement", "ROLLBACK_SNAPSHOT_INVALID", func(_ *testing.T, _ string, m *SnapshotManifest) {
			m.Files[0].SHA256 = strings.Repeat("0", 64)
		}},
		{"foreign schema", "ROLLBACK_SNAPSHOT_INVALID", func(_ *testing.T, _ string, m *SnapshotManifest) {
			m.Schema = SnapshotSchema + 1
		}},
		{"symlinked payload", "ROLLBACK_SNAPSHOT_INVALID", func(t *testing.T, dir string, m *SnapshotManifest) {
			payload := filepath.Join(dir, "payload", "link")
			if err := os.Symlink(filepath.Join(dir, "payload", "usr/local/libexec/meshmuxd"), payload); err != nil {
				t.Fatal(err)
			}
			m.Files[0].Payload = "payload/link"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeSnapshotTree(t, dir, valid)
			manifest, err := ReadSnapshotManifest(dir)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, dir, &manifest)
			forceSnapshotManifest(t, dir, manifest)
			scratch := t.TempDir()
			opts := NodeApplyOptions{Root: scratch, Runner: &fakeNodeRunner{users: map[string]bool{}}}
			_, err = RestoreNodeSnapshot(context.Background(), opts, dir, RestoreAnchors{
				FromAgentSHA256: agentSHA, FromPackageSHA256: agentSHA,
			})
			if code := installCode(err); code != tc.code {
				t.Fatalf("code = %q, want %q (err %v)", code, tc.code, err)
			}
		})
	}
}

// TestSnapshotRestoreAnchors is the old-package trust anchor: the payload may
// only be restored when its Agent bytes are the recorded from_agent digest.
func TestSnapshotRestoreAnchors(t *testing.T) {
	dir := t.TempDir()
	writeSnapshotTree(t, dir, []snapshotFileFixture{{target: node.AgentBinaryPath, body: "agent\n", mode: 0755}})
	opts := NodeApplyOptions{Root: t.TempDir(), Runner: &fakeNodeRunner{users: map[string]bool{}}}
	_, err := RestoreNodeSnapshot(context.Background(), opts, dir, RestoreAnchors{
		FromAgentSHA256: strings.Repeat("a", 64), FromPackageSHA256: strings.Repeat("a", 64),
	})
	if code := installCode(err); code != "ROLLBACK_ANCHOR_MISMATCH" {
		t.Fatalf("code = %q, want ROLLBACK_ANCHOR_MISMATCH (err %v)", code, err)
	}
	_, err = RestoreNodeSnapshot(context.Background(), opts, dir, RestoreAnchors{
		FromAgentSHA256: shaOfString("agent\n"), FromPackageSHA256: strings.Repeat("b", 64),
	})
	if code := installCode(err); code != "ROLLBACK_ANCHOR_MISMATCH" {
		t.Fatalf("split anchor code = %q, want ROLLBACK_ANCHOR_MISMATCH", code)
	}
}

// TestAdoptRestoredReleaseReconcilesConfigConflict is the §4.17 deliberate
// path: after a failed upgrade the ledger and agent.json may legitimately
// disagree. The revert restores both and reconciles the ledger identity instead
// of refusing the host with CONFIG_CONFLICT.
func TestAdoptRestoredReleaseReconcilesConfigConflict(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	state, _, err := ReadNodeState(f.root)
	if err != nil || state.Node == nil {
		t.Fatalf("ledger: %+v, %v", state, err)
	}
	original := *state.Node
	// The failed upgrade advanced the ledger to another release.
	advanced := *state.Node
	advanced.AgentVersion = "9.9.9"
	advanced.AgentSHA256 = strings.Repeat("9", 64)
	advanced.KernelSHA256 = strings.Repeat("8", 64)
	state.Node = &advanced
	state.Status = "installing"
	state.Stage = "apply"
	state.ErrorCode = "NODE_APPLY_FAILED"
	layout, err := resolveNodeLayout(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNodeState(f.root, layout, state); err != nil {
		t.Fatal(err)
	}
	// The revert already restored agent.json to the old release while the
	// ledger still names the failed target: the generic recorded-state path
	// would refuse CONFIG_CONFLICT between the two.
	if err := writeBytesAtomic(rooted(f.root, node.AgentConfigPath), mustJSON(t, original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AdoptRestoredRelease(f.root, strings.Repeat("e", 32)); err != nil {
		t.Fatalf("adopt restored release: %v", err)
	}
	restored, _, err := ReadNodeState(f.root)
	if err != nil || restored.Node == nil {
		t.Fatalf("ledger after adopt: %+v, %v", restored, err)
	}
	if restored.Status != "installed" || restored.Stage != "verify" ||
		restored.ErrorCode != "" || restored.Recovery != "" {
		t.Fatalf("adopted ledger is not installed: %+v", restored)
	}
	if restored.Node.AgentVersion != original.AgentVersion ||
		restored.Node.AgentSHA256 != original.AgentSHA256 ||
		restored.Node.KernelSHA256 != original.KernelSHA256 {
		t.Fatalf("adopted release = %+v, want %+v", restored.Node, original)
	}
}

// TestReadUpgradeSourceRequiresVerifiedSnapshot pins the update seam: the
// source is a 0700 private snapshot with a manifest naming the Agent binary; a
// missing or incomplete one is a refusal, never an empty rollback source.
// TestRefreshUpgradeSourceCapturesLiveState pins the post-confirm refresh: the
// Agent's runtime state (the LKG pair) is captured only after the new release
// booted, so the next upgrade's rollback source names what the host really
// runs.
func TestRefreshUpgradeSourceCapturesLiveState(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(f.root, node.RuntimeStatePath), []byte(`{"lkg":"bGl2ZQ=="}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RefreshUpgradeSource(f.root); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadSnapshotManifest(rooted(f.root, UpgradeSourceDir))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range manifest.Files {
		if entry.Target != node.RuntimeStatePath {
			continue
		}
		found = true
		if entry.SHA256 != shaOfString(`{"lkg":"bGl2ZQ=="}`+"\n") {
			t.Fatalf("runtime state digest = %s, want the live bytes", entry.SHA256)
		}
	}
	if !found {
		t.Fatalf("refreshed snapshot does not capture the LKG runtime state: %+v", manifest.Files)
	}
}

func TestReadUpgradeSourceRequiresVerifiedSnapshot(t *testing.T) {
	root := t.TempDir()
	if _, err := ReadUpgradeSource(root); codeOfInstall(err) != "ROLLBACK_SOURCE_MISSING" {
		t.Fatalf("missing source code = %q", codeOfInstall(err))
	}
	dir := rooted(root, UpgradeSourceDir)
	writeSnapshotTree(t, dir, []snapshotFileFixture{{target: node.AgentConfigPath, body: "config\n", mode: 0600}})
	if _, err := ReadUpgradeSource(root); codeOfInstall(err) != "ROLLBACK_SOURCE_INVALID" {
		t.Fatalf("source without an Agent binary code = %q", codeOfInstall(err))
	}
	writeSnapshotTree(t, dir, []snapshotFileFixture{{target: node.AgentBinaryPath, body: "agent\n", mode: 0755}})
	if got, err := ReadUpgradeSource(root); err != nil || got != dir {
		t.Fatalf("source = %q, %v; want %q", got, err, dir)
	}
}

// forceSnapshotManifest writes a deliberately invalid manifest so the reader,
// not the writer, is the thing under test.
func forceSnapshotManifest(t *testing.T, dir string, manifest SnapshotManifest) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SnapshotManifestName), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func requireInstallMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func shaOfString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func installCode(err error) string {
	var ie *InstallError
	if errors.As(err, &ie) {
		return ie.Code
	}
	return ""
}

func codeOfInstall(err error) string { return installCode(err) }

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
