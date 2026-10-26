package update

// Task 3 of 11c-2: the new binary's hidden install command. It re-checks its
// own bytes against the approved package digest, runs the fixed non-interactive
// install argv, restarts the Agent from its PID-1 unit (so the restart cannot
// kill it), and records every phase in <op>.result.json for Task 4 to reclaim.

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// exitStatus is a fixture process failure carrying the same coarse exit code
// production gets from *exec.ExitError.
type exitStatus int

func (e exitStatus) Error() string { return "exit status " + strconv.Itoa(int(e)) }
func (e exitStatus) ExitCode() int { return int(e) }

// installCmdRunner records each fixed argv and snapshots the result phase at
// the moment the step runs, so the phase-before-step order is observable.
type installCmdRunner struct {
	resultPath string
	installErr error
	restartErr error
	calls      [][]string
	phases     []string
	resultErrs []error
}

func (r *installCmdRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if stored, err := ReadResult(r.resultPath); err == nil {
		r.phases = append(r.phases, stored.Phase)
	} else {
		r.resultErrs = append(r.resultErrs, err)
	}
	if name == systemctlPath {
		return nil, r.restartErr
	}
	return nil, r.installErr
}

// runningExecutable is the real ELF executable of this test process: the same
// bytes production re-checks with --expected-sha256.
func runningExecutable(t *testing.T) (string, []byte) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read running executable: %v", err)
	}
	return path, data
}

func installCmdFixture(t *testing.T, operationID string) Config {
	t.Helper()
	self, data := runningExecutable(t)
	return Config{
		Target:         "1.0.1",
		ManifestSHA256: shaOf([]byte("approved manifest body")),
		PackageSHA256:  shaOf(data),
		OperationID:    operationID,
		WorkDir:        t.TempDir(),
		SelfExecutable: self,
		RecordedRole:   func() (node.Role, error) { return node.RoleOut, nil },
	}
}

// TestInstallCmdFixedArgv pins the whole chain: bytes first, then the one fixed
// install argv built from the recorded role and the chain's operation ID (no
// stdin, no pairing code), then the fixed restart argv, with each result phase
// already on disk before its step runs.
func TestInstallCmdFixedArgv(t *testing.T) {
	operationID := strings.Repeat("a", 32)
	cfg := installCmdFixture(t, operationID)
	runner := &installCmdRunner{resultPath: ResultPath(cfg.WorkDir, operationID)}

	result, err := RunInstall(context.Background(), cfg, runner)
	if err != nil {
		t.Fatalf("RunInstall: %v", err)
	}
	wantCalls := [][]string{
		{cfg.SelfExecutable, "install", "out", "--repair", "--non-interactive",
			"--from-recorded-state", "--operation-id", operationID},
		{systemctlPath, "restart", "meshmux-agent.service"},
	}
	if len(runner.calls) != len(wantCalls) {
		t.Fatalf("calls = %q, want %q", runner.calls, wantCalls)
	}
	for i := range wantCalls {
		if !slices.Equal(runner.calls[i], wantCalls[i]) {
			t.Fatalf("call %d = %q, want %q", i, runner.calls[i], wantCalls[i])
		}
	}
	// The install never waits for a terminal: --non-interactive is fixed and
	// no pairing-code flag can appear in the argv.
	if slices.Contains(runner.calls[0], "--pairing-code-file") {
		t.Fatalf("install argv carries a pairing code: %q", runner.calls[0])
	}
	if len(runner.resultErrs) != 0 {
		t.Fatalf("a step ran before its phase was on disk: %v", runner.resultErrs)
	}
	wantPhases := []string{ResultPhaseInstalling, ResultPhaseInstalledAwaitingRestart}
	if !slices.Equal(runner.phases, wantPhases) {
		t.Fatalf("phases at steps = %q, want %q", runner.phases, wantPhases)
	}

	stored, err := ReadResult(ResultPath(cfg.WorkDir, operationID))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if stored != result {
		t.Fatalf("stored result = %+v, returned %+v", stored, result)
	}
	if stored.Phase != ResultPhaseInstalledAwaitingRestart || stored.ExitCode != 0 {
		t.Fatalf("final result = %+v, want installed-awaiting-restart/0", stored)
	}
	if stored.OperationID != operationID || stored.Target != cfg.Target ||
		stored.Digest != cfg.PackageSHA256 || stored.Timestamp < 1 {
		t.Fatalf("result identity = %+v", stored)
	}
}

// TestInstallCmdRestartOnlyAfterInstallSuccess pins the chain order: a failed
// install is terminal, so systemctl never runs and the result keeps the
// installer's own exit code in the installing phase.
func TestInstallCmdRestartOnlyAfterInstallSuccess(t *testing.T) {
	operationID := strings.Repeat("b", 32)
	cfg := installCmdFixture(t, operationID)
	runner := &installCmdRunner{resultPath: ResultPath(cfg.WorkDir, operationID),
		installErr: exitStatus(6)}

	result, err := RunInstall(context.Background(), cfg, runner)
	if code := codeOf(err); code != "UPDATE_INSTALL_FAILED" {
		t.Fatalf("code = %q, want UPDATE_INSTALL_FAILED (err %v)", code, err)
	}
	if len(runner.calls) != 1 || !slices.Equal(runner.calls[0][:4], []string{cfg.SelfExecutable, "install", "out", "--repair"}) {
		t.Fatalf("calls = %q, want the install only", runner.calls)
	}
	if result.ExitCode != 6 || result.Phase != ResultPhaseInstalling {
		t.Fatalf("result = %+v, want installing/6", result)
	}
	stored, readErr := ReadResult(ResultPath(cfg.WorkDir, operationID))
	if readErr != nil {
		t.Fatalf("read result: %v", readErr)
	}
	if stored.ExitCode != 6 || stored.Phase != ResultPhaseInstalling {
		t.Fatalf("stored = %+v, want installing/6", stored)
	}
}

// TestInstallCmdWritesResultWithExitCode pins the terminal record of a failed
// install: the result file exists at the frozen path and carries the coarse
// exit code, never a prose error and never an applied claim.
func TestInstallCmdWritesResultWithExitCode(t *testing.T) {
	operationID := strings.Repeat("c", 32)
	cfg := installCmdFixture(t, operationID)
	runner := &installCmdRunner{resultPath: ResultPath(cfg.WorkDir, operationID),
		installErr: exitStatus(5)}

	if _, err := RunInstall(context.Background(), cfg, runner); err == nil {
		t.Fatal("a failed install returned no error")
	}
	stored, err := ReadResult(ResultPath(cfg.WorkDir, operationID))
	if err != nil {
		t.Fatalf("result file: %v", err)
	}
	if stored.ExitCode != 5 || stored.Phase != ResultPhaseInstalling {
		t.Fatalf("stored = %+v, want installing/5", stored)
	}
	if stored.OperationID != operationID || stored.Digest != cfg.PackageSHA256 {
		t.Fatalf("stored identity = %+v", stored)
	}
}

// TestInstallCmdRefusesTamperedStagedBytes is the --expected-sha256 self-check:
// bytes that do not match the approved digest are refused before the ledger is
// read, before any argv runs and before any result file exists.
func TestInstallCmdRefusesTamperedStagedBytes(t *testing.T) {
	operationID := strings.Repeat("d", 32)
	dir := t.TempDir()
	staged := filepath.Join(dir, "meshmuxd-1.0.1-"+runtime.GOARCH)
	if err := os.WriteFile(staged, []byte("tampered staged bytes"), 0700); err != nil {
		t.Fatal(err)
	}
	roleRead := false
	cfg := Config{
		Target:         "1.0.1",
		ManifestSHA256: shaOf([]byte("approved manifest body")),
		PackageSHA256:  shaOf([]byte("approved package bytes")),
		OperationID:    operationID,
		WorkDir:        dir,
		SelfExecutable: staged,
		RecordedRole: func() (node.Role, error) {
			roleRead = true
			return node.RoleEdge, nil
		},
	}
	runner := &installCmdRunner{resultPath: ResultPath(dir, operationID)}
	_, err := RunInstall(context.Background(), cfg, runner)
	if code := codeOf(err); code != "UPDATE_DIGEST_MISMATCH" {
		t.Fatalf("code = %q, want UPDATE_DIGEST_MISMATCH (err %v)", code, err)
	}
	if roleRead {
		t.Fatal("the ledger was read before the self-digest check")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("tampered bytes executed %v", runner.calls)
	}
	if _, statErr := os.Stat(ResultPath(dir, operationID)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("refusal wrote a result file: %v", statErr)
	}
}

// TestUpdaterRefusesForeignArch re-pins the wrong-architecture rule on the new
// path: a staged executable whose ELF machine is not this build's architecture
// is refused after its digest matches and before any host action.
func TestUpdaterRefusesForeignArch(t *testing.T) {
	operationID := strings.Repeat("e", 32)
	dir := t.TempDir()
	_, data := runningExecutable(t)
	foreign := foreignMachine(t, data)
	staged := filepath.Join(dir, "meshmuxd-1.0.1-"+foreignArchName())
	if err := os.WriteFile(staged, foreign, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Target:         "1.0.1",
		ManifestSHA256: shaOf([]byte("approved manifest body")),
		PackageSHA256:  shaOf(foreign),
		OperationID:    operationID,
		WorkDir:        dir,
		SelfExecutable: staged,
		RecordedRole: func() (node.Role, error) {
			t.Fatal("the ledger was read before the architecture check")
			return "", nil
		},
	}
	runner := &installCmdRunner{resultPath: ResultPath(dir, operationID)}
	_, err := RunInstall(context.Background(), cfg, runner)
	if code := codeOf(err); code != "MANIFEST_ARCH_INVALID" {
		t.Fatalf("code = %q, want MANIFEST_ARCH_INVALID (err %v)", code, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("foreign-arch bytes executed %v", runner.calls)
	}
	if _, statErr := os.Stat(ResultPath(dir, operationID)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("refusal wrote a result file: %v", statErr)
	}
}

// foreignMachine patches the ELF machine of an executable to the other
// supported architecture; every offset stays valid, only the target differs.
func foreignMachine(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) < 20 || string(data[:4]) != "\x7fELF" || data[5] != 1 {
		t.Fatalf("test executable is not a little-endian ELF")
	}
	machine := uint16(0xb7) // EM_AARCH64
	if runtime.GOARCH == "arm64" {
		machine = 0x3e // EM_X86_64
	}
	patched := slices.Clone(data)
	binary.LittleEndian.PutUint16(patched[18:20], machine)
	return patched
}

func foreignArchName() string {
	if runtime.GOARCH == "arm64" {
		return "amd64"
	}
	return "arm64"
}
