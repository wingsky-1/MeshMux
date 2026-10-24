package node

// Startup reconciliation (#11c-2 Task 4). The tests are fixture-driven: every
// path is rooted in t.TempDir, no host file, /proc entry or systemd unit is
// touched. The properties pinned here are the ones the marker was missing in
// 11c-1: a crash between the Agent binary and agent.json is reclaimable, an
// ownerless marker cannot wedge the node forever, a corrupt marker refuses
// startup with a manual-removal instruction, and "installed-awaiting-restart"
// is never treated as proof that the restart happened.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

func writeRawHandoffFile(t *testing.T, root string, marker map[string]any) {
	t.Helper()
	data, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	path := rooted(root, upgradeHandoffPath)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func handoffMarker(op, target, state, phase string, startedAt int64) map[string]any {
	marker := map[string]any{
		"schema":          upgradeHandoffSchema,
		"state":           state,
		"operation_id":    op,
		"target_version":  target,
		"manifest_sha256": strings.Repeat("d", 64),
		"revision":        10,
		"child_pid":       0,
		"started_at":      startedAt,
	}
	if phase != "" {
		marker["phase"] = phase
	}
	return marker
}

func writeHandoffResultFile(t *testing.T, root, op, target, phase string, exitCode int) {
	t.Helper()
	result := map[string]any{
		"operation_id": op,
		"phase":        phase,
		"exit_code":    exitCode,
		"digest":       strings.Repeat("e", 64),
		"target":       target,
		"ts":           time.Now().Unix(),
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	dir := rooted(root, upgradeHandoffResultDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, op+".result.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeClaimFile(t *testing.T, root, newSHA256, operationID string) {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"new_sha256":   newSHA256,
		"operation_id": operationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := rooted(root, upgradeHandoffClaimPath)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeAgentConfigFile(t *testing.T, root string, cfg Config) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := rooted(root, AgentConfigPath)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// crashWindowFixture stages the exact crash window of spec §4.8: the new Agent
// binary is on disk, agent.json still names the old build, and the installer
// left its claim record between the two renames.
func crashWindowFixture(t *testing.T) (root string, oldCfg Config, selfHash, operationID string, identity Identity, base *runtimeTestRunner) {
	t.Helper()
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	oldCfg = cfg
	oldCfg.AgentVersion = "0.9.9"
	oldCfg.AgentSHA256 = strings.Repeat("b", 64)
	writeAgentConfigFile(t, root, oldCfg)

	binaryPath := rooted(root, AgentBinaryPath)
	current, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	newBinary := append(append([]byte{}, current...), 0x7f)
	if err := os.WriteFile(binaryPath, newBinary, 0755); err != nil {
		t.Fatal(err)
	}
	selfHash = sha256Hex(newBinary)

	operationID = strings.Repeat("c", 32)
	writeRawHandoffFile(t, root, handoffMarker(operationID, CurrentAgentVersion,
		handoffRunning, handoffPhaseInstalling, time.Now().Unix()))
	writeClaimFile(t, root, selfHash, operationID)
	return root, oldCfg, selfHash, operationID, identity, base
}

func readAgentConfigFile(t *testing.T, root string) Config {
	t.Helper()
	data, _, err := readPrivateFile(rooted(root, AgentConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := decodeStrictJSON(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestCrashWindowClaimedOnBoot covers both directions of the crash-window
// claim: a matching record plus the exact binary on disk is adopted in memory
// (the Agent sandbox never writes agent.json; the claim stays for the outside
// convergence writer), while a missing or mismatching record fails closed.
func TestCrashWindowClaimedOnBoot(t *testing.T) {
	t.Run("matching claim is adopted in memory", func(t *testing.T) {
		root, oldCfg, selfHash, operationID, _, _ := crashWindowFixture(t)
		adopted, err := adoptCrashWindowClaim(root, oldCfg, selfHash)
		if err != nil {
			t.Fatal(err)
		}
		if adopted.AgentSHA256 != selfHash || adopted.AgentVersion != CurrentAgentVersion {
			t.Fatalf("adopted identity = %q/%q", adopted.AgentVersion, adopted.AgentSHA256)
		}
		if err := adopted.ValidateInstalled(); err != nil {
			t.Fatalf("adopted config does not validate: %v", err)
		}
		// The Agent never writes /etc: the on-disk config still names the old
		// build and the claim remains for the outside convergence writer.
		onDisk := readAgentConfigFile(t, root)
		if onDisk.AgentSHA256 != oldCfg.AgentSHA256 || onDisk.AgentVersion != oldCfg.AgentVersion {
			t.Fatalf("adoption rewrote agent.json from the Agent sandbox: %+v", onDisk)
		}
		if _, err := os.Lstat(rooted(root, upgradeHandoffClaimPath)); err != nil {
			t.Fatalf("claim record was dropped on in-memory adoption: %v", err)
		}
		marker, ok, err := readUpgradeHandoffFile(root)
		if err != nil || !ok || marker.OperationID != operationID {
			t.Fatalf("marker after adoption = %+v, %v, %v", marker, ok, err)
		}
	})

	for _, tc := range []struct {
		name   string
		change func(t *testing.T, root, selfHash, operationID string)
	}{
		{"binary hash mismatch", func(t *testing.T, root, _, operationID string) {
			writeClaimFile(t, root, strings.Repeat("f", 64), operationID)
		}},
		{"claim for another operation", func(t *testing.T, root, selfHash, _ string) {
			writeClaimFile(t, root, selfHash, strings.Repeat("a", 32))
		}},
		{"missing claim record", func(t *testing.T, root, _, _ string) {
			if err := os.Remove(rooted(root, upgradeHandoffClaimPath)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, oldCfg, selfHash, operationID, _, _ := crashWindowFixture(t)
			before, err := os.ReadFile(rooted(root, AgentConfigPath))
			if err != nil {
				t.Fatal(err)
			}
			tc.change(t, root, selfHash, operationID)
			if _, err := adoptCrashWindowClaim(root, oldCfg, selfHash); err == nil ||
				!errors.Is(err, stableError("AGENT_EXECUTABLE_MISMATCH")) ||
				errorCode(err) != "AGENT_EXECUTABLE_MISMATCH" {
				t.Fatalf("mismatch = %v, want a mappable AGENT_EXECUTABLE_MISMATCH", err)
			}
			after, err := os.ReadFile(rooted(root, AgentConfigPath))
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatal("a refused claim rewrote agent.json")
			}
		})
	}
}

// TestOrphanMarkerRecycled is D2: a running marker whose owner chain is gone
// and whose age is past the pure 30-minute bound becomes a local failure with
// UPGRADE_HANDOFF_ORPHANED. Only a later chain's stage step may clear that
// failed marker, and it does so before staging normally.
func TestOrphanMarkerRecycled(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, unitState: "inactive"}
	operationID := strings.Repeat("c", 32)
	writeRawHandoffFile(t, root, handoffMarker(operationID, "1.0.1",
		handoffRunning, handoffPhaseInstalling, time.Now().Add(-31*time.Minute).Unix()))

	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, nil)
	marker, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok {
		t.Fatalf("orphan marker = %+v, %v, %v", marker, ok, err)
	}
	if marker.State != handoffFailed || marker.ErrorCode != "UPGRADE_HANDOFF_ORPHANED" ||
		marker.Phase != handoffPhaseInstalling {
		t.Fatalf("orphaned marker = %+v", marker)
	}

	// The failed marker alone does not unblock this chain. A new chain's stage
	// step owns the node now: it clears the failed marker, then stages.
	next := task(protocol.KindConfigStage, strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 9)
	result := runtime.Execute(context.Background(), next)
	if result.Status != "healthy" || result.ErrorCode != "" {
		t.Fatalf("stage after orphan = %+v", result)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("failed marker survived the new chain: %v", err)
	}
}

// TestCorruptMarkerRefusedWithManualRemoval is the terminal-refusal rule: a
// marker the Agent cannot prove is valid never gets guessed at, and the error
// tells the operator exactly which file to remove by hand.
func TestCorruptMarkerRefusedWithManualRemoval(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker map[string]any
	}{
		{"missing fields", map[string]any{
			"schema": upgradeHandoffSchema,
			"state":  handoffRunning,
		}},
		{"unknown v2 field", func() map[string]any {
			marker := handoffMarker(strings.Repeat("c", 32), "1.0.1",
				handoffRunning, handoffPhaseStaged, time.Now().Unix())
			marker["unexpected"] = true
			return marker
		}()},
		{"v1 with a v2 field", func() map[string]any {
			marker := handoffMarker(strings.Repeat("c", 32), "1.0.1",
				handoffRunning, "", time.Now().Unix())
			marker["schema"] = upgradeHandoffSchemaV1
			marker["phase"] = handoffPhaseStaged
			return marker
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
			writeRawHandoffFile(t, root, tc.marker)
			_, err := NewRuntime(cfg, identity, RuntimeOptions{
				Root: root, Runner: base, Controller: &runtimeTestController{candidate: testCandidate(9)},
			})
			if err == nil || err.Error() != upgradeHandoffCorruptMessage {
				t.Fatalf("corrupt marker = %v, want the manual-removal refusal", err)
			}
			if !strings.Contains(err.Error(), "remove "+upgradeHandoffPath+" manually") {
				t.Fatalf("refusal does not name the file to remove: %v", err)
			}
		})
	}
}

// TestHandoffV1StillReads pins the compatibility rule of spec §5-D4: a v1
// marker (no phase, no error_code) is still a valid staged attempt. It is read
// strictly, so a v2-only field in a v1 file is corruption above.
func TestHandoffV1StillReads(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	operationID := strings.Repeat("c", 32)
	v1Marker := handoffMarker(operationID, "1.0.1",
		handoffRunning, "", time.Now().Unix())
	v1Marker["schema"] = upgradeHandoffSchemaV1
	writeRawHandoffFile(t, root, v1Marker)

	runtime := newTestRuntime(t, root, cfg, identity, base,
		&runtimeTestController{candidate: testCandidate(9)})
	marker, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok {
		t.Fatalf("v1 marker = %+v, %v, %v", marker, ok, err)
	}
	if marker.Phase != handoffPhaseStaged || marker.OperationID != operationID {
		t.Fatalf("v1 marker = %+v, want staged %s", marker, operationID)
	}
}

// TestInstalledAwaitingRestartIsNotRestartProof is the T1/T4 carry: the phase
// and a zero exit code from the unit are process signals, not evidence that the
// Agent restarted on the target. With the unit finished, the running release
// still old, and the result file saying installed-awaiting-restart, the gate
// must fail the chain honestly instead of clearing the marker or claiming
// success. Only the chain's readback can ever say applied.
func TestInstalledAwaitingRestartIsNotRestartProof(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, unitState: "inactive"}
	operationID := strings.Repeat("c", 32)
	writeRawHandoffFile(t, root, handoffMarker(operationID, "1.0.1",
		handoffRunning, handoffPhaseInstalledAwaitingRestart, time.Now().Unix()))
	writeHandoffResultFile(t, root, operationID, "1.0.1", handoffPhaseInstalledAwaitingRestart, 0)

	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, nil)
	marker, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok || marker.State != handoffRunning ||
		marker.Phase != handoffPhaseInstalledAwaitingRestart {
		t.Fatalf("marker was treated as a completed restart: %+v, %v, %v", marker, ok, err)
	}

	apply := task(protocol.KindConfigApply, strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "failed" || result.ErrorCode != "UPDATE_HANDOFF_INCOMPLETE" {
		t.Fatalf("apply after a finished unit = %+v", result)
	}
	if runner.restartCount != 0 {
		t.Fatalf("gated apply restarted the kernel %d times", runner.restartCount)
	}
	if _, err := os.Lstat(stagedConfigPath(root, 10)); !os.IsNotExist(err) {
		t.Fatalf("gated apply staged a config: %v", err)
	}
	marker, ok, err = runtime.readUpgradeHandoff()
	if err != nil || !ok || marker.State != handoffFailed ||
		marker.ErrorCode != "UPDATE_HANDOFF_INCOMPLETE" {
		t.Fatalf("failed marker = %+v, %v, %v", marker, ok, err)
	}
}

// TestActiveOldUnitStaysInFlight pins the orphan-rule intent explicitly: the
// 30-minute bound fails an OWNERLESS attempt. A transient unit that is still
// active owns the attempt, so the gate keeps reporting "applying" even after
// the age bound instead of failing the chain under a live install.
func TestActiveOldUnitStaysInFlight(t *testing.T) {
	root, cfg, identity, base := createRuntimeFixture(t, RoleEdge, 9)
	runner := &handoffRunner{runtimeTestRunner: base, unitState: "active"}
	operationID := strings.Repeat("c", 32)
	writeRawHandoffFile(t, root, handoffMarker(operationID, "1.0.1",
		handoffRunning, handoffPhaseInstalling, time.Now().Add(-31*time.Minute).Unix()))

	runtime := newUpgradeRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(9)}, nil)
	marker, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok || marker.State != handoffRunning {
		t.Fatalf("active old unit was failed: %+v, %v, %v", marker, ok, err)
	}
	readback := task(protocol.KindConfigReadback, strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 9)
	result := runtime.Execute(context.Background(), readback)
	if result.Status != "applying" || result.ErrorCode != "" {
		t.Fatalf("gate under a live old unit = %+v, want applying", result)
	}
	marker, ok, err = runtime.readUpgradeHandoff()
	if err != nil || !ok || marker.State != handoffRunning {
		t.Fatalf("live owner marker = %+v, %v, %v", marker, ok, err)
	}
}

// convergeWriter is the test seam of the outside-sandbox convergence contract.
// It behaves like the transient one-shot writer / next install --repair: it
// rewrites agent.json for the claimed digest; it never runs inside the Agent.
type convergeWriter struct {
	t        *testing.T
	root     string
	cfg      Config
	calls    int
	failWith error
}

func (w *convergeWriter) ConvergeHandoffConfig(_ context.Context, claim HandoffClaim) error {
	w.calls++
	if w.failWith != nil {
		return w.failWith
	}
	cfg := w.cfg
	cfg.AgentVersion = CurrentAgentVersion
	cfg.AgentSHA256 = claim.NewSHA256
	writeAgentConfigFile(w.t, w.root, cfg)
	return nil
}

// TestInMemoryAdoptionKeepsClaimUntilConvergence is the amended §4.2 rule: the
// Agent boots from the verified disk hash and continues (never writing
// /etc/meshmux/agent.json), but the claim survives that boot. Only the pair
// readback after an outside writer converges the config may remove it; with no
// writer the claim stays for the next repair and startup still succeeds.
func TestInMemoryAdoptionKeepsClaimUntilConvergence(t *testing.T) {
	root, oldCfg, selfHash, operationID, identity, base := crashWindowFixture(t)
	adopted, err := adoptCrashWindowClaim(root, oldCfg, selfHash)
	if err != nil {
		t.Fatal(err)
	}
	// No convergence writer is wired: boot must succeed and retain both the
	// claim and the marker (the on-disk pair is still old).
	runtime := newUpgradeRuntime(t, root, adopted, identity, base,
		&runtimeTestController{candidate: testCandidate(9)}, nil)
	if _, err := os.Lstat(rooted(root, upgradeHandoffClaimPath)); err != nil {
		t.Fatalf("in-memory adoption dropped the claim: %v", err)
	}
	marker, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok || marker.OperationID != operationID {
		t.Fatalf("marker after in-memory boot = %+v, %v, %v", marker, ok, err)
	}
	// The running target releases the chain gate without claiming applied and
	// without clearing the convergence debt.
	if _, pending, err := runtime.pendingUpgradeHandoff(); err != nil || pending {
		t.Fatalf("running target still gated the chain: pending=%v err=%v", pending, err)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffClaimPath)); err != nil {
		t.Fatalf("gate release cleared the claim: %v", err)
	}

	// A convergence writer becomes available; settlement still clears the
	// claim only after re-reading a matching on-disk pair.
	writer := &convergeWriter{t: t, root: root, cfg: oldCfg}
	runtime.handoffConvergence = writer
	if runtime.handoffPairConverged() {
		t.Fatal("pair readback passed before convergence")
	}
	runtime.settleHandoffClaim(context.Background())
	if writer.calls != 1 {
		t.Fatalf("convergence writer calls = %d, want 1", writer.calls)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffClaimPath)); !os.IsNotExist(err) {
		t.Fatalf("claim survived a converged pair: %v", err)
	}
	// The next gate pass can now drop the completed marker.
	if _, pending, err := runtime.pendingUpgradeHandoff(); err != nil || pending {
		t.Fatalf("pending after convergence = %v, %v", pending, err)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("converged marker survived: %v", err)
	}
}

// TestBootConvergenceWriterReleasesRecords is the positive side: when the
// outside writer is wired, boot requests it once, re-reads the pair and only
// then removes the claim and marker.
func TestBootConvergenceWriterReleasesRecords(t *testing.T) {
	root, oldCfg, selfHash, _, identity, base := crashWindowFixture(t)
	adopted, err := adoptCrashWindowClaim(root, oldCfg, selfHash)
	if err != nil {
		t.Fatal(err)
	}
	writer := &convergeWriter{t: t, root: root, cfg: oldCfg}
	_, err = NewRuntime(adopted, identity, RuntimeOptions{
		Root: root, Runner: base,
		Controller:         &runtimeTestController{candidate: testCandidate(9)},
		HandoffConvergence: writer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if writer.calls != 1 {
		t.Fatalf("boot convergence writer calls = %d, want 1", writer.calls)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffClaimPath)); !os.IsNotExist(err) {
		t.Fatalf("claim survived boot convergence: %v", err)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffPath)); !os.IsNotExist(err) {
		t.Fatalf("marker survived boot convergence: %v", err)
	}
}

// TestBootConvergenceWriterFailureKeepsClaim is the carried negative case from
// Task 4: a writer that fails (systemd refused the unit, the binary changed, the
// write was denied) must not fail startup and must not clear the claim. The
// convergence debt simply survives for the next repair.
func TestBootConvergenceWriterFailureKeepsClaim(t *testing.T) {
	root, oldCfg, selfHash, operationID, identity, base := crashWindowFixture(t)
	adopted, err := adoptCrashWindowClaim(root, oldCfg, selfHash)
	if err != nil {
		t.Fatal(err)
	}
	writer := &convergeWriter{t: t, root: root, cfg: oldCfg, failWith: errors.New("systemd unavailable")}
	runtime, err := NewRuntime(adopted, identity, RuntimeOptions{
		Root: root, Runner: base,
		Controller:         &runtimeTestController{candidate: testCandidate(9)},
		HandoffConvergence: writer,
	})
	if err != nil {
		t.Fatalf("a failing convergence writer failed startup: %v", err)
	}
	if writer.calls != 1 {
		t.Fatalf("convergence writer calls = %d, want 1", writer.calls)
	}
	claim, ok, claimErr := readUpgradeClaimFile(root)
	if claimErr != nil || !ok || claim.OperationID != operationID {
		t.Fatalf("claim after a failed convergence = %+v, %v, %v", claim, ok, claimErr)
	}
	marker, pending, markerErr := runtime.readUpgradeHandoff()
	if markerErr != nil || !pending || marker.State != handoffRunning {
		t.Fatalf("marker after a failed convergence = %+v, %v, %v", marker, pending, markerErr)
	}
	// The failed writer is retried on the next settlement, and only a real
	// convergence plus readback may clear the records.
	writer.failWith = nil
	runtime.settleHandoffClaim(context.Background())
	if writer.calls != 2 {
		t.Fatalf("convergence writer calls = %d, want 2", writer.calls)
	}
	if _, err := os.Lstat(rooted(root, upgradeHandoffClaimPath)); !os.IsNotExist(err) {
		t.Fatalf("claim survived a successful convergence: %v", err)
	}
}

// TestHandoffUnitStateArgvPinned is the drift guard for the mirrored Task-1
// liveness query: exactly one fixed `systemctl show` of ActiveState and
// ExecMainStatus for the derived unit name, no extra fields and no shell.
func TestHandoffUnitStateArgvPinned(t *testing.T) {
	operationID := strings.Repeat("d", 32)
	runner := &recordingRunner{out: []byte("ActiveState=active\nExecMainStatus=0\n")}
	runtime := &Runtime{runner: runner}
	state, status, err := runtime.handoffUnitState(operationID)
	if err != nil || state != handoffUnitActive || status != 0 {
		t.Fatalf("unit state = %q/%d/%v", state, status, err)
	}
	want := []string{
		systemctlPath, "show", "-p", "ActiveState", "-p", "ExecMainStatus",
		"meshmux-update-" + operationID,
	}
	if len(runner.calls) != 1 || !slices.Equal(runner.calls[0], want) {
		t.Fatalf("systemctl argv = %q, want %q", runner.calls, want)
	}
}

type recordingRunner struct {
	calls [][]string
	out   []byte
	err   error
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.out, r.err
}
