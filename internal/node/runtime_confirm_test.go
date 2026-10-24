package node

// Health-gated finalize (#11c-3 Task 3, spec §4.6/§4.16).
//
// The spec's rule is deliberately narrow: there is no confirmUpgrade verdict.
// The ONLY thing that may confirm an upgrade is the chain's own readback being
// accepted — the healthy result whose agent_version/agent_sha256 are the ones
// the updater recorded for the target. These tests pin that side effect, the
// silent no-op when the evidence does not match, and the separate
// <operation_id>.revert.json contract Task 4's transient revert executor will
// write (the 11c-2 <operation_id>.result.json schema is left untouched).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

// confirmCall is one ConfirmVersion invocation of the fixture confirmer.
type confirmCall struct {
	operationID string
	target      string
	agentSHA256 string
}

// confirmRecorder is the node-side half of the rollback-store seam. The
// production implementation lives in the updater (it owns the 0700 store and
// GCBackups) and is wired by the caller; the Agent only triggers it.
type confirmRecorder struct {
	calls []confirmCall
	err   error
}

func (c *confirmRecorder) ConfirmVersion(_ context.Context, operationID, target, agentSHA256 string) error {
	c.calls = append(c.calls, confirmCall{operationID: operationID, target: target, agentSHA256: agentSHA256})
	return c.err
}

func newConfirmRuntime(t *testing.T, root string, cfg Config, identity Identity,
	runner CommandRunner, controller Controller, confirmer UpgradeConfirmer) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
		UpgradeConfirmation: confirmer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

// writeUpgradeResultFile writes the frozen 11c-2 <op>.result.json the updater
// leaves after it installed the target. digest is the approved package digest;
// for a Node that is exactly the running Agent binary.
func writeUpgradeResultFile(t *testing.T, root, op, target, digest, phase string, exitCode int) {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"operation_id": op,
		"phase":        phase,
		"exit_code":    exitCode,
		"digest":       digest,
		"target":       target,
		"ts":           time.Now().Unix(),
	})
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

// writeRevertResultFile writes the Task 3 revert-result contract: a SEPARATE
// <op>.revert.json next to the frozen 11c-2 install result. The schema literal
// is deliberate: it is the frozen contract Task 4 writes against.
func writeRevertResultFile(t *testing.T, root, op, target, from, outcome, code string, exitCode int) {
	t.Helper()
	result := map[string]any{
		"schema":         "meshmux-upgrade-revert/v1",
		"operation_id":   op,
		"target_version": target,
		"from_version":   from,
		"outcome":        outcome,
		"exit_code":      exitCode,
		"ts":             time.Now().Unix(),
	}
	if code != "" {
		result["error_code"] = code
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	dir := rooted(root, upgradeHandoffResultDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, op+".revert.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func failedHandoffFixture(t *testing.T, root string, runtime *Runtime, operationID, target string) {
	t.Helper()
	handoff := upgradeHandoff{
		Schema:         upgradeHandoffSchema,
		State:          handoffFailed,
		Phase:          handoffPhaseInstalling,
		ErrorCode:      handoffIncompleteCode,
		OperationID:    operationID,
		TargetVersion:  target,
		ManifestSHA256: strings.Repeat("d", 64),
		Revision:       10,
		StartedAt:      time.Now().Add(-time.Minute).Unix(),
	}
	if err := runtime.writeUpgradeHandoff(handoff); err != nil {
		t.Fatal(err)
	}
}

// TestConfirmOnMatchingReadback is the positive property: an accepted readback
// of the target release triggers exactly one confirmation of the operation the
// updater recorded (and therefore the record confirm + N-1 GC on the updater
// side). The readback result itself stays the verdict; no new status, protocol
// kind or Hub code path is introduced.
func TestConfirmOnMatchingReadback(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	recorder := &confirmRecorder{}
	runtime := newConfirmRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(7)}, recorder)

	upgradeOperation := strings.Repeat("c", 32)
	writeUpgradeResultFile(t, root, upgradeOperation, cfg.AgentVersion,
		cfg.AgentSHA256, handoffPhaseInstalledAwaitingRestart, 0)

	readback := task(protocol.KindConfigReadback,
		strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
	result := runtime.Execute(context.Background(), readback)
	if result.Status != "healthy" || result.ErrorCode != "" {
		t.Fatalf("readback of the target release = %+v, want healthy", result)
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("confirmations = %+v, want exactly one", recorder.calls)
	}
	call := recorder.calls[0]
	if call.operationID != upgradeOperation || call.target != cfg.AgentVersion ||
		call.agentSHA256 != cfg.AgentSHA256 {
		t.Fatalf("confirmation = %+v, want (%s, %s, %s)",
			call, upgradeOperation, cfg.AgentVersion, cfg.AgentSHA256)
	}
}

// TestNoConfirmOnMismatchedReadback pins the negative half: only an ACCEPTED
// readback of evidence that matches the updater's record may confirm. A failed
// readback, another release, another package digest and a node with no upgrade
// record at all never trigger a confirmation (and therefore never release a
// rollback pointer to GC).
func TestNoConfirmOnMismatchedReadback(t *testing.T) {
	t.Run("readback not accepted", func(t *testing.T) {
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		recorder := &confirmRecorder{}
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, recorder)
		operationID := strings.Repeat("c", 32)
		writeUpgradeResultFile(t, root, operationID, cfg.AgentVersion,
			cfg.AgentSHA256, handoffPhaseInstalledAwaitingRestart, 0)

		// The live state is revision 7; asking for another revision fails before
		// any evidence is produced, so the target was never proven running.
		readback := task(protocol.KindConfigReadback,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 6)
		result := runtime.Execute(context.Background(), readback)
		if result.Status == "healthy" {
			t.Fatalf("stale-revision readback reported healthy: %+v", result)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("a failed readback confirmed %+v", recorder.calls)
		}
	})

	t.Run("running release is not the target", func(t *testing.T) {
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		recorder := &confirmRecorder{}
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, recorder)
		// The result names a release this build is not running.
		writeUpgradeResultFile(t, root, strings.Repeat("c", 32), "1.0.1",
			cfg.AgentSHA256, handoffPhaseInstalledAwaitingRestart, 0)

		readback := task(protocol.KindConfigReadback,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
		if result := runtime.Execute(context.Background(), readback); result.Status != "healthy" {
			t.Fatalf("readback = %+v, want healthy", result)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("a healthy readback of another release confirmed %+v", recorder.calls)
		}
	})

	t.Run("running binary is not the approved package", func(t *testing.T) {
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		recorder := &confirmRecorder{}
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, recorder)
		// The version string matches but the bytes do not: this is the silent
		// downgrade the digest anchor exists to refuse.
		writeUpgradeResultFile(t, root, strings.Repeat("c", 32), cfg.AgentVersion,
			strings.Repeat("f", 64), handoffPhaseInstalledAwaitingRestart, 0)

		readback := task(protocol.KindConfigReadback,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
		if result := runtime.Execute(context.Background(), readback); result.Status != "healthy" {
			t.Fatalf("readback = %+v, want healthy", result)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("a mismatched binary digest confirmed %+v", recorder.calls)
		}
	})

	t.Run("no upgrade record", func(t *testing.T) {
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		recorder := &confirmRecorder{}
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, recorder)

		readback := task(protocol.KindConfigReadback,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
		if result := runtime.Execute(context.Background(), readback); result.Status != "healthy" {
			t.Fatalf("readback = %+v, want healthy", result)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("an ordinary readback confirmed %+v", recorder.calls)
		}
	})

	// A nil confirmer is the state until Task 4 wires the rollback store. The
	// readback stays the verdict (healthy, legal, detail intact), no confirmation
	// is attempted, and the missing side effect is reported as a stable log code
	// instead of being silently skipped or turned into a failure.
	t.Run("nil confirmer keeps the verdict", func(t *testing.T) {
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, nil)
		var log bytes.Buffer
		runtime.logger = slog.New(slog.NewJSONHandler(&log, nil))
		writeUpgradeResultFile(t, root, strings.Repeat("c", 32), cfg.AgentVersion,
			cfg.AgentSHA256, handoffPhaseInstalledAwaitingRestart, 0)

		readback := task(protocol.KindConfigReadback,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
		result := runtime.Execute(context.Background(), readback)
		if result.Status != "healthy" || result.ErrorCode != "" || result.Detail == "" {
			t.Fatalf("readback without a confirmer = %+v, want the unchanged healthy verdict", result)
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			t.Fatalf("readback receipt is not a legal result: %v", err)
		}
		if !strings.Contains(log.String(), upgradeConfirmUnavailableCode) {
			t.Fatalf("missing confirmation was not reported: %s", log.String())
		}
		// The retry anchor survives: a nil confirmer is a deferred finalize, so
		// the next accepted readback can still confirm once Task 4 wires it.
		if _, ok, err := runtime.readHandoffResult(strings.Repeat("c", 32)); err != nil || !ok {
			t.Fatalf("nil confirmer consumed the upgrade record: ok=%v err=%v", ok, err)
		}
	})

	// A confirmer that fails must not flip an applied upgrade: the verdict stays
	// healthy, the failure is logged with its stable code, and the record is left
	// exactly as it was so the next accepted readback retries.
	t.Run("confirmer error keeps the verdict", func(t *testing.T) {
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		recorder := &confirmRecorder{err: errors.New("UPDATE_BACKUP_CORRUPT: the rollback record is not a private 0600 file")}
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, recorder)
		var log bytes.Buffer
		runtime.logger = slog.New(slog.NewJSONHandler(&log, nil))
		operationID := strings.Repeat("c", 32)
		writeUpgradeResultFile(t, root, operationID, cfg.AgentVersion,
			cfg.AgentSHA256, handoffPhaseInstalledAwaitingRestart, 0)

		readback := task(protocol.KindConfigReadback,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
		result := runtime.Execute(context.Background(), readback)
		if result.Status != "healthy" || result.ErrorCode != "" {
			t.Fatalf("readback after a failed confirmation = %+v, want the unchanged healthy verdict", result)
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			t.Fatalf("readback receipt is not a legal result: %v", err)
		}
		if len(recorder.calls) != 1 {
			t.Fatalf("confirmation attempts = %+v, want exactly one", recorder.calls)
		}
		if !strings.Contains(log.String(), "UPDATE_BACKUP_CORRUPT") {
			t.Fatalf("confirmation failure was not logged with its stable code: %s", log.String())
		}
		// No effect on the frozen install result: the retry anchor survives.
		if _, ok, err := runtime.readHandoffResult(operationID); err != nil || !ok {
			t.Fatalf("failed confirmation consumed the upgrade record: ok=%v err=%v", ok, err)
		}
	})
}

// TestRevertResultReporting pins the revert outcome contract Task 4's transient
// executor writes. A rolled-back attempt ends the chain as rolled_back (with the
// original failure code), a failed revert is terminal with the revert's own
// stable code plus manual guidance, and a missing or invalid revert record never
// invents a verdict.
func TestRevertResultReporting(t *testing.T) {
	const failedTarget = "1.0.1"

	newFailedRuntime := func(t *testing.T) (*Runtime, string) {
		t.Helper()
		root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
		runtime := newConfirmRuntime(t, root, cfg, identity, runner,
			&runtimeTestController{candidate: testCandidate(7)}, nil)
		operationID := strings.Repeat("c", 32)
		failedHandoffFixture(t, root, runtime, operationID, failedTarget)
		return runtime, operationID
	}

	t.Run("rolled back", func(t *testing.T) {
		runtime, operationID := newFailedRuntime(t)
		writeRevertResultFile(t, runtime.root, operationID, failedTarget,
			runtime.cfg.AgentVersion, "rolled_back", "", 0)

		stage := task(protocol.KindConfigStage,
			operationID, strings.Repeat("e", 32), 11, 10)
		result := runtime.Execute(context.Background(), stage)
		// The status stays failed: the Hub's frozen result machine only accepts
		// rolled_back from "applying", and a gated/pending row that reports it
		// would be refused and retried forever. The restored release travels in
		// the bounded detail instead, so the outcome is still reported honestly.
		if result.Status != "failed" || result.ErrorCode != handoffIncompleteCode {
			t.Fatalf("revert receipt = %+v, want failed with the attempt's code", result)
		}
		if !strings.Contains(result.Detail, `"revert":"rolled_back"`) ||
			!strings.Contains(result.Detail, runtime.cfg.AgentVersion) {
			t.Fatalf("revert detail = %q, want the restored release", result.Detail)
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			t.Fatalf("revert receipt is not a legal result: %v", err)
		}
		// stagedConfigPath already roots the path; double-rooting it would make
		// this negative assertion vacuous (it would stat a path that can never
		// exist). Guard the helper's shape, then assert the real path.
		staged := stagedConfigPath(runtime.root, 10)
		if !strings.HasPrefix(staged, runtime.root+string(os.PathSeparator)) {
			t.Fatalf("staged config path %q is outside the fixture root %q", staged, runtime.root)
		}
		if _, err := os.Lstat(staged); !os.IsNotExist(err) {
			t.Fatalf("a rolled-back attempt touched the data plane: %v", err)
		}

		apply := task(protocol.KindConfigApply,
			strings.Repeat("d", 32), strings.Repeat("f", 32), 12, 10)
		if got := runtime.Execute(context.Background(), apply); got.Status != "failed" ||
			got.ErrorCode != handoffIncompleteCode {
			t.Fatalf("apply after a rolled-back attempt = %+v, want the attempt's stable failure", got)
		}
	})

	t.Run("revert failed is terminal", func(t *testing.T) {
		runtime, operationID := newFailedRuntime(t)
		writeRevertResultFile(t, runtime.root, operationID, failedTarget,
			runtime.cfg.AgentVersion, "failed", "CONFIG_CONFLICT", 1)

		apply := task(protocol.KindConfigApply,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
		result := runtime.Execute(context.Background(), apply)
		if result.Status != "failed" || result.ErrorCode != "CONFIG_CONFLICT" {
			t.Fatalf("failed revert receipt = %+v, want the revert's stable code", result)
		}
		// The long-form error string is discarded by Execute once a stable code
		// is set, so the operator hint must survive in the bounded detail.
		if !strings.Contains(result.Detail, `"action":"`+upgradeRevertManualAction+`"`) ||
			!strings.Contains(result.Detail, `"cause":"`+handoffIncompleteCode+`"`) {
			t.Fatalf("failed revert detail = %q, want the fixed manual-action hint", result.Detail)
		}
		if len(result.Detail) > 512 || strings.Contains(result.Detail, runtime.root) {
			t.Fatalf("failed revert detail is unbounded or leaks a path: %q", result.Detail)
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			t.Fatalf("failed revert receipt is not a legal result: %v", err)
		}
		// Terminal: a redelivery replays the same receipt and never retries the
		// revert or touches the data plane.
		if replay := runtime.Execute(context.Background(), apply); replay != result {
			t.Fatalf("replay = %+v, want the cached %+v", replay, result)
		}
	})

	t.Run("no revert result", func(t *testing.T) {
		runtime, _ := newFailedRuntime(t)
		apply := task(protocol.KindConfigApply,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
		result := runtime.Execute(context.Background(), apply)
		if result.Status != "failed" || result.ErrorCode != handoffIncompleteCode {
			t.Fatalf("receipt without a revert record = %+v, want the handoff failure", result)
		}
	})

	t.Run("invalid revert result invents nothing", func(t *testing.T) {
		runtime, operationID := newFailedRuntime(t)
		// An unknown field is corruption under the frozen schema, not a verdict.
		data := []byte(`{"schema":"meshmux-upgrade-revert/v1","operation_id":"` + operationID +
			`","target_version":"` + failedTarget + `","from_version":"` + runtime.cfg.AgentVersion +
			`","outcome":"rolled_back","exit_code":0,"ts":1,"claim":"applied"}`)
		dir := rooted(runtime.root, upgradeHandoffResultDir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, operationID+".revert.json"), data, 0600); err != nil {
			t.Fatal(err)
		}

		apply := task(protocol.KindConfigApply,
			strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 10)
		result := runtime.Execute(context.Background(), apply)
		if result.Status != "failed" || result.ErrorCode != handoffIncompleteCode {
			t.Fatalf("corrupt revert record became a verdict: %+v", result)
		}
	})
}

// TestReadbackAdvancesMarkerToVerifying is the §4.16 phase rule: the readback
// step owns `verifying`, so an upgrade marker that still exists when the
// readback runs (the in-memory adoption path) advances monotonically instead of
// staying at installed-awaiting-restart. The marker is only cleared once the
// on-disk pair is proven, exactly as 11c-2 froze.
func TestReadbackAdvancesMarkerToVerifying(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newConfirmRuntime(t, root, cfg, identity, runner,
		&runtimeTestController{candidate: testCandidate(7)}, nil)
	operationID := strings.Repeat("c", 32)
	handoff := upgradeHandoff{
		Schema:         upgradeHandoffSchema,
		State:          handoffRunning,
		Phase:          handoffPhaseInstalledAwaitingRestart,
		OperationID:    operationID,
		TargetVersion:  cfg.AgentVersion,
		ManifestSHA256: strings.Repeat("d", 64),
		Revision:       10,
		StartedAt:      time.Now().Unix(),
	}
	if err := runtime.writeUpgradeHandoff(handoff); err != nil {
		t.Fatal(err)
	}

	readback := task(protocol.KindConfigReadback,
		strings.Repeat("d", 32), strings.Repeat("e", 32), 11, 7)
	if result := runtime.Execute(context.Background(), readback); result.Status != "healthy" {
		t.Fatalf("readback = %+v, want healthy", result)
	}
	marker, ok, err := runtime.readUpgradeHandoff()
	if err != nil || !ok {
		t.Fatalf("marker after readback = %+v, %v, %v", marker, ok, err)
	}
	if marker.Phase != handoffPhaseVerifying {
		t.Fatalf("marker phase = %q, want %q", marker.Phase, handoffPhaseVerifying)
	}
	if marker.State != handoffRunning {
		t.Fatalf("marker state = %q, want running until the pair is proven", marker.State)
	}
}
