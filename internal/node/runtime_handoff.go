package node

// The upgrade handoff marker (#11c-1). The stage step starts the local update
// and returns at once, so nothing in the chain can observe the child directly.
// The marker is that observation point, and it has three jobs:
//
//  1. It keeps the stage row non-terminal at the Hub: the Agent reports the
//     legal non-terminal status "applying" while the marker exists, so
//     TASKS_IN_PROGRESS still refuses a second approval and no healthy/staged
//     evidence is written before the new release is actually running.
//  2. It keeps config.apply and config.readback away from the data plane: both
//     report a non-terminal or explicitly failed result without staging,
//     activating or restarting anything while an install is in flight. A chain
//     step that has not run never claims it did.
//  3. It makes the handoff restart-safe: the marker is written before the child
//     is spawned and carries its PID, so a redelivered stage row (after an Agent
//     restart) starts no second install, and a child that is gone without
//     installing the target ends the chain with a stable failure instead of
//     wedging it.
//
// A marker is cleared when the running release equals its target (the update
// installed and this Agent restarted on the new version), when the child is gone
// without installing (the chain fails), or when a new chain's stage step claims
// the node after such a failure. Recovery of a half-installed host remains
// 11c-2/11c-3 territory.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

const (
	upgradeHandoffSchema = "meshmux-upgrade-handoff/v1"
	// upgradeHandoffPath lives in the private Agent directory, next to the runtime
	// state and the staged revisions.
	upgradeHandoffPath = "/var/lib/meshmux-agent/upgrade-handoff.json"
	// upgradeHandoffMaxAge bounds a marker whose child PID cannot be trusted any
	// more (PID reuse, a lost reaper). The update CLI bounds itself at 15
	// minutes, so twice that is comfortably past any honest install.
	upgradeHandoffMaxAge = 30 * time.Minute

	handoffRunning = "running"
	handoffFailed  = "failed"
)

// upgradeHandoff is the persisted "an update is in flight" record. It names the
// operation that approved it, the exact target, and the child PID used to tell
// a running install from one that died. State distinguishes a live install from
// one that ended without installing the target, so the remaining steps of the
// same chain fail honestly instead of running against the old release, while a
// later chain can still take the node.
type upgradeHandoff struct {
	Schema         string `json:"schema"`
	State          string `json:"state"`
	OperationID    string `json:"operation_id"`
	TargetVersion  string `json:"target_version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Revision       int64  `json:"revision"`
	ChildPID       int    `json:"child_pid"`
	StartedAt      int64  `json:"started_at"`
}

// readUpgradeHandoff reads the in-flight marker. A missing marker is
// (zero, false, nil); an unsafe or malformed one is a stable refusal, never a
// silently ignored file.
func (r *Runtime) readUpgradeHandoff() (upgradeHandoff, bool, error) {
	path := rooted(r.root, upgradeHandoffPath)
	data, _, err := readPrivateFile(path)
	if os.IsNotExist(err) {
		return upgradeHandoff{}, false, nil
	}
	if err != nil {
		return upgradeHandoff{}, false, errors.New("UPGRADE_HANDOFF_UNSAFE")
	}
	var handoff upgradeHandoff
	if decodeStrictJSON(data, &handoff) != nil || handoff.Schema != upgradeHandoffSchema ||
		!nodeIDPattern.MatchString(handoff.OperationID) ||
		!stageTargetVersion.MatchString(handoff.TargetVersion) ||
		!sha256Pattern.MatchString(handoff.ManifestSHA256) ||
		handoff.Revision < 1 || handoff.StartedAt < 1 || handoff.ChildPID < 0 ||
		handoff.State != handoffRunning && handoff.State != handoffFailed {
		return upgradeHandoff{}, false, errors.New("UPGRADE_HANDOFF_INVALID")
	}
	return handoff, true, nil
}

// writeUpgradeHandoff persists the marker atomically in the private Agent
// directory. It is written before the child exists, so a crash between the two
// can never lose the gate.
func (r *Runtime) writeUpgradeHandoff(handoff upgradeHandoff) error {
	data, err := json.MarshalIndent(handoff, "", "  ")
	if err != nil {
		return errors.New("UPGRADE_HANDOFF_ENCODE_FAILED")
	}
	data = append(data, '\n')
	path := rooted(r.root, upgradeHandoffPath)
	if err := ensureNoSymlinkAncestors(r.root, path); err != nil {
		return errors.New("UPGRADE_HANDOFF_UNSAFE")
	}
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := writeAtomic(path, data, 0600, false); err != nil {
		return errors.New("UPGRADE_HANDOFF_WRITE_FAILED")
	}
	return nil
}

// clearUpgradeHandoff removes the marker. A missing file is success: the caller
// only cares that no marker survives.
func (r *Runtime) clearUpgradeHandoff() error {
	if err := os.Remove(rooted(r.root, upgradeHandoffPath)); err != nil && !os.IsNotExist(err) {
		return errors.New("UPGRADE_HANDOFF_CLEAR_FAILED")
	}
	return nil
}

// handoffChildAlive reports whether the spawned update child still exists. The
// check goes through the runtime's proc root so the fixture host is inspected,
// never the real /proc.
func (r *Runtime) handoffChildAlive(pid int) bool {
	if pid < 1 {
		return false
	}
	_, err := os.Lstat(filepath.Join(r.procRoot, strconv.Itoa(pid)))
	return err == nil
}

// handoffInFlight reports whether the marker still describes a running update.
// A child that is gone means the update is over — either it installed (the
// running version then equals the target and the marker is cleared before this
// check) or it failed. The age bound covers a PID that cannot be observed
// (lost reaper, reused PID): the update CLI bounds itself at 15 minutes.
func (r *Runtime) handoffInFlight(handoff upgradeHandoff) bool {
	if handoff.State != handoffRunning {
		return false
	}
	if r.now().Sub(time.Unix(handoff.StartedAt, 0)) > upgradeHandoffMaxAge {
		return false
	}
	if handoff.ChildPID < 1 {
		// The spawn-time marker has no PID yet; the age bound still applies.
		return true
	}
	return r.handoffChildAlive(handoff.ChildPID)
}

// pendingUpgradeHandoff returns the marker that still governs this node, or
// (zero, false, nil) when none does. A marker whose target is already the
// running release means the update completed and this Agent restarted on it:
// the handoff is done, so the marker is cleared and the chain may continue as a
// normal chain.
func (r *Runtime) pendingUpgradeHandoff() (upgradeHandoff, bool, error) {
	handoff, ok, err := r.readUpgradeHandoff()
	if err != nil || !ok {
		return upgradeHandoff{}, false, err
	}
	if handoff.TargetVersion == r.cfg.AgentVersion {
		if err := r.clearUpgradeHandoff(); err != nil {
			return upgradeHandoff{}, false, err
		}
		return upgradeHandoff{}, false, nil
	}
	return handoff, true, nil
}

// upgradeQueuedReceipt is the stage step's non-terminal receipt: a legal
// "applying" result that says the handoff is queued, never that it was applied.
// The detail is stable across polls, so the Hub's in-place result check treats
// a redelivery as the same receipt.
func upgradeQueuedReceipt(operationID, target string) protocol.TaskResult {
	data, err := json.Marshal(struct {
		State  string `json:"state"`
		Target string `json:"target"`
	}{State: "queued", Target: target})
	if err != nil {
		data = []byte(`{"state":"queued"}`)
	}
	return protocol.TaskResult{OperationID: operationID, Status: "applying", Detail: string(data)}
}

// handoffGate is the apply/readback gate. It returns (receipt, true, nil) while
// an update is in flight: the caller must report that receipt (a legal
// non-terminal "applying", no detail) and must not touch the data plane. A
// marker that already failed returns the terminal UPDATE_HANDOFF_INCOMPLETE, so
// the rest of that chain ends honestly instead of applying the old release.
// (receipt, false, nil) means no handoff governs this node and the step may run
// normally.
func (r *Runtime) handoffGate(operationID string) (protocol.TaskResult, bool, error) {
	result := protocol.TaskResult{OperationID: operationID, Status: "failed"}
	handoff, pending, err := r.pendingUpgradeHandoff()
	if err != nil {
		return failedResult(result, errorCode(err)), true, err
	}
	if !pending {
		return protocol.TaskResult{}, false, nil
	}
	if r.handoffInFlight(handoff) {
		// "applying" is the only legal non-terminal result for a config step
		// that is waiting on the update. The detail stays empty: a step that has
		// not run must not name a target or a result, and the cycle pre-reports
		// the apply step with an empty detail too.
		return protocol.TaskResult{OperationID: operationID, Status: "applying"}, true, nil
	}
	return failedResult(result, "UPDATE_HANDOFF_INCOMPLETE"), true,
		errors.New("UPDATE_HANDOFF_INCOMPLETE: the update child exited before installing the target")
}

// failUpgradeHandoff records that the child is gone without installing the
// target. The marker stays in the failed state until a later chain's stage step
// claims the node, so the remaining steps of this chain fail with the same
// stable code instead of applying the old release.
func (r *Runtime) failUpgradeHandoff(handoff upgradeHandoff) error {
	handoff.State = handoffFailed
	handoff.ChildPID = 0
	return r.writeUpgradeHandoff(handoff)
}
