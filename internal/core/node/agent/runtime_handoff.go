package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
)

// The upgrade handoff marker (#11c-1, v2 in #11c-2). The stage step starts the
// local update and returns at once, so nothing in the chain can observe the
// update directly. The marker is that observation point, and it has three jobs:
//
//  1. It keeps the stage row non-terminal at the Hub: the Agent reports the
//     legal non-terminal status "applying" while the marker exists, so
//     TASKS_IN_PROGRESS still refuses a second approval and no healthy/staged
//     evidence is written before the new release is actually running.
//  2. It keeps config.apply and config.readback away from the data plane: both
//     report a non-terminal or explicitly failed result without staging,
//     activating or restarting anything while an install is in flight. A chain
//     step that has not run never claims it did.
//  3. It makes the handoff restart-safe: the marker is written before the
//     updater exists, and it is reconciled from the updater's own result file
//     and the transient unit's state after a restart or a crash, so a
//     redelivered stage row starts no second install and an ownerless attempt
//     ends the chain with a stable failure instead of wedging it.
//
// # Marker v2 and the single-writer rule
//
// The marker is Agent-exclusive: the transient updater never writes it (spec
// §4.7). The updater only writes <operation_id>.result.json; the Agent advances
// the marker's phase from that file. State and phase are one combination:
//
//	state   phase                        sole writer
//	running staged                       Agent stageOrHandOff (marker creation)
//	running installing                   Agent reconcileHandoff (result file)
//	running installed-awaiting-restart   Agent reconcileHandoff (result file)
//	running verifying                    Agent finalizeUpgradeReadback (accepted
//	                                     readback; 11c-3)
//	failed  the phase the attempt stopped at
//	                                     Agent failUpgradeHandoff / orphan boot
//
// Only (running, any phase) and (failed, the frozen endpoint phase) exist. A
// failed marker never advances its phase again; failure paths are the only
// writers of "failed", and the claim/gate paths are the only callers of
// failUpgradeHandoff. "installed-awaiting-restart" is a process signal, never
// restart proof: the phase plus the unit's exit status says the install was
// attempted, while the running release and the chain's readback decide whether
// the target is actually applied (spec §4.1/§4.6).
//
// # Revert result (11c-3)
//
// The revert executor (Task 4) writes its own <operation_id>.revert.json, not a
// new phase of <operation_id>.result.json: the install result schema is frozen
// at its three phases and its writer is the install unit, while a revert is a
// different verdict from a different transient unit. The file is versioned
// (meshmux-upgrade-revert/v1), lives in the same fixed private directory and is
// read with the same strict rules, so the Agent can report "rolled back" or a
// failed revert without touching the frozen 11c-2 contract.
//
// v1 markers (no phase, no error_code) remain readable as a strict, separate
// schema and are treated as "staged". Unknown fields are corruption in either
// version, never something to ignore.

const (
	upgradeHandoffSchemaV1 = "meshmux-upgrade-handoff/v1"
	// upgradeHandoffSchema is v2: v1 fields plus the monotonic phase and the
	// stable failure code. The schema is frozen for 11c-3.
	upgradeHandoffSchema = "meshmux-upgrade-handoff/v2"
	// upgradeHandoffPath lives in the private Agent directory, next to the
	// runtime state and the staged revisions.
	upgradeHandoffPath = "/var/lib/meshmux-agent/upgrade-handoff.json"
	// upgradeHandoffClaimPath is the installer's crash-window record. The
	// installer writes it between the Agent binary rename and the agent.json
	// rename (spec §4.8), and only the boot self-check consumes it. It is not
	// the handoff marker and the updater never writes it.
	upgradeHandoffClaimPath = "/var/lib/meshmux-agent/upgrade-claim.json"
	// upgradeHandoffResultDir is the updater's fixed work directory; the
	// result file name derives from the operation only.
	upgradeHandoffResultDir = "/var/lib/meshmux-agent/update"
	// upgradeHandoffUnitPrefix names the transient unit of one operation. It
	// must stay byte-identical to update.UnitActiveState's prefix; the node
	// package cannot import the updater (the updater imports node), so the
	// fixed argv below re-uses the same two names and no new command.
	upgradeHandoffUnitPrefix = "meshmux-update-"
	// upgradeHandoffResultSuffix is the frozen 11c-2 install-result name. The
	// readback finalize scans for it to recover the upgrade operation after the
	// marker is gone, so it is written once here.
	upgradeHandoffResultSuffix = ".result.json"
	// upgradeRevertSchema and upgradeRevertSuffix are the SEPARATE revert
	// result (spec §4.16 choice). The 11c-2 install result keeps its frozen
	// three-phase schema untouched; a revert is a different verdict from a
	// different transient executor (Task 4). Frozen for 11c-3 Task 3/4.
	upgradeRevertSchema = "meshmux-upgrade-revert/v1"
	upgradeRevertSuffix = ".revert.json"
	// upgradeRevertMaxBytes bounds the revert record read.
	upgradeRevertMaxBytes = 4096
	// upgradeResultScanMax bounds the directory scan that links the restarted
	// Agent back to its upgrade operation.
	upgradeResultScanMax = 256
	// upgradeHandoffMaxAge is D2's pure age bound: an ownerless attempt older
	// than this becomes a local failure without asking the Hub. The updater's
	// own install is bounded at 15 minutes, so twice that covers any honest run.
	upgradeHandoffMaxAge = 30 * time.Minute
	// upgradeHandoffCorruptMessage is the terminal boot refusal. The operator
	// gets the exact path to remove after proving no upgrade is running; the
	// Agent never guesses at a marker it cannot validate (fail-closed).
	upgradeHandoffCorruptMessage = "UPGRADE_HANDOFF_CORRUPT: upgrade-handoff.json is not a valid v1 or v2 marker; remove /var/lib/meshmux-agent/upgrade-handoff.json manually after confirming no upgrade is running"

	handoffRunning = "running"
	handoffFailed  = "failed"

	handoffPhaseStaged                   = "staged"
	handoffPhaseInstalling               = "installing"
	handoffPhaseInstalledAwaitingRestart = "installed-awaiting-restart"
	handoffPhaseVerifying                = "verifying"

	handoffOrphanedErrorCode = "UPGRADE_HANDOFF_ORPHANED"
	handoffIncompleteCode    = "UPDATE_HANDOFF_INCOMPLETE"
	handoffMismatchCode      = "AGENT_EXECUTABLE_MISMATCH"

	// The two frozen revert outcomes and the codes the finalize side effect
	// reports when it cannot run. These are logs only; they never change the
	// readback result, which stays the verdict.
	upgradeRevertRolledBack       = "rolled_back"
	upgradeRevertFailed           = "failed"
	upgradeConfirmUnavailableCode = "UPDATE_CONFIRM_UNAVAILABLE"
	upgradeConfirmFailedCode      = "UPDATE_CONFIRM_FAILED"
	upgradeRevertUnavailableCode  = "UPDATE_REVERT_UNAVAILABLE"

	// upgradeRevertManualAction is the fixed-vocabulary operator hint carried in
	// a failed-revert receipt. It names no path, host, secret or command: the
	// detail is stored and rendered by the Hub, so it stays a stable phrase the
	// UI can key on. The matching long-form guidance belongs in the operator
	// docs, not in this field.
	upgradeRevertManualAction = "inspect node and restore manually"
)

var errUpgradeHandoffCorrupt = errors.New(upgradeHandoffCorruptMessage)

// upgradeHandoff is the persisted "an update is in flight" record. It names the
// operation that approved it, the exact target, the phase the attempt reached
// and the stable failure code when it failed. State distinguishes a live
// attempt from one that ended without installing the target, so the remaining
// steps of the same chain fail honestly instead of running against the old
// release, while a later chain can still take the node.
type upgradeHandoff struct {
	Schema         string `json:"schema"`
	State          string `json:"state"`
	Phase          string `json:"phase"`
	ErrorCode      string `json:"error_code,omitempty"`
	OperationID    string `json:"operation_id"`
	TargetVersion  string `json:"target_version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Revision       int64  `json:"revision"`
	// ChildPID is diagnostic only since 11c-2. The updater helper exits after
	// systemd-run enqueues the transient unit, so the helper's PID says nothing
	// about the install; liveness is the unit state (handoffUnitState).
	ChildPID  int   `json:"child_pid"`
	StartedAt int64 `json:"started_at"`
}

// upgradeHandoffV1 is the pre-11c-2 shape. It is decoded separately and
// strictly, so a v1 file carrying a v2 field is corruption rather than a
// silently accepted upgrade.
type upgradeHandoffV1 struct {
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
// (zero, false, nil); an unsafe, malformed or unknown-schema one is the
// terminal manual-removal refusal, never a silently ignored file.
func (r *Runtime) readUpgradeHandoff() (upgradeHandoff, bool, error) {
	return readUpgradeHandoffFile(r.root)
}

func readUpgradeHandoffFile(root string) (upgradeHandoff, bool, error) {
	path := rooted(root, upgradeHandoffPath)
	data, _, err := readPrivateFile(path)
	if os.IsNotExist(err) {
		return upgradeHandoff{}, false, nil
	}
	if err != nil {
		return upgradeHandoff{}, false, errUpgradeHandoffCorrupt
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return upgradeHandoff{}, false, errUpgradeHandoffCorrupt
	}
	var handoff upgradeHandoff
	switch probe.Schema {
	case upgradeHandoffSchemaV1:
		var v1 upgradeHandoffV1
		if decodeStrictJSON(data, &v1) != nil {
			return upgradeHandoff{}, false, errUpgradeHandoffCorrupt
		}
		handoff = upgradeHandoff{
			Schema: upgradeHandoffSchema, State: v1.State, Phase: handoffPhaseStaged,
			OperationID: v1.OperationID, TargetVersion: v1.TargetVersion,
			ManifestSHA256: v1.ManifestSHA256, Revision: v1.Revision,
			ChildPID: v1.ChildPID, StartedAt: v1.StartedAt,
		}
	case upgradeHandoffSchema:
		if decodeStrictJSON(data, &handoff) != nil {
			return upgradeHandoff{}, false, errUpgradeHandoffCorrupt
		}
	default:
		return upgradeHandoff{}, false, errUpgradeHandoffCorrupt
	}
	if !validUpgradeHandoff(handoff) {
		return upgradeHandoff{}, false, errUpgradeHandoffCorrupt
	}
	return handoff, true, nil
}

func validUpgradeHandoff(handoff upgradeHandoff) bool {
	if handoff.Schema != upgradeHandoffSchema ||
		!protocol.ValidID(handoff.OperationID) ||
		!protocol.ValidSemVer(handoff.TargetVersion) ||
		!protocol.ValidSHA256(handoff.ManifestSHA256) ||
		handoff.Revision < 1 || handoff.StartedAt < 1 || handoff.ChildPID < 0 {
		return false
	}
	if handoff.State != handoffRunning && handoff.State != handoffFailed {
		return false
	}
	if _, ok := handoffPhaseRank(handoff.Phase); !ok {
		return false
	}
	if handoff.State == handoffRunning {
		// Only a failure path may name a failure, and a running attempt has
		// none yet.
		return handoff.ErrorCode == ""
	}
	return handoff.ErrorCode == "" || protocol.ValidErrorCode(handoff.ErrorCode)
}

// writeUpgradeHandoff persists the marker atomically in the private Agent
// directory. It is written before the updater exists, so a crash between the
// two can never lose the gate. The Agent is the only writer (spec §4.7).
func (r *Runtime) writeUpgradeHandoff(handoff upgradeHandoff) error {
	handoff.Schema = upgradeHandoffSchema
	if handoff.Phase == "" {
		handoff.Phase = handoffPhaseStaged
	}
	if !validUpgradeHandoff(handoff) {
		return errors.New("UPGRADE_HANDOFF_INVALID")
	}
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

// HandoffClaim is the installer's crash-window record (spec §4.8): the digest
// of the Agent binary that was just renamed into place, plus the operation that
// owns the rename. It is written between the binary and agent.json renames. It
// is not a protocol document and carries no version or prose. It is exported for
// the convergence writer contract below.
type HandoffClaim struct {
	NewSHA256   string `json:"new_sha256"`
	OperationID string `json:"operation_id"`
}

// HandoffConvergenceWriter is the convergence-writer contract for the on-disk
// half of the crash window. The Agent's unit keeps `/etc` read-only
// (ProtectSystem=strict, ReadOnlyPaths=agent.json), so the Agent NEVER writes
// agent.json: it adopts the verified disk hash in memory for this boot and
// leaves the claim in place. A process outside the Agent mount namespace — the
// transient one-shot updater or the next `install --repair` — must atomically
// rewrite agent.json so it names claim.NewSHA256. The Agent calls this hook when
// one is wired, then clears the claim only after a readback proves the on-disk
// pair matches; with no hook it keeps the claim for the next repair. Task 5 owns
// the writer implementation; this package owns the claim format and the
// post-convergence readback.
type HandoffConvergenceWriter interface {
	ConvergeHandoffConfig(context.Context, HandoffClaim) error
}

func readUpgradeClaimFile(root string) (HandoffClaim, bool, error) {
	path := rooted(root, upgradeHandoffClaimPath)
	data, _, err := readPrivateFile(path)
	if os.IsNotExist(err) {
		return HandoffClaim{}, false, nil
	}
	if err != nil {
		return HandoffClaim{}, false, errors.New("UPGRADE_CLAIM_UNSAFE")
	}
	var claim HandoffClaim
	if decodeStrictJSON(data, &claim) != nil ||
		!protocol.ValidSHA256(claim.NewSHA256) ||
		!protocol.ValidID(claim.OperationID) {
		return HandoffClaim{}, false, errors.New("UPGRADE_CLAIM_INVALID")
	}
	return claim, true, nil
}

func clearUpgradeClaimFile(root string) error {
	if err := os.Remove(rooted(root, upgradeHandoffClaimPath)); err != nil && !os.IsNotExist(err) {
		return errors.New("UPGRADE_CLAIM_CLEAR_FAILED")
	}
	return nil
}

func (r *Runtime) clearUpgradeClaim() error {
	return clearUpgradeClaimFile(r.root)
}

// handoffPairConverged is the readback that gates claim removal. It checks the
// on-disk pair: agent.json's digest and version must name the running build, and
// the on-disk Agent binary must hash to that same digest. An in-memory adoption
// alone never satisfies it because the old agent.json still carries the old
// digest, so the claim survives until an outside writer (or repair) converges.
func (r *Runtime) handoffPairConverged() bool {
	data, _, err := readPrivateFile(rooted(r.root, AgentConfigPath))
	if err != nil {
		return false
	}
	var onDisk Config
	if decodeStrictJSON(data, &onDisk) != nil {
		return false
	}
	if onDisk.AgentSHA256 != r.cfg.AgentSHA256 || onDisk.AgentVersion != r.cfg.AgentVersion {
		return false
	}
	diskHash, err := sha256File(rooted(r.root, AgentBinaryPath))
	return err == nil && diskHash == onDisk.AgentSHA256
}

// requestHandoffConvergence asks the outside-sandbox writer to rewrite
// agent.json. It is best effort and never fails the Agent: nil means the
// convergence is deferred to the next install --repair, which writes the same
// file as part of its normal apply.
func (r *Runtime) requestHandoffConvergence(ctx context.Context, claim HandoffClaim) {
	if r.handoffConvergence == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := r.handoffConvergence.ConvergeHandoffConfig(ctx, claim); err != nil {
		r.logger.WarnContext(ctx, "handoff config convergence unavailable",
			"operation_id", claim.OperationID, "error_code", errorCodeOr(err, "UPGRADE_CONVERGENCE_FAILED"))
	}
}

// settleHandoffClaim is the only claim-removal path. It may run on boot or
// immediately after a successful readback. The claim is cleared only after the
// on-disk pair readback matches; if the pair is still old, a configured writer
// gets one chance, and a missing/failed writer leaves the claim in place for the
// next repair. It never returns an error: convergence is never a startup
// failure.
func (r *Runtime) settleHandoffClaim(ctx context.Context) {
	claim, ok, err := readUpgradeClaimFile(r.root)
	if err != nil || !ok {
		return
	}
	if r.handoffPairConverged() {
		if err := r.clearUpgradeClaim(); err != nil {
			r.logger.WarnContext(ctx, "handoff claim could not be cleared",
				"operation_id", claim.OperationID, "error_code", errorCode(err))
		}
		return
	}
	// Never ask a writer to publish a config for a binary that is not the one
	// on disk: that would turn a failed install into a mismatched pair.
	diskHash, err := sha256File(rooted(r.root, AgentBinaryPath))
	if err != nil || diskHash != claim.NewSHA256 {
		return
	}
	r.requestHandoffConvergence(ctx, claim)
	if r.handoffPairConverged() {
		if err := r.clearUpgradeClaim(); err != nil {
			r.logger.WarnContext(ctx, "handoff claim could not be cleared",
				"operation_id", claim.OperationID, "error_code", errorCode(err))
		}
	}
}

// adoptCrashWindowClaim is the boot recovery of the one real window in the
// two-rename handoff (spec §4.2 amended, §4.8). The running binary's digest
// already failed the agent.json self-check, so the claim must prove all of the
// following:
//
//   - the digest of the binary actually on disk equals the claim record;
//   - the claim names the operation the pending marker names;
//   - the marker's target is exactly the running build's pinned version.
//
// Only then does this boot continue, with the in-memory identity taken from the
// verified disk hash and the claim. The Agent deliberately does NOT rewrite
// agent.json here: its unit has `/etc` read-only. That convergence belongs to a
// writer outside this mount namespace (the next install --repair or the
// transient one-shot updater); the claim stays until a pair readback proves the
// on-disk config matches. A missing claim, a stale claim and any mismatch are
// fail-closed: startup is refused with AGENT_EXECUTABLE_MISMATCH rather than
// guessing which bytes the host runs.
func adoptCrashWindowClaim(root string, cfg Config, selfHash string) (Config, error) {
	mismatch := func(detail string) error {
		return fmt.Errorf("%w: %s", stableError(handoffMismatchCode), detail)
	}
	if !protocol.ValidSHA256(selfHash) {
		return cfg, mismatch("the running executable digest is not 64 lowercase hex")
	}
	claim, ok, err := readUpgradeClaimFile(root)
	if err != nil {
		return cfg, mismatch("the crash-window claim record is unreadable")
	}
	if !ok {
		return cfg, mismatch("no crash-window claim record exists")
	}
	if claim.NewSHA256 != selfHash {
		return cfg, mismatch("the crash-window claim names another binary digest")
	}
	marker, ok, err := readUpgradeHandoffFile(root)
	if err != nil || !ok || marker.State != handoffRunning ||
		marker.OperationID != claim.OperationID ||
		marker.TargetVersion != spec.CurrentAgentVersion() {
		return cfg, mismatch("the claim does not match the pending handoff marker")
	}
	if err := verifyExecutableHash(rooted(root, AgentBinaryPath), selfHash); err != nil {
		return cfg, mismatch("the installed Agent binary does not match the claim record")
	}
	adopted := cfg
	adopted.AgentVersion = spec.CurrentAgentVersion()
	adopted.AgentSHA256 = selfHash
	if err := adopted.ValidateInstalled(); err != nil {
		return cfg, mismatch("the recovered configuration does not validate")
	}
	// In-memory only. The claim and the old agent.json stay exactly as they
	// are; NewRuntime's boot reconciliation keeps the claim and hands the
	// convergence to a writer outside this sandbox.
	return adopted, nil
}

// handoffResult is the fixed <operation_id>.result.json schema the updater
// writes (11c-2 Task 2, frozen). The node package cannot import the updater
// (the updater imports node), so the fields are mirrored here and read with the
// same strict rules: unknown fields, wrong mode/owner or a name that does not
// derive from its operation are refusals.
type handoffResult struct {
	OperationID string `json:"operation_id"`
	Phase       string `json:"phase"`
	ExitCode    int    `json:"exit_code"`
	Digest      string `json:"digest"`
	Target      string `json:"target"`
	Timestamp   int64  `json:"ts"`
}

func readHandoffResultFile(root, operationID string) (handoffResult, bool, error) {
	if !protocol.ValidID(operationID) {
		return handoffResult{}, false, errors.New("OPERATION_ID_INVALID")
	}
	name := operationID + upgradeHandoffResultSuffix
	path := rooted(root, filepath.Join(upgradeHandoffResultDir, name))
	data, _, err := readPrivateFile(path)
	if os.IsNotExist(err) {
		return handoffResult{}, false, nil
	}
	if err != nil {
		return handoffResult{}, false, errors.New("UPDATE_RESULT_INVALID")
	}
	var result handoffResult
	if decodeStrictJSON(data, &result) != nil || result.OperationID != operationID ||
		!protocol.ValidSemVer(result.Target) ||
		!protocol.ValidSHA256(result.Digest) ||
		result.ExitCode < 0 || result.ExitCode > 255 || result.Timestamp < 1 {
		return handoffResult{}, false, errors.New("UPDATE_RESULT_INVALID")
	}
	if _, ok := handoffPhaseRank(result.Phase); !ok {
		return handoffResult{}, false, errors.New("UPDATE_RESULT_INVALID")
	}
	// The result schema is frozen at Task 2's three phases; "verifying" is a
	// marker phase only and the updater never writes it.
	switch result.Phase {
	case handoffPhaseStaged, handoffPhaseInstalling, handoffPhaseInstalledAwaitingRestart:
	default:
		return handoffResult{}, false, errors.New("UPDATE_RESULT_INVALID")
	}
	return result, true, nil
}

func (r *Runtime) readHandoffResult(operationID string) (handoffResult, bool, error) {
	return readHandoffResultFile(r.root, operationID)
}

// handoffPhaseRank orders the monotonic phase. verifying belongs to the 11c-3
// readback step: the Agent advances a surviving marker to it from an accepted
// readback, and it is the last phase a running marker can reach.
func handoffPhaseRank(phase string) (int, bool) {
	switch phase {
	case handoffPhaseStaged:
		return 0, true
	case handoffPhaseInstalling:
		return 1, true
	case handoffPhaseInstalledAwaitingRestart:
		return 2, true
	case handoffPhaseVerifying:
		return 3, true
	default:
		return 0, false
	}
}

// Handoff unit liveness. D5 reads one fixed `systemctl show` of exactly
// ActiveState and ExecMainStatus; these are the same two fields, the same unit
// name and the same executable as 11c-2 Task 1's update.UnitActiveState. The
// node package cannot import the updater (the updater imports node), so this is
// the same fixed argv, not a new command surface.
type handoffUnitState string

const (
	handoffUnitActive       handoffUnitState = "active"
	handoffUnitReloading    handoffUnitState = "reloading"
	handoffUnitInactive     handoffUnitState = "inactive"
	handoffUnitFailed       handoffUnitState = "failed"
	handoffUnitActivating   handoffUnitState = "activating"
	handoffUnitDeactivating handoffUnitState = "deactivating"
	handoffUnitMaintenance  handoffUnitState = "maintenance"
)

var handoffUnitStates = map[handoffUnitState]bool{
	handoffUnitActive: true, handoffUnitReloading: true, handoffUnitInactive: true,
	handoffUnitFailed: true, handoffUnitActivating: true, handoffUnitDeactivating: true,
	handoffUnitMaintenance: true,
}

func handoffUnitRunning(state handoffUnitState) bool {
	switch state {
	case handoffUnitActive, handoffUnitReloading, handoffUnitActivating:
		return true
	default:
		return false
	}
}

func (r *Runtime) handoffUnitState(operationID string) (handoffUnitState, int, error) {
	if !protocol.ValidID(operationID) {
		return "", 0, errors.New("OPERATION_ID_INVALID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := r.runner.Run(ctx, systemctlPath, "show", "-p", "ActiveState", "-p", "ExecMainStatus",
		upgradeHandoffUnitPrefix+operationID)
	if err != nil {
		return "", 0, errors.New("UPDATE_UNIT_QUERY_FAILED")
	}
	var state handoffUnitState
	var status int
	var haveState, haveStatus bool
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			if haveState {
				return "", 0, errors.New("UPDATE_UNIT_STATE_INVALID")
			}
			state, haveState = handoffUnitState(value), true
		case "ExecMainStatus":
			if haveStatus {
				return "", 0, errors.New("UPDATE_UNIT_STATE_INVALID")
			}
			n, convErr := strconv.Atoi(value)
			if convErr != nil || n < 0 {
				return "", 0, errors.New("UPDATE_UNIT_STATE_INVALID")
			}
			status, haveStatus = n, true
		}
	}
	if !haveState || !haveStatus || !handoffUnitStates[state] {
		return "", 0, errors.New("UPDATE_UNIT_STATE_INVALID")
	}
	return state, status, nil
}
