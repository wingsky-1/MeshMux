package node

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
//	running verifying                    Agent (reserved for the 11c-3 readback step)
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
// v1 markers (no phase, no error_code) remain readable as a strict, separate
// schema and are treated as "staged". Unknown fields are corruption in either
// version, never something to ignore.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

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
)

var (
	errUpgradeHandoffCorrupt = errors.New(upgradeHandoffCorruptMessage)
	handoffFailureCodeRE     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

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
		!nodeIDPattern.MatchString(handoff.OperationID) ||
		!stageTargetVersion.MatchString(handoff.TargetVersion) ||
		!sha256Pattern.MatchString(handoff.ManifestSHA256) ||
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
	return handoff.ErrorCode == "" || handoffFailureCodeRE.MatchString(handoff.ErrorCode)
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
		!sha256Pattern.MatchString(claim.NewSHA256) ||
		!nodeIDPattern.MatchString(claim.OperationID) {
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
	if !sha256Pattern.MatchString(selfHash) {
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
		marker.TargetVersion != CurrentAgentVersion {
		return cfg, mismatch("the claim does not match the pending handoff marker")
	}
	if err := verifyExecutableHash(rooted(root, AgentBinaryPath), selfHash); err != nil {
		return cfg, mismatch("the installed Agent binary does not match the claim record")
	}
	adopted := cfg
	adopted.AgentVersion = CurrentAgentVersion
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
	if !nodeIDPattern.MatchString(operationID) {
		return handoffResult{}, false, errors.New("OPERATION_ID_INVALID")
	}
	name := operationID + ".result.json"
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
		!stageTargetVersion.MatchString(result.Target) ||
		!sha256Pattern.MatchString(result.Digest) ||
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

// handoffPhaseRank orders the monotonic phase. verifying is reserved for the
// 11c-3 readback step; it is legal in the schema but no writer produces it yet.
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
	if !nodeIDPattern.MatchString(operationID) {
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

// reconcileHandoff advances a running marker from the updater's result file
// (the Agent is the marker's only writer) and applies D2's ownerless rule. The
// result file's exit code and phase are process signals only: they are recorded
// by the phase transition, never interpreted as "applied".
func (r *Runtime) reconcileHandoff(handoff upgradeHandoff) (upgradeHandoff, error) {
	if handoff.State != handoffRunning {
		return handoff, nil
	}
	result, ok, err := r.readHandoffResult(handoff.OperationID)
	if err != nil {
		// A result the updater wrote but the Agent cannot validate is a local
		// failure, not a reason to leave the node wedged in "running". The
		// failed marker still blocks this chain and is clearable by a new one.
		handoff.State = handoffFailed
		handoff.ErrorCode = errorCodeOr(err, "UPDATE_RESULT_INVALID")
		handoff.ChildPID = 0
		if writeErr := r.writeUpgradeHandoff(handoff); writeErr != nil {
			return handoff, writeErr
		}
		return handoff, err
	}
	if ok {
		if result.Target != handoff.TargetVersion {
			handoff.State = handoffFailed
			handoff.ErrorCode = "UPDATE_RESULT_MISMATCH"
			handoff.ChildPID = 0
			if writeErr := r.writeUpgradeHandoff(handoff); writeErr != nil {
				return handoff, writeErr
			}
			return handoff, errors.New("UPDATE_RESULT_MISMATCH")
		}
		if next, _ := handoffPhaseRank(result.Phase); next > phaseRank(handoff.Phase) {
			handoff.Phase = result.Phase
			if err := r.writeUpgradeHandoff(handoff); err != nil {
				return handoff, err
			}
		}
	}
	if r.handoffOrphaned(handoff) {
		handoff.State = handoffFailed
		handoff.ErrorCode = handoffOrphanedErrorCode
		handoff.ChildPID = 0
		if err := r.writeUpgradeHandoff(handoff); err != nil {
			return handoff, err
		}
	}
	return handoff, nil
}

func phaseRank(phase string) int {
	rank, _ := handoffPhaseRank(phase)
	return rank
}

// handoffOrphaned is the local 30-minute rule (D2): no Hub query, no guessing
// about a chain that has disappeared. The age bound alone is not enough while
// the unit is still running; an active unit is the live owner of the attempt.
func (r *Runtime) handoffOrphaned(handoff upgradeHandoff) bool {
	if r.now().Sub(time.Unix(handoff.StartedAt, 0)) <= upgradeHandoffMaxAge {
		return false
	}
	state, _, err := r.handoffUnitState(handoff.OperationID)
	if err != nil {
		// Unobservable and over age: the owner cannot be proven alive.
		return true
	}
	return !handoffUnitRunning(state)
}

// handoffInFlight reports whether the marker still describes a running update.
// The updater helper's PID is no longer load-bearing: the transient unit and
// its result file are. Intent for the age bound is explicit: a unit that is
// still active owns the attempt and keeps it in flight even past 30 minutes
// (reconcileHandoff only fails an ownerless attempt); the age bound decides only
// when the unit cannot be observed or has not appeared yet (the updater helper
// may still be fetching). A finished unit with a result record is over — the
// caller fails the chain because the old release is still running.
func (r *Runtime) handoffInFlight(handoff upgradeHandoff) bool {
	if handoff.State != handoffRunning {
		return false
	}
	state, _, err := r.handoffUnitState(handoff.OperationID)
	overAge := r.now().Sub(time.Unix(handoff.StartedAt, 0)) > upgradeHandoffMaxAge
	if err != nil {
		// Unobservable: the local age bound is the only safe verdict.
		return !overAge
	}
	if handoffUnitRunning(state) {
		return true
	}
	if overAge {
		// Defensive: reconcileHandoff has already turned this ownerless
		// attempt into the failed/UPGRADE_HANDOFF_ORPHANED state.
		return false
	}
	if _, ok, err := r.readHandoffResult(handoff.OperationID); err == nil && ok {
		return false
	}
	return true
}

// pendingUpgradeHandoff returns the marker that still governs this node, or
// (zero, false, nil) when none does. A marker whose target is already the
// running release means the install reached the running build: the handoff no
// longer gates the chain, and this is never an applied claim (readback remains
// the anchor). The marker itself is cleared only after the on-disk pair
// readback passes; an in-memory adoption (old agent.json, new binary) keeps the
// marker and claim for the outside convergence writer / next repair while
// still letting apply and readback run against the running target.
func (r *Runtime) pendingUpgradeHandoff() (upgradeHandoff, bool, error) {
	handoff, ok, err := r.readUpgradeHandoff()
	if err != nil || !ok {
		return upgradeHandoff{}, false, err
	}
	if handoff.TargetVersion == r.cfg.AgentVersion {
		if r.handoffPairConverged() {
			if err := r.clearUpgradeHandoff(); err != nil {
				return upgradeHandoff{}, false, err
			}
			if err := r.clearUpgradeClaim(); err != nil {
				return upgradeHandoff{}, false, err
			}
		}
		return upgradeHandoff{}, false, nil
	}
	return handoff, true, nil
}

// reconcileHandoffOnBoot is the startup half of the recovery rules (spec §4.2
// amended, §4.6), called by NewRuntime before journal recovery. It never claims
// the upgrade applied: when the running release is the target it only releases
// the gate so the chain's readback step can prove the result. A corrupt marker
// is a terminal refusal. An in-memory claim adoption never fails startup and
// never clears the claim: convergence happens outside this sandbox.
func (r *Runtime) reconcileHandoffOnBoot() error {
	handoff, ok, err := r.readUpgradeHandoff()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if !ok {
		// A claim can outlive its marker (a completed or repaired handoff).
		// Settle it only by the on-disk pair readback; never invent a marker.
		r.settleHandoffClaim(ctx)
		return nil
	}
	if handoff.State == handoffRunning && handoff.TargetVersion == r.cfg.AgentVersion {
		if r.handoffPairConverged() {
			if err := r.clearUpgradeHandoff(); err != nil {
				return err
			}
			r.settleHandoffClaim(ctx)
			return nil
		}
		// The target is running but agent.json still names the old binary:
		// this is the in-memory adoption branch. Ask an outside-sandbox
		// writer once, if one is wired, then re-read the pair. A missing
		// writer keeps both records for the next install --repair.
		r.settleHandoffClaim(ctx)
		if r.handoffPairConverged() {
			if err := r.clearUpgradeHandoff(); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := r.reconcileHandoff(handoff); err != nil {
		// A corrupt updater result must not prevent the Agent from starting;
		// the marker has already been moved to failed where possible, and the
		// chain gate reports the stable code.
		r.logger.ErrorContext(ctx, "upgrade handoff result rejected on boot",
			"operation_id", handoff.OperationID, "error_code", errorCode(err))
		return nil
	}
	// A failed marker is intentionally left in place: only a later chain's
	// stage step may clear it (D2), and this Agent has just started with no
	// chain to resolve it.
	return nil
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
// marker that already failed returns its recorded terminal code, so the rest of
// that chain ends honestly instead of applying the old release.
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
	handoff, err = r.reconcileHandoff(handoff)
	if err != nil {
		return failedResult(result, errorCode(err)), true, err
	}
	if r.handoffInFlight(handoff) {
		// "applying" is the only legal non-terminal result for a config step
		// that is waiting on the update. The detail stays empty: a step that has
		// not run must not name a target or a result, and the cycle pre-reports
		// the apply step with an empty detail too.
		return protocol.TaskResult{OperationID: operationID, Status: "applying"}, true, nil
	}
	if err := r.failUpgradeHandoff(handoff); err != nil {
		return failedResult(result, errorCode(err)), true, err
	}
	code := handoffFailureCode(handoff)
	return failedResult(result, code), true,
		fmt.Errorf("%s: the update unit finished without installing the target", code)
}

func handoffFailureCode(handoff upgradeHandoff) string {
	if handoff.ErrorCode != "" {
		return handoff.ErrorCode
	}
	return handoffIncompleteCode
}

// failUpgradeHandoff records that the owner chain is gone without installing
// the target. The marker stays in the failed state until a later chain's stage
// step claims the node, so the remaining steps of this chain fail with the same
// stable code instead of applying the old release. The phase is frozen at the
// endpoint the attempt reached.
func (r *Runtime) failUpgradeHandoff(handoff upgradeHandoff) error {
	if handoff.State == handoffFailed {
		return nil
	}
	handoff.State = handoffFailed
	handoff.ErrorCode = handoffIncompleteCode
	handoff.ChildPID = 0
	return r.writeUpgradeHandoff(handoff)
}
