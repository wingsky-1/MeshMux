package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

const (
	runtimeStateSchema = "meshmux-node-state/v1"
	journalTXNSchema   = "meshmux-node-journal/v1"
	maxIdempotency     = 1024
	maxFinalCache      = 1024
)

// stageTargetVersion is the release shape the Agent accepts for a stamped
// upgrade target. It mirrors the update CLI's own SemVer gate; a floating tag
// never reaches the fixed argv.
var stageTargetVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

// errRuntimeStateTooLarge refuses a runtime state that does not fit the
// state size bound. The previous readable state stays untouched.
var errRuntimeStateTooLarge = errors.New("RUNTIME_STATE_TOO_LARGE")

// Controller is the narrow outbound Hub control-plane boundary.
type Controller interface {
	Candidate(context.Context, int64) (CandidateDocument, error)
	Heartbeat(context.Context, protocol.HeartbeatRequest) error
	Tasks(context.Context) ([]protocol.Task, error)
	Report(context.Context, protocol.TaskResult) error
}

// RuntimeOptions supplies the fixed host boundary and outbound controller.
type RuntimeOptions struct {
	Root         string
	Runner       CommandRunner
	Controller   Controller
	HTTPClient   *http.Client
	Logger       *slog.Logger
	PollInterval time.Duration
	// LockTimeout bounds one poll-cycle wait for the shared runtime lock. Zero
	// means agentLockTimeout (5s, spec §4.9); tests set a shorter bound.
	LockTimeout time.Duration
	// StartupLockTimeout bounds the startup wait for that same lock. Zero means
	// runtimeStartupLockTimeout (60s, the installer's own unattended window);
	// tests set a shorter bound.
	StartupLockTimeout time.Duration
	// BootstrapReadbackTimeout bounds the whole startup readback retry, which
	// runs while the runtime lock is held. Zero means agentLockTimeout (5s), so
	// startup holds the lock no longer than one contended poll cycle; tests set
	// a shorter bound.
	BootstrapReadbackTimeout time.Duration
	// StageTargets reports the release the Hub stamped onto a pending
	// config.stage row (#11b). It is optional: without it every stage row is an
	// ordinary config stage, which is the pre-upgrade behaviour.
	StageTargets StageTargetSource
	// HandoffConvergence is the optional outside-sandbox writer that rewrites
	// agent.json after an in-memory crash-window adoption. Nil means
	// convergence is deferred to the next install --repair; the Agent never
	// writes /etc/meshmux/agent.json itself.
	HandoffConvergence HandoffConvergenceWriter
	// UpgradeConfirmation is the optional rollback-store seam of the finalize
	// side effect (spec §4.6). The updater owns the private 0700 store and its
	// N-1 GC, and this package cannot import it (the updater imports node), so
	// the accepted readback calls this contract instead of reimplementing the
	// record format. Nil means confirmation is unavailable: the readback still
	// succeeds, the Agent logs UPDATE_CONFIRM_UNAVAILABLE, and the next
	// readback retries.
	UpgradeConfirmation UpgradeConfirmer
	// UpgradeRevert is the optional transient revert executor (spec §4.7). A
	// failed attempt must have finished reverting before its first terminal
	// receipt is cached, so the Agent awaits this contract instead of spawning
	// a fire-and-forget child. Nil keeps Task 3's honest handoff failure.
	UpgradeRevert UpgradeReverter
}

// Runtime executes the frozen task set against one installed node.
type Runtime struct {
	cfg                 Config
	identity            Identity
	root                string
	runner              CommandRunner
	controller          Controller
	httpClient          *http.Client
	logger              *slog.Logger
	pollInterval        time.Duration
	lockTimeout         time.Duration
	bootstrapTimeout    time.Duration
	stageTargets        StageTargetSource
	handoffConvergence  HandoffConvergenceWriter
	upgradeConfirmation UpgradeConfirmer
	upgradeRevert       UpgradeReverter
	now                 func() time.Time
	procRoot            string
	writeState          func(*runtimeState) error
	enforceProcArgs     bool
}

// StageTarget is the release record the Hub stamped onto one pending
// config.stage row: the version and the pinned manifest digest the node should
// converge to. It is deliberately not a task parameter — config.* params stay
// frozen — so the Agent reads it over the outbound Hub boundary.
type StageTarget struct {
	Version        string
	ManifestSHA256 string
}

// StageTargetSource reports the stamped upgrade target of one config.stage
// task. A false ok means the row carries no target and is an ordinary config
// stage.
//
// The Hub exposes the read as `GET /api/agent/upgrade-target/{operation_id}` on
// the authenticated agent channel — the same shape as
// `GET /api/agent/config/{revision}` — returning the stamped `target_version` +
// `manifest_sha256` for the row regardless of its status (404 when the row is
// unstamped). `(*node.Client).StageTarget(ctx, operationID)` is the client side
// and is wired as `RuntimeOptions.StageTargets` by `runInstalledAgent`
// (internal/node/command.go). A runtime without a source keeps the pre-upgrade
// behaviour: a stamped row is staged as ordinary config instead of handing off,
// so no upgrade starts and nothing false is reported.
type StageTargetSource interface {
	StageTarget(context.Context, string) (StageTarget, bool, error)
}

type runtimeState struct {
	Schema           string   `json:"schema"`
	NodeID           string   `json:"node_id"`
	Role             Role     `json:"role"`
	Revision         int64    `json:"revision,omitempty"`
	LastTaskRevision int64    `json:"last_task_revision,omitempty"`
	Digest           string   `json:"digest,omitempty"`
	LKG              []byte   `json:"lkg,omitempty"`
	LKGDigest        string   `json:"lkg_digest,omitempty"`
	AllowedSources   []string `json:"allowed_sources,omitempty"`
	// AllowedSourcesRecorded distinguishes an applied empty allowlist (the
	// fail-closed default-deny data plane, which must be asserted exactly) from
	// no recorded authorization at all (a fresh bootstrap or a lost state file,
	// where only the guard shape can be proven).
	AllowedSourcesRecorded bool                           `json:"allowed_sources_recorded,omitempty"`
	Journal                *applyJournal                  `json:"journal,omitempty"`
	Idempotency            map[string]idempotencyItem     `json:"idempotency,omitempty"`
	FinalResults           map[string]protocol.TaskResult `json:"final_results,omitempty"`
}

// aclExpectation returns the readback expectation for this state: the recorded
// applied allowlist when one exists, otherwise a shape-only expectation.
//
// A state written before AllowedSourcesRecorded existed may still carry a
// non-empty list; that list is a real applied record, so it counts as recorded.
// An empty list without the flag is "nothing recorded", never "authorize
// nobody", because treating it as the latter would permanently fail an Out
// whose state file was lost until the Hub re-applied.
func (s runtimeState) aclExpectation() aclExpectation {
	recorded := s.AllowedSourcesRecorded || len(s.AllowedSources) > 0
	return aclExpectation{sources: s.AllowedSources, assertSet: recorded}
}

type idempotencyItem struct {
	PayloadDigest string              `json:"payload_digest"`
	TaskRevision  int64               `json:"task_revision"`
	OperationID   string              `json:"operation_id"`
	Result        protocol.TaskResult `json:"result"`
}

type applyJournal struct {
	Schema         string   `json:"schema"`
	OperationID    string   `json:"operation_id"`
	Idempotency    string   `json:"idempotency_key"`
	Payload        string   `json:"payload_digest"`
	TaskRevision   int64    `json:"task_revision"`
	Revision       int64    `json:"revision"`
	Digest         string   `json:"digest"`
	Candidate      []byte   `json:"candidate"`
	Config         []byte   `json:"config"`
	Reported       bool     `json:"reported"`
	ExpectedPID    int      `json:"expected_pid,omitempty"`
	PreviousPID    int      `json:"previous_pid,omitempty"`
	AllowedSources []string `json:"allowed_sources,omitempty"`
}

func emptyRuntimeState(cfg Config) runtimeState {
	return runtimeState{
		Schema:       runtimeStateSchema,
		NodeID:       cfg.NodeID,
		Role:         cfg.Role,
		Idempotency:  make(map[string]idempotencyItem),
		FinalResults: make(map[string]protocol.TaskResult),
	}
}

// NewRuntime validates all fixed paths and recovers an interrupted apply before
// returning a runtime that can execute new tasks. It uses a background lifetime:
// callers that own a shutdown signal should use NewRuntimeContext.
func NewRuntime(cfg Config, identity Identity, opts RuntimeOptions) (*Runtime, error) {
	return NewRuntimeContext(context.Background(), cfg, identity, opts)
}

// NewRuntimeContext is NewRuntime with the caller's lifetime attached to it. The
// startup wait for the shared runtime lock and the bootstrap readback retry both
// stop when ctx ends, so a stop request during startup is not delayed by the
// bounded lock wait or by a kernel that never becomes ready.
func NewRuntimeContext(ctx context.Context, cfg Config, identity Identity, opts RuntimeOptions) (*Runtime, error) {
	if err := cfg.ValidateInstalled(); err != nil {
		return nil, err
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return nil, err
	}
	if _, ok := KernelReleaseFor(runtime.GOARCH); !ok {
		return nil, errors.New("ARCHITECTURE_UNSUPPORTED")
	}
	root, err := trustedRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	if release, ok := KernelReleaseFor(runtime.GOARCH); !ok || root == "/" && cfg.KernelSHA256 != release.BinarySHA256 {
		return nil, errors.New("KERNEL_RELEASE_MISMATCH")
	}
	// Startup has no next poll to be redelivered on, so its lock wait is bounded
	// by the installer's own unattended window and expires as
	// RUNTIME_LOCK_TIMEOUT instead of waiting forever (spec §4.9 / D7).
	if opts.StartupLockTimeout <= 0 {
		opts.StartupLockTimeout = runtimeStartupLockTimeout
	}
	lock, err := acquireStartupRuntimeLock(ctx, root, opts.StartupLockTimeout)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Controller == nil {
		return nil, errors.New("CONTROLLER_REQUIRED")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if opts.LockTimeout <= 0 {
		opts.LockTimeout = agentLockTimeout
	}
	// The bootstrap readback runs while the startup lock is held: its whole
	// retry reuses the per-cycle lock budget, so a starting kernel costs the
	// shared lock one contended poll cycle and no more.
	if opts.BootstrapReadbackTimeout <= 0 {
		opts.BootstrapReadbackTimeout = agentLockTimeout
	}
	r := &Runtime{
		cfg:                 cfg,
		identity:            identity,
		root:                root,
		runner:              opts.Runner,
		controller:          opts.Controller,
		httpClient:          opts.HTTPClient,
		logger:              opts.Logger,
		pollInterval:        defaultPollInterval(opts.PollInterval),
		lockTimeout:         opts.LockTimeout,
		bootstrapTimeout:    opts.BootstrapReadbackTimeout,
		stageTargets:        opts.StageTargets,
		handoffConvergence:  opts.HandoffConvergence,
		upgradeConfirmation: opts.UpgradeConfirmation,
		upgradeRevert:       opts.UpgradeRevert,
		now:                 time.Now,
		procRoot:            rooted(root, "/proc"),
		enforceProcArgs:     root == "/",
	}
	r.writeState = r.persistState
	if err := r.ensureLayout(); err != nil {
		return nil, err
	}
	// Startup reconciliation runs before journal recovery (spec §4.6): the
	// marker decides whether the previous chain completed, is still owned by a
	// live unit, or must be failed locally. A corrupt marker refuses startup
	// with the manual-removal instruction instead of being guessed at.
	if err := r.reconcileHandoffOnBoot(); err != nil {
		return nil, err
	}
	state, err := r.loadOrInitializeState(ctx)
	if err != nil {
		return nil, err
	}
	if state.Journal != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err = r.recoverJournal(recoveryCtx, &state)
		cancel()
		if err != nil {
			r.logger.ErrorContext(context.Background(), "runtime recovery failed",
				"operation_id", state.Journal.OperationID, "error_code", errorCode(err))
			return nil, err
		}
	}
	if err := r.saveState(&state); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Runtime) ensureLayout() error {
	for _, dir := range []string{
		rooted(r.root, agentDataDir),
		rooted(r.root, stagedDir),
	} {
		if err := ensureNoSymlinkAncestors(r.root, dir); err != nil {
			return err
		}
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			if err = os.Mkdir(dir, 0700); err != nil {
				return errors.New("RUNTIME_DIRECTORY_CREATE_FAILED")
			}
			info, err = os.Lstat(dir)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("RUNTIME_DIRECTORY_UNSAFE")
		}
		if info.Mode().Perm() != 0700 {
			return errors.New("DATA_PERMISSIONS")
		}
	}
	return nil
}

func (r *Runtime) loadOrInitializeState(ctx context.Context) (runtimeState, error) {
	path := rooted(r.root, RuntimeStatePath)
	data, _, err := readRuntimeStateFile(path)
	if os.IsNotExist(err) {
		state := emptyRuntimeState(r.cfg)
		if err := r.bootstrapLKG(ctx, &state); err != nil {
			return state, err
		}
		if err := r.saveState(&state); err != nil {
			return state, err
		}
		return state, nil
	}
	if err != nil {
		return runtimeState{}, errors.New("RUNTIME_STATE_UNSAFE")
	}
	var state runtimeState
	if err := decodeStrictJSON(data, &state); err != nil || state.Schema != runtimeStateSchema ||
		state.NodeID != r.cfg.NodeID || state.Role != r.cfg.Role {
		return runtimeState{}, errors.New("RUNTIME_STATE_INVALID")
	}
	if state.Idempotency == nil {
		state.Idempotency = make(map[string]idempotencyItem)
	}
	for key, item := range state.Idempotency {
		if !terminalTaskResult(item.Result.Status) {
			delete(state.Idempotency, key)
		}
	}
	if state.FinalResults == nil {
		state.FinalResults = make(map[string]protocol.TaskResult)
	}
	return state, nil
}

func (r *Runtime) bootstrapLKG(ctx context.Context, state *runtimeState) error {
	candidateData, _, err := readRegularFile(rooted(r.root, ActiveCandidatePath), true)
	if err != nil {
		return errors.New("BOOTSTRAP_CANDIDATE_UNAVAILABLE")
	}
	var document CandidateDocument
	if err = decodeStrictJSON(candidateData, &document); err != nil {
		return errors.New("BOOTSTRAP_CANDIDATE_INVALID")
	}
	if err = document.ValidateFor(r.cfg); err != nil {
		return err
	}
	if err = writeStageAtomic(r.root, stagedCandidatePath(r.root, document.Revision), candidateData); err != nil {
		return err
	}
	configData, _, err := readRegularFile(rooted(r.root, ActiveConfigPath), false)
	if err != nil {
		return errors.New("BOOTSTRAP_CONFIG_UNAVAILABLE")
	}
	expected, err := CompileCandidate(document.Candidate())
	if err != nil || !bytes.Equal(configData, expected) {
		return errors.New("BOOTSTRAP_CONFIG_INVALID")
	}
	if err = writeStageAtomic(r.root, stagedConfigPath(r.root, document.Revision), configData); err != nil {
		return err
	}
	// No runtime state exists yet, so there is no trusted record of an applied
	// allowlist. The managed ACL file is deliberately not read here: a file
	// edited out of band would then authorize itself. The bootstrap readback
	// proves only the guard shape and both drops; the real authorization
	// arrives with the next Hub task and is recorded in state.json there.
	// The kernel may still be starting (systemd runs Agent and kernel
	// concurrently with no ordering between them). Poll for
	// startup-transient signals inside one bounded, cancellable budget;
	// anything deterministic fails fast so a broken data plane is never
	// mistaken for a slow one.
	readback, err := r.bootstrapReadback(ctx, document.Candidate(), sha256Hex(configData))
	if err != nil {
		return err
	}
	state.Revision = document.Revision
	state.Digest = sha256Hex(candidateData)
	state.LKG = append([]byte(nil), configData...)
	state.LKGDigest = readback.ConfigSHA256
	return nil
}

// bootstrapRetryInterval is the pause between startup readback attempts. The
// whole retry shares one bounded budget (BootstrapReadbackTimeout, agentLockTimeout
// by default), so the interval only decides how many chances fit inside it.
const bootstrapRetryInterval = 500 * time.Millisecond

// bootstrapReadback retries the first live readback while the failure still
// looks startup-transient. It is bounded and cancellable on purpose: the
// startup lock is held across it, so a slow kernel must cost the shared lock one
// agentLockTimeout budget at most (the same bound a contended poll cycle gets),
// and a stop request ends the wait at once instead of sleeping through it.
func (r *Runtime) bootstrapReadback(ctx context.Context, candidate Candidate, configHash string) (Readback, error) {
	budget := r.bootstrapTimeout
	if budget <= 0 {
		budget = agentLockTimeout
	}
	retryCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var lastTransient error
	for {
		readback, err := r.readbackFor(retryCtx, r.cfg.Role, candidate, configHash, aclExpectation{})
		if err == nil {
			return readback, nil
		}
		if ctx.Err() != nil {
			return Readback{}, errors.New("REQUEST_CANCELLED")
		}
		if !TransientReadback(err) {
			// The budget may have cut a live readback short (a killed systemctl
			// or ss). The last startup-transient signal is still the honest
			// verdict; a deterministic failure is reported as itself.
			if retryCtx.Err() != nil && lastTransient != nil {
				return Readback{}, lastTransient
			}
			return readback, err
		}
		lastTransient = err
		if retryCtx.Err() != nil {
			return Readback{}, lastTransient
		}
		timer := time.NewTimer(bootstrapRetryInterval)
		select {
		case <-retryCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return Readback{}, errors.New("REQUEST_CANCELLED")
			}
			return Readback{}, lastTransient
		case <-timer.C:
		}
	}
}

func (r *Runtime) persistState(state *runtimeState) error {
	if len(state.Idempotency) > maxIdempotency {
		state.trimAcknowledged()
		if len(state.Idempotency) > maxIdempotency {
			return errors.New("IDEMPOTENCY_CACHE_FULL")
		}
	}
	if len(state.FinalResults) > maxFinalCache {
		return errors.New("FINAL_OUTBOX_FULL")
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("RUNTIME_STATE_ENCODE_FAILED")
	}
	data = append(data, '\n')
	// The size is checked before the atomic replace, so a state that does not
	// fit never reaches the disk and the previous readable state stays in
	// place for the next start.
	if len(data) > maxRuntimeStateSize {
		return errRuntimeStateTooLarge
	}
	path := rooted(r.root, RuntimeStatePath)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return writeAtomic(path, data, 0600, false)
	}
	return writeAtomic(path, data, 0600, true)
}

func (r *Runtime) saveState(state *runtimeState) error {
	if r.writeState != nil {
		return r.writeState(state)
	}
	return r.persistState(state)
}

// statePersistCode maps a state persistence failure to a stable error code.
// A state that does not fit the size bound keeps its own code, because the
// previous readable state is still in place and only the new state was
// refused.
func statePersistCode(err error) string {
	if errors.Is(err, errRuntimeStateTooLarge) {
		return "RUNTIME_STATE_TOO_LARGE"
	}
	return "STATE_PERSIST_FAILED"
}

func (s *runtimeState) trimAcknowledged() {
	for key, item := range s.Idempotency {
		if _, pending := s.FinalResults[item.OperationID]; !pending && terminalTaskResult(item.Result.Status) {
			delete(s.Idempotency, key)
			if len(s.Idempotency) <= maxIdempotency {
				return
			}
		}
	}
}

// Execute validates and executes exactly one frozen task.
func (r *Runtime) Execute(ctx context.Context, task protocol.Task) protocol.TaskResult {
	// The upgrade gate is answered before the runtime lock (spec §4.9). While
	// an install is in flight an apply/readback must return its non-terminal
	// receipt without waiting behind the lock the install/repair holds; the
	// lock is only needed by work that would touch the data plane.
	if gated, stop := r.preLockHandoffGate(ctx, task); stop {
		r.logger.InfoContext(withOperation(ctx, task.OperationID), "task stage",
			"operation_id", task.OperationID, "stage", "handoff", "error_code", gated.ErrorCode)
		return gated
	}
	lock, err := acquireRuntimeLock(ctx, r.root, true, r.lockTimeout)
	if err != nil {
		return failedResult(protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}, errorCode(err))
	}
	defer lock.Close()
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	payload, err := canonicalTaskPayload(task)
	if err != nil {
		return failedResult(result, "TASK_ENCODE_FAILED")
	}
	digest := sha256Hex(payload)
	if err = protocol.ValidateTask(task); err != nil {
		if task.OperationID == "" {
			result.OperationID = strings.Repeat("0", 32)
		}
		return failedResult(result, errorCode(err))
	}
	if task.NodeID != r.cfg.NodeID {
		return failedResult(result, "NODE_SCOPE_MISMATCH")
	}
	revision, err := taskRevision(task)
	if err != nil {
		return failedResult(result, errorCode(err))
	}
	state, err := r.loadStateForExecution()
	if err != nil {
		return failedResult(result, errorCode(err))
	}
	if item, ok := state.Idempotency[task.IdempotencyKey]; ok {
		if item.PayloadDigest != digest || item.TaskRevision != task.Revision || item.OperationID != task.OperationID {
			return failedResult(result, "IDEMPOTENCY_CONFLICT")
		}
		return item.Result
	}
	for _, item := range state.Idempotency {
		if item.OperationID == task.OperationID {
			return failedResult(result, "OPERATION_REUSE_CONFLICT")
		}
	}
	if task.Revision <= state.LastTaskRevision {
		return failedResult(result, "TASK_REVISION_STALE")
	}
	if len(state.FinalResults) >= maxFinalCache {
		return failedResult(result, "FINAL_OUTBOX_FULL")
	}
	taskContext := withOperation(ctx, task.OperationID)
	allowed, hasAllowed, err := taskAllowedSources(task)
	if err != nil {
		return failedResult(result, errorCode(err))
	}
	r.logger.InfoContext(taskContext, "task stage",
		"operation_id", task.OperationID, "stage", "validate", "error_code", "")
	// The upgrade handoff keeps the chain open: while an install is in flight,
	// apply and readback must not touch the data plane. They report a legal
	// non-terminal state instead, so TASKS_IN_PROGRESS still sees an unfinished
	// chain and no step claims work it did not do.
	var executeErr error
	gated := false
	if task.Kind == protocol.KindConfigReadback ||
		task.Kind == protocol.KindConfigApply && state.Journal == nil {
		gateResult, stop, gateErr := r.handoffGate(ctx, task.OperationID)
		if stop {
			result, executeErr, gated = gateResult, gateErr, true
		}
	}
	if !gated {
		switch task.Kind {
		case protocol.KindConfigCheck:
			if state.Journal != nil {
				result, executeErr = failedResult(result, "RECOVERY_REQUIRED"), errors.New("RECOVERY_REQUIRED")
				break
			}
			result, executeErr = r.check(taskContext, revision, allowed)
		case protocol.KindConfigStage:
			if state.Journal != nil {
				result, executeErr = failedResult(result, "RECOVERY_REQUIRED"), errors.New("RECOVERY_REQUIRED")
				break
			}
			result, executeErr = r.stageOrHandOff(taskContext, task, revision, allowed)
		case protocol.KindConfigApply:
			if state.Journal != nil {
				return failedResult(result, "RECOVERY_REQUIRED")
			}
			applyResult := r.apply(taskContext, task, digest, revision, state, allowed)
			return applyResult
		case protocol.KindConfigReadback:
			result, executeErr = r.readback(taskContext, revision, allowed, hasAllowed)
		case protocol.KindHealthStatus, protocol.KindNodeStatus:
			result, executeErr = r.status(taskContext)
		default:
			executeErr = errors.New("TASK_KIND_REJECTED")
		}
	}
	if executeErr != nil && result.ErrorCode == "" {
		result = failedResult(result, errorCode(executeErr))
	}
	if result.Status == "partial" || result.Status == "failed" {
		result.Status = "failed"
	}
	if !terminalTaskResult(result.Status) {
		// A non-terminal receipt is not a final result: the step is redelivered
		// on the next poll and replays it while the handoff runs. Nothing is
		// cached and LastTaskRevision stays put, so the chain cannot be advanced
		// past a step that has not completed.
		r.logger.InfoContext(taskContext, "task stage",
			"operation_id", task.OperationID, "stage", "handoff", "error_code", result.ErrorCode)
		return result
	}
	final := result
	state.Idempotency[task.IdempotencyKey] = idempotencyItem{
		PayloadDigest: digest, TaskRevision: task.Revision, OperationID: task.OperationID, Result: final,
	}
	state.FinalResults[task.OperationID] = final
	state.LastTaskRevision = task.Revision
	if err := r.saveState(&state); err != nil {
		r.logger.ErrorContext(ctx, "persist final task result failed",
			"operation_id", task.OperationID, "error_code", errorCode(err))
		return failedResult(result, statePersistCode(err))
	}
	r.logger.InfoContext(taskContext, "task stage",
		"operation_id", task.OperationID, "stage", "final", "error_code", result.ErrorCode)
	return final
}

// preLockHandoffGate answers the upgrade gate without the runtime lock. Only a
// non-terminal answer (the install is in flight) takes this early path; a
// terminal gate answer falls through to the locked path so it is cached and
// replayed like every other final result. The cheap preconditions are the same
// ones the locked path would check first, so a malformed, stale or already
// answered task still gets its ordinary result.
func (r *Runtime) preLockHandoffGate(ctx context.Context, task protocol.Task) (protocol.TaskResult, bool) {
	if task.Kind != protocol.KindConfigApply && task.Kind != protocol.KindConfigReadback {
		return protocol.TaskResult{}, false
	}
	if err := protocol.ValidateTask(task); err != nil || task.NodeID != r.cfg.NodeID {
		return protocol.TaskResult{}, false
	}
	revision, err := taskRevision(task)
	if err != nil {
		return protocol.TaskResult{}, false
	}
	state, err := r.loadStateForExecution()
	if err != nil || revision <= state.LastTaskRevision {
		return protocol.TaskResult{}, false
	}
	if _, ok := state.Idempotency[task.IdempotencyKey]; ok {
		return protocol.TaskResult{}, false
	}
	for _, item := range state.Idempotency {
		if item.OperationID == task.OperationID {
			return protocol.TaskResult{}, false
		}
	}
	if task.Kind == protocol.KindConfigApply && state.Journal != nil {
		return protocol.TaskResult{}, false
	}
	result, stop, _ := r.handoffGate(ctx, task.OperationID)
	if !stop || terminalTaskResult(result.Status) {
		return protocol.TaskResult{}, false
	}
	return result, true
}

// stageOrHandOff runs the config.stage step of one task chain. A row stamped
// with an upgrade target that differs from the running version is not a local
// stage at all: the Agent starts the local update with the fixed argv and
// reports a non-terminal handoff receipt at once. Every other row keeps the
// existing stage path.
//
// The child is never waited for. The poll interval is 30s, so blocking here
// would stop the heartbeat and make a live node look offline for the length of
// an install. The handoff is recorded in the persisted marker before the child
// exists, and the stage row stays "applying" until the marker resolves, so the
// Hub keeps the whole chain open: apply and readback are gated (see
// handoffGate) and TASKS_IN_PROGRESS refuses a second approval.
//
// The update writes its verified rollback record to
// upgrade-backups/<operation_id>/record.json before it mutates anything
// (TestHandoffBacksUpBeforeMutating), so the rollback source exists regardless
// of how the handoff ends. The Agent never reads the child's Result; the
// separate <operation_id>.revert.json is the revert outcome it reads.
func (r *Runtime) stageOrHandOff(ctx context.Context, task protocol.Task, revision int64, allowed []string) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	handoff, pending, err := r.pendingUpgradeHandoff()
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if pending {
		// Advance the Agent-owned phase from the updater's result file and
		// apply the local 30-minute orphan rule before deciding who owns the
		// node. A marker that is already failed is never advanced again.
		handoff, err = r.reconcileHandoff(handoff)
		if err != nil {
			return failedResult(result, errorCode(err)), err
		}
	}
	if pending && handoff.OperationID == task.OperationID {
		if handoff.State == handoffFailed {
			return r.handoffFailureReceipt(ctx, task.OperationID, handoff)
		}
		if r.handoffInFlight(handoff) {
			// Redelivery while the install still runs: replay the same
			// non-terminal receipt and never start a second update.
			return upgradeQueuedReceipt(task.OperationID, handoff.TargetVersion), nil
		}
		// The owner chain is gone and the running release is still not the
		// target: the update did not install. Record the failure so the
		// remaining steps of this chain fail honestly, and fail this step.
		if err = r.failUpgradeHandoff(handoff); err != nil {
			return failedResult(result, errorCode(err)), err
		}
		return r.handoffFailureReceipt(ctx, task.OperationID, handoff)
	}
	if pending && handoff.State == handoffFailed {
		// A previous chain's upgrade failed. This new chain owns the node now:
		// drop the stale marker so its steps may run. The previous chain's own
		// rows are already terminal.
		if err = r.clearUpgradeHandoff(); err != nil {
			return failedResult(result, errorCode(err)), err
		}
		if err = r.clearUpgradeClaim(); err != nil {
			return failedResult(result, errorCode(err)), err
		}
	} else if pending {
		// A different chain is being installed. The Hub serializes chains, so
		// this is a contract violation; staging this row would let two installs
		// race. Refuse without touching anything.
		return failedResult(result, "UPDATE_HANDOFF_IN_PROGRESS"),
			errors.New("UPDATE_HANDOFF_IN_PROGRESS: another upgrade handoff owns this node")
	}
	target, stamped, err := r.stampedStageTarget(ctx, task)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if !stamped {
		return r.stage(ctx, revision, allowed)
	}
	spawner, ok := r.runner.(Spawner)
	if !ok {
		return failedResult(result, "UPDATE_SPAWN_UNAVAILABLE"), errors.New("UPDATE_SPAWN_UNAVAILABLE")
	}
	// The executable is the fixed installed Agent, never a caller-named path.
	// On a real root its digest is the configured one, so a swapped binary is
	// refused instead of started.
	binary, err := fixedBinary(r.root, AgentBinaryPath, r.cfg)
	if err != nil {
		return failedResult(result, errorCodeOr(err, "UPDATE_SPAWN_FAILED")), err
	}
	// The marker is written before the child exists, so a crash between the two
	// can never lose the gate that keeps apply off the data plane.
	record := upgradeHandoff{
		Schema:         upgradeHandoffSchema,
		State:          handoffRunning,
		Phase:          handoffPhaseStaged,
		OperationID:    task.OperationID,
		TargetVersion:  target.Version,
		ManifestSHA256: target.ManifestSHA256,
		Revision:       revision,
		StartedAt:      r.now().Unix(),
	}
	if err = r.writeUpgradeHandoff(record); err != nil {
		return failedResult(result, errorCode(err)), err
	}
	// The child outlives this poll cycle: a cancelled cycle (Agent shutdown,
	// task timeout) must not kill an update that is already installing. Its
	// lifetime is the update's own, not the poll's.
	pid, err := spawner.Spawn(context.WithoutCancel(ctx), binary,
		"__internal-update",
		"--target", target.Version,
		"--manifest-sha256", target.ManifestSHA256,
		"--operation-id", task.OperationID,
		"--confirm-target")
	if err != nil {
		// The update never started, so no install can be in flight: drop the
		// gate and fail the step. The node is not wedged.
		_ = r.clearUpgradeHandoff()
		return failedResult(result, "UPDATE_SPAWN_FAILED"), err
	}
	record.ChildPID = pid
	if err = r.writeUpgradeHandoff(record); err != nil {
		// The child is already running. The marker without its PID still gates
		// (by age), so keep going and log; refusing here would let apply run
		// against a version that is being replaced.
		r.logger.ErrorContext(ctx, "handoff marker pid not recorded",
			"operation_id", task.OperationID, "error_code", errorCode(err))
	}
	return upgradeQueuedReceipt(task.OperationID, target.Version), nil
}

// stampedStageTarget reports the upgrade target stamped onto this stage row and
// whether it is an upgrade at all. No source means the pre-upgrade behaviour: a
// plain config stage. A stamped target equal to the running version is the same
// chain's redelivery after the update installed it, so it is a plain stage too;
// treating it as a second upgrade would loop.
func (r *Runtime) stampedStageTarget(ctx context.Context, task protocol.Task) (StageTarget, bool, error) {
	if r.stageTargets == nil {
		return StageTarget{}, false, nil
	}
	target, ok, err := r.stageTargets.StageTarget(ctx, task.OperationID)
	if err != nil {
		return StageTarget{}, false, fmt.Errorf("STAGE_TARGET_UNAVAILABLE: %w", err)
	}
	if !ok {
		return StageTarget{}, false, nil
	}
	if !stageTargetVersion.MatchString(target.Version) || !sha256Pattern.MatchString(target.ManifestSHA256) {
		return StageTarget{}, false, errors.New("STAGE_TARGET_INVALID: target must be a pinned SemVer release")
	}
	if target.Version == r.cfg.AgentVersion {
		return StageTarget{}, false, nil
	}
	return target, true, nil
}

func (r *Runtime) loadStateForExecution() (runtimeState, error) {
	path := rooted(r.root, RuntimeStatePath)
	data, _, err := readRuntimeStateFile(path)
	if err != nil {
		return runtimeState{}, errors.New("RUNTIME_STATE_UNSAFE")
	}
	var state runtimeState
	if err = decodeStrictJSON(data, &state); err != nil || state.Schema != runtimeStateSchema ||
		state.NodeID != r.cfg.NodeID || state.Role != r.cfg.Role {
		return runtimeState{}, errors.New("RUNTIME_STATE_INVALID")
	}
	if state.Idempotency == nil {
		state.Idempotency = make(map[string]idempotencyItem)
	}
	if state.FinalResults == nil {
		state.FinalResults = make(map[string]protocol.TaskResult)
	}
	return state, nil
}

// Run heartbeats and drains tasks. Control-plane failures are logged and
// retried without touching an active data plane.
func (r *Runtime) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	r.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.cycle(ctx)
		}
	}
}

func (r *Runtime) cycle(ctx context.Context) {
	heartbeat := protocol.HeartbeatRequest{AgentVersion: r.cfg.AgentVersion, KernelVersion: KernelVersion}
	if err := heartbeat.Validate(); err != nil {
		r.logger.ErrorContext(ctx, "heartbeat invalid", "error_code", errorCode(err))
		return
	}
	if err := r.controller.Heartbeat(ctx, heartbeat); err != nil {
		r.logger.WarnContext(ctx, "heartbeat unavailable", "error_code", "CONTROL_PLANE_UNAVAILABLE")
	}
	if err := r.replayResults(ctx); err != nil {
		r.logger.WarnContext(ctx, "result replay unavailable", "error_code", errorCode(err))
		return
	}
	tasks, err := r.controller.Tasks(ctx)
	if err != nil {
		r.logger.WarnContext(ctx, "task poll unavailable", "error_code", "CONTROL_PLANE_UNAVAILABLE")
		return
	}
	for _, task := range tasks {
		if ctx.Err() != nil {
			return
		}
		var result protocol.TaskResult
		if task.Kind == protocol.KindConfigApply {
			if cached, ok := r.cachedTaskResult(task); ok {
				if reportErr := r.controller.Report(ctx, cached); reportErr != nil {
					if isAlreadyFinal(reportErr) {
						_ = r.removeOutbox(task.OperationID)
						continue
					}
					return
				}
				_ = r.removeOutbox(task.OperationID)
				continue
			}
			// While an upgrade handoff is in flight the apply step must not even
			// announce progress: the "applying" pre-report implies the data plane
			// is being changed. Execute still runs because it owns the gate
			// receipt and persists a terminal gate failure.
			if _, stop, _ := r.handoffGate(ctx, task.OperationID); stop {
				result = r.Execute(withApplyAcknowledged(ctx), task)
			} else {
				if reportErr := r.controller.Report(ctx, protocol.TaskResult{
					OperationID: task.OperationID, Status: "applying",
				}); reportErr != nil {
					if isAlreadyFinal(reportErr) {
						_ = r.removeOutbox(task.OperationID)
					}
					return
				}
				result = r.Execute(withApplyAcknowledged(ctx), task)
			}
		} else {
			result = r.Execute(ctx, task)
		}
		if result.ErrorCode == "RUNTIME_BUSY" {
			// The shared lock belongs to an install/repair. Reporting a failure
			// would end the chain over a transient condition, so skip this
			// cycle: the task is redelivered on the next poll, and this
			// cycle's heartbeat already went out above (spec §4.9).
			r.logger.WarnContext(ctx, "runtime busy; retry next poll",
				"operation_id", task.OperationID, "error_code", "RUNTIME_BUSY")
			return
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			result = failedResult(result, "RESULT_INVALID")
		}
		if err := r.controller.Report(ctx, result); err != nil {
			r.logger.WarnContext(ctx, "task report deferred",
				"operation_id", task.OperationID, "error_code", "RESULT_REPORT_UNAVAILABLE")
			if isAlreadyFinal(err) {
				_ = r.removeOutbox(task.OperationID)
				continue
			}
			return
		}
		if terminalTaskResult(result.Status) {
			_ = r.removeOutbox(task.OperationID)
		}
	}
}

func (r *Runtime) replayResults(ctx context.Context) error {
	state, err := r.loadStateForExecution()
	if err != nil {
		return err
	}
	for operationID, result := range state.FinalResults {
		if err = r.controller.Report(ctx, result); err != nil {
			if isAlreadyFinal(err) {
				r.logger.WarnContext(ctx, "report result already final",
					"operation_id", operationID, "error_code", "TASK_ALREADY_FINAL")
				delete(state.FinalResults, operationID)
				if err = r.saveState(&state); err != nil {
					return err
				}
				continue
			}
			return err
		}
		delete(state.FinalResults, operationID)
		if err = r.saveState(&state); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) cachedTaskResult(task protocol.Task) (protocol.TaskResult, bool) {
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	if err := protocol.ValidateTask(task); err != nil || task.NodeID != r.cfg.NodeID {
		return failedResult(result, errorCode(err)), true
	}
	payload, err := canonicalTaskPayload(task)
	if err != nil {
		return failedResult(result, "TASK_ENCODE_FAILED"), true
	}
	state, err := r.loadStateForExecution()
	if err != nil {
		return failedResult(result, errorCode(err)), true
	}
	if item, ok := state.Idempotency[task.IdempotencyKey]; ok {
		if item.PayloadDigest != sha256Hex(payload) || item.TaskRevision != task.Revision || item.OperationID != task.OperationID {
			return failedResult(result, "IDEMPOTENCY_CONFLICT"), true
		}
		return item.Result, true
	}
	for _, item := range state.Idempotency {
		if item.OperationID == task.OperationID {
			return failedResult(result, "OPERATION_REUSE_CONFLICT"), true
		}
	}
	if task.Revision <= state.LastTaskRevision {
		return failedResult(result, "TASK_REVISION_STALE"), true
	}
	if len(state.FinalResults) >= maxFinalCache {
		return failedResult(result, "FINAL_OUTBOX_FULL"), true
	}
	return protocol.TaskResult{}, false
}

func terminalTaskResult(status string) bool {
	switch status {
	case "healthy", "partial", "failed", "rolled_back":
		return true
	default:
		return false
	}
}

func (r *Runtime) removeOutbox(operationID string) error {
	state, err := r.loadStateForExecution()
	if err != nil {
		return err
	}
	delete(state.FinalResults, operationID)
	return r.saveState(&state)
}

func isAlreadyFinal(err error) bool {
	var clientErr *ClientError
	return errors.As(err, &clientErr) && clientErr.Code == "TASK_ALREADY_FINAL"
}

func canonicalTaskPayload(task protocol.Task) ([]byte, error) {
	var params any
	decoder := json.NewDecoder(bytes.NewReader(task.Params))
	decoder.UseNumber()
	if len(task.Params) == 0 || decoder.Decode(&params) != nil {
		return nil, errors.New("PARAMS_INVALID")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("PARAMS_INVALID")
	}
	task.Params = nil
	normalized, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	const marker = `"params":null`
	index := bytes.LastIndex(normalized, []byte(marker))
	if index < 0 {
		return nil, errors.New("TASK_ENCODE_FAILED")
	}
	result := make([]byte, 0, len(normalized)+len(paramsJSON))
	result = append(result, normalized[:index]...)
	result = append(result, `"params":`...)
	result = append(result, paramsJSON...)
	result = append(result, normalized[index+len(marker):]...)
	return result, nil
}

func taskRevision(task protocol.Task) (int64, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(task.Params, &values); err != nil {
		return 0, errors.New("PARAMS_INVALID")
	}
	if len(values) == 0 {
		return task.Revision, nil
	}
	raw, ok := values["revision"]
	if !ok {
		return 0, errors.New("PARAMS_INVALID")
	}
	var revision int64
	if err := json.Unmarshal(raw, &revision); err != nil || revision < 1 {
		return 0, errors.New("REVISION_INVALID")
	}
	return revision, nil
}

// taskAllowedSources extracts the optional per-Line source allowlist the Hub
// attaches to a config task. The boolean reports whether the task carried the
// key at all, so an explicit empty array ("authorize nobody") is distinct from
// an absent key ("no expectation"). An unknown or malformed value fails the
// task instead of silently applying a different authorization.
func taskAllowedSources(task protocol.Task) ([]string, bool, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(task.Params, &values); err != nil {
		return nil, false, errors.New("PARAMS_INVALID")
	}
	raw, ok := values["allowed_sources"]
	if !ok {
		return nil, false, nil
	}
	var allowed []string
	if err := json.Unmarshal(raw, &allowed); err != nil || allowed == nil {
		return nil, false, errors.New("ACL_SOURCE_INVALID: allowed_sources must be an array of strings")
	}
	if _, err := normalizeACLSources(allowed); err != nil {
		return nil, false, err
	}
	return allowed, true, nil
}

func currentOperation(ctx context.Context) string {
	if value, ok := ctx.Value(operationContextKey{}).(string); ok {
		return value
	}
	return strings.Repeat("0", 32)
}

type operationContextKey struct{}
type applyAcknowledgedKey struct{}

func withOperation(ctx context.Context, operationID string) context.Context {
	return context.WithValue(ctx, operationContextKey{}, operationID)
}

func withApplyAcknowledged(ctx context.Context) context.Context {
	return context.WithValue(ctx, applyAcknowledgedKey{}, true)
}

func applyAcknowledged(ctx context.Context) bool {
	value, _ := ctx.Value(applyAcknowledgedKey{}).(bool)
	return value
}

func failedResult(result protocol.TaskResult, code string) protocol.TaskResult {
	result.Status = "failed"
	result.ErrorCode = stableCode(code)
	result.Detail = ""
	return result
}

// stableCode returns code when it is one of the registered runtime codes, and
// taskFailedCode otherwise. Only the registry decides what reaches a task
// result: a caller-supplied message, a wrapped error and a free-form value all
// collapse to taskFailedCode instead of becoming an ad-hoc code.
func stableCode(code string) string {
	if isRuntimeCode(code) {
		return code
	}
	return taskFailedCode
}

// errorCode extracts the stable code of err. Only the text before the first
// colon can name a code, and only a registered one is returned; the rest of the
// message (a path, a digest, a raw subprocess line) stays out of the contract.
func errorCode(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if index := strings.IndexByte(message, ':'); index > 0 {
		message = message[:index]
	}
	return stableCode(message)
}

func errorCodeOr(err error, fallback string) string {
	code := errorCode(err)
	if code == "" || code == taskFailedCode {
		return stableCode(fallback)
	}
	return code
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func boundedDetail(data []byte) string {
	if len(data) <= 512 {
		return string(data)
	}
	var full, compact map[string]json.RawMessage
	if json.Unmarshal(data, &full) != nil {
		return "{}"
	}
	compact = make(map[string]json.RawMessage)
	for _, key := range []string{
		"active_revision", "agent_sha256", "agent_version", "architecture",
		"config_sha256", "kernel_sha256", "kernel_version", "local_active",
		"out_default_deny",
	} {
		if value, ok := full[key]; ok {
			compact[key] = value
		}
	}
	shortened, err := json.Marshal(compact)
	if err != nil || len(shortened) > 512 {
		return "{}"
	}
	return string(shortened)
}

func newRunLogger(writer io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey:
				return slog.Attr{}
			case slog.LevelKey:
				return slog.Attr{}
			}
			return attr
		},
	}))
}
