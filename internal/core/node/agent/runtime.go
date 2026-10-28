package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/client"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
	"github.com/wingsky-1/MeshMux/internal/logging"
)

const (
	runtimeStateSchema = "meshmux-node-state/v1"
	journalTXNSchema   = "meshmux-node-journal/v1"
	maxIdempotency     = 1024
	maxFinalCache      = 1024
	// journalRecoveryTimeout bounds one attempt to settle the interrupted-apply
	// journal. Recovery restores the LKG, restarts the kernel and proves it, so
	// it gets more than one poll cycle's lock budget; a host that cannot finish
	// inside it leaves the journal for the degraded retry below.
	journalRecoveryTimeout = 20 * time.Second
	// journalRecoveryRetryLimit bounds the degraded startup. A startup-transient
	// failure keeps check/stage/apply at RECOVERY_REQUIRED while the poll loop
	// retries; after this many attempts the journal is retired with the partial
	// receipt that was already recorded, so a kernel that never settles still
	// leaves the node manageable instead of refusing every config task forever.
	journalRecoveryRetryLimit = 3
)

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
	// journalRecoveryOperation and journalRecoveryAttempts track the degraded
	// startup retry in memory. They are deliberately not persisted: a restart
	// gets a fresh budget, while one Agent process never retries the same
	// unresolved journal forever.
	journalRecoveryOperation string
	journalRecoveryAttempts  int
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
	if _, ok := spec.KernelReleaseFor(runtime.GOARCH); !ok {
		return nil, errors.New("ARCHITECTURE_UNSUPPORTED")
	}
	root, err := trustedRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	if release, ok := spec.KernelReleaseFor(runtime.GOARCH); !ok || root == "/" && cfg.KernelSHA256 != release.BinarySHA256 {
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
		// The runtime and the client use one budget, so a slow Hub cannot make
		// the poll loop and the request layer disagree about a timeout.
		opts.HTTPClient = &http.Client{Timeout: client.DefaultRequestTimeout}
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
		// A journal that could not be settled must not end startup: systemd
		// would restart the Agent into the same failure, and the Hub would see a
		// crash loop instead of a node that can report. The failed attempt has
		// already recorded its terminal partial receipt in the state. Only the
		// journal that can still change on a later attempt is kept, so
		// check/stage/apply answer RECOVERY_REQUIRED while the poll loop
		// retries; everything else converges here and leaves a manageable node.
		operationID := state.Journal.OperationID
		recoveryCtx, cancel := context.WithTimeout(context.Background(), journalRecoveryTimeout)
		retryable, recoveryErr := r.recoverJournal(recoveryCtx, &state)
		cancel()
		if recoveryErr != nil {
			if retryable {
				r.journalRecoveryOperation = operationID
				r.journalRecoveryAttempts = 1
				r.logger.ErrorContext(context.Background(), "runtime recovery degraded",
					"operation_id", operationID, "error_code", errorCode(recoveryErr),
					"recovery_required", true)
			} else {
				r.logger.ErrorContext(context.Background(), "runtime recovery settled with a partial receipt",
					"operation_id", operationID, "error_code", errorCode(recoveryErr))
			}
		}
	}
	if err := r.saveState(&state); err != nil {
		// Nothing can be reported or retried without a durable state: this is
		// the one recovery-adjacent failure that still refuses startup.
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

// newRunLogger is the Agent's one log sink: JSON on stderr with the time and
// level keys dropped, because journald already stamps both and the stable codes
// in the message are what an operator greps. The level comes from
// internal/logging (default Warn, MESHMUX_LOG_LEVEL overrides), so a healthy
// 1s-heartbeat Agent stays out of the journal.
func newRunLogger(writer io.Writer) *slog.Logger {
	level, ok := logging.FromEnv()
	return newRunLoggerAt(writer, level, ok)
}

// newRunLoggerAt is newRunLogger with an explicit level resolution result, so a
// test can read what each setting emits without touching the process
// environment.
func newRunLoggerAt(writer io.Writer, level slog.Level, ok bool) *slog.Logger {
	logger := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: level,
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
	if !ok {
		// The value is never echoed: it is unvetted operator input. The stable
		// code points at MESHMUX_LOG_LEVEL and the floor is unchanged, so the
		// Agent still runs.
		logger.Warn("log_level_invalid", "error_code", "LOG_LEVEL_INVALID")
	}
	return logger
}
