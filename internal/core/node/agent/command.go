package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/client"
)

const (
	systemctlPath = "/usr/bin/systemctl"
	nftPath       = "/usr/sbin/nft"
	ssPath        = "/usr/bin/ss"
	// RuntimeLockPath is shared by the Agent transaction writer and installer
	// repair. It is never held for the lifetime of the Agent process.
	RuntimeLockPath = "/var/lib/meshmux-agent/runtime.lock"
	// defaultAgentPollInterval is the Agent's heartbeat and task-poll cadence:
	// one ticker carries both, so this is also how fast a queued task is
	// picked up. One second keeps last_heartbeat fresh against the Hub's
	// 2-minute OfflineAfter window at the cost of one small authenticated
	// request per second per node; the fleet is small, so the extra load is
	// accepted.
	defaultAgentPollInterval = time.Second
	// agentLockTimeout bounds one poll cycle's wait for the shared runtime
	// lock. A lock held by an install/repair costs one retry and never turns
	// into a terminal failure, so the task is simply redelivered on a later
	// poll (spec §4.9). The wait is longer than one 1s interval on purpose: a
	// contended cycle is dropped by the ticker, and the heartbeat sent at the
	// top of the next cycle is still far inside the Hub's 2-minute offline
	// window. The startup readback retry reuses this same budget: while the
	// lock is held for bootstrap, the Agent must not wait longer than one
	// contended poll cycle.
	agentLockTimeout = 5 * time.Second
	// runtimeStartupLockTimeout bounds the startup wait for that same lock. It
	// is the installer's own unattended window (install.installLockWait, 60s),
	// so startup survives exactly one ordinary install/repair and no more; a
	// host still holding the lock after that needs an operator, not a longer
	// wait. Expiry is RUNTIME_LOCK_TIMEOUT, never RUNTIME_BUSY: startup has no
	// next poll to be redelivered on (spec §4.9 / D7).
	runtimeStartupLockTimeout = 60 * time.Second
)

// CommandRunner is the fixed process boundary used by the Agent. Implementors
// execute one argv without a shell.
type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// Spawner is the start-only half of the same boundary. Spawn returns once the
// child exists, with its PID, and the Agent never waits for it: the poll loop
// must keep heartbeating while the child runs (1s poll interval). The PID is
// how the next poll tells "the update is still running" from "the child died
// without installing the target".
type Spawner interface {
	Spawn(context.Context, string, ...string) (int, error)
}

// ExecRunner invokes one executable with an explicit argv and no shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Spawn starts one fixed argv and returns without waiting. The child's exit is
// reaped on its own goroutine so a long-lived Agent accumulates no zombies; the
// caller's poll loop is never held. Stdin and stdout stay empty, so the child can
// never wait on a terminal, and its stderr joins the Agent's own journal so a
// failed update still leaves its stable code behind. A cgroup/transient-unit
// boundary for the child is 11c-2.
func (ExecRunner) Spawn(ctx context.Context, name string, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	return pid, nil
}

// The production runner must keep both halves of the boundary: a lost Spawn
// would turn every upgrade handoff into UPDATE_SPAWN_UNAVAILABLE at runtime.
var _ Spawner = ExecRunner{}

type runtimeLock struct {
	file *os.File
}

// AcquireRuntimeLock serializes dynamic Node writes across the Agent and
// install --repair. Callers must close the returned lock after their
// readback/apply/rollback transaction. The wait is bounded by ctx only: the
// installer owns its own lock-wait policy (spec §4.9 / D7).
func AcquireRuntimeLock(ctx context.Context, root string) (io.Closer, error) {
	root, err := trustedRoot(root)
	if err != nil {
		return nil, err
	}
	return acquireRuntimeLock(ctx, root, true, 0)
}

// acquireRuntimeLock takes the shared lock. With wait=false a busy lock is
// RUNTIME_BUSY at once; with wait=true it polls until ctx ends
// (RUNTIME_LOCK_CANCELLED) or, when timeout is positive, until that bound
// expires (RUNTIME_BUSY). The Agent passes agentLockTimeout for a poll cycle, so
// a contended lock costs one cycle at most.
func acquireRuntimeLock(ctx context.Context, root string, wait bool, timeout time.Duration) (io.Closer, error) {
	return acquireRuntimeLockWithin(ctx, root, wait, timeout, "RUNTIME_BUSY")
}

// acquireStartupRuntimeLock takes the shared lock for startup, where the wait is
// bounded by runtimeStartupLockTimeout. Exhausting it is RUNTIME_LOCK_TIMEOUT,
// not RUNTIME_BUSY: a poll cycle is redelivered on the next poll, while a
// startup that could not take the lock has no next cycle and must name its own
// refusal. The installer's own lock-wait policy is untouched (spec §4.9 / D7).
func acquireStartupRuntimeLock(ctx context.Context, root string, timeout time.Duration) (io.Closer, error) {
	lock, err := acquireRuntimeLockWithin(ctx, root, true, timeout, "RUNTIME_LOCK_TIMEOUT")
	if err != nil && errorCode(err) == "RUNTIME_LOCK_TIMEOUT" {
		// The exit line names the refusal itself: there is no task receipt to
		// carry it and no next poll to retry on.
		return nil, stableError("RUNTIME_LOCK_TIMEOUT")
	}
	return lock, err
}

// acquireRuntimeLockWithin takes the lock, reporting expiryCode when a positive
// timeout runs out. Every attempt is LOCK_NB, so a wedged holder can never block
// a caller past its own bound.
func acquireRuntimeLockWithin(ctx context.Context, root string, wait bool, timeout time.Duration, expiryCode string) (io.Closer, error) {
	path := rooted(root, RuntimeLockPath)
	if err := ensureNoSymlinkAncestors(root, path); err != nil {
		return nil, errors.New("RUNTIME_LOCK_UNSAFE")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, errors.New("RUNTIME_LOCK_UNAVAILABLE")
	}
	if err := ensurePrivateDirOwnedBy(filepath.Dir(path), managedFileUID(root)); err != nil {
		return nil, errors.New("RUNTIME_LOCK_UNSAFE")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("RUNTIME_LOCK_UNAVAILABLE")
	}
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		int(stat.Uid) != managedFileUID(root) {
		file.Close()
		return nil, errors.New("RUNTIME_LOCK_UNSAFE")
	}
	var deadline time.Time
	if wait && timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &runtimeLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			file.Close()
			return nil, errors.New("RUNTIME_LOCK_FAILED")
		}
		if !wait {
			file.Close()
			return nil, errors.New("RUNTIME_BUSY")
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			file.Close()
			return nil, errors.New(expiryCode)
		}
		poll := 50 * time.Millisecond
		if !deadline.IsZero() {
			if remaining := time.Until(deadline); remaining < poll {
				poll = remaining
			}
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			file.Close()
			return nil, errors.New("RUNTIME_LOCK_CANCELLED")
		case <-timer.C:
		}
	}
}

func (l *runtimeLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return errors.New("RUNTIME_UNLOCK_FAILED")
	}
	return closeErr
}

func verifyExecutableHash(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("EXECUTABLE_UNSAFE")
	}
	actual, err := sha256File(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("EXECUTABLE_SHA256_MISMATCH")
	}
	return nil
}

func fixedBinary(root, path string, cfg Config) (string, error) {
	if root != "/" {
		return rooted(root, path), nil
	}
	switch path {
	case AgentBinaryPath:
		return path, verifyExecutableHash(path, cfg.AgentSHA256)
	case SingBoxBinaryPath:
		return path, verifyExecutableHash(path, cfg.KernelSHA256)
	default:
		return "", errors.New("BINARY_PATH_REJECTED")
	}
}

func checkSingBox(ctx context.Context, runner CommandRunner, binary, configPath string) error {
	_, err := runner.Run(ctx, binary, "check", "-c", configPath)
	return err
}

// RunOption is one CLI-wired dependency of the installed Agent. The node
// package cannot import the updater (the updater imports node), so the
// outside-sandbox convergence writer is injected here instead of constructed.
type RunOption func(*RuntimeOptions)

// WithHandoffConvergence wires the writer that publishes agent.json after an
// in-memory crash-window adoption. Nil keeps the claim until the next repair.
func WithHandoffConvergence(writer HandoffConvergenceWriter) RunOption {
	return func(opts *RuntimeOptions) { opts.HandoffConvergence = writer }
}

// RunCommand runs the installed Agent. The hidden command accepts no
// arguments and uses only fixed production paths.
func RunCommand(args []string, stderr io.Writer, options ...RunOption) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "USAGE: meshmux __internal-agent\n")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runInstalledAgent(ctx, stderr, options)
	if err == nil {
		return 0
	}
	code := "AGENT_RUNTIME_FAILED"
	for _, stable := range []string{
		"AGENT_CONFIG_UNAVAILABLE",
		"AGENT_CONFIG_UNSAFE",
		"AGENT_IDENTITY_UNAVAILABLE",
		"AGENT_IDENTITY_UNSAFE",
		"AGENT_IDENTITY_MISMATCH",
		"AGENT_EXECUTABLE_MISMATCH",
		"AGENT_KERNEL_MISMATCH",
		"RUNTIME_LOCK_TIMEOUT",
		"RUNTIME_STATE_UNSAFE",
	} {
		if errors.Is(err, stableError(stable)) {
			code = stable
			break
		}
	}
	// Always include the underlying error detail (capped): the exit code
	// alone cannot distinguish a missing file from a poisoned state, and
	// that distinction is exactly what post-reboot debugging needs. Values
	// reaching here are ports, paths, hashes and stable codes.
	detail := firstErrorLine(err.Error())
	if detail == "" || detail == code {
		_, _ = io.WriteString(stderr, code+"\n")
	} else {
		_, _ = io.WriteString(stderr, code+": "+detail+"\n")
	}
	return 1
}

// firstErrorLine returns the first line of an error message, capped so logs
// stay one line and cannot smuggle multi-line payloads into journal output.
func firstErrorLine(msg string) string {
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	msg = strings.TrimSpace(msg)
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

type stableError string

func (e stableError) Error() string { return string(e) }

func runInstalledAgent(ctx context.Context, stderr io.Writer, options []RunOption) error {
	cfgData, _, err := readPrivateFile(AgentConfigPath)
	if err != nil {
		return stableError("AGENT_CONFIG_UNSAFE")
	}
	var cfg Config
	if err := decodeStrictJSON(cfgData, &cfg); err != nil {
		return stableError("AGENT_CONFIG_UNAVAILABLE")
	}
	// The self-check reads the running executable before validating the
	// recorded config: a crash between the Agent binary rename and the
	// agent.json rename leaves the new binary running against the old
	// agent.json, which must be recognized as the recoverable crash window
	// rather than as a config failure (spec §4.8).
	selfHash, err := sha256File("/proc/self/exe")
	if err != nil {
		return stableError("AGENT_EXECUTABLE_MISMATCH")
	}
	if selfHash != cfg.AgentSHA256 {
		adopted, adoptErr := adoptCrashWindowClaim("/", cfg, selfHash)
		if adoptErr != nil {
			return adoptErr
		}
		cfg = adopted
	}
	if err := cfg.ValidateInstalled(); err != nil {
		return stableError("AGENT_CONFIG_UNAVAILABLE")
	}
	identityData, _, err := readPrivateFile(IdentityPath)
	if err != nil {
		return stableError("AGENT_IDENTITY_UNSAFE")
	}
	var identity Identity
	if err := decodeStrictJSON(identityData, &identity); err != nil {
		return stableError("AGENT_IDENTITY_UNAVAILABLE")
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return stableError("AGENT_IDENTITY_MISMATCH")
	}
	if selfHash != cfg.AgentSHA256 {
		return stableError("AGENT_EXECUTABLE_MISMATCH")
	}
	if err := verifyExecutableHash(SingBoxBinaryPath, cfg.KernelSHA256); err != nil {
		return stableError("AGENT_KERNEL_MISMATCH")
	}
	controller, err := client.NewClient(cfg, identity, nil)
	if err != nil {
		return stableError("AGENT_CONTROLLER_UNAVAILABLE")
	}
	runtimeOpts := RuntimeOptions{
		Root:       "/",
		Runner:     ExecRunner{},
		Controller: controller,
		Logger:     newRunLogger(stderr),
		// The stamped upgrade target is read over the authenticated agent
		// channel (#11c-1): the target never travels in the frozen config.*
		// params. Without this the stage step would stage a stamped row as an
		// ordinary config change and no upgrade could ever start.
		StageTargets: controller,
	}
	for _, option := range options {
		option(&runtimeOpts)
	}
	agentRuntime, err := NewRuntimeContext(ctx, cfg, identity, runtimeOpts)
	if err != nil {
		return err
	}
	// Warn, not Info: the run sink's default floor is Warn (internal/logging),
	// so this is the one line that proves a restart reached the poll loop. An
	// operator needs it after an upgrade or after confirming the 1s heartbeat
	// cadence, and it is written once per process, not once per tick.
	agentRuntime.logger.Warn("agent_started", "role", string(cfg.Role), "agent_version", cfg.AgentVersion)
	return agentRuntime.Run(ctx)
}

func defaultPollInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultAgentPollInterval
	}
	// Sub-second overrides stay clamped: one heartbeat plus one task poll per
	// interval per node is the whole cost, so a shorter one only multiplies
	// requests without making liveness fresher than the Hub needs.
	if d < defaultAgentPollInterval {
		return defaultAgentPollInterval
	}
	return d
}

var _ Controller = (*client.Client)(nil)
