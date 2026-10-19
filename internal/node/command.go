package node

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const (
	systemctlPath = "/usr/bin/systemctl"
	nftPath       = "/usr/sbin/nft"
	ssPath        = "/usr/bin/ss"
	// RuntimeLockPath is shared by the Agent transaction writer and installer
	// repair. It is never held for the lifetime of the Agent process.
	RuntimeLockPath = "/var/lib/meshmux-agent/runtime.lock"
)

// CommandRunner is the fixed process boundary used by the Agent. Implementors
// execute one argv without a shell.
type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// ExecRunner invokes one executable with an explicit argv and no shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type runtimeLock struct {
	file *os.File
}

// AcquireRuntimeLock serializes dynamic Node writes across the Agent and
// install --repair. Callers must close the returned lock after their
// readback/apply/rollback transaction.
func AcquireRuntimeLock(ctx context.Context, root string) (io.Closer, error) {
	root, err := trustedRoot(root)
	if err != nil {
		return nil, err
	}
	return acquireRuntimeLock(ctx, root, true)
}

func acquireRuntimeLock(ctx context.Context, root string, wait bool) (io.Closer, error) {
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
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &runtimeLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || !wait {
			file.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, errors.New("RUNTIME_BUSY")
			}
			return nil, errors.New("RUNTIME_LOCK_FAILED")
		}
		timer := time.NewTimer(50 * time.Millisecond)
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

func checkOutACL(ctx context.Context, runner CommandRunner, root string, candidate Candidate) error {
	data, err := CompileACL(candidate)
	if err != nil {
		return err
	}
	if candidate.Role == RoleEdge {
		return nil
	}
	dir := rooted(root, agentDataDir)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".acl-check-*")
	if err != nil {
		return errors.New("ACL_CHECK_FILE_CREATE_FAILED")
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("ACL_CHECK_FILE_WRITE_FAILED")
	}
	_, err = runner.Run(ctx, nftPath, "-c", "-f", name)
	return err
}

// RunCommand runs the installed Agent. The hidden command accepts no
// arguments and uses only fixed production paths.
func RunCommand(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "USAGE: meshmux __internal-agent\n")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runInstalledAgent(ctx, stderr)
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
		"RUNTIME_STATE_UNSAFE",
	} {
		if errors.Is(err, stableError(stable)) {
			code = stable
			break
		}
	}
	_, _ = io.WriteString(stderr, code+"\n")
	return 1
}

type stableError string

func (e stableError) Error() string { return string(e) }

func runInstalledAgent(ctx context.Context, stderr io.Writer) error {
	cfgData, _, err := readPrivateFile(AgentConfigPath)
	if err != nil {
		return stableError("AGENT_CONFIG_UNSAFE")
	}
	var cfg Config
	if err := decodeStrictJSON(cfgData, &cfg); err != nil {
		return stableError("AGENT_CONFIG_UNAVAILABLE")
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
	selfHash, err := sha256File("/proc/self/exe")
	if err != nil || selfHash != cfg.AgentSHA256 {
		return stableError("AGENT_EXECUTABLE_MISMATCH")
	}
	if err := verifyExecutableHash(SingBoxBinaryPath, cfg.KernelSHA256); err != nil {
		return stableError("AGENT_KERNEL_MISMATCH")
	}
	controller, err := NewClient(cfg, identity, nil)
	if err != nil {
		return stableError("AGENT_CONTROLLER_UNAVAILABLE")
	}
	agentRuntime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root:       "/",
		Runner:     ExecRunner{},
		Controller: controller,
		Logger:     newRunLogger(stderr),
	})
	if err != nil {
		return err
	}
	return agentRuntime.Run(ctx)
}

func defaultPollInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	if d < time.Second {
		return time.Second
	}
	return d
}

var _ Controller = (*Client)(nil)
