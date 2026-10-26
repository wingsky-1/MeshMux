package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// installLockPath is the single host-wide lock that serialises Hub and Line
// apply operations. It is a fixed internal path: no caller, user input or
// remote request can select the lock location.
const installLockPath = "/run/lock/meshmux-install.lock"

// installLockWait is the bounded wait an unattended install accepts for the
// host-wide lock (spec §4.9 / D7). An interactive run keeps the immediate
// INSTALL_BUSY refusal: a human can decide when to retry, while a Web-driven
// handoff has no operator and must survive one ordinary install holding the
// lock. Exhausting the window is UPDATE_RETRY_EXHAUSTED, never INSTALL_BUSY:
// the two name different remediation.
const installLockWait = 60 * time.Second

// installLock owns the descriptor that carries the installer flock.
type installLock struct {
	file *os.File
}

// acquireInstallLock takes the exclusive installer lock under root without
// waiting. A concurrent apply operation fails with INSTALL_BUSY instead of
// blocking. symlinkRecovery is the operator guidance for a rejected symlink
// ancestor; the Hub and Line callers keep their existing wording verbatim.
func acquireInstallLock(root, symlinkRecovery string) (*installLock, *InstallError) {
	return acquireInstallLockWithin(context.Background(), root, symlinkRecovery, 0)
}

// acquireInstallLockWithin takes the same lock, but for a positive wait it
// retries until the deadline (or ctx) instead of failing at once. The lock is
// still taken with LOCK_NB on every attempt, so a wedged holder can never block
// the caller past its own bound. A zero wait keeps the historical immediate
// INSTALL_BUSY behaviour byte for byte.
func acquireInstallLockWithin(ctx context.Context, root, symlinkRecovery string, wait time.Duration) (*installLock, *InstallError) {
	lockPath := rooted(root, installLockPath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return nil, &InstallError{Stage: "preflight", Code: "INSTALL_LOCK_UNAVAILABLE", Recovery: "Check /run/lock permissions and retry."}
	}
	if err := ensureNoSymlinkAncestors(filepath.Dir(lockPath)); err != nil {
		return nil, &InstallError{Stage: "preflight", Code: "INSTALL_LOCK_UNAVAILABLE", Recovery: symlinkRecovery}
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, &InstallError{Stage: "preflight", Code: "INSTALL_LOCK_UNAVAILABLE", Recovery: "Check /run/lock permissions and retry."}
	}
	var deadline time.Time
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &installLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = file.Close()
			return nil, &InstallError{Stage: "preflight", Code: "INSTALL_LOCK_UNAVAILABLE", Recovery: "Check /run/lock permissions and retry."}
		}
		if deadline.IsZero() {
			_ = file.Close()
			return nil, &InstallError{Stage: "preflight", Code: "INSTALL_BUSY", Recovery: "Another MeshMux installation is running; wait for it to finish."}
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, &InstallError{Stage: "preflight", Code: "UPDATE_RETRY_EXHAUSTED", Recovery: "Another MeshMux installation held the installer lock for the whole retry window; preserve the active data plane and retry the handoff after it finishes."}
		}
		poll := 50 * time.Millisecond
		if remaining := time.Until(deadline); remaining < poll {
			poll = remaining
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, &InstallError{Stage: "preflight", Code: "UPDATE_RETRY_EXHAUSTED", Recovery: "The handoff was cancelled while waiting for the installer lock; preserve the active data plane and retry once the other operation finishes."}
		case <-timer.C:
		}
	}
}

// Close releases the flock and the descriptor.
func (l *installLock) Close() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}
