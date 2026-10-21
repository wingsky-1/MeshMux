package install

import (
	"os"
	"path/filepath"
	"syscall"
)

// installLockPath is the single host-wide lock that serialises Hub and Line
// apply operations. It is a fixed internal path: no caller, user input or
// remote request can select the lock location.
const installLockPath = "/run/lock/meshmux-install.lock"

// installLock owns the descriptor that carries the installer flock.
type installLock struct {
	file *os.File
}

// acquireInstallLock takes the exclusive installer lock under root without
// waiting. A concurrent apply operation fails with INSTALL_BUSY instead of
// blocking. symlinkRecovery is the operator guidance for a rejected symlink
// ancestor; the Hub and Line callers keep their existing wording verbatim.
func acquireInstallLock(root, symlinkRecovery string) (*installLock, *InstallError) {
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
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, &InstallError{Stage: "preflight", Code: "INSTALL_BUSY", Recovery: "Another MeshMux installation is running; wait for it to finish."}
	}
	return &installLock{file: file}, nil
}

// Close releases the flock and the descriptor.
func (l *installLock) Close() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}
