package install

// The host-wide installer lock is owned by install/core's lock.go:
// AcquireInstallLock/AcquireInstallLockWithin take the single
// /run/lock/meshmux-install.lock flock without waiting (a non-interactive run
// retries for InstallLockWait), so a concurrent install fails as INSTALL_BUSY
// instead of blocking or interleaving with a running apply.
//
// It is not re-exported here because only the installer entry points acquire
// it; a caller that could take the lock directly could bypass the
// preflight -> stage -> apply -> verify sequencing it protects.
