package core

import (
	"context"
	"os"
	"time"
)

// newOperationRecorder builds the journal append function for one operation.
// The caller still selects the journal path: a Line records under its own
// layout, while the Hub keeps the fixed installer path.
func NewOperationRecorder(operationID, journalPath string) func(stage, status, code string) error {
	return func(stage, status, code string) error {
		return AppendOperationEvent(journalPath, OperationEvent{OperationID: operationID, Stage: stage, Status: status, ErrorCode: code, Time: time.Now().UTC()})
	}
}

// ensureDebianPackages installs only the Debian packages missing from the
// host. The caller supplies the role-specific PACKAGE_INDEX_FAILED and
// PACKAGE_INSTALL_FAILED errors so Hub and Line keep their exact recovery
// wording. The missing set is returned because the Line checks it for nftables.
//
// python3-systemd is not a recommendation failure to leave to the base image:
// both Hub and Line jails use `backend = systemd`, and Debian only Recommends
// the binding package. Installing with --no-install-recommends leaves a
// minimal Debian 12 or 13 host with a Fail2ban that cannot load any jail.
func EnsureDebianPackages(ctx context.Context, runner CommandRunner, indexErr, installErr *InstallError) ([]string, *InstallError) {
	missing := MissingDebianPackages(ctx, runner, "ca-certificates", "fail2ban", "nftables", "python3-systemd")
	if len(missing) > 0 {
		if _, err := runner.Run(ctx, "apt-get", "update"); err != nil {
			return missing, indexErr
		}
		args := append([]string{"install", "-y", "--no-install-recommends"}, missing...)
		if _, err := runner.Run(ctx, "apt-get", args...); err != nil {
			return missing, installErr
		}
	}
	return missing, nil
}

// validateStagedUnits validates the generated systemd units and the Fail2ban
// configuration before any unit is started or reloaded.
func ValidateStagedUnits(ctx context.Context, runner CommandRunner, unitPaths []string, unitErr, fail2banErr *InstallError) *InstallError {
	if _, err := runner.Run(ctx, "systemd-analyze", append([]string{"verify"}, unitPaths...)...); err != nil {
		return unitErr
	}
	if _, err := runner.Run(ctx, "fail2ban-client", "-t"); err != nil {
		return fail2banErr
	}
	return nil
}

// restoreFileSnapshots undoes the staged file set recorded by the apply step.
// Snapshots are restored in reverse order, targets this operation created are
// removed, and restored targets are re-owned only when the installer runs
// against the live root. It reports whether every step succeeded so the caller
// can escalate a failed rollback to ROLLBACK_FAILED. Unit stop/start,
// daemon-reload and ledger reconciliation stay with the caller because Hub and
// Node differ there.
func RestoreFileSnapshots(root string, snapshots []FileSnapshot) bool {
	ok := true
	for i := len(snapshots) - 1; i >= 0; i-- {
		s := snapshots[i]
		if !s.Exists {
			if err := os.Remove(s.Target); err != nil && !os.IsNotExist(err) {
				ok = false
			}
			continue
		}
		if err := CopyAtomic(s.Backup, s.Target, s.Mode.Perm()); err != nil {
			ok = false
			continue
		}
		if root == "/" {
			if err := os.Chown(s.Target, s.UID, s.GID); err != nil {
				ok = false
			}
		}
	}
	return ok
}

// ensureFail2banRunning starts Fail2ban when it is inactive, otherwise reloads
// it so the new jail is loaded. A running daemon is never restarted.
func EnsureFail2banRunning(ctx context.Context, runner CommandRunner, startErr, reloadErr *InstallError) *InstallError {
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", "fail2ban.service"); err != nil {
		if _, runErr := runner.Run(ctx, "systemctl", "enable", "--now", "fail2ban.service"); runErr != nil {
			return startErr
		}
	} else if _, err := runner.Run(ctx, "fail2ban-client", "reload"); err != nil {
		return reloadErr
	}
	return nil
}
