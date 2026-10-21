package install

import (
	"context"
	"time"
)

// newOperationRecorder builds the journal append function for one operation.
// The caller still selects the journal path: a Line records under its own
// layout, while the Hub keeps the fixed installer path.
func newOperationRecorder(operationID, journalPath string) func(stage, status, code string) error {
	return func(stage, status, code string) error {
		return appendOperationEvent(journalPath, operationEvent{OperationID: operationID, Stage: stage, Status: status, ErrorCode: code, Time: time.Now().UTC()})
	}
}

// ensureDebianPackages installs only the Debian packages missing from the
// host. The caller supplies the role-specific PACKAGE_INDEX_FAILED and
// PACKAGE_INSTALL_FAILED errors so Hub and Line keep their exact recovery
// wording. The missing set is returned because the Line checks it for nftables.
func ensureDebianPackages(ctx context.Context, runner CommandRunner, indexErr, installErr *InstallError) ([]string, *InstallError) {
	missing := missingDebianPackages(ctx, runner, "ca-certificates", "fail2ban", "nftables")
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
func validateStagedUnits(ctx context.Context, runner CommandRunner, unitPaths []string, unitErr, fail2banErr *InstallError) *InstallError {
	if _, err := runner.Run(ctx, "systemd-analyze", append([]string{"verify"}, unitPaths...)...); err != nil {
		return unitErr
	}
	if _, err := runner.Run(ctx, "fail2ban-client", "-t"); err != nil {
		return fail2banErr
	}
	return nil
}

// ensureFail2banRunning starts Fail2ban when it is inactive, otherwise reloads
// it so the new jail is loaded. A running daemon is never restarted.
func ensureFail2banRunning(ctx context.Context, runner CommandRunner, startErr, reloadErr *InstallError) *InstallError {
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", "fail2ban.service"); err != nil {
		if _, runErr := runner.Run(ctx, "systemctl", "enable", "--now", "fail2ban.service"); runErr != nil {
			return startErr
		}
	} else if _, err := runner.Run(ctx, "fail2ban-client", "reload"); err != nil {
		return reloadErr
	}
	return nil
}
