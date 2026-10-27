package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CodeFail2banBaselineInvalid is the stable preflight code of a Fail2ban
// configuration that its own self-test rejects. The Node installer emits it
// before any pairing code can be consumed, so a broken packaged baseline never
// surfaces only while apply/verify is already replacing files.
const CodeFail2banBaselineInvalid = "FAIL2BAN_BASELINE_INVALID"

const (
	// CodeFail2banRepairFailed is the stable code of an operator-confirmed
	// baseline repair that could not be applied. The baseline code stays the
	// primary failure when the self-test still rejects the configuration.
	CodeFail2banRepairFailed = "FAIL2BAN_REPAIR_FAILED"
	// fail2banBaselineCheckName is the plan check that carries the self-test.
	fail2banBaselineCheckName = "fail2ban_baseline"
	// fail2banSystemdBackendPackage provides the `systemd` Fail2ban backend.
	// Every MeshMux jail uses backend = systemd, and Debian's fail2ban only
	// recommends this package; the installer installs with
	// --no-install-recommends, so a minimal image (Debian 12 and 13 alike)
	// otherwise starts no jail at all.
	fail2banSystemdBackendPackage = "python3-systemd"
	// fail2banBackendDropInPath is the MeshMux-owned override of only the
	// packaged sshd jail backend. It is a *.local drop-in, so Fail2ban reads
	// it after jail.conf/jail.local and only the named key changes.
	fail2banBackendDropInPath = fail2banJailDir + "/meshmux-backend.local"
)

// fail2banBackendDropInBody overrides exactly one key of the packaged sshd
// jail. No other jail, key or filter is touched.
const fail2banBackendDropInBody = `# MeshMux operator-confirmed Fail2ban baseline repair.
# The packaged sshd jail reads /var/log/auth.log, which a journal-only host
# does not have. Only the backend of that jail is overridden here.
[sshd]
backend = systemd
`

// fail2banBaselineRecovery is the single next action of a rejected baseline.
// It names the two repairs the installer can apply only after an explicit
// operator confirmation, so a --yes run can stop with the same instruction the
// interactive run offers.
const fail2banBaselineRecovery = "Install rsyslog so /var/log/auth.log exists (apt-get install -y --no-install-recommends rsyslog, then systemctl enable --now rsyslog.service) and re-run the install, or confirm a backend=systemd override for only the packaged sshd jail. python3-systemd is installed with the fixed Debian packages before the pairing code is consumed."

// Fail2banBaselineRepair is one operator-confirmed preflight repair. Only
// these two exists; the installer never edits an existing jail on its own.
type Fail2banBaselineRepair string

const (
	// Fail2banRepairRsyslog installs rsyslog so the packaged sshd jail finds
	// the /var/log/auth.log it expects.
	Fail2banRepairRsyslog Fail2banBaselineRepair = "rsyslog"
	// Fail2banRepairSystemdBackend writes a MeshMux-owned jail.d drop-in that
	// changes only the backend of the packaged sshd jail.
	Fail2banRepairSystemdBackend Fail2banBaselineRepair = "systemd-backend"
)

func (r Fail2banBaselineRepair) valid() bool {
	return r == Fail2banRepairRsyslog || r == Fail2banRepairSystemdBackend
}

// fail2banInstalled reports whether the fixed Debian package is already
// configured. A query failure is "not installed", the same rule
// missingDebianPackages uses.
func fail2banInstalled(ctx context.Context, runner CommandRunner, pkg string) bool {
	out, err := runner.Run(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	return err == nil && strings.Contains(string(out), "install ok installed")
}

// nodeFail2banBaselineCheck is the read-only preflight gate. It runs the
// packaged self-test only when Fail2ban is installed, because the binary does
// not exist before the fixed Debian packages are installed. When the binary is
// absent, or only the systemd backend package is absent, the report says the
// self-test is repeated after package installation and before pairing; the
// stage gate enforces exactly that.
func nodeFail2banBaselineCheck(ctx context.Context, runner CommandRunner) Check {
	if runner == nil {
		runner = ExecRunner{}
	}
	if !fail2banInstalled(ctx, runner, "fail2ban") {
		return Check{
			Name: fail2banBaselineCheckName, Status: "pass",
			Detail: "fail2ban is not installed yet; the fixed Debian packages are installed during stage and fail2ban-client -t runs again before the pairing code is consumed",
		}
	}
	if _, err := runner.Run(ctx, "fail2ban-client", "-t"); err != nil {
		if !fail2banInstalled(ctx, runner, fail2banSystemdBackendPackage) {
			// The fixed package set supplies the missing backend; the stage
			// gate then proves the self-test before pairing. Failing here would
			// demand a manual package install that the installer performs
			// itself.
			return Check{
				Name: fail2banBaselineCheckName, Status: "pass",
				Detail: fail2banSystemdBackendPackage + " is missing; the fixed Debian packages install it and fail2ban-client -t runs again before the pairing code is consumed",
			}
		}
		return Check{
			Name: fail2banBaselineCheckName, Status: "fail", Code: CodeFail2banBaselineInvalid,
			Detail:   "fail2ban-client -t rejected the packaged configuration",
			Recovery: fail2banBaselineRecovery,
		}
	}
	return Check{Name: fail2banBaselineCheckName, Status: "pass", Detail: "fail2ban-client -t passed"}
}

// requireFail2banBaseline is the stage gate: it runs the same self-test after
// the fixed Debian packages are installed and before identity/pairing work.
// A host whose baseline was only waiting for python3-systemd converges here
// instead of failing later in apply.
func requireFail2banBaseline(ctx context.Context, runner CommandRunner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if _, err := runner.Run(ctx, "fail2ban-client", "-t"); err != nil {
		return errors.New(CodeFail2banBaselineInvalid)
	}
	return nil
}

func fail2banBaselineError(recovery string) error {
	return &InstallError{Stage: "preflight", Code: CodeFail2banBaselineInvalid, Recovery: recovery}
}

// RepairNodeFail2banBaseline applies exactly one operator-confirmed repair,
// records the confirmation and its outcome in the operation journal, and
// re-runs the self-test. A repair that does not restore the baseline rolls
// back the change it made (the backend drop-in) instead of leaving an
// unverified jail override behind.
func RepairNodeFail2banBaseline(ctx context.Context, root, operationID string, repair Fail2banBaselineRepair, runner CommandRunner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if root == "" {
		root = "/"
	}
	if !operationIDPattern.MatchString(operationID) {
		return &InstallError{Stage: "preflight", Code: CodeOperationIDInvalid, Recovery: "Generate a new operation ID and retry."}
	}
	if !repair.valid() {
		return &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Choose rsyslog or systemd-backend; no host change was made."}
	}
	if !fail2banInstalled(ctx, runner, "fail2ban") {
		return fail2banBaselineError("Fail2ban is not installed yet; run the install so the fixed Debian packages are installed, then repair the baseline before pairing.")
	}
	layout, err := resolveNodeLayout(root)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return ie
		}
		return &InstallError{Stage: "preflight", Code: CodeInstallStateInvalid, Recovery: "Inspect the recorded installer state before repairing the Fail2ban baseline."}
	}
	journal := rooted(root, layout.OperationDir+"/"+operationID+"/events.jsonl")
	record := func(status, code, detail string) error {
		return appendOperationEvent(journal, operationEvent{
			OperationID: operationID, Stage: "preflight", Status: status, ErrorCode: code,
			Detail: detail, Time: time.Now().UTC(),
		})
	}
	// The confirmation is journaled before the first host change. A journal
	// that cannot be written stops the repair instead of leaving an
	// unauditable jail or package change behind.
	if err := record("fail2ban_repair_confirmed", "", string(repair)); err != nil {
		return &InstallError{Stage: "preflight", Code: "OPERATION_LOG_FAILED", Recovery: "Check installer state directory permissions and retry; no host change was made."}
	}
	rollback := func() error { return nil }
	switch repair {
	case Fail2banRepairRsyslog:
		if err := installRsyslogForBaseline(ctx, runner); err != nil {
			_ = record("fail2ban_repair_failed", CodeFail2banRepairFailed, string(repair))
			return err
		}
	case Fail2banRepairSystemdBackend:
		restore, err := applyFail2banBackendOverride(root)
		if err != nil {
			_ = record("fail2ban_repair_failed", CodeFail2banRepairFailed, string(repair))
			return err
		}
		rollback = restore
	}
	if err := requireFail2banBaseline(ctx, runner); err != nil {
		_ = rollback()
		_ = record("fail2ban_repair_failed", CodeFail2banBaselineInvalid, string(repair))
		return fail2banBaselineError(fail2banBaselineRecovery)
	}
	if err := record("fail2ban_repair_applied", "", string(repair)); err != nil {
		return &InstallError{Stage: "preflight", Code: "OPERATION_LOG_FAILED", Recovery: "The Fail2ban baseline now passes but the journal write failed; inspect the operation journal before retrying."}
	}
	return nil
}

// installRsyslogForBaseline installs only the fixed rsyslog package and starts
// it so the auth.log the packaged sshd jail expects exists.
func installRsyslogForBaseline(ctx context.Context, runner CommandRunner) error {
	if missing := missingDebianPackages(ctx, runner, "rsyslog"); len(missing) > 0 {
		if _, err := runner.Run(ctx, "apt-get", "update"); err != nil {
			return &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Check Debian repository connectivity; rsyslog was not installed and no Fail2ban jail was changed."}
		}
		args := append([]string{"install", "-y", "--no-install-recommends"}, missing...)
		if _, err := runner.Run(ctx, "apt-get", args...); err != nil {
			return &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Review Debian apt status; only the fixed rsyslog package is installed and no Fail2ban jail was changed."}
		}
	}
	if _, err := runner.Run(ctx, "systemctl", "enable", "--now", "rsyslog.service"); err != nil {
		return &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Start rsyslog manually so /var/log/auth.log exists, then run the install again."}
	}
	return nil
}

// applyFail2banBackendOverride writes the MeshMux-owned drop-in and returns
// the undo action. An existing path is only ever rewritten after the operator
// confirmed this exact repair, and its bytes are restored when the self-test
// still fails.
func applyFail2banBackendOverride(root string) (func() error, error) {
	path := rooted(root, fail2banBackendDropInPath)
	info, err := os.Lstat(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Inspect the Fail2ban drop-in path; symlinks and non-regular files are never replaced."}
	}
	if exists && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Inspect the Fail2ban drop-in path; symlinks and non-regular files are never replaced."}
	}
	var previous []byte
	if exists {
		previous, err = os.ReadFile(path)
		if err != nil {
			return nil, &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Read the existing Fail2ban drop-in before replacing it; no jail was changed."}
		}
	}
	if _, statErr := os.Lstat(filepath.Dir(path)); os.IsNotExist(statErr) {
		if mkErr := ensureDirectory(filepath.Dir(path), 0755); mkErr != nil {
			return nil, &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Create /etc/fail2ban/jail.d before writing the backend override."}
		}
	}
	if err := writeBytesAtomic(path, []byte(fail2banBackendDropInBody), 0644); err != nil {
		return nil, &InstallError{Stage: "preflight", Code: CodeFail2banRepairFailed, Recovery: "Check /etc/fail2ban/jail.d permissions; the backend override was not written."}
	}
	return func() error {
		if exists {
			return writeBytesAtomic(path, previous, 0644)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}, nil
}
