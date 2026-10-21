package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// hubApplyErrors carries the exact Hub apply/verify failure templates. The Hub
// recovery wording must stay verbatim and guard-checked, so InstallHub owns
// every literal and this phase only selects the applicable entry.
type hubApplyErrors struct {
	packageIndex      *InstallError
	packageInstall    *InstallError
	accountCreate     *InstallError
	dataDirectory     *InstallError
	backupDirectory   *InstallError
	backupSnapshot    *InstallError
	fileApply         *InstallError
	fileOwnership     *InstallError
	fileReadback      *InstallError
	stateWritePerFile *InstallError
	journalFilesWrite *InstallError
	systemdUnit       *InstallError
	fail2banConfig    *InstallError
	journalValidated  *InstallError
	systemdReload     *InstallError
	unitStartRecovery string
	fail2banStart     *InstallError
	fail2banReload    *InstallError
	sshJail           *InstallError
	caddyStart        *InstallError
	serviceVerify     *InstallError
	finalLedger       *InstallError
	journalVerifyPass *InstallError
}

// hubApplyAndVerify runs the Hub apply and verify phases: package and account
// preparation, backups and snapshots, per-file apply with a ledger write after
// every single file, unit validation, service activation, and the final
// service verification. Mutable operation state is updated through the
// pointers it receives, never returned for the caller to reassign.
func hubApplyAndVerify(ctx context.Context, result *InstallResult, state *InstallState, previous InstallState, hasState, repair bool, opts ApplyOptions, record func(string, string, string) error, c Config, operationID, operationDir string, targets []string, staged hubStaged, checks []Check, artifacts []Artifact, failures hubApplyErrors) error {
	fail := func(haveSnapshots bool, snapshots []fileSnapshot, stage, code, recovery string) error {
		res, err := failAndRollback(*result, *state, previous, hasState, opts, snapshots, haveSnapshots, record, stage, code, recovery)
		*result = res
		return err
	}
	failErr := func(haveSnapshots bool, snapshots []fileSnapshot, stage string, cause *InstallError) error {
		return fail(haveSnapshots, snapshots, stage, cause.Code, cause.Recovery)
	}
	stageDir, caddyPath, headscalePath := staged.stageDir, staged.caddyPath, staged.headscalePath
	runtimeStage, runtimeHash := staged.runtimeStage, staged.runtimeHash
	keys, stagedConfigs := staged.keys, staged.stagedConfigs

	// Query first, install second (the cloud-init pattern). Repair must not
	// re-run apt unconditionally: a transient repository failure would then
	// block a repair that has nothing to do with packages, and an unbounded
	// upgrade could move Fail2ban/nftables off the recorded component set.
	_, pkgErr := ensureDebianPackages(ctx, opts.Runner, failures.packageIndex, failures.packageInstall)
	if pkgErr != nil {
		return failErr(false, nil, pkgErr.Stage, pkgErr)
	}
	if err := ensureSystemUsers(ctx, opts.Runner, opts.Root, hasState); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail(false, nil, "apply", ie.Code, ie.Recovery)
		}
		return failErr(false, nil, "apply", failures.accountCreate)
	}
	if err := ensureDataDirectories(ctx, opts); err != nil {
		return failErr(false, nil, "apply", failures.dataDirectory)
	}

	backupDir := filepath.Join(operationDir, "backup")
	if err := ensureDirectory(backupDir, 0700); err != nil {
		return failErr(false, nil, "apply", failures.backupDirectory)
	}
	snapshots, err := snapshotTargets(opts.Root, targets, *state, hasState, backupDir)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail(false, nil, "apply", ie.Code, ie.Recovery)
		}
		return failErr(false, nil, "apply", failures.backupSnapshot)
	}

	applyFiles := map[string]string{
		runtimeBinaryPath:   runtimeStage,
		caddyBinaryPath:     caddyPath,
		headscaleBinaryPath: headscalePath,
	}
	for _, target := range keys {
		applyFiles[target] = stagedConfigs[target]
	}
	applyKeys := make([]string, 0, len(applyFiles))
	for target := range applyFiles {
		applyKeys = append(applyKeys, target)
	}
	sort.Strings(applyKeys)
	for _, target := range applyKeys {
		mode, owner := filePolicy(target)
		if err := copyAtomic(applyFiles[target], rooted(opts.Root, target), mode); err != nil {
			return failErr(true, snapshots, "apply", failures.fileApply)
		}
		if opts.Root == "/" && owner != "" {
			if _, err := opts.Runner.Run(ctx, "chown", owner, target); err != nil {
				return failErr(true, snapshots, "apply", failures.fileOwnership)
			}
		}
		digest, err := sha256File(rooted(opts.Root, target))
		if err != nil {
			return failErr(true, snapshots, "apply", failures.fileReadback)
		}
		state.ManagedFiles[target] = digest
		if target == runtimeBinaryPath {
			state.ManagedFiles[target] = runtimeHash
			// The Hub publishes the exact runtime build a co-located Line
			// may reuse. The Line verifies this digest before it runs the
			// shared binary and never replaces it.
			if state.SharedBinaries == nil {
				state.SharedBinaries = map[string]SharedBinary{}
			}
			state.SharedBinaries[sharedAgentKey] = SharedBinary{
				Path:   runtimeBinaryPath,
				SHA256: runtimeHash,
			}
		}
		if err := writeState(opts.Root, *state); err != nil {
			return failErr(true, snapshots, "apply", failures.stateWritePerFile)
		}
	}
	if err := record("apply", "files_written", ""); err != nil {
		return failErr(true, snapshots, "apply", failures.journalFilesWrite)
	}
	units := []string{
		rooted(opts.Root, "/etc/systemd/system/meshmux-web.service"),
		rooted(opts.Root, "/etc/systemd/system/meshmux-headscale.service"),
		rooted(opts.Root, "/etc/systemd/system/meshmux-caddy.service"),
	}
	if unitErr := validateStagedUnits(ctx, opts.Runner, units, failures.systemdUnit, failures.fail2banConfig); unitErr != nil {
		return failErr(true, snapshots, unitErr.Stage, unitErr)
	}
	if err := record("apply", "validated", ""); err != nil {
		return failErr(true, snapshots, "apply", failures.journalValidated)
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return failErr(true, snapshots, "apply", failures.systemdReload)
	}
	for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service"} {
		if err := activateUnit(ctx, opts.Runner, unit, repair); err != nil {
			code := "WEB_START_FAILED"
			if strings.Contains(unit, "headscale") {
				code = "HEADSCALE_START_FAILED"
			}
			return fail(true, snapshots, "verify", code, failures.unitStartRecovery)
		}
	}
	if fail2banErr := ensureFail2banRunning(ctx, opts.Runner, failures.fail2banStart, failures.fail2banReload); fail2banErr != nil {
		return failErr(true, snapshots, fail2banErr.Stage, fail2banErr)
	}
	if _, err := opts.Runner.Run(ctx, "fail2ban-client", "status", "meshmux-sshd"); err != nil {
		return failErr(true, snapshots, "verify", failures.sshJail)
	}
	if err := activateUnit(ctx, opts.Runner, "meshmux-caddy.service", repair); err != nil {
		return failErr(true, snapshots, "verify", failures.caddyStart)
	}
	if err := opts.Verify(ctx, c, opts.Runner, opts.TLSProbe); err != nil {
		code := "SERVICE_VERIFY_FAILED"
		var ie *InstallError
		if errors.As(err, &ie) {
			code = ie.Code
		}
		return fail(true, snapshots, "verify", code, failures.serviceVerify.Recovery)
	}

	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.UpdatedAt = time.Now().UTC()
	state.LastOperation = operationID
	if err := writeState(opts.Root, *state); err != nil {
		return failErr(true, snapshots, "verify", failures.finalLedger)
	}
	if err := record("verify", "pass", ""); err != nil {
		return failErr(true, snapshots, "verify", failures.journalVerifyPass)
	}
	_ = os.RemoveAll(backupDir)
	_ = os.RemoveAll(stageDir)
	result.Stage, result.Status, result.Checks = "verify", "installed", checks
	result.Artifacts = componentsFor(artifacts)
	return nil
}
