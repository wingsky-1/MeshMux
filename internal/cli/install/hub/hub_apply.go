package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// hubApplyErrors carries the exact Hub apply/verify failure templates. The Hub
// recovery wording must stay verbatim and guard-checked, so InstallHub owns
// every literal and this phase only selects the applicable entry.
type hubApplyErrors struct {
	packageIndex      *core.InstallError
	packageInstall    *core.InstallError
	accountCreate     *core.InstallError
	dataDirectory     *core.InstallError
	backupDirectory   *core.InstallError
	backupSnapshot    *core.InstallError
	fileApply         *core.InstallError
	fileOwnership     *core.InstallError
	fileReadback      *core.InstallError
	stateWritePerFile *core.InstallError
	journalFilesWrite *core.InstallError
	systemdUnit       *core.InstallError
	fail2banConfig    *core.InstallError
	journalValidated  *core.InstallError
	systemdReload     *core.InstallError
	unitStartRecovery string
	fail2banStart     *core.InstallError
	fail2banReload    *core.InstallError
	sshJail           *core.InstallError
	caddyStart        *core.InstallError
	serviceVerify     *core.InstallError
	finalLedger       *core.InstallError
	journalVerifyPass *core.InstallError
}

// hubApplyAndVerify runs the Hub apply and verify phases: package and account
// preparation, backups and snapshots, per-file apply with a ledger write after
// every single file, unit validation, service activation, and the final
// service verification. Mutable operation state is updated through the
// pointers it receives, never returned for the caller to reassign.
func hubApplyAndVerify(ctx context.Context, result *core.InstallResult, state *core.InstallState, previous core.InstallState, hasState, repair bool, opts core.ApplyOptions, record func(string, string, string) error, c core.Config, operationID, operationDir string, targets []string, staged hubStaged, checks []core.Check, artifacts []core.Artifact, failures hubApplyErrors) error {
	fail := func(haveSnapshots bool, snapshots []core.FileSnapshot, stage, code, recovery string) error {
		res, err := core.FailAndRollback(*result, *state, previous, hasState, opts, snapshots, haveSnapshots, record, stage, code, recovery)
		noteHubDatabaseBackup(opts.Root, &res, err, record, stage)
		*result = res
		return err
	}
	failErr := func(haveSnapshots bool, snapshots []core.FileSnapshot, stage string, cause *core.InstallError) error {
		return fail(haveSnapshots, snapshots, stage, cause.Code, cause.Recovery)
	}
	stageDir, caddyPath, headscalePath := staged.stageDir, staged.caddyPath, staged.headscalePath
	runtimeStage, runtimeHash := staged.runtimeStage, staged.runtimeHash
	keys, stagedConfigs := staged.keys, staged.stagedConfigs

	// Query first, install second (the cloud-init pattern). Repair must not
	// re-run apt unconditionally: a transient repository failure would then
	// block a repair that has nothing to do with packages, and an unbounded
	// upgrade could move Fail2ban/nftables off the recorded component set.
	_, pkgErr := core.EnsureDebianPackages(ctx, opts.Runner, failures.packageIndex, failures.packageInstall)
	if pkgErr != nil {
		return failErr(false, nil, pkgErr.Stage, pkgErr)
	}
	if err := core.EnsureSystemUsers(ctx, opts.Runner, opts.Root, hasState); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(false, nil, "apply", ie.Code, ie.Recovery)
		}
		return failErr(false, nil, "apply", failures.accountCreate)
	}
	// The preflight layout ran before the fresh-install meshmux account existed;
	// now that it does, fix the result directory's group so the Web can read it.
	if err := ensureHubUpgradeOwnership(opts.Root); err != nil {
		return fail(false, nil, "apply", "HUB_UPGRADE_STATE_LAYOUT_FAILED", "Create the meshmux account and inspect /var/lib/meshmux-installer ownership.")
	}
	if err := core.EnsureDataDirectories(ctx, opts); err != nil {
		return failErr(false, nil, "apply", failures.dataDirectory)
	}

	backupDir := filepath.Join(operationDir, "backup")
	if err := core.EnsureDirectory(backupDir, 0700); err != nil {
		return failErr(false, nil, "apply", failures.backupDirectory)
	}
	snapshots, err := core.SnapshotTargets(opts.Root, targets, *state, hasState, backupDir)
	if err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(false, nil, "apply", ie.Code, ie.Recovery)
		}
		return failErr(false, nil, "apply", failures.backupSnapshot)
	}

	applyFiles := map[string]string{
		core.RuntimeBinaryPath:   runtimeStage,
		core.CaddyBinaryPath:     caddyPath,
		core.HeadscaleBinaryPath: headscalePath,
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
		mode, owner := core.FilePolicy(target)
		if err := core.CopyAtomic(applyFiles[target], core.Rooted(opts.Root, target), mode); err != nil {
			return failErr(true, snapshots, "apply", failures.fileApply)
		}
		if opts.Root == "/" && owner != "" {
			if _, err := opts.Runner.Run(ctx, "chown", owner, target); err != nil {
				return failErr(true, snapshots, "apply", failures.fileOwnership)
			}
		}
		digest, err := core.SHA256File(core.Rooted(opts.Root, target))
		if err != nil {
			return failErr(true, snapshots, "apply", failures.fileReadback)
		}
		state.ManagedFiles[target] = digest
		if target == core.RuntimeBinaryPath {
			state.ManagedFiles[target] = runtimeHash
			// The Hub publishes the exact runtime build a co-located Line
			// may reuse. The Line verifies this digest before it runs the
			// shared binary and never replaces it.
			if state.SharedBinaries == nil {
				state.SharedBinaries = map[string]core.SharedBinary{}
			}
			state.SharedBinaries[core.SharedAgentKey] = core.SharedBinary{
				Path:   core.RuntimeBinaryPath,
				SHA256: runtimeHash,
			}
		}
		if err := core.WriteState(opts.Root, *state); err != nil {
			return failErr(true, snapshots, "apply", failures.stateWritePerFile)
		}
	}
	if err := record("apply", "files_written", ""); err != nil {
		return failErr(true, snapshots, "apply", failures.journalFilesWrite)
	}
	units := []string{
		core.Rooted(opts.Root, versions.WebUnitPath),
		core.Rooted(opts.Root, core.HeadscaleUnitPath),
		core.Rooted(opts.Root, core.CaddyUnitPath),
	}
	for _, path := range hubDispatchManagedTargets() {
		units = append(units, core.Rooted(opts.Root, path))
	}
	if unitErr := core.ValidateStagedUnits(ctx, opts.Runner, units, failures.systemdUnit, failures.fail2banConfig); unitErr != nil {
		return failErr(true, snapshots, unitErr.Stage, unitErr)
	}
	if err := record("apply", "validated", ""); err != nil {
		return failErr(true, snapshots, "apply", failures.journalValidated)
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return failErr(true, snapshots, "apply", failures.systemdReload)
	}
	// Create the root-owned request/result tree before the path unit can fire.
	// The drop-in is applied with the rest of the managed files above.
	if _, err := opts.Runner.Run(ctx, "systemd-tmpfiles", "--create", hubTmpfilesPath); err != nil {
		return fail(true, snapshots, "apply", "SYSTEMD_TMPFILES_FAILED", "Install the MeshMux tmpfiles drop-in and inspect systemd-tmpfiles output.")
	}
	// Only the path unit is enabled: the oneshot has no [Install] section and is
	// started by the path trigger, never at boot on its own.
	if _, err := opts.Runner.Run(ctx, "systemctl", "enable", "--now", core.HubDispatchPathUnit); err != nil {
		return fail(true, snapshots, "apply", "HUB_DISPATCH_ENABLE_FAILED", "Inspect meshmux-hub-dispatch.path and systemd state.")
	}
	for _, unit := range []string{core.HeadscaleUnitName, versions.WebUnitName} {
		if err := core.ActivateUnit(ctx, opts.Runner, unit, repair); err != nil {
			code := "WEB_START_FAILED"
			if strings.Contains(unit, "headscale") {
				code = "HEADSCALE_START_FAILED"
			}
			return fail(true, snapshots, "verify", code, failures.unitStartRecovery)
		}
	}
	if fail2banErr := core.EnsureFail2banRunning(ctx, opts.Runner, failures.fail2banStart, failures.fail2banReload); fail2banErr != nil {
		return failErr(true, snapshots, fail2banErr.Stage, fail2banErr)
	}
	if _, err := opts.Runner.Run(ctx, "fail2ban-client", "status", "meshmux-sshd"); err != nil {
		return failErr(true, snapshots, "verify", failures.sshJail)
	}
	if err := core.ActivateUnit(ctx, opts.Runner, "meshmux-caddy.service", repair); err != nil {
		return failErr(true, snapshots, "verify", failures.caddyStart)
	}
	if err := opts.Verify(ctx, c, opts.Runner, opts.TLSProbe); err != nil {
		code := "SERVICE_VERIFY_FAILED"
		var ie *core.InstallError
		if errors.As(err, &ie) {
			code = ie.Code
		}
		return fail(true, snapshots, "verify", code, failures.serviceVerify.Recovery)
	}

	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.UpdatedAt = time.Now().UTC()
	state.LastOperation = operationID
	if err := core.WriteState(opts.Root, *state); err != nil {
		return failErr(true, snapshots, "verify", failures.finalLedger)
	}
	if err := record("verify", "pass", ""); err != nil {
		return failErr(true, snapshots, "verify", failures.journalVerifyPass)
	}
	_ = os.RemoveAll(backupDir)
	_ = os.RemoveAll(stageDir)
	result.Stage, result.Status, result.Checks = "verify", "installed", checks
	result.Artifacts = core.ComponentsFor(artifacts)
	return nil
}

// hubDataDirPath is the fixed Hub data directory; the Web service owns it and
// the installer never guesses a different one.
const hubDataDirPath = versions.HubDataDir

// noteHubDatabaseBackup adds the verified pre-migration database backup to a
// failed Hub apply. The new binary snapshots the database before its first
// schema migration, so a failure after that point leaves the only way back on
// disk; the rollback path must name it instead of letting the operator discover
// SCHEMA_TOO_NEW in journalctl. The note is best-effort and factual: when no
// verified pointer exists (a failure before the new binary started), nothing is
// added. The operation journal records the same path so the recovery evidence
// survives the terminal result.
func noteHubDatabaseBackup(root string, result *core.InstallResult, err error, record func(string, string, string) error, stage string) {
	dataDir := core.Rooted(root, hubDataDirPath)
	owner, ok := directoryOwner(dataDir)
	if !ok {
		return
	}
	pointer, pointerErr := backup.ReadFlatPointer(filepath.Join(dataDir, versions.HubDatabaseBackupDir), owner)
	if pointerErr != nil {
		return
	}
	note := fmt.Sprintf(" A pre-migration Hub database backup exists: record %s, database copy %s (from_version %s, db_schema %d).",
		pointer.RecordPath, pointer.PayloadPath, pointer.Record.FromVersion, pointer.Record.DBSchema)
	result.Recovery = strings.TrimSpace(result.Recovery + note)
	var ie *core.InstallError
	if errors.As(err, &ie) {
		ie.Recovery = result.Recovery
	}
	if record != nil {
		_ = record(stage, "hub_database_backup", pointer.RecordPath)
	}
}

// directoryOwner returns the account of an existing private directory. The
// installer reads the Hub store as root but must apply the same owner rule the
// Web applies: the data directory names the service account whose files may be
// trusted.
func directoryOwner(path string) (int, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}
