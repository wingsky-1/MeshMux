package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// Contract:
//
//	input     one validated Config (three domains + Caddy trust mode), the
//	          operation id, the repair flag and the rooted ApplyOptions;
//	validate  Config.Validate + operationIDPattern + root/ownership checks,
//	          then the host preflight (OS, arch, ports, disk, systemd);
//	assemble  the staged artifact set and the rendered candidate files, with no
//	          host-visible write until the whole candidate validates;
//	effects   snapshot -> replace only MeshMux-owned files -> write the ledger
//	          after each file -> start/verify units -> terminal ledger;
//	return    one InstallResult carrying the stage, the stable error_code and
//	          the recovery action; a failure never claims the Hub is applied.
//
// It is the only Hub host-mutation entry the CLI calls. A helper below either
// transforms values or returns a coded diagnostic; it never re-enters this
// function's effects or reaches into the web layer.
func InstallHub(ctx context.Context, c core.Config, operationID string, repair bool, opts core.ApplyOptions) (core.InstallResult, error) {
	result := core.InstallResult{OperationID: operationID, Stage: "preflight", Status: "failed"}
	fail := func(stage, code, recovery string) (core.InstallResult, error) {
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "failed", code, recovery
		return result, &core.InstallError{Stage: stage, Code: code, Recovery: recovery}
	}
	if !core.OperationIDPattern.MatchString(operationID) {
		return fail("preflight", core.CodeOperationIDInvalid, "Generate a new operation ID and retry.")
	}
	if err := c.Validate(); err != nil {
		return fail("preflight", "DOMAIN_INVALID", "Supply three distinct lowercase public DNS names.")
	}
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.Root == "/" && os.Geteuid() != 0 {
		return fail("preflight", "ROOT_REQUIRED", "Run the installer as root; the Web service itself runs unprivileged.")
	}
	if opts.Runner == nil {
		opts.Runner = core.ExecRunner{}
	}
	if opts.Preflight == nil {
		opts.Preflight = PreflightWithMode
	}
	if opts.DownloadArtifact == nil {
		opts.DownloadArtifact = func(ctx context.Context, a core.Artifact, dir string) (string, error) {
			return core.DownloadVerified(ctx, opts.HTTPClient, a, dir)
		}
	}
	if opts.TLSProbe == nil {
		opts.TLSProbe = core.WaitForHTTPS
	}
	if opts.Verify == nil {
		opts.Verify = core.VerifyServices
	}

	lock, lockErr := core.AcquireInstallLock(opts.Root, "Check /run/lock path ownership and symlinks.")
	if lockErr != nil {
		return fail(lockErr.Stage, lockErr.Code, lockErr.Recovery)
	}
	defer lock.Close()

	state, hasState, err := core.ReadState(opts.Root)
	if err != nil {
		return fail("preflight", core.CodeInstallStateInvalid, "Inspect the recorded installer state; do not delete application data or Headscale keys.")
	}
	if repair && !hasState {
		return fail("preflight", core.CodeRepairStateMissing, "Repair requires a state record created by MeshMux.")
	}
	if opts.NonInteractive && !repair {
		// A Web-driven handoff reuses the recorded installation; without
		// --repair the only continuation is an operator decision.
		return fail("preflight", "UPDATE_INTERACTIVE_REFUSED", "A non-interactive handoff must pass repair and reuse the recorded installation.")
	}
	if hasState && !core.SameConfig(state.Config, c) {
		return fail("preflight", core.CodeConfigConflict, "Repair only supports the recorded domains and proxy trust mode; domain migration is not part of this operation.")
	}
	if hasState && state.Status == "installed" && !repair {
		if err := opts.Verify(ctx, c, opts.Runner, opts.TLSProbe); err != nil {
			return fail("verify", "INSTALL_NEEDS_REPAIR", "The recorded installation is unhealthy. Review service logs, then run install hub --repair with the same configuration.")
		}
		result.Stage, result.Status = "verify", "already_installed"
		result.Recovery = "No files or data were changed. Use --repair only when an explicit repair is required."
		result.Artifacts = core.ComponentsFor(opts.Artifacts)
		return result, nil
	}
	if hasState && state.Status != "installed" && !repair {
		return fail("preflight", "INSTALL_PARTIAL_REPAIR_REQUIRED", "A previous operation is incomplete. Review its journal and run --repair with the same domains.")
	}
	if hasState && state.Status != "installed" && state.Status != "partial" && state.Status != "installing" {
		return fail("preflight", core.CodeInstallStateInvalid, "Inspect installer state before retrying.")
	}

	checks, sshPorts := opts.Preflight(ctx, c, hasState)
	result.Checks = checks
	for _, check := range checks {
		if check.Status == "fail" {
			recovery := check.Recovery
			if recovery == "" {
				recovery = "Resolve the failed preflight check and retry."
			}
			result.Stage, result.Status, result.ErrorCode, result.Recovery = "preflight", "preflight_blocked", check.Code, recovery
			return result, &core.InstallError{Stage: "preflight", Code: check.Code, Recovery: recovery}
		}
	}
	if len(sshPorts) == 0 {
		return fail("preflight", "SSH_LISTENER_UNKNOWN", "Determine the effective SSH listening port before installing Fail2ban.")
	}

	architecture := core.ArchitectureForRuntime()
	if architecture == "" {
		return fail("preflight", "ARCH_UNSUPPORTED", "Use Debian 13 on amd64 or arm64.")
	}
	// A co-located Line pins the exact Hub runtime build it reuses. The Hub
	// must not move to a different build while that pin exists: the Line
	// would silently run a MeshMux binary it never verified. The coordinated
	// Web upgrade that changes both layouts at once is Issue #11; this
	// profile only refuses the unsafe single-sided change. The check runs
	// before any file is replaced.
	if err := core.CheckLocalLineSharedBinaryForExecutable(opts.Root, opts); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(ie.Stage, ie.Code, ie.Recovery)
		}
		return fail("preflight", "SHARED_BINARY_MISMATCH",
			"The co-located Line pins a different MeshMux runtime build. Restore the matching build on both layouts, or use the validated coordinated Web upgrade from Issue #11 once it is available.")
	}
	artifacts := opts.Artifacts
	if len(artifacts) == 0 {
		artifacts = core.PinnedArtifacts(architecture)
	}
	if len(artifacts) != 2 || core.FindArtifact(artifacts, "caddy").Component == "" || core.FindArtifact(artifacts, "headscale").Component == "" {
		return fail("stage", "ARTIFACT_MANIFEST_INVALID", "Use the pinned Caddy and Headscale manifest for a supported architecture.")
	}
	targetFiles, err := candidateFiles(c, sshPorts, opts.InternalTLSForTest)
	if err != nil {
		return fail("stage", "CONFIG_INVALID", "Review the domains and detected SSH listener ports.")
	}
	targets := core.ManagedTargets(targetFiles)
	if err := core.CheckTargetOwnership(opts.Root, targets, state, hasState); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail("preflight", ie.Code, ie.Recovery)
		}
		return fail("preflight", "MANAGED_PATH_CONFLICT", "A target path already exists without an ownership record; inspect it manually.")
	}
	if err := core.CheckDataOwnership(opts.Root, hasState); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail("preflight", ie.Code, ie.Recovery)
		}
		return fail("preflight", "DATA_STATE_CONFLICT", "Inspect existing MeshMux or Headscale data; do not adopt or delete it automatically.")
	}
	if err := core.CheckSystemUsers(ctx, opts.Runner, hasState); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail("preflight", ie.Code, ie.Recovery)
		}
		return fail("preflight", "ACCOUNT_CONFLICT", "A MeshMux service account already exists without a matching installer state record.")
	}

	now := time.Now().UTC()
	// The installer state root is 0711: the Web must traverse it to read the
	// root-preset target manifest and the dispatcher result, but it must not be
	// able to list the tree. Both ledgers below it stay 0600 root and local-line
	// stays 0700 (spec §5.9, plan ruling 1).
	if err := ensureHubUpgradeLayout(opts.Root); err != nil {
		return fail("stage", core.CodeInstallStateUnavailable, "Create a root-owned traversable installer state directory and retry.")
	}
	operationDir := core.Rooted(opts.Root, versions.InstallerRoot+"/operations/"+operationID)
	if err := core.EnsureDirectory(operationDir, 0700); err != nil {
		return fail("stage", "OPERATION_LOG_FAILED", "Check private installer state directory permissions.")
	}
	journalPath := filepath.Join(operationDir, "events.jsonl")
	record := core.NewOperationRecorder(operationID, journalPath)
	if err := record("preflight", "pass", ""); err != nil {
		return fail("preflight", "OPERATION_LOG_FAILED", "Check installer state directory permissions.")
	}

	// A repair must preserve the previous manifest by value: maps are mutable
	// references, and staged file updates must never rewrite rollback metadata.
	previous := core.CloneInstallState(state)
	if !hasState {
		state = core.InstallState{Schema: 1, CreatedAt: now, ManagedFiles: map[string]string{}, Artifacts: map[string]string{}}
	}
	if state.ManagedFiles == nil {
		state.ManagedFiles = map[string]string{}
	}
	if state.Artifacts == nil {
		state.Artifacts = map[string]string{}
	}
	state.OperationID, state.LastOperation = operationID, operationID
	state.Status, state.Stage = "installing", "stage"
	state.Config, state.Architecture, state.UpdatedAt = c, architecture, now
	state.SSHPorts, state.ErrorCode, state.Recovery = sshPorts, "", ""
	if err := core.WriteState(opts.Root, state); err != nil {
		return fail("stage", "INSTALL_STATE_WRITE_FAILED", "Check disk space and permissions under /var/lib/meshmux-installer.")
	}
	if err := record("stage", "started", ""); err != nil {
		return core.FailAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions.")
	}

	stageFailures := hubStageErrors{
		stageCache:               &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check /var/cache space and permissions."},
		artifactDownloadRecovery: "Check outbound HTTPS to the pinned official GitHub release and retry; unverified files are never applied.",
		artifactChecksum:         &core.InstallError{Stage: "stage", Code: "ARTIFACT_CHECKSUM_MISMATCH", Recovery: "Delete the staged download and retry; do not bypass SHA-256 verification."},
		artifactStage:            &core.InstallError{Stage: "stage", Code: "ARTIFACT_STAGE_FAILED", Recovery: "Check permission on the verified Headscale binary."},
		artifactManifest:         &core.InstallError{Stage: "stage", Code: "ARTIFACT_MANIFEST_INVALID", Recovery: "The manifest must contain the pinned Caddy and Headscale binaries."},
		artifactFormat:           &core.InstallError{Stage: "stage", Code: "ARTIFACT_FORMAT_INVALID", Recovery: "Re-download the official Caddy archive; do not extract unverified archives."},
		caddyVersion:             &core.InstallError{Stage: "stage", Code: "CADDY_VERSION_INVALID", Recovery: "Use the exact pinned Caddy release for this architecture."},
		headscaleVersion:         &core.InstallError{Stage: "stage", Code: "HEADSCALE_VERSION_INVALID", Recovery: "Use the exact pinned Headscale release for this architecture."},
		meshmuxBinary:            &core.InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID", Recovery: "Run the installer from a regular, readable MeshMux executable and retry."},
		sharedBinary:             &core.InstallError{Stage: "preflight", Code: "SHARED_BINARY_MISMATCH", Recovery: "The co-located Line pins a different MeshMux runtime build. Restore the matching build on both layouts, or use the validated coordinated Web upgrade from Issue #11 once it is available."},
		stageTemporary:           &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check temporary disk space and permissions."},
		caddyConfig:              &core.InstallError{Stage: "stage", Code: "CADDY_CONFIG_INVALID", Recovery: "Review the generated Caddy configuration and domain values."},
		stageValidation:          &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check installer staging directory permissions."},
		headscaleConfig:          &core.InstallError{Stage: "stage", Code: "HEADSCALE_CONFIG_INVALID", Recovery: "Review the generated Headscale configuration for version 0.29.5."},
		operationLog:             &core.InstallError{Stage: "stage", Code: "OPERATION_LOG_FAILED", Recovery: "Check installer state directory permissions."},
	}
	staged, stageErr := hubStageArtifacts(ctx, &result, &state, previous, hasState, opts, record, operationID, artifacts, targetFiles, stageFailures)
	if stageErr != nil {
		return result, stageErr
	}
	applyFailures := hubApplyErrors{
		packageIndex:      &core.InstallError{Stage: "apply", Code: "PACKAGE_INDEX_FAILED", Recovery: "Check Debian repository connectivity; no third-party repository was added."},
		packageInstall:    &core.InstallError{Stage: "apply", Code: "PACKAGE_INSTALL_FAILED", Recovery: "Review Debian apt status and retry; do not remove existing packages or rules."},
		accountCreate:     &core.InstallError{Stage: "apply", Code: "ACCOUNT_CREATE_FAILED", Recovery: "Inspect the three dedicated service accounts before retrying."},
		dataDirectory:     &core.InstallError{Stage: "apply", Code: "DATA_DIRECTORY_FAILED", Recovery: "Check MeshMux data directory ownership; never delete SQLite or Headscale key files."},
		backupDirectory:   &core.InstallError{Stage: "apply", Code: "BACKUP_FAILED", Recovery: "Check installer state disk space before applying files."},
		backupSnapshot:    &core.InstallError{Stage: "apply", Code: "BACKUP_FAILED", Recovery: "No managed files were replaced; inspect the operation journal."},
		fileApply:         &core.InstallError{Stage: "apply", Code: "FILE_APPLY_FAILED", Recovery: "The installer is rolling back MeshMux-managed files; inspect the operation journal if rollback is incomplete."},
		fileOwnership:     &core.InstallError{Stage: "apply", Code: "FILE_OWNERSHIP_FAILED", Recovery: "The installer is restoring managed files; check service account and group ownership."},
		fileReadback:      &core.InstallError{Stage: "apply", Code: "FILE_READBACK_FAILED", Recovery: "The installer is restoring managed files; check the target filesystem."},
		stateWritePerFile: &core.InstallError{Stage: "apply", Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "Do not remove state or data; inspect disk space and run --repair."},
		journalFilesWrite: &core.InstallError{Stage: "apply", Code: "OPERATION_LOG_FAILED", Recovery: "Inspect the operation journal and installer state."},
		systemdUnit:       &core.InstallError{Stage: "verify", Code: "SYSTEMD_UNIT_INVALID", Recovery: "Review the generated unit files; no service is considered installed until validation succeeds."},
		fail2banConfig:    &core.InstallError{Stage: "verify", Code: "FAIL2BAN_CONFIG_INVALID", Recovery: "Review the MeshMux SSH jail and preserve existing Fail2ban configuration."},
		journalValidated:  &core.InstallError{Stage: "apply", Code: "OPERATION_LOG_FAILED", Recovery: "Inspect the operation journal and installer state."},
		systemdReload:     &core.InstallError{Stage: "apply", Code: "SYSTEMD_RELOAD_FAILED", Recovery: "Restore MeshMux-managed units and inspect systemd."},
		unitStartRecovery: "The installer is rolling back managed files; inspect journalctl for this unit and retry with --repair.",
		fail2banStart:     &core.InstallError{Stage: "verify", Code: "FAIL2BAN_START_FAILED", Recovery: "Review Fail2ban logs and SSH jail configuration; do not alter sshd or flush nftables."},
		fail2banReload:    &core.InstallError{Stage: "verify", Code: "FAIL2BAN_RELOAD_FAILED", Recovery: "Review Fail2ban logs and preserve existing jails and nftables rules."},
		sshJail:           &core.InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Verify the detected SSH ports and MeshMux-specific Fail2ban jail."},
		caddyStart:        &core.InstallError{Stage: "verify", Code: "CADDY_START_FAILED", Recovery: "Check TCP 80/443 ownership and Caddy logs; no third-party web server was replaced."},
		serviceVerify:     &core.InstallError{Stage: "verify", Code: "SERVICE_VERIFY_FAILED", Recovery: "Check DNS A/AAAA, TCP 80/443, certificate issuance, Headscale socket/DB and Fail2ban status; rerun --repair after fixing the cause."},
		finalLedger:       &core.InstallError{Stage: "verify", Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "Services were started but state readback failed; inspect the operation journal before retrying."},
		journalVerifyPass: &core.InstallError{Stage: "verify", Code: "OPERATION_LOG_FAILED", Recovery: "Inspect the operation journal and installer state."},
	}
	if applyErr := hubApplyAndVerify(ctx, &result, &state, previous, hasState, repair, opts, record, c, operationID, operationDir, targets, staged, checks, artifacts, applyFailures); applyErr != nil {
		return result, applyErr
	}
	return result, nil
}
