package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	nodeAgentStateDir = versions.AgentRoot
	nodeKernelDataDir = "/var/lib/meshmux-singbox"
)

// Contract:
//
//	input     the recorded-or-supplied node.Config, the operation id, the repair
//	          flag, one pairing code (never persisted) and the rooted options;
//	validate  cfg.Validate + the operation id shape + the pairing code shape,
//	          then preflight, then the recorded-state cross-check;
//	assemble  the artifact set, the rendered config/units and the candidate
//	          revision; nothing is written before the candidate validates;
//	effects   identity/pairing -> snapshot -> apply -> verify -> terminal ledger;
//	return    one InstallResult with the stage, the stable error_code and the
//	          recovery action. A failed verify never claims the node is online.
func InstallNode(ctx context.Context, cfg corenode.Config, operationID string, repair bool, pairingCode string, opts core.NodeApplyOptions) (core.InstallResult, error) {
	result := core.InstallResult{OperationID: operationID, Stage: "preflight", Status: "failed"}
	fail := func(stage, code, recovery string) (core.InstallResult, error) {
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "failed", code, recovery
		return result, &core.InstallError{Stage: stage, Code: code, Recovery: recovery}
	}
	if !core.OperationIDPattern.MatchString(operationID) {
		return fail("preflight", core.CodeOperationIDInvalid, "Generate a new operation ID and retry.")
	}
	if err := cfg.Validate(); err != nil {
		return fail("preflight", "CONFIG_INVALID", "Supply a valid HTTPS Hub URL, node identity, edge/out role and distinct SSH/VLESS ports.")
	}
	if opts.NonInteractive && !repair {
		// A Web-driven handoff never has an operator at the terminal: a fresh
		// install would have to prompt for a pairing code, so it is refused
		// before any file is staged.
		return fail("preflight", "UPDATE_INTERACTIVE_REFUSED", "A non-interactive handoff must pass repair and reuse the recorded identity.")
	}
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.FromRecordedState {
		// The hidden handoff family owns every input: no configuration and no
		// identity travel through argv, so a run that is not a repair, or that
		// could still wait for an operator, is refused before any read.
		if !repair || !opts.NonInteractive {
			return fail("preflight", "UPDATE_INTERACTIVE_REFUSED",
				"A recorded-state handoff must pass --repair --non-interactive; it never becomes a second install mode.")
		}
		recorded, recordedErr := recordedNodeConfig(opts.Root, cfg.Role)
		if recordedErr != nil {
			return fail(recordedErr.Stage, recordedErr.Code, recordedErr.Recovery)
		}
		cfg = recorded
	}
	if err := cfg.Validate(); err != nil {
		return fail("preflight", "CONFIG_INVALID", "Supply a valid HTTPS Hub URL, node identity, edge/out role and distinct SSH/VLESS ports.")
	}
	if opts.Root == "/" && os.Geteuid() != 0 {
		return fail("preflight", "ROOT_REQUIRED", "Run the installer as root; the Agent service does not listen for management traffic.")
	}
	if opts.Runner == nil {
		opts.Runner = core.ExecRunner{}
	}
	if opts.Preflight == nil {
		opts.Preflight = func(ctx context.Context, cfg corenode.Config, allowManaged bool) ([]core.Check, []int) {
			return preflightNode(ctx, cfg, allowManaged, opts.Root, opts.Runner)
		}
	}
	if opts.DownloadArtifact == nil {
		opts.DownloadArtifact = func(ctx context.Context, a core.Artifact, dir string) (string, error) {
			return core.DownloadVerified(ctx, opts.HTTPClient, a, dir)
		}
	}
	if opts.Pair == nil {
		opts.Pair = func(ctx context.Context, cfg corenode.Config, code string) (corenode.Identity, error) {
			client, err := corenode.NewClient(cfg, corenode.Identity{}, opts.HTTPClient)
			if err != nil {
				return corenode.Identity{}, err
			}
			return client.Pair(ctx, code)
		}
	}
	if opts.Metadata == nil {
		opts.Metadata = func(ctx context.Context, cfg corenode.Config, identity corenode.Identity) (corenode.Metadata, error) {
			client, err := corenode.NewClient(cfg, identity, opts.HTTPClient)
			if err != nil {
				return corenode.Metadata{}, err
			}
			return client.Metadata(ctx)
		}
	}
	if opts.Candidate == nil {
		opts.Candidate = func(ctx context.Context, cfg corenode.Config, identity corenode.Identity, revision int64) (corenode.CandidateDocument, error) {
			client, err := corenode.NewClient(cfg, identity, opts.HTTPClient)
			if err != nil {
				return corenode.CandidateDocument{}, err
			}
			return client.Candidate(ctx, revision)
		}
	}
	if opts.Readback == nil {
		opts.Readback = corenode.ReadbackLocal
	}
	if opts.Verify == nil {
		opts.Verify = verifyNodeInstall
	}

	// An unattended handoff retries the host-wide lock for a bounded window
	// (60s, D7) because no operator can retry it; an interactive run keeps the
	// immediate INSTALL_BUSY refusal (spec §4.9).
	lock, lockErr := core.AcquireInstallLockWithin(ctx, opts.Root, "Check /run/lock ownership and symlinks.", installLockWaitFor(opts))
	if lockErr != nil {
		return fail(lockErr.Stage, lockErr.Code, lockErr.Recovery)
	}
	defer lock.Close()

	// The ledger this operation owns is selected from the host's own
	// recorded state. A host that already runs the Hub hosts one
	// co-located Line with a separate ledger; the Hub ledger, its
	// services and its Fail2ban jail are never rewritten here.
	layout, err := core.ResolveNodeLayout(opts.Root)
	if err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(ie.Stage, ie.Code, ie.Recovery)
		}
		return fail("preflight", core.CodeInstallStateInvalid, "Inspect the recorded installer state before retrying.")
	}
	if layout.HubHost && !layout.CoLocated {
		// A Hub host that cannot publish a pinned reusable runtime cannot
		// host a Line. The Line ledger would have to record a second MeshMux
		// binary, and the Hub ledger can never prove Node ownership. This is
		// an ownership failure, not a layout conflict: repair the Hub first.
		return fail("preflight", core.NodeOwnershipUnverified,
			"This host records a Hub layout that cannot host a co-located Line because the Hub does not publish a pinned reusable MeshMux runtime. Repair the Hub layout first; a Line never falls back to the Hub ledger.")
	}
	if layout.CoLocated {
		// A co-located Line may only talk to the Hub that owns this host.
		// Any other Hub origin is a remote node, not this local Line.
		if origin := core.HubOriginFor(layout.HubState); origin == "" || cfg.HubURL != origin {
			return fail("preflight", "LOCAL_LINE_HUB_MISMATCH",
				"A Line co-located with this Hub must use the Hub origin of the installed management host.")
		}
	}

	state, hasState, err := core.ReadNodeStateAt(opts.Root, layout)
	if err != nil {
		return fail("preflight", core.CodeInstallStateInvalid, "Inspect the recorded installer state; do not delete Agent identity or kernel data.")
	}
	if hasState {
		if state.Node != nil && (state.Config.ManagementDomain != "" || state.Config.SubscriptionDomain != "" || state.Config.HeadscaleDomain != "") {
			return fail("preflight", "HOST_LAYOUT_CONFLICT", "This host contains a Hub layout. Hub, edge and out layouts are mutually exclusive and are never overwritten in place.")
		}
		if state.Node == nil {
			return fail("preflight", "HOST_LAYOUT_CONFLICT", "This host already has a non-Node MeshMux layout; use a separate host.")
		}
		if !core.SameNodeConfig(*state.Node, cfg) {
			return fail("preflight", core.CodeConfigConflict, "Repair only supports the recorded Hub URL, node, role and ports; create a new node enrollment for migration.")
		}
	}
	if repair && !hasState {
		return fail("preflight", core.CodeRepairStateMissing, "Repair requires a Node state record created by MeshMux.")
	}
	if hasState && state.Status != "installed" && state.Status != "partial" && state.Status != "installing" && !repair {
		return fail("preflight", "INSTALL_PARTIAL_REPAIR_REQUIRED", "Inspect the operation journal and run --repair with the same Node configuration.")
	}
	if hasState && state.Status == "installed" && !repair {
		return fail("preflight", "REINSTALL_REJECTED", "Reinstalling over an installed Node is not supported; run --repair with the same Node configuration.")
	}
	allowManaged := hasState && state.Node != nil
	checks, sshPorts := opts.Preflight(ctx, cfg, allowManaged)
	result.Checks = checks
	for _, c := range checks {
		if c.Status == "fail" {
			recovery := c.Recovery
			if recovery == "" {
				recovery = "Resolve the failed Node preflight check and retry."
			}
			result.Stage, result.Status, result.ErrorCode, result.Recovery = "preflight", "preflight_blocked", c.Code, recovery
			return result, &core.InstallError{Stage: "preflight", Code: c.Code, Recovery: recovery}
		}
	}
	if len(sshPorts) == 0 || !core.ContainsPort(sshPorts, cfg.SSHPort) {
		return fail("preflight", "SSH_LISTENER_UNKNOWN", "Determine the actual SSH listener before installing Fail2ban or VLESS.")
	}
	if core.ContainsPort(sshPorts, cfg.VLESSPort) {
		return fail("preflight", "PORT_CONFLICT", "VLESS cannot use any actual SSH listener port.")
	}
	// A co-located Line reuses the Hub's Fail2ban SSH jail. The reuse is
	// only safe when the Hub's jail provably covers this host's actual SSH
	// listeners; otherwise the Line refuses rather than duplicating the
	// jail or leaving the listener unprotected.
	if err := core.CheckLocalLineSSHJailReuse(layout, sshPorts); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(ie.Stage, ie.Code, ie.Recovery)
		}
		return fail("preflight", "SSH_JAIL_REUSE_CONFLICT",
			"The Hub's Fail2ban SSH jail does not cover this host's actual SSH listeners. Repair the Hub so its jail matches, then install the Line.")
	}

	architecture, err := dpkgArchitecture(ctx, opts.Runner)
	if err != nil {
		return fail("preflight", "ARCH_UNSUPPORTED", "Use Debian 13 on amd64 or arm64 and run the matching MeshMux binary.")
	}
	if err := ValidateNodeArchitecture(architecture); err != nil {
		return fail("preflight", "ARCH_UNSUPPORTED", "Use Debian 13 on amd64 or arm64.")
	}
	release, ok := corenode.KernelReleaseFor(architecture)
	if !ok {
		return fail("stage", "ARTIFACT_MANIFEST_INVALID", "Use the pinned Node manifest for this architecture.")
	}
	artifacts := core.PinnedNodeArtifacts(architecture)
	if opts.Root != "/" && len(opts.Artifacts) > 0 {
		artifacts = append([]core.Artifact(nil), opts.Artifacts...)
	}
	if len(artifacts) != 1 || artifacts[0].Component != "sing-box" || artifacts[0].Version != corenode.KernelVersion ||
		!core.ValidDigest.MatchString(artifacts[0].SHA256) || artifacts[0].Source != release.SourceURL {
		return fail("stage", "ARTIFACT_MANIFEST_INVALID", "Use exactly the pinned sing-box release; latest and caller-supplied URLs are rejected.")
	}
	if err := checkNodeTargets(opts.Root, cfg, sshPorts, state, hasState, layout); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(ie.Stage, ie.Code, ie.Recovery)
		}
		return fail("preflight", "MANAGED_PATH_CONFLICT", "Inspect the fixed Node paths manually; MeshMux does not adopt third-party files or tables.")
	}

	now := time.Now().UTC()
	previous := core.CloneInstallState(state)
	// A re-entry of the same operation is an idempotent redo (ruling I13), not
	// a conflict. It is decided from the ledger as it was read, before this
	// attempt overwrites the operation stamps below.
	sameOperationRedo := hasState && state.LastOperation == operationID
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
	state.Config = core.Config{}
	// The recorded Node carries the verified binary hashes after the first
	// install. A repair must not wipe them back to the hashless user config,
	// otherwise the next repair preflight cannot recognize its own kernel
	// listener and fails with PORT_CONFLICT.
	if !hasState || state.Node == nil {
		state.Node = core.CloneNodeConfig(&cfg)
	}
	state.Artifacts["sing-box"] = artifacts[0].SHA256
	state.Architecture, state.SSHPorts, state.ErrorCode, state.Recovery = architecture, sortedInts(sshPorts), "", ""
	if layout.CoLocated {
		// The Line pins the exact Hub-owned runtime build it reuses. The pin
		// is what lets a later Hub repair detect a mismatching shared
		// binary instead of silently moving the Line to another build.
		if state.SharedBinaries == nil {
			state.SharedBinaries = map[string]core.SharedBinary{}
		}
		state.SharedBinaries[core.SharedAgentKey] = core.SharedBinary{
			Path:   layout.SharedAgent,
			SHA256: layout.SharedAgentSHA256,
		}
	}
	state.UpdatedAt = now
	if err := core.WriteNodeState(opts.Root, layout, state); err != nil {
		return fail("stage", core.CodeInstallStateWriteFailed, "Check disk space and permissions under /var/lib/meshmux-installer.")
	}
	operationDir := core.Rooted(opts.Root, layout.OperationDir+"/"+operationID)
	journalPath := filepath.Join(operationDir, "events.jsonl")
	record := core.NewOperationRecorder(operationID, journalPath)
	if err := record("stage", "started", ""); err != nil {
		return failNodePartial(result, state, opts, layout, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions and run --repair.")
	}
	if opts.FromRecordedState && sameOperationRedo {
		// Ruling I13: re-entering the same operation is an idempotent redo,
		// not a conflict. Every apply step below is a verified atomic replace
		// of recorded files, so the redo converges; the journal entry is the
		// audit record that it happened.
		if err := recordSameOperationRedo(record); err != nil {
			return failNodePartial(result, state, opts, layout, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions and run --repair.")
		}
	}
	stage, stageErr := stageNodeArtifacts(ctx, &result, &state, &opts, layout, record, cfg, hasState, operationID, artifacts[0], release, nodeStageErrors{
		stageRemove:              &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Remove only the incomplete staging directory for this operation and retry."},
		stageCache:               &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check /var/cache space and permissions; no host files were applied."},
		stageTemporary:           &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check temporary disk space and permissions."},
		artifactDownloadRecovery: "Check outbound HTTPS to the pinned official GitHub asset; unverified archives are never applied.",
		artifactChecksum:         &core.InstallError{Stage: "stage", Code: "ARTIFACT_CHECKSUM_MISMATCH", Recovery: "Delete the staged archive and retry; never bypass archive SHA-256 verification."},
		artifactFormat:           &core.InstallError{Stage: "stage", Code: "ARTIFACT_FORMAT_INVALID", Recovery: "Use the official pinned sing-box archive for this architecture."},
		kernelChecksum:           &core.InstallError{Stage: "stage", Code: "KERNEL_CHECKSUM_MISMATCH", Recovery: "Delete the staged kernel and retry; the binary must match the release manifest."},
		kernelVersion:            &core.InstallError{Stage: "stage", Code: "KERNEL_VERSION_INVALID", Recovery: "Use the exact pinned sing-box release for this architecture."},
		meshmuxBinary:            &core.InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID", Recovery: "Run the installer from a regular MeshMux executable and retry."},
		candidateRender:          &core.InstallError{Stage: "stage", Code: "CANDIDATE_RENDER_FAILED", Recovery: "Review the Node role and VLESS port."},
		kernelConfig:             &core.InstallError{Stage: "stage", Code: "KERNEL_CONFIG_INVALID", Recovery: "Review the generated native sing-box configuration."},
		packageIndex:             &core.InstallError{Stage: "apply", Code: "PACKAGE_INDEX_FAILED", Recovery: "Check Debian repository connectivity; no package upgrade or third-party repository is used."},
		packageInstall:           &core.InstallError{Stage: "apply", Code: "PACKAGE_INSTALL_FAILED", Recovery: "Review Debian apt status; only the listed missing packages are installed."},
		fail2banBaseline:         &core.InstallError{Stage: "preflight", Code: CodeFail2banBaselineInvalid, Recovery: fail2banBaselineRecovery},
		aclProbe:                 &core.InstallError{Stage: "apply", Code: "ACL_TABLE_PROBE_FAILED", Recovery: "Re-run the exact nft ownership readback. MeshMux will not adopt, overwrite or delete an unverified table."},
		aclRender:                &core.InstallError{Stage: "stage", Code: "ACL_RENDER_FAILED", Recovery: "Review the Out role configuration."},
		aclConfig:                &core.InstallError{Stage: "stage", Code: "ACL_CONFIG_INVALID", Recovery: "Review the generated default-deny Out table; the host ruleset was not changed."},
		operationLog:             &core.InstallError{Stage: "stage", Code: "OPERATION_LOG_FAILED", Recovery: "Check installer state directory permissions and run --repair."},
	})
	if stageErr != nil {
		return result, stageErr
	}
	stageDir, kernelPath, agentPath, installedCfg := stage.stageDir, stage.kernelPath, stage.agentPath, stage.installedCfg

	identityFailures := nodeIdentityErrors{
		identityInvalid:       &core.InstallError{Stage: "stage", Code: "IDENTITY_INVALID", Recovery: "Inspect the private Agent identity; do not delete it until the Hub identity is revoked."},
		pairingFailedRepair:   &core.InstallError{Stage: "stage", Code: "PAIRING_FAILED", Recovery: "Check the one-time code, Hub reachability and node role/ports. A failed request may still have been consumed; reissue a code before retrying."},
		pairingRequired:       &core.InstallError{Stage: "stage", Code: "PAIRING_REQUIRED", Recovery: "The recorded identity was revoked or replaced. Reissue a pairing code in Hub Web and run --repair with the fresh code."},
		pairingMetadataRepair: &core.InstallError{Stage: "stage", Code: "PAIRING_METADATA_FAILED", Recovery: "The private identity is preserved. Fix Hub metadata/candidate availability and run --repair; do not request another code."},
		pairingMetadataFresh:  &core.InstallError{Stage: "stage", Code: "PAIRING_METADATA_FAILED", Recovery: "The private identity is persisted. Fix Hub metadata/candidate availability and run --repair; do not request another code."},
		identityMissing:       &core.InstallError{Stage: "stage", Code: "IDENTITY_MISSING", Recovery: "A repair reuses the private identity when it is still valid. Restore the identity, or revoke and re-enroll the node; a revoked identity needs a fresh pairing code."},
		pairingCodeRequired:   &core.InstallError{Stage: "pairing", Code: "PAIRING_CODE_REQUIRED", Recovery: "Enter the current one-time code on stdin after local staging checks pass."},
		pairingFailedFresh:    &core.InstallError{Stage: "stage", Code: "PAIRING_FAILED", Recovery: "Check the one-time code, Hub reachability and node role/ports. A failed request may still have been consumed."},
		agentStateUnsafe:      &core.InstallError{Stage: "stage", Code: "AGENT_STATE_UNSAFE", Recovery: "Use a root-owned 0700 Agent directory; the kernel group must not read identity tokens."},
		identityPersistFailed: &core.InstallError{Stage: "stage", Code: "IDENTITY_PERSIST_FAILED", Recovery: "The Hub code may already be consumed. Preserve this operation's journal, reissue a code for the same node in Web and retry after fixing disk permissions."},
		stateWriteFailed:      &core.InstallError{Stage: "stage", Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "Check installer state disk space and permissions; preserve the private identity."},
	}
	if opts.FromRecordedState {
		// No operator is present: a lost or revoked identity is terminal
		// (UPDATE_REENROLL_REQUIRED) and never becomes a prompt.
		identityFailures = recordedStateIdentityErrors(identityFailures)
	}
	resolved, resolveErr := nodeResolveIdentityAndCandidate(ctx, &result, &state, &opts, layout, record, installedCfg, repair, pairingCode, identityFailures)
	if resolveErr != nil {
		return result, resolveErr
	}
	if resolved.pairingPending {
		if opts.NonInteractive {
			// Defensive: no Web-driven handoff may stop at a prompt. The
			// preflight already refuses this path; this keeps the invariant
			// next to the branch that would wait.
			return fail("pairing", "UPDATE_INTERACTIVE_REFUSED", "A non-interactive handoff cannot wait for a pairing code.")
		}
		return result, identityFailures.pairingCodeRequired
	}
	identity, candidate := resolved.identity, resolved.candidate
	candidateFailures := nodeCandidateErrors{
		marshalFailed:      &core.InstallError{Stage: "stage", Code: "CANDIDATE_RENDER_FAILED", Recovery: "Review the Hub candidate response and retry with --repair."},
		compileFailed:      &core.InstallError{Stage: "stage", Code: "CANDIDATE_RENDER_FAILED", Recovery: "Review the Hub candidate role, node and port binding."},
		candidateInvalid:   &core.InstallError{Stage: "stage", Code: "CANDIDATE_INVALID", Recovery: "The Hub candidate failed local validation; no active kernel configuration was replaced."},
		configRenderFailed: &core.InstallError{Stage: "stage", Code: "CONFIG_RENDER_FAILED", Recovery: "Review the actual SSH listeners and the fixed Node service layout."},
		stageTemporary:     &core.InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check temporary disk space and permissions."},
		operationLog:       &core.InstallError{Stage: "stage", Code: "OPERATION_LOG_FAILED", Recovery: "Check installer state directory permissions and run --repair."},
	}
	finalized, finalizeErr := nodeFinalizeCandidate(ctx, &result, &state, &opts, layout, record, repair, cfg, installedCfg, identity, candidate, sshPorts, stageDir, kernelPath, candidateFailures)
	if finalizeErr != nil {
		return result, finalizeErr
	}
	activeCandidate, candidateConfig := finalized.activeCandidate, finalized.candidateConfig
	managed, stagedManaged := finalized.managed, finalized.stagedManaged
	repairNotice := finalized.repairNotice

	applyFailures := nodeApplyErrors{
		accountCreate:     &core.InstallError{Stage: "apply", Code: "ACCOUNT_CREATE_FAILED", Recovery: "Inspect meshmux-singbox and meshmux-agent accounts before retrying."},
		dataDirectory:     &core.InstallError{Stage: "apply", Code: "DATA_DIRECTORY_FAILED", Recovery: "Check Agent and kernel data directory ownership; never expose the identity directory to the kernel group."},
		backupDirectory:   &core.InstallError{Stage: "apply", Code: "BACKUP_FAILED", Recovery: "Check installer state disk space."},
		backupSnapshot:    &core.InstallError{Stage: "apply", Code: "BACKUP_FAILED", Recovery: "No managed files were replaced; inspect the operation journal."},
		journalFilesWrite: &core.InstallError{Stage: "apply", Code: "OPERATION_LOG_FAILED", Recovery: "Restore the journal before another apply."},
		systemdUnit:       &core.InstallError{Stage: "verify", Code: "SYSTEMD_UNIT_INVALID", Recovery: "Review the fixed Agent, kernel and ACL units; no Node is installed until validation succeeds."},
		fail2banConfig:    &core.InstallError{Stage: "verify", Code: "FAIL2BAN_CONFIG_INVALID", Recovery: "Review the Node SSH jail and preserve all existing Fail2ban jails."},
		systemdReload:     &core.InstallError{Stage: "apply", Code: "SYSTEMD_RELOAD_FAILED", Recovery: "Inspect systemd and run --repair."},
		fail2banStart:     &core.InstallError{Stage: "verify", Code: "FAIL2BAN_START_FAILED", Recovery: "Review Fail2ban logs and the Node SSH jail; do not alter sshd or flush nftables."},
		fail2banReload:    &core.InstallError{Stage: "verify", Code: "FAIL2BAN_RELOAD_FAILED", Recovery: "Review Fail2ban logs and preserve existing jails."},
		fail2banWait:      &core.InstallError{Stage: "verify", Code: "FAIL2BAN_START_FAILED", Recovery: "The Fail2ban service never became queryable; inspect the service and run --repair."},
		hubJailReadback: func(err error) *core.InstallError {
			return &core.InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Read back the Hub Fail2ban action ports (" + err.Error() + ") and require every actual SSH listener, excluding VLESS."}
		},
		standaloneJailReadback: func(err error) *core.InstallError {
			return &core.InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Read back the Fail2ban action ports (" + err.Error() + ") and require every actual SSH listener, excluding VLESS."}
		},
	}
	backupDir := filepath.Join(operationDir, "backup")
	applied, applyErr := nodeApplyAndVerify(ctx, &result, &state, &opts, layout, record, previous, hasState, repair, cfg, managed, stagedManaged, agentPath, kernelPath, backupDir, sshPorts, applyFailures)
	if applyErr != nil {
		return result, applyErr
	}
	backupDir = applied.backupDir
	verifyFailures := nodeVerifyErrors{
		runtimeBusy:          &core.InstallError{Stage: "verify", Code: "NODE_RUNTIME_BUSY", Recovery: "The Agent runtime is applying a task. Preserve the active data plane and repair after the shared runtime lock is free."},
		kernelConfigApply:    &core.InstallError{Stage: "apply", Code: "KERNEL_CONFIG_APPLY_FAILED", Recovery: "The validated data plane files could not be installed; no Agent was started."},
		outACLApply:          &core.InstallError{Stage: "verify", Code: "OUT_ACL_APPLY_FAILED", Recovery: "Out ACL failed before the kernel started; no VLESS data plane is considered installed."},
		outACLReadback:       &core.InstallError{Stage: "verify", Code: "OUT_ACL_READBACK_FAILED", Recovery: "Out ACL ownership or default-deny readback failed; keep the kernel stopped and repair the exact table."},
		kernelStart:          &core.InstallError{Stage: "verify", Code: "KERNEL_START_FAILED", Recovery: "Review sing-box logs and the active configuration; the Agent remains stopped."},
		nativeReadbackFormat: "The kernel remains active but native readback failed (%v). Repair the data plane; the Agent was not started.",
		journalDataPlane:     &core.InstallError{Stage: "verify", Code: "OPERATION_LOG_FAILED", Recovery: "The validated data plane is active; restore the journal before retrying."},
		agentStart:           &core.InstallError{Stage: "verify", Code: "AGENT_START_FAILED", Recovery: "The verified data plane remains active. Repair only the Agent service; do not stop sing-box."},
		finalLedger:          &core.InstallError{Stage: "verify", Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "The data plane and Agent are active but the final ledger failed; preserve them and repair state."},
		journalVerifyPass:    &core.InstallError{Stage: "verify", Code: "OPERATION_LOG_FAILED", Recovery: "The Node is active but the journal write failed; repair only state/logging."},
	}
	if verifyErr := nodeVerifyTail(ctx, &result, &state, &opts, layout, record, repair, cfg, installedCfg, activeCandidate, candidateConfig, repairNotice, checks, artifacts, stageDir, backupDir, verifyFailures); verifyErr != nil {
		return result, verifyErr
	}
	return result, nil
}

func failNodePartial(result core.InstallResult, state core.InstallState, opts core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, stage, code, recovery string) (core.InstallResult, error) {
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
	state.UpdatedAt = time.Now().UTC()
	_ = core.WriteNodeState(opts.Root, layout, state)
	result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "partial", code, recovery
	_ = record(stage, "failed", code)
	return result, &core.InstallError{Stage: stage, Code: code, Recovery: recovery}
}

func failVerifiedPartial(result core.InstallResult, state core.InstallState, opts core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, stage, code, recovery string) (core.InstallResult, error) {
	// The validated data plane is intentionally left running. Do not call
	// Hub rollback: it would stop unrelated Hub units or the active kernel.
	return failNodePartial(result, state, opts, layout, record, stage, code, recovery)
}

func rollbackNodeFailure(result core.InstallResult, state, previous core.InstallState, hadPrevious bool, opts core.NodeApplyOptions, layout core.NodeLayout, snapshots []core.FileSnapshot, record func(string, string, string) error, stage string, cause error) (core.InstallResult, error) {
	code, recovery := "NODE_APPLY_FAILED", "No Agent is considered installed. Inspect the operation journal and run --repair."
	var ie *core.InstallError
	if errors.As(cause, &ie) {
		code, recovery = ie.Code, ie.Recovery
	}
	rollbackOK := core.RollbackNodeFiles(context.Background(), opts, snapshots, hadPrevious && previous.Status == "installed")
	if rollbackOK && hadPrevious && previous.Status == "installed" {
		previous.LastOperation, previous.ErrorCode, previous.Recovery = state.OperationID, code, recovery
		previous.UpdatedAt = time.Now().UTC()
		_ = core.WriteNodeState(opts.Root, layout, previous)
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "rolled_back", code, recovery
	} else {
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		if rollbackOK {
			core.ReconcileManagedLedger(&state, snapshots)
		}
		_ = core.WriteNodeState(opts.Root, layout, state)
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "partial", code, recovery
	}
	if !rollbackOK {
		result.Status, result.ErrorCode = "partial", "ROLLBACK_FAILED"
		result.Recovery = "Do not delete identity or kernel data. Inspect the journal and restore only recorded MeshMux Node files."
	}
	_ = record(stage, "failed", result.ErrorCode)
	return result, &core.InstallError{Stage: stage, Code: result.ErrorCode, Recovery: result.Recovery}
}

// verifyNodeACLReadback proves the live Out guard is the retired, rule-free
// table. The source allowlist is gone, so there is no authorization to compare:
// the table must exist, carry the MeshMux input chain, and contain no rule. A
// legacy accept or dport drop is a failure, because it would filter clients the
// Out link key now admits.
func verifyNodeACLReadback(ctx context.Context, runner core.CommandRunner, root string, cfg corenode.Config, candidate corenode.Candidate, vlessPort int) error {
	aclPath := core.Rooted(root, corenode.ACLPath)
	info, err := os.Lstat(aclPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return errors.New("OUT_ACL_READBACK_FAILED")
	}
	out, err := runner.Run(ctx, "nft", "-j", "list", "table", "inet", corenode.ACLTable)
	if err != nil {
		return errors.New("OUT_ACL_READBACK_FAILED")
	}
	if err := corenode.VerifyOutACLShapeDocument(out, vlessPort); err != nil {
		return errors.New("OUT_ACL_READBACK_FAILED")
	}
	return nil
}
