package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
)

const (
	nodeAgentStateDir = "/var/lib/meshmux-agent"
	nodeKernelDataDir = "/var/lib/meshmux-singbox"
)

// clientUnauthorized reports whether a Hub client failure is an identity
// rejection (revoked or replaced identity) rather than a transport or data
// problem. Only revocation may prompt the operator for a fresh pairing code.
func clientUnauthorized(err error) bool {
	var ce *node.ClientError
	if errors.As(err, &ce) {
		return ce.StatusCode == 401
	}
	return false
}

func InstallNode(ctx context.Context, cfg node.Config, operationID string, repair bool, pairingCode string, opts NodeApplyOptions) (InstallResult, error) {
	result := InstallResult{OperationID: operationID, Stage: "preflight", Status: "failed"}
	fail := func(stage, code, recovery string) (InstallResult, error) {
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "failed", code, recovery
		return result, &InstallError{Stage: stage, Code: code, Recovery: recovery}
	}
	if !operationIDPattern.MatchString(operationID) {
		return fail("preflight", "OPERATION_ID_INVALID", "Generate a new operation ID and retry.")
	}
	if err := cfg.Validate(); err != nil {
		return fail("preflight", "CONFIG_INVALID", "Supply a valid HTTPS Hub URL, node identity, edge/out role and distinct SSH/VLESS ports.")
	}
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.Root == "/" && os.Geteuid() != 0 {
		return fail("preflight", "ROOT_REQUIRED", "Run the installer as root; the Agent service does not listen for management traffic.")
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Preflight == nil {
		opts.Preflight = func(ctx context.Context, cfg node.Config, allowManaged bool) ([]Check, []int) {
			return preflightNode(ctx, cfg, allowManaged, opts.Root, opts.Runner)
		}
	}
	if opts.DownloadArtifact == nil {
		opts.DownloadArtifact = func(ctx context.Context, a Artifact, dir string) (string, error) {
			return DownloadVerified(ctx, opts.HTTPClient, a, dir)
		}
	}
	if opts.Pair == nil {
		opts.Pair = func(ctx context.Context, cfg node.Config, code string) (node.Identity, error) {
			client, err := node.NewClient(cfg, node.Identity{}, opts.HTTPClient)
			if err != nil {
				return node.Identity{}, err
			}
			return client.Pair(ctx, code)
		}
	}
	if opts.Metadata == nil {
		opts.Metadata = func(ctx context.Context, cfg node.Config, identity node.Identity) (node.Metadata, error) {
			client, err := node.NewClient(cfg, identity, opts.HTTPClient)
			if err != nil {
				return node.Metadata{}, err
			}
			return client.Metadata(ctx)
		}
	}
	if opts.Candidate == nil {
		opts.Candidate = func(ctx context.Context, cfg node.Config, identity node.Identity, revision int64) (node.CandidateDocument, error) {
			client, err := node.NewClient(cfg, identity, opts.HTTPClient)
			if err != nil {
				return node.CandidateDocument{}, err
			}
			return client.Candidate(ctx, revision)
		}
	}
	if opts.Readback == nil {
		opts.Readback = node.ReadbackLocal
	}
	if opts.Verify == nil {
		opts.Verify = verifyNodeInstall
	}

	lock, lockErr := acquireInstallLock(opts.Root, "Check /run/lock ownership and symlinks.")
	if lockErr != nil {
		return fail(lockErr.Stage, lockErr.Code, lockErr.Recovery)
	}
	defer lock.Close()

	// The ledger this operation owns is selected from the host's own
	// recorded state. A host that already runs the Hub hosts one
	// co-located Line with a separate ledger; the Hub ledger, its
	// services and its Fail2ban jail are never rewritten here.
	layout, err := resolveNodeLayout(opts.Root)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail(ie.Stage, ie.Code, ie.Recovery)
		}
		return fail("preflight", "INSTALL_STATE_INVALID", "Inspect the recorded installer state before retrying.")
	}
	if layout.HubHost && !layout.CoLocated {
		// A Hub host that cannot publish a pinned reusable runtime cannot
		// host a Line. The Line ledger would have to record a second MeshMux
		// binary, and the Hub ledger can never prove Node ownership. This is
		// an ownership failure, not a layout conflict: repair the Hub first.
		return fail("preflight", nodeOwnershipUnverified,
			"This host records a Hub layout that cannot host a co-located Line because the Hub does not publish a pinned reusable MeshMux runtime. Repair the Hub layout first; a Line never falls back to the Hub ledger.")
	}
	if layout.CoLocated {
		// A co-located Line may only talk to the Hub that owns this host.
		// Any other Hub origin is a remote node, not this local Line.
		if origin := hubOriginFor(layout.HubState); origin == "" || cfg.HubURL != origin {
			return fail("preflight", "LOCAL_LINE_HUB_MISMATCH",
				"A Line co-located with this Hub must use the Hub origin of the installed management host.")
		}
	}

	state, hasState, err := readNodeState(opts.Root, layout)
	if err != nil {
		return fail("preflight", "INSTALL_STATE_INVALID", "Inspect the recorded installer state; do not delete Agent identity or kernel data.")
	}
	if hasState {
		if state.Node != nil && (state.Config.ManagementDomain != "" || state.Config.SubscriptionDomain != "" || state.Config.HeadscaleDomain != "") {
			return fail("preflight", "HOST_LAYOUT_CONFLICT", "This host contains a Hub layout. Hub, edge and out layouts are mutually exclusive and are never overwritten in place.")
		}
		if state.Node == nil {
			return fail("preflight", "HOST_LAYOUT_CONFLICT", "This host already has a non-Node MeshMux layout; use a separate host.")
		}
		if !SameNodeConfig(*state.Node, cfg) {
			return fail("preflight", "CONFIG_CONFLICT", "Repair only supports the recorded Hub URL, node, role and ports; create a new node enrollment for migration.")
		}
	}
	if repair && !hasState {
		return fail("preflight", "REPAIR_STATE_MISSING", "Repair requires a Node state record created by MeshMux.")
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
			return result, &InstallError{Stage: "preflight", Code: c.Code, Recovery: recovery}
		}
	}
	if len(sshPorts) == 0 || !containsPort(sshPorts, cfg.SSHPort) {
		return fail("preflight", "SSH_LISTENER_UNKNOWN", "Determine the actual SSH listener before installing Fail2ban or VLESS.")
	}
	if containsPort(sshPorts, cfg.VLESSPort) {
		return fail("preflight", "PORT_CONFLICT", "VLESS cannot use any actual SSH listener port.")
	}
	// A co-located Line reuses the Hub's Fail2ban SSH jail. The reuse is
	// only safe when the Hub's jail provably covers this host's actual SSH
	// listeners; otherwise the Line refuses rather than duplicating the
	// jail or leaving the listener unprotected.
	if err := checkLocalLineSSHJailReuse(layout, sshPorts); err != nil {
		var ie *InstallError
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
	if err := validateNodeArchitecture(architecture); err != nil {
		return fail("preflight", "ARCH_UNSUPPORTED", "Use Debian 13 on amd64 or arm64.")
	}
	release, ok := node.KernelReleaseFor(architecture)
	if !ok {
		return fail("stage", "ARTIFACT_MANIFEST_INVALID", "Use the pinned Node manifest for this architecture.")
	}
	artifacts := PinnedNodeArtifacts(architecture)
	if opts.Root != "/" && len(opts.Artifacts) > 0 {
		artifacts = append([]Artifact(nil), opts.Artifacts...)
	}
	if len(artifacts) != 1 || artifacts[0].Component != "sing-box" || artifacts[0].Version != node.KernelVersion ||
		!validDigest.MatchString(artifacts[0].SHA256) || artifacts[0].Source != release.SourceURL {
		return fail("stage", "ARTIFACT_MANIFEST_INVALID", "Use exactly the pinned sing-box release; latest and caller-supplied URLs are rejected.")
	}
	if err := checkNodeTargets(opts.Root, cfg, sshPorts, state, hasState, layout); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail(ie.Stage, ie.Code, ie.Recovery)
		}
		return fail("preflight", "MANAGED_PATH_CONFLICT", "Inspect the fixed Node paths manually; MeshMux does not adopt third-party files or tables.")
	}

	now := time.Now().UTC()
	previous := cloneInstallState(state)
	if !hasState {
		state = InstallState{Schema: 1, CreatedAt: now, ManagedFiles: map[string]string{}, Artifacts: map[string]string{}}
	}
	if state.ManagedFiles == nil {
		state.ManagedFiles = map[string]string{}
	}
	if state.Artifacts == nil {
		state.Artifacts = map[string]string{}
	}
	state.OperationID, state.LastOperation = operationID, operationID
	state.Status, state.Stage = "installing", "stage"
	state.Config = Config{}
	// The recorded Node carries the verified binary hashes after the first
	// install. A repair must not wipe them back to the hashless user config,
	// otherwise the next repair preflight cannot recognize its own kernel
	// listener and fails with PORT_CONFLICT.
	if !hasState || state.Node == nil {
		state.Node = cloneNodeConfig(&cfg)
	}
	state.Artifacts["sing-box"] = artifacts[0].SHA256
	state.Architecture, state.SSHPorts, state.ErrorCode, state.Recovery = architecture, sortedInts(sshPorts), "", ""
	if layout.CoLocated {
		// The Line pins the exact Hub-owned runtime build it reuses. The pin
		// is what lets a later Hub repair detect a mismatching shared
		// binary instead of silently moving the Line to another build.
		if state.SharedBinaries == nil {
			state.SharedBinaries = map[string]SharedBinary{}
		}
		state.SharedBinaries[sharedAgentKey] = SharedBinary{
			Path:   layout.SharedAgent,
			SHA256: layout.SharedAgentSHA256,
		}
	}
	state.UpdatedAt = now
	if err := writeNodeState(opts.Root, layout, state); err != nil {
		return fail("stage", "INSTALL_STATE_WRITE_FAILED", "Check disk space and permissions under /var/lib/meshmux-installer.")
	}
	operationDir := rooted(opts.Root, layout.OperationDir+"/"+operationID)
	journalPath := filepath.Join(operationDir, "events.jsonl")
	record := newOperationRecorder(operationID, journalPath)
	if err := record("stage", "started", ""); err != nil {
		return failNodePartial(result, state, opts, layout, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions and run --repair.")
	}

	stage, stageErr := stageNodeArtifacts(ctx, &result, &state, &opts, layout, record, cfg, hasState, operationID, artifacts[0], release, nodeStageErrors{
		stageRemove:              &InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Remove only the incomplete staging directory for this operation and retry."},
		stageCache:               &InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check /var/cache space and permissions; no host files were applied."},
		stageTemporary:           &InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check temporary disk space and permissions."},
		artifactDownloadRecovery: "Check outbound HTTPS to the pinned official GitHub asset; unverified archives are never applied.",
		artifactChecksum:         &InstallError{Stage: "stage", Code: "ARTIFACT_CHECKSUM_MISMATCH", Recovery: "Delete the staged archive and retry; never bypass archive SHA-256 verification."},
		artifactFormat:           &InstallError{Stage: "stage", Code: "ARTIFACT_FORMAT_INVALID", Recovery: "Use the official pinned sing-box archive for this architecture."},
		kernelChecksum:           &InstallError{Stage: "stage", Code: "KERNEL_CHECKSUM_MISMATCH", Recovery: "Delete the staged kernel and retry; the binary must match the release manifest."},
		kernelVersion:            &InstallError{Stage: "stage", Code: "KERNEL_VERSION_INVALID", Recovery: "Use the exact pinned sing-box release for this architecture."},
		meshmuxBinary:            &InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID", Recovery: "Run the installer from a regular MeshMux executable and retry."},
		candidateRender:          &InstallError{Stage: "stage", Code: "CANDIDATE_RENDER_FAILED", Recovery: "Review the Node role and VLESS port."},
		kernelConfig:             &InstallError{Stage: "stage", Code: "KERNEL_CONFIG_INVALID", Recovery: "Review the generated native sing-box configuration."},
		packageIndex:             &InstallError{Stage: "apply", Code: "PACKAGE_INDEX_FAILED", Recovery: "Check Debian repository connectivity; no package upgrade or third-party repository is used."},
		packageInstall:           &InstallError{Stage: "apply", Code: "PACKAGE_INSTALL_FAILED", Recovery: "Review Debian apt status; only the listed missing packages are installed."},
		aclProbe:                 &InstallError{Stage: "apply", Code: "ACL_TABLE_PROBE_FAILED", Recovery: "Re-run the exact nft ownership readback. MeshMux will not adopt, overwrite or delete an unverified table."},
		aclRender:                &InstallError{Stage: "stage", Code: "ACL_RENDER_FAILED", Recovery: "Review the Out role configuration."},
		aclConfig:                &InstallError{Stage: "stage", Code: "ACL_CONFIG_INVALID", Recovery: "Review the generated default-deny Out table; the host ruleset was not changed."},
		operationLog:             &InstallError{Stage: "stage", Code: "OPERATION_LOG_FAILED", Recovery: "Check installer state directory permissions and run --repair."},
	})
	if stageErr != nil {
		return result, stageErr
	}
	stageDir, kernelPath, agentPath, installedCfg := stage.stageDir, stage.kernelPath, stage.agentPath, stage.installedCfg

	identityFailures := nodeIdentityErrors{
		identityInvalid:       &InstallError{Stage: "stage", Code: "IDENTITY_INVALID", Recovery: "Inspect the private Agent identity; do not delete it until the Hub identity is revoked."},
		pairingFailedRepair:   &InstallError{Stage: "stage", Code: "PAIRING_FAILED", Recovery: "Check the one-time code, Hub reachability and node role/ports. A failed request may still have been consumed; reissue a code before retrying."},
		pairingRequired:       &InstallError{Stage: "stage", Code: "PAIRING_REQUIRED", Recovery: "The recorded identity was revoked or replaced. Reissue a pairing code in Hub Web and run --repair with the fresh code."},
		pairingMetadataRepair: &InstallError{Stage: "stage", Code: "PAIRING_METADATA_FAILED", Recovery: "The private identity is preserved. Fix Hub metadata/candidate availability and run --repair; do not request another code."},
		pairingMetadataFresh:  &InstallError{Stage: "stage", Code: "PAIRING_METADATA_FAILED", Recovery: "The private identity is persisted. Fix Hub metadata/candidate availability and run --repair; do not request another code."},
		identityMissing:       &InstallError{Stage: "stage", Code: "IDENTITY_MISSING", Recovery: "A repair reuses the private identity when it is still valid. Restore the identity, or revoke and re-enroll the node; a revoked identity needs a fresh pairing code."},
		pairingCodeRequired:   &InstallError{Stage: "pairing", Code: "PAIRING_CODE_REQUIRED", Recovery: "Enter the current one-time code on stdin after local staging checks pass."},
		pairingFailedFresh:    &InstallError{Stage: "stage", Code: "PAIRING_FAILED", Recovery: "Check the one-time code, Hub reachability and node role/ports. A failed request may still have been consumed."},
		agentStateUnsafe:      &InstallError{Stage: "stage", Code: "AGENT_STATE_UNSAFE", Recovery: "Use a root-owned 0700 Agent directory; the kernel group must not read identity tokens."},
		identityPersistFailed: &InstallError{Stage: "stage", Code: "IDENTITY_PERSIST_FAILED", Recovery: "The Hub code may already be consumed. Preserve this operation's journal, reissue a code for the same node in Web and retry after fixing disk permissions."},
		stateWriteFailed:      &InstallError{Stage: "stage", Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "Check installer state disk space and permissions; preserve the private identity."},
	}
	resolved, resolveErr := nodeResolveIdentityAndCandidate(ctx, &result, &state, &opts, layout, record, installedCfg, repair, pairingCode, identityFailures)
	if resolveErr != nil {
		return result, resolveErr
	}
	if resolved.pairingPending {
		return result, identityFailures.pairingCodeRequired
	}
	identity, candidate := resolved.identity, resolved.candidate
	candidateFailures := nodeCandidateErrors{
		marshalFailed:      &InstallError{Stage: "stage", Code: "CANDIDATE_RENDER_FAILED", Recovery: "Review the Hub candidate response and retry with --repair."},
		compileFailed:      &InstallError{Stage: "stage", Code: "CANDIDATE_RENDER_FAILED", Recovery: "Review the Hub candidate role, node and port binding."},
		candidateInvalid:   &InstallError{Stage: "stage", Code: "CANDIDATE_INVALID", Recovery: "The Hub candidate failed local validation; no active kernel configuration was replaced."},
		configRenderFailed: &InstallError{Stage: "stage", Code: "CONFIG_RENDER_FAILED", Recovery: "Review the actual SSH listeners and the fixed Node service layout."},
		stageTemporary:     &InstallError{Stage: "stage", Code: "STAGE_UNAVAILABLE", Recovery: "Check temporary disk space and permissions."},
		operationLog:       &InstallError{Stage: "stage", Code: "OPERATION_LOG_FAILED", Recovery: "Check installer state directory permissions and run --repair."},
	}
	finalized, finalizeErr := nodeFinalizeCandidate(ctx, &result, &state, &opts, layout, record, repair, cfg, installedCfg, identity, candidate, sshPorts, stageDir, kernelPath, candidateFailures)
	if finalizeErr != nil {
		return result, finalizeErr
	}
	activeCandidate, candidateConfig := finalized.activeCandidate, finalized.candidateConfig
	managed, stagedManaged := finalized.managed, finalized.stagedManaged

	applyFailures := nodeApplyErrors{
		accountCreate:     &InstallError{Stage: "apply", Code: "ACCOUNT_CREATE_FAILED", Recovery: "Inspect meshmux-singbox and meshmux-agent accounts before retrying."},
		dataDirectory:     &InstallError{Stage: "apply", Code: "DATA_DIRECTORY_FAILED", Recovery: "Check Agent and kernel data directory ownership; never expose the identity directory to the kernel group."},
		backupDirectory:   &InstallError{Stage: "apply", Code: "BACKUP_FAILED", Recovery: "Check installer state disk space."},
		backupSnapshot:    &InstallError{Stage: "apply", Code: "BACKUP_FAILED", Recovery: "No managed files were replaced; inspect the operation journal."},
		journalFilesWrite: &InstallError{Stage: "apply", Code: "OPERATION_LOG_FAILED", Recovery: "Restore the journal before another apply."},
		systemdUnit:       &InstallError{Stage: "verify", Code: "SYSTEMD_UNIT_INVALID", Recovery: "Review the fixed Agent, kernel and ACL units; no Node is installed until validation succeeds."},
		fail2banConfig:    &InstallError{Stage: "verify", Code: "FAIL2BAN_CONFIG_INVALID", Recovery: "Review the Node SSH jail and preserve all existing Fail2ban jails."},
		systemdReload:     &InstallError{Stage: "apply", Code: "SYSTEMD_RELOAD_FAILED", Recovery: "Inspect systemd and run --repair."},
		fail2banStart:     &InstallError{Stage: "verify", Code: "FAIL2BAN_START_FAILED", Recovery: "Review Fail2ban logs and the Node SSH jail; do not alter sshd or flush nftables."},
		fail2banReload:    &InstallError{Stage: "verify", Code: "FAIL2BAN_RELOAD_FAILED", Recovery: "Review Fail2ban logs and preserve existing jails."},
		fail2banWait:      &InstallError{Stage: "verify", Code: "FAIL2BAN_START_FAILED", Recovery: "The Fail2ban service never became queryable; inspect the service and run --repair."},
		hubJailReadback: func(err error) *InstallError {
			return &InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Read back the Hub Fail2ban action ports (" + err.Error() + ") and require every actual SSH listener, excluding VLESS."}
		},
		standaloneJailReadback: func(err error) *InstallError {
			return &InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Read back the Fail2ban action ports (" + err.Error() + ") and require every actual SSH listener, excluding VLESS."}
		},
	}
	backupDir := filepath.Join(operationDir, "backup")
	applied, applyErr := nodeApplyAndVerify(ctx, &result, &state, &opts, layout, record, previous, hasState, repair, cfg, managed, stagedManaged, agentPath, kernelPath, backupDir, sshPorts, applyFailures)
	if applyErr != nil {
		return result, applyErr
	}
	backupDir = applied.backupDir
	if repair {
		lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lock, lockErr := node.AcquireRuntimeLock(lockCtx, opts.Root)
		cancel()
		if lockErr != nil {
			return failVerifiedPartial(result, state, opts, layout, record, "verify", "NODE_RUNTIME_BUSY", "The Agent runtime is applying a task. Preserve the active data plane and repair after the shared runtime lock is free.")
		}
		defer lock.Close()
	}
	_, lkgOK := nodeValidLKG(opts.Root, installedCfg)
	if !repair || !lkgOK {
		if err := installNodeDynamic(ctx, opts, activeCandidate, candidateConfig, installedCfg.Role); err != nil {
			return failVerifiedPartial(result, state, opts, layout, record, "apply", "KERNEL_CONFIG_APPLY_FAILED", "The validated data plane files could not be installed; no Agent was started.")
		}
	}
	if cfg.Role == node.RoleOut {
		// The ACL unit applies /var/lib/meshmux-agent/out.nft, which is
		// written by installNodeDynamic above. Starting it earlier fails on
		// a clean host where the file does not exist yet.
		if err := activateNodeUnit(ctx, opts.Runner, node.ACLUnit, repair); err != nil {
			return failVerifiedPartial(result, state, opts, layout, record, "verify", "OUT_ACL_APPLY_FAILED", "Out ACL failed before the kernel started; no VLESS data plane is considered installed.")
		}
		if err := verifyNodeACLReadback(ctx, opts.Runner, installedCfg.VLESSPort); err != nil {
			return failVerifiedPartial(result, state, opts, layout, record, "verify", "OUT_ACL_READBACK_FAILED", "Out ACL ownership or default-deny readback failed; keep the kernel stopped and repair the exact table.")
		}
	}
	if err := activateNodeUnit(ctx, opts.Runner, node.SingBoxUnit, repair); err != nil {
		return failVerifiedPartial(result, state, opts, layout, record, "verify", "KERNEL_START_FAILED", "Review sing-box logs and the active configuration; the Agent remains stopped.")
	}
	nativeReadback, err := pollNodeReadback(ctx, opts, installedCfg)
	if err == nil {
		err = nativeReadback.Validate()
	}
	if err == nil {
		err = opts.Verify(ctx, installedCfg, opts.Runner, nativeReadback)
	}
	if err == nil && lkgOK {
		if currentDigest, currentOK := nodeValidLKG(opts.Root, installedCfg); !currentOK || currentDigest != nativeReadback.ConfigSHA256 {
			err = errors.New("LKG_READBACK_HASH_MISMATCH")
		}
	}
	if err != nil {
		return failVerifiedPartial(result, state, opts, layout, record, "verify", "NATIVE_READBACK_FAILED", fmt.Sprintf("The kernel remains active but native readback failed (%v). Repair the data plane; the Agent was not started.", err))
	}
	if err := record("verify", "data_plane_active", ""); err != nil {
		return failVerifiedPartial(result, state, opts, layout, record, "verify", "OPERATION_LOG_FAILED", "The validated data plane is active; restore the journal before retrying.")
	}
	// The installer holds the shared runtime lock here. Do not restart an
	// already-running Agent: restart would make the new process wait on this
	// same lock. enable --now is idempotent and starts it only when inactive.
	if _, err := opts.Runner.Run(ctx, "systemctl", "enable", "--now", node.AgentUnit); err != nil {
		return failVerifiedPartial(result, state, opts, layout, record, "verify", "AGENT_START_FAILED", "The verified data plane remains active. Repair only the Agent service; do not stop sing-box.")
	}
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.UpdatedAt = time.Now().UTC()
	if err := writeNodeState(opts.Root, layout, state); err != nil {
		return failVerifiedPartial(result, state, opts, layout, record, "verify", "INSTALL_STATE_WRITE_FAILED", "The data plane and Agent are active but the final ledger failed; preserve them and repair state.")
	}
	if err := record("verify", "pass", ""); err != nil {
		return failVerifiedPartial(result, state, opts, layout, record, "verify", "OPERATION_LOG_FAILED", "The Node is active but the journal write failed; repair only state/logging.")
	}
	_ = os.RemoveAll(stageDir)
	_ = os.RemoveAll(backupDir)
	result.Stage, result.Status, result.Checks = "verify", "installed", checks
	result.Artifacts = nodeComponents(artifacts)
	return result, nil
}

func failNodePartial(result InstallResult, state InstallState, opts NodeApplyOptions, layout nodeLayout, record func(string, string, string) error, stage, code, recovery string) (InstallResult, error) {
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
	state.UpdatedAt = time.Now().UTC()
	_ = writeNodeState(opts.Root, layout, state)
	result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "partial", code, recovery
	_ = record(stage, "failed", code)
	return result, &InstallError{Stage: stage, Code: code, Recovery: recovery}
}

func failVerifiedPartial(result InstallResult, state InstallState, opts NodeApplyOptions, layout nodeLayout, record func(string, string, string) error, stage, code, recovery string) (InstallResult, error) {
	// The validated data plane is intentionally left running. Do not call
	// Hub rollback: it would stop unrelated Hub units or the active kernel.
	return failNodePartial(result, state, opts, layout, record, stage, code, recovery)
}

func rollbackNodeFailure(result InstallResult, state, previous InstallState, hadPrevious bool, opts NodeApplyOptions, layout nodeLayout, snapshots []fileSnapshot, record func(string, string, string) error, stage string, cause error) (InstallResult, error) {
	code, recovery := "NODE_APPLY_FAILED", "No Agent is considered installed. Inspect the operation journal and run --repair."
	var ie *InstallError
	if errors.As(cause, &ie) {
		code, recovery = ie.Code, ie.Recovery
	}
	rollbackOK := rollbackNodeFiles(context.Background(), opts, snapshots, hadPrevious && previous.Status == "installed")
	if rollbackOK && hadPrevious && previous.Status == "installed" {
		previous.LastOperation, previous.ErrorCode, previous.Recovery = state.OperationID, code, recovery
		previous.UpdatedAt = time.Now().UTC()
		_ = writeNodeState(opts.Root, layout, previous)
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "rolled_back", code, recovery
	} else {
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		if rollbackOK {
			reconcileManagedLedger(&state, snapshots)
		}
		_ = writeNodeState(opts.Root, layout, state)
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "partial", code, recovery
	}
	if !rollbackOK {
		result.Status, result.ErrorCode = "partial", "ROLLBACK_FAILED"
		result.Recovery = "Do not delete identity or kernel data. Inspect the journal and restore only recorded MeshMux Node files."
	}
	_ = record(stage, "failed", result.ErrorCode)
	return result, &InstallError{Stage: stage, Code: result.ErrorCode, Recovery: result.Recovery}
}

func rollbackNodeFiles(ctx context.Context, opts NodeApplyOptions, snapshots []fileSnapshot, restoreRunning bool) bool {
	ok := true
	for _, unit := range []string{node.AgentUnit, node.SingBoxUnit, node.ACLUnit} {
		_, _ = opts.Runner.Run(ctx, "systemctl", "stop", unit)
	}
	for i := len(snapshots) - 1; i >= 0; i-- {
		s := snapshots[i]
		if !s.Exists {
			if err := os.Remove(s.Target); err != nil && !os.IsNotExist(err) {
				ok = false
			}
			continue
		}
		if err := copyAtomic(s.Backup, s.Target, s.Mode.Perm()); err != nil {
			ok = false
			continue
		}
		if opts.Root == "/" {
			if err := os.Chown(s.Target, s.UID, s.GID); err != nil {
				ok = false
			}
		}
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		ok = false
	}
	if restoreRunning && ok {
		for _, unit := range []string{node.SingBoxUnit, node.AgentUnit} {
			if _, err := opts.Runner.Run(ctx, "systemctl", "start", unit); err != nil {
				ok = false
			}
		}
	}
	return ok
}

func applyNodeFiles(ctx context.Context, opts NodeApplyOptions, layout nodeLayout, state InstallState, managed map[string]nodeManagedFile, files map[string]string, backupDir string) error {
	keys := make([]string, 0, len(files))
	for path := range files {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	for _, target := range keys {
		mode, owner := os.FileMode(0644), "root:root"
		if file, ok := managed[target]; ok {
			mode, owner = os.FileMode(file.Mode), file.Owner
		} else if target == node.AgentBinaryPath || target == node.SingBoxBinaryPath {
			mode = 0755
		} else if target == node.IdentityPath {
			mode = 0600
		}
		if err := copyAtomic(files[target], rooted(opts.Root, target), mode); err != nil {
			return &InstallError{Code: "FILE_APPLY_FAILED", Recovery: "No Agent was started; inspect the operation journal and run --repair."}
		}
		if opts.Root == "/" {
			if _, err := opts.Runner.Run(ctx, "chown", owner, target); err != nil {
				return &InstallError{Code: "FILE_OWNERSHIP_FAILED", Recovery: "No Agent was started; inspect service-account ownership and run --repair."}
			}
		}
		digest, err := sha256File(rooted(opts.Root, target))
		if err != nil {
			return &InstallError{Code: "FILE_READBACK_FAILED", Recovery: "Readback failed after an atomic write; inspect the target filesystem."}
		}
		if file, ok := managed[target]; ok && file.Static {
			state.ManagedFiles[target] = digest
		} else if target == node.AgentBinaryPath || target == node.SingBoxBinaryPath {
			// Staged binaries are hash-verified before apply. Recording them
			// lets a later repair recognize its own binaries instead of
			// rejecting them as third-party files; drift still fails closed
			// as MANAGED_FILE_DRIFT.
			state.ManagedFiles[target] = digest
		}
		if err := writeNodeState(opts.Root, layout, state); err != nil {
			return &InstallError{Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "The file ledger failed to persist; preserve the journal and run --repair."}
		}
	}
	return nil
}

func snapshotNodeTargets(root string, targets []string, state InstallState, hasState bool, backupDir string) ([]fileSnapshot, error) {
	var snapshots []fileSnapshot
	for _, target := range targets {
		path := rooted(root, target)
		info, err := os.Lstat(path)
		snapshot := fileSnapshot{Target: path, Logical: target, Backup: filepath.Join(backupDir, strings.TrimPrefix(strings.ReplaceAll(target, "/", "_"), "_"))}
		if os.IsNotExist(err) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return snapshots, &InstallError{Code: "MANAGED_PATH_UNSAFE", Recovery: "Inspect the target; symlinks and non-regular files are never replaced."}
		}
		if !hasState {
			return snapshots, &InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The target exists without MeshMux ownership state."}
		}
		if target == node.IdentityPath && !stateOwnsNodeState(state) {
			return snapshots, &InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The private identity appeared after it was created by this operation; inspect concurrent access."}
		}
		if _, recorded := state.ManagedFiles[target]; !recorded {
			if target == node.IdentityPath || target == node.ActiveConfigPath || target == node.ActiveCandidatePath {
				// These are protected dynamic/private paths. A repair may
				// snapshot them, but only the identity is reused and the
				// dynamic LKG is never overwritten merely to repair layout.
			} else {
				return snapshots, &InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The target is not recorded as MeshMux-managed."}
			}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return snapshots, errors.New("TARGET_OWNER_UNKNOWN")
		}
		if err := copyAtomic(path, snapshot.Backup, info.Mode().Perm()); err != nil {
			return snapshots, err
		}
		snapshot.Exists, snapshot.Mode, snapshot.UID, snapshot.GID = true, info.Mode(), int(st.Uid), int(st.Gid)
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func stateOwnsNodeState(state InstallState) bool {
	return state.Node != nil && state.Schema == 1 && operationIDPattern.MatchString(state.OperationID)
}

// checkNodeTargets verifies that the paths this Node operation will write
// are either free or recorded as MeshMux-managed by this Node's own ledger.
//
// A co-located Line does not own the Hub's runtime binary: the shared
// binary is verified separately against the digest the Hub published, and
// it is never adopted into the Line's own managed-file ledger.
func checkNodeTargets(root string, cfg node.Config, ssh []int, state InstallState, hasState bool, layout nodeLayout) error {
	paths := []string{
		node.AgentBinaryPath, node.SingBoxBinaryPath, node.AgentConfigPath,
		"/etc/systemd/system/" + node.AgentUnit, "/etc/systemd/system/" + node.SingBoxUnit,
	}
	if !layout.ReuseHubSSHJail {
		paths = append(paths, nodeSSHJailPath)
	}
	if cfg.Role == node.RoleOut {
		paths = append(paths, "/etc/systemd/system/"+node.ACLUnit)
	}
	if layout.CoLocated {
		// The Hub owns the shared runtime. The Line verifies the recorded
		// digest instead of claiming ownership of the file.
		paths = removeTarget(paths, layout.SharedAgent)
	}
	if err := checkTargetOwnership(root, paths, state, hasState); err != nil {
		return err
	}
	if layout.CoLocated {
		if !sharedAgentMatches(root, layout.SharedAgent, layout.SharedAgentSHA256) {
			return &InstallError{Stage: "preflight", Code: "SHARED_BINARY_MISMATCH",
				Recovery: "The Hub-owned MeshMux runtime on this host no longer matches the recorded digest. Repair the Hub and the Line together; the Line never replaces the shared binary."}
		}
	}
	if cfg.Role == node.RoleOut {
		if err := checkDynamicNodeTarget(root, node.ACLPath, state, hasState); err != nil {
			return err
		}
	}
	for _, dir := range []string{nodeAgentStateDir, nodeKernelDataDir} {
		info, err := os.Lstat(rooted(root, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &InstallError{Stage: "preflight", Code: "DATA_PATH_UNSAFE", Recovery: "Inspect the fixed Node data directory; symlinks are rejected."}
		}
		if !hasState {
			entries, readErr := os.ReadDir(rooted(root, dir))
			if readErr != nil || len(entries) > 0 {
				return &InstallError{Stage: "preflight", Code: "DATA_STATE_CONFLICT", Recovery: "Data exists without a Node installer record; preserve and inspect it manually."}
			}
		}
	}
	return nil
}

func extractNodeKernel(archivePath, target string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		if filepath.Base(h.Name) != "sing-box" || h.Size < 1 || h.Size > maxInstallerFile {
			continue
		}
		if found {
			return errors.New("KERNEL_ARCHIVE_AMBIGUOUS")
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, maxInstallerFile+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n != h.Size || n > maxInstallerFile {
			_ = os.Remove(target)
			return errors.New("KERNEL_ARCHIVE_INVALID")
		}
		found = true
	}
	if !found {
		return errors.New("KERNEL_BINARY_MISSING")
	}
	return os.Chmod(target, 0755)
}

func ensurePrivateNodeDirectory(path string) error {
	if err := ensureNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("AGENT_STATE_UNSAFE")
	}
	return nil
}

func loadNodeIdentity(root string, cfg node.Config) (node.Identity, bool, error) {
	path := rooted(root, node.IdentityPath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return node.Identity{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return node.Identity{}, false, errors.New("IDENTITY_INVALID")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return node.Identity{}, false, errors.New("IDENTITY_INVALID")
	}
	var identity node.Identity
	if err := jsonUnmarshal(data, &identity); err != nil {
		return node.Identity{}, false, errors.New("IDENTITY_INVALID")
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return node.Identity{}, false, errors.New("IDENTITY_MISMATCH")
	}
	return identity, true, nil
}

func persistNodeIdentity(root string, identity node.Identity) error {
	if err := ensurePrivateNodeDirectory(rooted(root, nodeAgentStateDir)); err != nil {
		return err
	}
	data, err := jsonMarshal(identity)
	if err != nil {
		return err
	}
	return writeBytesAtomic(rooted(root, node.IdentityPath), data, 0600)
}

func ensureNodeAccounts(ctx context.Context, runner CommandRunner, root string, hasState bool) error {
	for _, account := range []struct {
		name, home string
	}{
		{"meshmux-agent", nodeAgentStateDir},
		{"meshmux-singbox", nodeKernelDataDir},
	} {
		out, err := runner.Run(ctx, "getent", "passwd", account.name)
		if err == nil && strings.TrimSpace(string(out)) != "" {
			continue
		}
		if _, err := runner.Run(ctx, "useradd", "--system", "--user-group", "--home-dir", account.home, "--no-create-home", "--shell", "/usr/sbin/nologin", account.name); err != nil {
			return err
		}
	}
	return nil
}

func ensureNodeDirectories(ctx context.Context, opts NodeApplyOptions) error {
	agentDir := rooted(opts.Root, nodeAgentStateDir)
	if err := ensurePrivateNodeDirectory(agentDir); err != nil {
		return err
	}
	kernelDir := rooted(opts.Root, nodeKernelDataDir)
	if err := ensureDirectory(kernelDir, 0750); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chown", "root:meshmux-agent", nodeAgentStateDir); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chmod", "0700", nodeAgentStateDir); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chown", "root:meshmux-singbox", nodeKernelDataDir); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chmod", "0750", nodeKernelDataDir); err != nil {
		return err
	}
	return nil
}

func nodeStaticTargets(files map[string]nodeManagedFile) []string {
	var out []string
	for path, file := range files {
		if file.Static {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func nodeUnitPaths(root string, cfg node.Config) []string {
	units := []string{rooted(root, "/etc/systemd/system/"+node.AgentUnit), rooted(root, "/etc/systemd/system/"+node.SingBoxUnit)}
	if cfg.Role == node.RoleOut {
		units = append(units, rooted(root, "/etc/systemd/system/"+node.ACLUnit))
	}
	return units
}

func activateNodeUnit(ctx context.Context, runner CommandRunner, unit string, repair bool) error {
	if repair {
		_, err := runner.Run(ctx, "systemctl", "restart", unit)
		return err
	}
	_, err := runner.Run(ctx, "systemctl", "enable", "--now", unit)
	return err
}

func verifyNodeACLReadback(ctx context.Context, runner CommandRunner, vlessPort int) error {
	out, err := runner.Run(ctx, "nft", "list", "table", "inet", node.ACLTable)
	if err != nil {
		return err
	}
	text := string(out)
	if !strings.Contains(text, "table inet "+node.ACLTable) || !strings.Contains(text, "policy accept") ||
		!strings.Contains(text, fmt.Sprintf("tcp dport %d drop", vlessPort)) ||
		!strings.Contains(text, fmt.Sprintf("udp dport %d drop", vlessPort)) {
		return errors.New("OUT_ACL_READBACK_FAILED")
	}
	return nil
}

func verifyNodeTableOwnershipAfterInstall(ctx context.Context, root string, runner CommandRunner, cfg node.Config, hasState bool) error {
	result := nodeTableOwnership(ctx, root, runner, cfg, hasState)
	if result.Kind == tableAbsent ||
		(result.Kind == tableManaged && tableOwnedByLedger(cfg, hasState)) {
		return nil
	}
	check := result.checkName("out_acl_table")
	return &InstallError{Code: check.Code, Recovery: check.Recovery}
}

func tableOwnedByLedger(cfg node.Config, hasState bool) bool {
	return hasState && cfg.Role == node.RoleOut
}

func usedPackage(packages []string, want string) bool {
	for _, pkg := range packages {
		if pkg == want {
			return true
		}
	}
	return false
}

// fail2banReadyTimeout/Interval bound the wait for the daemon socket and
// our jail after (re)start. Tests shrink them; production uses the defaults.
var fail2banReadyTimeout = 30 * time.Second
var fail2banReadyInterval = time.Second

// waitFail2banJail blocks until the Line's own jail answers queries.
// `enable --now` and `reload` return before the daemon recreates its socket
// and loads the jail, so an immediate readback fails with exit 255 on fast
// hosts.
func waitFail2banJail(ctx context.Context, runner CommandRunner) error {
	return waitFail2banJailNamed(ctx, runner, nodeSSHJailName)
}

// waitFail2banJailNamed blocks until the named jail answers queries. A
// co-located Line reuses the Hub's jail instead of installing a second one
// for the same SSH listeners.
func waitFail2banJailNamed(ctx context.Context, runner CommandRunner, jail string) error {
	if jail == "" {
		jail = nodeSSHJailName
	}
	deadline := time.Now().Add(fail2banReadyTimeout)
	for {
		if _, err := runner.Run(ctx, "fail2ban-client", "status", jail); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("FAIL2BAN_JAIL_UNAVAILABLE")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(fail2banReadyInterval):
		}
	}
}

// verifyNodeSSHJail reads the Line's own jail port set back from the running
// daemon.
func verifyNodeSSHJail(ctx context.Context, runner CommandRunner, ssh ...int) error {
	return verifyFail2banJailPorts(ctx, runner, nodeSSHJailName, ssh)
}

// verifyFail2banJailPorts reads a named jail's effective port set back from
// the running daemon. The jail name is explicit: a co-located Line verifies
// the Hub's jail instead of a second jail of its own.
//
// fail2ban 1.1.0 (Debian 13) removed `get <JAIL> port`; the jail port is
// read back through the nftables-multiport action instance, which also
// proves the daemon loaded the jail (an unknown jail errors out).
func verifyFail2banJailPorts(ctx context.Context, runner CommandRunner, jail string, ssh []int) error {
	if jail == "" {
		jail = nodeSSHJailName
	}
	portsOut, err := runner.Run(ctx, "fail2ban-client", "get", jail, "action", "nftables-multiport", "port")
	if err != nil {
		return fmt.Errorf("SSH_JAIL_QUERY_FAILED jail port readback: %v", err)
	}
	actionOut, err := runner.Run(ctx, "fail2ban-client", "get", jail, "action", "nftables-multiport", "actionstart")
	if err != nil {
		return fmt.Errorf("SSH_JAIL_QUERY_FAILED acl action readback: %v", err)
	}
	jailPorts, err := parseFail2banPorts(string(portsOut))
	if err != nil {
		return fmt.Errorf("SSH_JAIL_PORT_MISMATCH jail ports unparsable: %v", err)
	}
	actionPorts, err := parseFail2banActionPorts(string(actionOut))
	if err != nil {
		return fmt.Errorf("SSH_JAIL_PORT_MISMATCH acl action unparsable: %v", err)
	}
	want := sortedInts(ssh)
	if !equalIntSets(jailPorts, want) || !equalIntSets(actionPorts, want) {
		return fmt.Errorf("SSH_JAIL_PORT_MISMATCH jail=%v action=%v want=%v", jailPorts, actionPorts, want)
	}
	return nil
}

func parseFail2banPorts(output string) ([]int, error) {
	value := strings.TrimSpace(output)
	if output == value+"\n" {
		// A single CLI response line is expected, but a final newline alone
		// does not add a second value.
	} else if strings.ContainsAny(value, "\r\n") {
		return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
	}
	var ports []int
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if strings.Contains(raw, ":") {
			return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
		}
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 || containsPort(ports, port) {
			return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
		}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

// Real fail2ban 1.1.0 actionstart commands shell-escape the set braces
// (dport \{ ... \}), while older output used bare braces. Accept both so
// the readback works against the daemon instead of only the L1 fake.
var fail2banDportPattern = regexp.MustCompile(`dport\s+(?:\\?\{([^}]*)\}|([0-9]+))`)
var fail2banInteger = regexp.MustCompile(`\b[0-9]+\b`)

func parseFail2banActionPorts(output string) ([]int, error) {
	matches := fail2banDportPattern.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
	}
	var ports []int
	for _, match := range matches {
		var body string
		if match[1] != "" {
			body = match[1]
		} else {
			body = match[2]
		}
		for _, raw := range fail2banInteger.FindAllString(body, -1) {
			port, err := strconv.Atoi(raw)
			if err != nil || port < 1 || port > 65535 || containsPort(ports, port) {
				return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
			}
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

func equalIntSets(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA, sortedB := append([]int(nil), a...), append([]int(nil), b...)
	sort.Ints(sortedA)
	sort.Ints(sortedB)
	for i := range sortedA {
		if sortedA[i] != sortedB[i] {
			return false
		}
	}
	return true
}

func checkDynamicNodeTarget(root, target string, state InstallState, hasState bool) error {
	info, err := os.Lstat(rooted(root, target))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return &InstallError{Code: "MANAGED_PATH_UNSAFE", Recovery: "Inspect the dynamic MeshMux file; symlinks and non-private files are rejected."}
	}
	if !hasState {
		return &InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The dynamic file exists without a Node installer ledger."}
	}
	return nil
}

func currentNodeCandidate(root string, cfg node.Config) (node.CandidateDocument, bool) {
	candidateData, err := os.ReadFile(rooted(root, node.ActiveCandidatePath))
	if err != nil {
		return node.CandidateDocument{}, false
	}
	var document node.CandidateDocument
	if err := json.Unmarshal(candidateData, &document); err != nil || document.ValidateFor(cfg) != nil {
		return node.CandidateDocument{}, false
	}
	return document, true
}

func nodeValidLKG(root string, cfg node.Config) (string, bool) {
	active, ok := currentNodeCandidate(root, cfg)
	if !ok {
		return "", false
	}
	candidatePath := rooted(root, node.ActiveCandidatePath)
	candidateInfo, err := os.Lstat(candidatePath)
	if err != nil || !candidateInfo.Mode().IsRegular() || candidateInfo.Mode()&os.ModeSymlink != 0 || candidateInfo.Mode().Perm() != 0600 {
		return "", false
	}
	configPath := rooted(root, node.ActiveConfigPath)
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 {
		return "", false
	}
	if root == "/" && !nodeFileOwnedBy(configPath, 0, "meshmux-singbox") {
		return "", false
	}
	actual, err := os.ReadFile(configPath)
	if err != nil {
		return "", false
	}
	expected, err := node.CompileCandidate(active.Candidate())
	if err != nil || !bytes.Equal(actual, expected) {
		return "", false
	}
	if cfg.Role == node.RoleOut {
		// The Out ACL unit applies this file before the kernel starts.
		// A last-known-good data plane must include an exact ACL match,
		// otherwise repair would restart the kernel with a stale table.
		aclPath := rooted(root, node.ACLPath)
		aclInfo, err := os.Lstat(aclPath)
		if err != nil || !aclInfo.Mode().IsRegular() || aclInfo.Mode()&os.ModeSymlink != 0 || aclInfo.Mode().Perm() != 0600 {
			return "", false
		}
		aclActual, err := os.ReadFile(aclPath)
		if err != nil {
			return "", false
		}
		aclExpected, err := node.CompileACL(active.Candidate())
		if err != nil || !bytes.Equal(aclActual, aclExpected) {
			return "", false
		}
	}
	digest := sumBytes(actual)
	return digest, digest == sumBytes(expected)
}

// nodeAgentReference resolves which executable the staged Agent binary must
// be a copy of: the running installer itself, or the explicit Executable
// the install was launched from (the VM harness stages /tmp/meshmux while
// driving the install from install.test).
func nodeAgentReference(executable string) string {
	if executable == "" {
		return "/proc/self/exe"
	}
	return executable
}

// pollNodeReadback re-reads the live data plane until it validates or the
// deadline hits. The kernel needs a moment after (re)start before its
// process, listeners and nft state are observable, especially under QEMU
// software emulation. Only startup-transient failures are retried; a
// deterministic config or ownership failure still fails fast so a broken
// data plane is never mistaken for a slow one.
func pollNodeReadback(ctx context.Context, opts NodeApplyOptions, cfg node.Config) (node.Readback, error) {
	deadline := time.Now().Add(60 * time.Second)
	var last error = errors.New("NATIVE_READBACK_UNAVAILABLE")
	for {
		readback, err := opts.Readback(ctx, cfg, opts.Root, opts.Runner)
		if err == nil {
			return readback, nil
		}
		last = err
		if !node.TransientReadback(err) || time.Now().After(deadline) {
			return node.Readback{}, last
		}
		select {
		case <-ctx.Done():
			return node.Readback{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// nodeFileOwnedBy checks exact UID and group ownership. It is only used for
// production-root readbacks; isolated test roots keep whatever UID the test
// runner has, so ownership is not asserted there.
func nodeFileOwnedBy(path string, uid uint32, group string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if stat.Uid != uid {
		return false
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil || gid < 0 {
		return false
	}
	return stat.Gid == uint32(gid)
}

func installNodeDynamic(ctx context.Context, opts NodeApplyOptions, candidate node.CandidateDocument, compiled []byte, role node.Role) error {
	dir := rooted(opts.Root, nodeKernelDataDir)
	if err := ensureDirectory(dir, 0750); err != nil {
		return err
	}
	if err := writeBytesAtomic(rooted(opts.Root, node.ActiveConfigPath), compiled, 0640); err != nil {
		return err
	}
	if opts.Root == "/" {
		// The active kernel configuration must stay readable by the
		// meshmux-singbox service account. writeBytesAtomic leaves a
		// root-owned file behind, so the ownership is fixed explicitly.
		if _, err := opts.Runner.Run(ctx, "chown", "root:meshmux-singbox", node.ActiveConfigPath); err != nil {
			return &InstallError{Code: "FILE_OWNERSHIP_FAILED", Recovery: "The sing-box service account cannot read the active configuration; inspect ownership and run --repair."}
		}
	}
	candidateBody, err := jsonMarshal(candidate)
	if err != nil {
		return err
	}
	if err := writeBytesAtomic(rooted(opts.Root, node.ActiveCandidatePath), candidateBody, 0600); err != nil {
		return err
	}
	if role == node.RoleOut {
		acl, err := node.CompileACL(candidate.Candidate())
		if err != nil {
			return err
		}
		if err := writeBytesAtomic(rooted(opts.Root, node.ACLPath), acl, 0600); err != nil {
			return err
		}
	}
	return nil
}

func verifyNodeCandidate(ctx context.Context, opts NodeApplyOptions, kernelPath string, compiled []byte, stageDir string) error {
	path := filepath.Join(stageDir, "candidate-check.json")
	if err := os.WriteFile(path, compiled, 0600); err != nil {
		return err
	}
	_, err := opts.Runner.Run(ctx, kernelPath, "check", "-c", path)
	return err
}

func verifyAgentBinary(ctx context.Context, opts NodeApplyOptions, stagedPath, stagedHash string) error {
	if opts.VerifyAgent != nil {
		return opts.VerifyAgent(stagedPath, stagedHash)
	}
	if opts.Root != "/" {
		return errors.New("AGENT_VERIFIER_REQUIRED")
	}
	// The staged Agent must be a copy of the exact executable being
	// installed. That is /proc/self/exe for a real install, or the explicit
	// Executable (the VM harness stages /tmp/meshmux while driving the
	// install from install.test).
	reference := nodeAgentReference(opts.Executable)
	selfHash, err := sha256File(reference)
	if err != nil || selfHash != stagedHash {
		return errors.New("AGENT_NOT_SELF_COPY")
	}
	// Exact zero-arg version probe: output must equal the pinned Agent
	// version after trimming surrounding whitespace. Substring matches,
	// extra output or echoed arguments are rejected.
	out, err := opts.Runner.Run(ctx, stagedPath, "__internal-agent-version")
	if err != nil {
		return errors.New("AGENT_VERSION_PROBE_FAILED")
	}
	if strings.TrimSpace(string(out)) != node.CurrentAgentVersion {
		return errors.New("AGENT_VERSION_MISMATCH")
	}
	return nil
}

func verifyNodeInstall(ctx context.Context, cfg node.Config, runner CommandRunner, rb node.Readback) error {
	if rb.AgentSHA256 == "" || rb.KernelSHA256 == "" || !rb.LocalActive {
		return errors.New("NODE_READBACK_INCOMPLETE")
	}
	if cfg.Role == node.RoleOut && !rb.OutDefaultDeny {
		return errors.New("OUT_DEFAULT_DENY_MISSING")
	}
	return nil
}

func nodeComponents(artifacts []Artifact) []Component {
	out := []Component{{Name: "MeshMux Agent", Version: node.CurrentAgentVersion, Distribution: "same executable as installer; SHA-256 verified"}}
	for _, a := range artifacts {
		out = append(out, Component{Name: a.Component, Version: a.Version, Distribution: "pinned official GitHub archive; archive and binary SHA-256 verified"})
	}
	out = append(out,
		Component{Name: "Fail2ban", Version: "Debian 13 package", Distribution: "official Debian repository"},
		Component{Name: "nftables", Version: "Debian 13 package", Distribution: "official Debian repository"},
	)
	return out
}

func cloneNodeConfig(cfg *node.Config) *node.Config {
	if cfg == nil {
		return nil
	}
	copyCfg := *cfg
	return &copyCfg
}

// Small wrappers keep the transaction's error messages stable while sharing
// the standard library encoding behavior.
func jsonMarshal(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func sumBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
