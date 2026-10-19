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
			return preflightNode(ctx, cfg, allowManaged, opts.Runner)
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

	lockPath := rooted(opts.Root, "/run/lock/meshmux-install.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return fail("preflight", "INSTALL_LOCK_UNAVAILABLE", "Check /run/lock permissions and retry.")
	}
	if err := ensureNoSymlinkAncestors(filepath.Dir(lockPath)); err != nil {
		return fail("preflight", "INSTALL_LOCK_UNAVAILABLE", "Check /run/lock ownership and symlinks.")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fail("preflight", "INSTALL_LOCK_UNAVAILABLE", "Check /run/lock permissions and retry.")
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail("preflight", "INSTALL_BUSY", "Another MeshMux installation is running; wait for it to finish.")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	state, hasState, err := ReadState(opts.Root)
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
	if err := checkNodeTargets(opts.Root, cfg, sshPorts, state, hasState); err != nil {
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
	state.Node = cloneNodeConfig(&cfg)
	state.Artifacts["sing-box"] = artifacts[0].SHA256
	state.Architecture, state.SSHPorts, state.ErrorCode, state.Recovery = architecture, sortedInts(sshPorts), "", ""
	state.UpdatedAt = now
	if err := writeState(opts.Root, state); err != nil {
		return fail("stage", "INSTALL_STATE_WRITE_FAILED", "Check disk space and permissions under /var/lib/meshmux-installer.")
	}
	operationDir := rooted(opts.Root, "/var/lib/meshmux-installer/operations/"+operationID)
	journalPath := filepath.Join(operationDir, "events.jsonl")
	record := func(stage, status, code string) error {
		return appendOperationEvent(journalPath, operationEvent{OperationID: operationID, Stage: stage, Status: status, ErrorCode: code, Time: time.Now().UTC()})
	}
	if err := record("stage", "started", ""); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions and run --repair.")
	}

	stageDir := rooted(opts.Root, "/var/cache/meshmux-installer/"+operationID)
	artifactsDir := filepath.Join(stageDir, "artifacts")
	if err := os.RemoveAll(stageDir); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Remove only the incomplete staging directory for this operation and retry.")
	}
	if err := ensureDirectory(stageDir, 0700); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check /var/cache space and permissions; no host files were applied.")
	}
	if err := ensureDirectory(artifactsDir, 0700); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check /var/cache space and permissions; no host files were applied.")
	}
	archivePath, err := opts.DownloadArtifact(ctx, artifacts[0], artifactsDir)
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", artifactErrorCode(err), "Check outbound HTTPS to the pinned official GitHub asset; unverified archives are never applied.")
	}
	if err := VerifyFile(archivePath, artifacts[0].SHA256); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "ARTIFACT_CHECKSUM_MISMATCH", "Delete the staged archive and retry; never bypass archive SHA-256 verification.")
	}
	kernelPath := filepath.Join(stageDir, "meshmux-sing-box")
	if err := extractNodeKernel(archivePath, kernelPath); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "ARTIFACT_FORMAT_INVALID", "Use the official pinned sing-box archive for this architecture.")
	}
	kernelHash, err := sha256File(kernelPath)
	if err != nil || (opts.Root == "/" && kernelHash != release.BinarySHA256) {
		return failNodePartial(result, state, opts, record, "stage", "KERNEL_CHECKSUM_MISMATCH", "Delete the staged kernel and retry; the binary must match the release manifest.")
	}
	if err := verifyBinaryVersion(ctx, opts.Runner, kernelPath, node.KernelVersion); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "KERNEL_VERSION_INVALID", "Use the exact pinned sing-box release for this architecture.")
	}
	executable := opts.Executable
	if executable == "" {
		executable = "/proc/self/exe"
	}
	agentPath := filepath.Join(stageDir, "meshmuxd")
	agentHash, err := copyExecutable(executable, agentPath)
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", "MESHMUX_BINARY_INVALID", "Run the installer from a regular MeshMux executable and retry.")
	}
	if err := verifyAgentBinary(ctx, opts, agentPath, agentHash); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "MESHMUX_BINARY_INVALID", "Run the installer from the exact MeshMux build being installed; external Agent binaries are rejected.")
	}
	installedCfg := cfg
	installedCfg.AgentVersion = node.CurrentAgentVersion
	installedCfg.AgentSHA256 = agentHash
	installedCfg.KernelSHA256 = kernelHash
	compiled, err := node.CompileCandidate(node.Candidate{
		NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
		VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
	})
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", "CANDIDATE_RENDER_FAILED", "Review the Node role and VLESS port.")
	}
	stagedCandidate := filepath.Join(stageDir, "config.json")
	if err := os.WriteFile(stagedCandidate, compiled, 0600); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
	}
	if _, err := opts.Runner.Run(ctx, kernelPath, "check", "-c", stagedCandidate); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "KERNEL_CONFIG_INVALID", "Review the generated native sing-box configuration.")
	}
	// The staged Out ACL is syntax-checked with nft -c below, so the Debian
	// packages must be installed before that check, not later in apply.
	missing := missingDebianPackages(ctx, opts.Runner, "ca-certificates", "fail2ban", "nftables")
	if len(missing) > 0 {
		if _, err := opts.Runner.Run(ctx, "apt-get", "update"); err != nil {
			return failNodePartial(result, state, opts, record, "apply", "PACKAGE_INDEX_FAILED", "Check Debian repository connectivity; no package upgrade or third-party repository is used.")
		}
		args := append([]string{"install", "-y", "--no-install-recommends"}, missing...)
		if _, err := opts.Runner.Run(ctx, "apt-get", args...); err != nil {
			return failNodePartial(result, state, opts, record, "apply", "PACKAGE_INSTALL_FAILED", "Review Debian apt status; only the listed missing packages are installed.")
		}
	}
	if usedPackage(missing, "nftables") {
		if err := verifyNodeTableOwnershipAfterInstall(ctx, opts.Runner, installedCfg, hasState); err != nil {
			code, recovery := "ACL_TABLE_PROBE_FAILED", "Re-run the exact nft ownership readback. MeshMux will not adopt, overwrite or delete an unverified table."
			var ie *InstallError
			if errors.As(err, &ie) {
				code, recovery = ie.Code, ie.Recovery
			}
			return failNodePartial(result, state, opts, record, "apply", code, recovery)
		}
	}
	if cfg.Role == node.RoleOut {
		acl, err := node.CompileACL(node.Candidate{
			NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
			VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
		})
		if err != nil {
			return failNodePartial(result, state, opts, record, "stage", "ACL_RENDER_FAILED", "Review the Out role configuration.")
		}
		aclPath := filepath.Join(stageDir, "out.nft")
		if err := os.WriteFile(aclPath, acl, 0600); err != nil {
			return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
		}
		if _, err := opts.Runner.Run(ctx, "nft", "-c", "-f", aclPath); err != nil {
			return failNodePartial(result, state, opts, record, "stage", "ACL_CONFIG_INVALID", "Review the generated default-deny Out table; the host ruleset was not changed.")
		}
	}
	if err := record("stage", "validated", ""); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions and run --repair.")
	}

	identity, identityLoaded, err := loadNodeIdentity(opts.Root, installedCfg)
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", "IDENTITY_INVALID", "Inspect the private Agent identity; do not delete it until the Hub identity is revoked.")
	}
	var metadata node.Metadata
	var candidate node.CandidateDocument
	if identityLoaded {
		if repair {
			if pairingCode != "" {
				fresh, pairErr := opts.Pair(ctx, installedCfg, pairingCode)
				if pairErr == nil {
					pairErr = fresh.ValidateFor(installedCfg)
				}
				if pairErr == nil {
					pairErr = persistNodeIdentity(opts.Root, fresh)
				}
				if pairErr != nil {
					return failNodePartial(result, state, opts, record, "stage", "PAIRING_FAILED", "Check the one-time code, Hub reachability and node role/ports. A failed request may still have been consumed; reissue a code before retrying.")
				}
				identity = fresh
			}
			metadata, err = opts.Metadata(ctx, installedCfg, identity)
			if err == nil {
				candidate, err = opts.Candidate(ctx, installedCfg, identity, 1)
			}
			if err == nil && metadata.NodeID != "" {
				err = metadata.ValidateFor(installedCfg)
			}
			if err == nil && candidate.Schema != "" {
				err = candidate.ValidateFor(installedCfg)
			}
			if err != nil {
				if clientUnauthorized(err) {
					return failNodePartial(result, state, opts, record, "stage", "PAIRING_REQUIRED", "The recorded identity was revoked or replaced. Reissue a pairing code in Hub Web and run --repair with the fresh code.")
				}
				return failNodePartial(result, state, opts, record, "stage", "PAIRING_METADATA_FAILED", "The private identity is preserved. Fix Hub metadata/candidate availability and run --repair; do not request another code.")
			}
		}
	} else {
		if repair {
			return failNodePartial(result, state, opts, record, "stage", "IDENTITY_MISSING", "A repair reuses the private identity when it is still valid. Restore the identity, or revoke and re-enroll the node; a revoked identity needs a fresh pairing code.")
		}
		if pairingCode == "" {
			state.Stage = "pairing"
			state.Status = "partial"
			state.ErrorCode, state.Recovery = "PAIRING_CODE_REQUIRED", "Enter the current one-time code on stdin after local staging checks pass."
			state.UpdatedAt = time.Now().UTC()
			_ = writeState(opts.Root, state)
			result.Stage, result.Status, result.ErrorCode, result.Recovery = "pairing", "partial", state.ErrorCode, state.Recovery
			_ = record("pairing", "waiting", state.ErrorCode)
			return result, &InstallError{Stage: "pairing", Code: state.ErrorCode, Recovery: state.Recovery}
		}
		identity, err = opts.Pair(ctx, installedCfg, pairingCode)
		if err == nil {
			err = identity.ValidateFor(installedCfg)
		}
		if err != nil {
			return failNodePartial(result, state, opts, record, "stage", "PAIRING_FAILED", "Check the one-time code, Hub reachability and node role/ports. A failed request may still have been consumed.")
		}
		if err := ensurePrivateNodeDirectory(rooted(opts.Root, nodeAgentStateDir)); err != nil {
			return failNodePartial(result, state, opts, record, "stage", "AGENT_STATE_UNSAFE", "Use a root-owned 0700 Agent directory; the kernel group must not read identity tokens.")
		}
		if err := persistNodeIdentity(opts.Root, identity); err != nil {
			return failNodePartial(result, state, opts, record, "stage", "IDENTITY_PERSIST_FAILED", "The Hub code may already be consumed. Preserve this operation's journal, reissue a code for the same node in Web and retry after fixing disk permissions.")
		}
		state.Node = cloneNodeConfig(&installedCfg)
		if err := writeState(opts.Root, state); err != nil {
			return failNodePartial(result, state, opts, record, "stage", "INSTALL_STATE_WRITE_FAILED", "Check installer state disk space and permissions; preserve the private identity.")
		}
		metadata, err = opts.Metadata(ctx, installedCfg, identity)
		if err == nil {
			candidate, err = opts.Candidate(ctx, installedCfg, identity, 1)
		}
		if err == nil && metadata.NodeID != "" {
			err = metadata.ValidateFor(installedCfg)
		}
		if err == nil && candidate.Schema != "" {
			err = candidate.ValidateFor(installedCfg)
		}
		if err != nil {
			return failNodePartial(result, state, opts, record, "stage", "PAIRING_METADATA_FAILED", "The private identity is persisted. Fix Hub metadata/candidate availability and run --repair; do not request another code.")
		}
	}
	activeCandidate := candidate
	if repair {
		if existing, ok := currentNodeCandidate(opts.Root, installedCfg); ok {
			activeCandidate = existing
		}
	}
	if activeCandidate.Schema == "" {
		activeCandidate = node.NewCandidateDocument(node.Candidate{
			NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
			VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
		})
	}
	candidateBody, err := jsonMarshal(activeCandidate)
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", "CANDIDATE_RENDER_FAILED", "Review the Hub candidate response and retry with --repair.")
	}
	candidateConfig, err := node.CompileCandidate(activeCandidate.Candidate())
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", "CANDIDATE_RENDER_FAILED", "Review the Hub candidate role, node and port binding.")
	}
	if err := verifyNodeCandidate(ctx, opts, kernelPath, candidateConfig, stageDir); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "CANDIDATE_INVALID", "The Hub candidate failed local validation; no active kernel configuration was replaced.")
	}

	managed, err := nodeManagedFiles(installedCfg, sshPorts, identity)
	if err != nil {
		return failNodePartial(result, state, opts, record, "stage", "CONFIG_RENDER_FAILED", "Review the actual SSH listeners and the fixed Node service layout.")
	}
	stagedManaged := map[string]string{}
	for path, file := range managed {
		if !file.Static {
			continue
		}
		staged := filepath.Join(stageDir, "managed", strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_"))
		if err := writeBytesAtomic(staged, []byte(file.Body), os.FileMode(file.Mode)); err != nil {
			return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
		}
		stagedManaged[path] = staged
	}
	if err := writeBytesAtomic(filepath.Join(stageDir, "active-candidate.json"), candidateBody, 0600); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
	}
	if err := writeBytesAtomic(filepath.Join(stageDir, "config.json"), candidateConfig, 0640); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
	}
	if err := record("stage", "candidate_validated", ""); err != nil {
		return failNodePartial(result, state, opts, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions and run --repair.")
	}

	if err := ensureNodeAccounts(ctx, opts.Runner, opts.Root, hasState); err != nil {
		return failNodePartial(result, state, opts, record, "apply", "ACCOUNT_CREATE_FAILED", "Inspect meshmux-singbox and meshmux-agent accounts before retrying.")
	}
	if err := ensureNodeDirectories(ctx, opts); err != nil {
		return failNodePartial(result, state, opts, record, "apply", "DATA_DIRECTORY_FAILED", "Check Agent and kernel data directory ownership; never expose the identity directory to the kernel group.")
	}

	backupDir := filepath.Join(operationDir, "backup")
	if err := ensureDirectory(backupDir, 0700); err != nil {
		return failNodePartial(result, state, opts, record, "apply", "BACKUP_FAILED", "Check installer state disk space.")
	}
	staticTargets := nodeStaticTargets(managed)
	allTargets := append(append([]string{}, staticTargets...), node.AgentBinaryPath, node.SingBoxBinaryPath)
	if repair {
		allTargets = append(allTargets, node.ActiveCandidatePath, node.ActiveConfigPath)
	}
	snapshots, err := snapshotNodeTargets(opts.Root, allTargets, state, hasState, backupDir)
	if err != nil {
		return failNodePartial(result, state, opts, record, "apply", "BACKUP_FAILED", "No managed files were replaced; inspect the operation journal.")
	}
	applyFiles := map[string]string{
		node.AgentBinaryPath: agentPath, node.SingBoxBinaryPath: kernelPath,
	}
	for path, staged := range stagedManaged {
		applyFiles[path] = staged
	}
	if err := applyNodeFiles(ctx, opts, state, managed, applyFiles, backupDir); err != nil {
		return rollbackNodeFailure(result, state, previous, hasState, opts, snapshots, record, "apply", err)
	}
	if err := record("apply", "files_written", ""); err != nil {
		return rollbackNodeFailure(result, state, previous, hasState, opts, snapshots, record, "apply", &InstallError{Code: "OPERATION_LOG_FAILED", Recovery: "Restore the journal before another apply."})
	}

	unitPaths := nodeUnitPaths(opts.Root, cfg)
	if _, err := opts.Runner.Run(ctx, "systemd-analyze", append([]string{"verify"}, unitPaths...)...); err != nil {
		return rollbackNodeFailure(result, state, previous, hasState, opts, snapshots, record, "verify", &InstallError{Code: "SYSTEMD_UNIT_INVALID", Recovery: "Review the fixed Agent, kernel and ACL units; no Node is installed until validation succeeds."})
	}
	if _, err := opts.Runner.Run(ctx, "fail2ban-client", "-t"); err != nil {
		return rollbackNodeFailure(result, state, previous, hasState, opts, snapshots, record, "verify", &InstallError{Code: "FAIL2BAN_CONFIG_INVALID", Recovery: "Review the Node SSH jail and preserve all existing Fail2ban jails."})
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return rollbackNodeFailure(result, state, previous, hasState, opts, snapshots, record, "apply", &InstallError{Code: "SYSTEMD_RELOAD_FAILED", Recovery: "Inspect systemd and run --repair."})
	}

	if _, err := opts.Runner.Run(ctx, "systemctl", "is-active", "--quiet", "fail2ban.service"); err != nil {
		if _, startErr := opts.Runner.Run(ctx, "systemctl", "enable", "--now", "fail2ban.service"); startErr != nil {
			return failVerifiedPartial(result, state, opts, record, "verify", "FAIL2BAN_START_FAILED", "Review Fail2ban logs and the Node SSH jail; do not alter sshd or flush nftables.")
		}
	} else if _, err := opts.Runner.Run(ctx, "fail2ban-client", "reload"); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "FAIL2BAN_RELOAD_FAILED", "Review Fail2ban logs and preserve existing jails.")
	}
	if err := verifyNodeSSHJail(ctx, opts.Runner, installedCfg.SSHPort); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "SSH_FAIL2BAN_JAIL_UNAVAILABLE", "Read back the Fail2ban action ports and require every actual SSH listener, excluding VLESS.")
	}
	if repair {
		lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lock, lockErr := node.AcquireRuntimeLock(lockCtx, opts.Root)
		cancel()
		if lockErr != nil {
			return failVerifiedPartial(result, state, opts, record, "verify", "NODE_RUNTIME_BUSY", "The Agent runtime is applying a task. Preserve the active data plane and repair after the shared runtime lock is free.")
		}
		defer lock.Close()
	}
	_, lkgOK := nodeValidLKG(opts.Root, installedCfg)
	if !repair || !lkgOK {
		if err := installNodeDynamic(ctx, opts, activeCandidate, candidateConfig, installedCfg.Role); err != nil {
			return failVerifiedPartial(result, state, opts, record, "apply", "KERNEL_CONFIG_APPLY_FAILED", "The validated data plane files could not be installed; no Agent was started.")
		}
	}
	if cfg.Role == node.RoleOut {
		// The ACL unit applies /var/lib/meshmux-agent/out.nft, which is
		// written by installNodeDynamic above. Starting it earlier fails on
		// a clean host where the file does not exist yet.
		if err := activateNodeUnit(ctx, opts.Runner, node.ACLUnit, repair); err != nil {
			return failVerifiedPartial(result, state, opts, record, "verify", "OUT_ACL_APPLY_FAILED", "Out ACL failed before the kernel started; no VLESS data plane is considered installed.")
		}
		if err := verifyNodeACLReadback(ctx, opts.Runner, installedCfg.VLESSPort); err != nil {
			return failVerifiedPartial(result, state, opts, record, "verify", "OUT_ACL_READBACK_FAILED", "Out ACL ownership or default-deny readback failed; keep the kernel stopped and repair the exact table.")
		}
	}
	if err := activateNodeUnit(ctx, opts.Runner, node.SingBoxUnit, repair); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "KERNEL_START_FAILED", "Review sing-box logs and the active configuration; the Agent remains stopped.")
	}
	nativeReadback, err := opts.Readback(ctx, installedCfg, opts.Root, opts.Runner)
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
		return failVerifiedPartial(result, state, opts, record, "verify", "NATIVE_READBACK_FAILED", "The kernel remains active but native readback failed. Repair the data plane; the Agent was not started.")
	}
	if err := record("verify", "data_plane_active", ""); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "OPERATION_LOG_FAILED", "The validated data plane is active; restore the journal before retrying.")
	}
	// The installer holds the shared runtime lock here. Do not restart an
	// already-running Agent: restart would make the new process wait on this
	// same lock. enable --now is idempotent and starts it only when inactive.
	if _, err := opts.Runner.Run(ctx, "systemctl", "enable", "--now", node.AgentUnit); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "AGENT_START_FAILED", "The verified data plane remains active. Repair only the Agent service; do not stop sing-box.")
	}
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.UpdatedAt = time.Now().UTC()
	if err := writeState(opts.Root, state); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "INSTALL_STATE_WRITE_FAILED", "The data plane and Agent are active but the final ledger failed; preserve them and repair state.")
	}
	if err := record("verify", "pass", ""); err != nil {
		return failVerifiedPartial(result, state, opts, record, "verify", "OPERATION_LOG_FAILED", "The Node is active but the journal write failed; repair only state/logging.")
	}
	_ = os.RemoveAll(stageDir)
	_ = os.RemoveAll(backupDir)
	result.Stage, result.Status, result.Checks = "verify", "installed", checks
	result.Artifacts = nodeComponents(artifacts)
	return result, nil
}

func failNodePartial(result InstallResult, state InstallState, opts NodeApplyOptions, record func(string, string, string) error, stage, code, recovery string) (InstallResult, error) {
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
	state.UpdatedAt = time.Now().UTC()
	_ = writeState(opts.Root, state)
	result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "partial", code, recovery
	_ = record(stage, "failed", code)
	return result, &InstallError{Stage: stage, Code: code, Recovery: recovery}
}

func failVerifiedPartial(result InstallResult, state InstallState, opts NodeApplyOptions, record func(string, string, string) error, stage, code, recovery string) (InstallResult, error) {
	// The validated data plane is intentionally left running. Do not call
	// Hub rollback: it would stop unrelated Hub units or the active kernel.
	return failNodePartial(result, state, opts, record, stage, code, recovery)
}

func rollbackNodeFailure(result InstallResult, state, previous InstallState, hadPrevious bool, opts NodeApplyOptions, snapshots []fileSnapshot, record func(string, string, string) error, stage string, cause error) (InstallResult, error) {
	code, recovery := "NODE_APPLY_FAILED", "No Agent is considered installed. Inspect the operation journal and run --repair."
	var ie *InstallError
	if errors.As(cause, &ie) {
		code, recovery = ie.Code, ie.Recovery
	}
	rollbackOK := rollbackNodeFiles(context.Background(), opts, snapshots, hadPrevious && previous.Status == "installed")
	if rollbackOK && hadPrevious && previous.Status == "installed" {
		previous.LastOperation, previous.ErrorCode, previous.Recovery = state.OperationID, code, recovery
		previous.UpdatedAt = time.Now().UTC()
		_ = writeState(opts.Root, previous)
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "rolled_back", code, recovery
	} else {
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		if rollbackOK {
			reconcileManagedLedger(&state, snapshots)
		}
		_ = writeState(opts.Root, state)
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

func applyNodeFiles(ctx context.Context, opts NodeApplyOptions, state InstallState, managed map[string]nodeManagedFile, files map[string]string, backupDir string) error {
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
		if err := writeState(opts.Root, state); err != nil {
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

func checkNodeTargets(root string, cfg node.Config, ssh []int, state InstallState, hasState bool) error {
	paths := []string{
		node.AgentBinaryPath, node.SingBoxBinaryPath, node.AgentConfigPath,
		"/etc/systemd/system/" + node.AgentUnit, "/etc/systemd/system/" + node.SingBoxUnit,
		"/etc/fail2ban/jail.d/meshmux-node-ssh.local",
	}
	if cfg.Role == node.RoleOut {
		paths = append(paths, "/etc/systemd/system/"+node.ACLUnit)
	}
	if err := checkTargetOwnership(root, paths, state, hasState); err != nil {
		return err
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

func verifyNodeTableOwnershipAfterInstall(ctx context.Context, runner CommandRunner, cfg node.Config, hasState bool) error {
	result := nodeTableOwnership(ctx, runner, cfg, hasState)
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

func verifyNodeSSHJail(ctx context.Context, runner CommandRunner, ssh ...int) error {
	// fail2ban 1.1.0 (Debian 13) removed `get <JAIL> port`; the jail port
	// is read back through the nftables-multiport action instance, which
	// also proves the daemon loaded the jail (an unknown jail errors out).
	portsOut, err := runner.Run(ctx, "fail2ban-client", "get", "meshmux-node-sshd", "action", "nftables-multiport", "port")
	if err != nil {
		return err
	}
	actionOut, err := runner.Run(ctx, "fail2ban-client", "get", "meshmux-node-sshd", "action", "nftables-multiport", "actionstart")
	if err != nil {
		return err
	}
	jailPorts, err := parseFail2banPorts(string(portsOut))
	if err != nil {
		return err
	}
	actionPorts, err := parseFail2banActionPorts(string(actionOut))
	if err != nil {
		return err
	}
	want := sortedInts(ssh)
	if !equalIntSets(jailPorts, want) || !equalIntSets(actionPorts, want) {
		return errors.New("SSH_JAIL_PORT_MISMATCH")
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

var fail2banDportPattern = regexp.MustCompile(`dport\s+(?:\{([^}]*)\}|([0-9]+))`)
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
	for i := range a {
		if a[i] != b[i] {
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
