package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// nodeStageErrors carries the exact stage-phase failure templates. The Line
// recovery wording must stay verbatim and guard-checked, so InstallNode owns
// every literal and this phase only selects the applicable entry. The
// download recovery is text-only because its code comes from the wrapped error.
type nodeStageErrors struct {
	stageRemove              *InstallError
	stageCache               *InstallError
	stageTemporary           *InstallError
	artifactDownloadRecovery string
	artifactChecksum         *InstallError
	artifactFormat           *InstallError
	kernelChecksum           *InstallError
	kernelVersion            *InstallError
	meshmuxBinary            *InstallError
	candidateRender          *InstallError
	kernelConfig             *InstallError
	packageIndex             *InstallError
	packageInstall           *InstallError
	aclProbe                 *InstallError
	aclRender                *InstallError
	aclConfig                *InstallError
	operationLog             *InstallError
}

// nodeStaged reports what stageNodeArtifacts prepared for the later apply
// phases. Mutable operation state is updated through the pointers the function
// receives, never returned for the caller to reassign.
type nodeStaged struct {
	stageDir     string
	kernelPath   string
	agentPath    string
	installedCfg node.Config
}

// stageNodeArtifacts is the InstallNode staging phase: it empties and recreates
// the operation stage, downloads and verifies the pinned sing-box archive,
// stages the kernel and Agent binaries, renders and locally checks the
// candidate configuration, installs only the missing Debian packages and
// validates the Out ACL. The failure texts stay parameters so the call site
// keeps the exact Line wording.
func stageNodeArtifacts(ctx context.Context, result *InstallResult, state *InstallState, opts *NodeApplyOptions, layout nodeLayout, record func(string, string, string) error, cfg node.Config, hasState bool, operationID string, artifact Artifact, release node.KernelRelease, failures nodeStageErrors) (nodeStaged, error) {
	fail := func(failure *InstallError) (nodeStaged, error) {
		res, err := failNodePartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
		*result = res
		return nodeStaged{}, err
	}
	stageDir := rooted(opts.Root, layout.StageRoot+"/"+operationID)
	artifactsDir := filepath.Join(stageDir, "artifacts")
	if err := os.RemoveAll(stageDir); err != nil {
		return fail(failures.stageRemove)
	}
	if err := ensureDirectory(stageDir, 0700); err != nil {
		return fail(failures.stageCache)
	}
	if err := ensureDirectory(artifactsDir, 0700); err != nil {
		return fail(failures.stageCache)
	}
	archivePath, err := opts.DownloadArtifact(ctx, artifact, artifactsDir)
	if err != nil {
		return fail(&InstallError{Stage: "stage", Code: artifactErrorCode(err), Recovery: failures.artifactDownloadRecovery})
	}
	if err := VerifyFile(archivePath, artifact.SHA256); err != nil {
		return fail(failures.artifactChecksum)
	}
	kernelPath := filepath.Join(stageDir, "meshmux-sing-box")
	if err := extractNodeKernel(archivePath, kernelPath); err != nil {
		return fail(failures.artifactFormat)
	}
	kernelHash, err := sha256File(kernelPath)
	if err != nil || (opts.Root == "/" && kernelHash != release.BinarySHA256) {
		return fail(failures.kernelChecksum)
	}
	if err := verifyBinaryVersion(ctx, opts.Runner, kernelPath, node.KernelVersion); err != nil {
		return fail(failures.kernelVersion)
	}
	// The Agent binary is resolved from the host layout. A co-located Line
	// reuses the Hub-owned runtime verbatim and never stages, overwrites or
	// snapshots a replacement.
	agentPath, agentHash, err := resolveNodeAgent(ctx, *opts, layout, stageDir)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail(ie)
		}
		return fail(failures.meshmuxBinary)
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
		return fail(failures.candidateRender)
	}
	stagedCandidate := filepath.Join(stageDir, "config.json")
	if err := os.WriteFile(stagedCandidate, compiled, 0600); err != nil {
		return fail(failures.stageTemporary)
	}
	if _, err := opts.Runner.Run(ctx, kernelPath, "check", "-c", stagedCandidate); err != nil {
		return fail(failures.kernelConfig)
	}
	// The staged Out ACL is syntax-checked with nft -c below, so the Debian
	// packages must be installed before that check, not later in apply.
	missing, pkgErr := ensureDebianPackages(ctx, opts.Runner, failures.packageIndex, failures.packageInstall)
	if pkgErr != nil {
		return fail(pkgErr)
	}
	if usedPackage(missing, "nftables") {
		if err := verifyNodeTableOwnershipAfterInstall(ctx, opts.Root, opts.Runner, installedCfg, hasState); err != nil {
			probeFailure := *failures.aclProbe
			var ie *InstallError
			if errors.As(err, &ie) {
				probeFailure.Code, probeFailure.Recovery = ie.Code, ie.Recovery
			}
			return fail(&probeFailure)
		}
	}
	if cfg.Role == node.RoleOut {
		acl, err := node.CompileACL(node.Candidate{
			NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
			VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
		}, nil)
		if err != nil {
			return fail(failures.aclRender)
		}
		aclPath := filepath.Join(stageDir, "out.nft")
		if err := os.WriteFile(aclPath, acl, 0600); err != nil {
			return fail(failures.stageTemporary)
		}
		if _, err := opts.Runner.Run(ctx, "nft", "-c", "-f", aclPath); err != nil {
			return fail(failures.aclConfig)
		}
	}
	if err := record("stage", "validated", ""); err != nil {
		return fail(failures.operationLog)
	}
	return nodeStaged{stageDir: stageDir, kernelPath: kernelPath, agentPath: agentPath, installedCfg: installedCfg}, nil
}
