package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// nodeStageErrors carries the exact stage-phase failure templates. The Line
// recovery wording must stay verbatim and guard-checked, so InstallNode owns
// every literal and this phase only selects the applicable entry. The
// download recovery is text-only because its code comes from the wrapped error.
type nodeStageErrors struct {
	stageRemove              *core.InstallError
	stageCache               *core.InstallError
	stageTemporary           *core.InstallError
	artifactDownloadRecovery string
	artifactChecksum         *core.InstallError
	artifactFormat           *core.InstallError
	kernelChecksum           *core.InstallError
	kernelVersion            *core.InstallError
	meshmuxBinary            *core.InstallError
	candidateRender          *core.InstallError
	kernelConfig             *core.InstallError
	packageIndex             *core.InstallError
	packageInstall           *core.InstallError
	fail2banBaseline         *core.InstallError
	aclProbe                 *core.InstallError
	aclRender                *core.InstallError
	aclConfig                *core.InstallError
	operationLog             *core.InstallError
}

// nodeStaged reports what stageNodeArtifacts prepared for the later apply
// phases. Mutable operation state is updated through the pointers the function
// receives, never returned for the caller to reassign.
type nodeStaged struct {
	stageDir     string
	kernelPath   string
	agentPath    string
	installedCfg corenode.Config
}

// stageNodeArtifacts is the InstallNode staging phase: it empties and recreates
// the operation stage, downloads and verifies the pinned sing-box archive,
// stages the kernel and Agent binaries, renders and locally checks the
// candidate configuration, installs only the missing Debian packages and
// validates the Out ACL. The failure texts stay parameters so the call site
// keeps the exact Line wording.
func stageNodeArtifacts(ctx context.Context, result *core.InstallResult, state *core.InstallState, opts *core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, cfg corenode.Config, hasState bool, operationID string, artifact core.Artifact, release corenode.KernelRelease, failures nodeStageErrors) (nodeStaged, error) {
	fail := func(failure *core.InstallError) (nodeStaged, error) {
		res, err := failNodePartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
		*result = res
		return nodeStaged{}, err
	}
	stageDir := core.Rooted(opts.Root, layout.StageRoot+"/"+operationID)
	artifactsDir := filepath.Join(stageDir, "artifacts")
	if err := os.RemoveAll(stageDir); err != nil {
		return fail(failures.stageRemove)
	}
	if err := core.EnsureDirectory(stageDir, 0700); err != nil {
		return fail(failures.stageCache)
	}
	if err := core.EnsureDirectory(artifactsDir, 0700); err != nil {
		return fail(failures.stageCache)
	}
	archivePath, err := opts.DownloadArtifact(ctx, artifact, artifactsDir)
	if err != nil {
		return fail(&core.InstallError{Stage: "stage", Code: core.ArtifactErrorCode(err), Recovery: failures.artifactDownloadRecovery})
	}
	if err := core.VerifyFile(archivePath, artifact.SHA256); err != nil {
		return fail(failures.artifactChecksum)
	}
	kernelPath := filepath.Join(stageDir, "meshmux-sing-box")
	if err := extractNodeKernel(archivePath, kernelPath); err != nil {
		return fail(failures.artifactFormat)
	}
	kernelHash, err := core.SHA256File(kernelPath)
	if err != nil || (opts.Root == "/" && kernelHash != release.BinarySHA256) {
		return fail(failures.kernelChecksum)
	}
	if err := core.VerifyBinaryVersion(ctx, opts.Runner, kernelPath, corenode.KernelVersion); err != nil {
		return fail(failures.kernelVersion)
	}
	// The Agent binary is resolved from the host layout. A co-located Line
	// reuses the Hub-owned runtime verbatim and never stages, overwrites or
	// snapshots a replacement.
	agentPath, agentHash, err := core.ResolveNodeAgent(ctx, *opts, layout, stageDir)
	if err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(ie)
		}
		return fail(failures.meshmuxBinary)
	}
	installedCfg := cfg
	installedCfg.AgentVersion = corenode.CurrentAgentVersion()
	installedCfg.AgentSHA256 = agentHash
	installedCfg.KernelSHA256 = kernelHash
	compiled, err := corenode.CompileCandidate(corenode.Candidate{
		NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
		VLESSPort: cfg.VLESSPort, KernelVersion: corenode.KernelVersion,
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
	missing, pkgErr := core.EnsureDebianPackages(ctx, opts.Runner, failures.packageIndex, failures.packageInstall)
	if pkgErr != nil {
		return fail(pkgErr)
	}
	// The fixed package set is now present, so the preflight self-test can
	// finally run on a host whose fail2ban (or python3-systemd) was missing.
	// This still happens before identity work and before any pairing code is
	// consumed.
	if err := requireFail2banBaseline(ctx, opts.Runner); err != nil {
		return fail(failures.fail2banBaseline)
	}
	if usedPackage(missing, "nftables") {
		if err := verifyNodeTableOwnershipAfterInstall(ctx, opts.Root, opts.Runner, installedCfg, hasState); err != nil {
			probeFailure := *failures.aclProbe
			var ie *core.InstallError
			if errors.As(err, &ie) {
				probeFailure.Code, probeFailure.Recovery = ie.Code, ie.Recovery
			}
			return fail(&probeFailure)
		}
	}
	if cfg.Role == corenode.RoleOut {
		acl, err := corenode.CompileACL(corenode.Candidate{
			NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
			VLESSPort: cfg.VLESSPort, KernelVersion: corenode.KernelVersion,
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
