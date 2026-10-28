package node

import (
	"context"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// nodeApplyErrors carries the exact apply/early-verify failure templates. The
// Line recovery wording must stay verbatim and guard-checked, so InstallNode
// owns every literal and this phase only selects the applicable entry.
type nodeApplyErrors struct {
	accountCreate     *core.InstallError
	dataDirectory     *core.InstallError
	backupDirectory   *core.InstallError
	backupSnapshot    *core.InstallError
	journalFilesWrite *core.InstallError
	systemdUnit       *core.InstallError
	fail2banConfig    *core.InstallError
	systemdReload     *core.InstallError
	fail2banStart     *core.InstallError
	fail2banReload    *core.InstallError
	fail2banWait      *core.InstallError
	// The jail readback recovery embeds the underlying readback error, so the
	// caller supplies the exact wording as a function of that error.
	hubJailReadback        func(error) *core.InstallError
	standaloneJailReadback func(error) *core.InstallError
}

// nodeApplied reports the read-only context the later verify phases still need.
// Mutable operation state is updated through the pointers nodeApplyAndVerify
// receives, never returned for the caller to reassign.
type nodeApplied struct {
	backupDir string
}

// nodeApplyAndVerify runs the Node apply phase and the early verify phase:
// service accounts and data directories, backups and snapshots, managed file
// application, unit/Fail2ban validation, daemon-reload, Fail2ban start or
// reload, and the SSH jail readback. The two failure paths stay asymmetric on
// purpose: everything up to and including daemon-reload rolls back through
// rollbackNodeFailure, while the following Fail2ban and jail checks fail
// verified-partial and leave the applied files in place.
func nodeApplyAndVerify(ctx context.Context, result *core.InstallResult, state *core.InstallState, opts *core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, previous core.InstallState, hasState, repair bool, cfg corenode.Config, managed map[string]nodeManagedFile, stagedManaged map[string]string, agentPath, kernelPath, backupDir string, sshPorts []int, failures nodeApplyErrors) (nodeApplied, error) {
	if err := ensureNodeAccounts(ctx, opts.Runner, opts.Root, hasState); err != nil {
		return nodeFailPartial(result, state, opts, layout, record, failures.accountCreate)
	}
	if err := ensureNodeDirectories(ctx, *opts); err != nil {
		return nodeFailPartial(result, state, opts, layout, record, failures.dataDirectory)
	}

	if err := core.EnsureDirectory(backupDir, 0700); err != nil {
		return nodeFailPartial(result, state, opts, layout, record, failures.backupDirectory)
	}
	staticTargets := nodeStaticTargets(managed)
	allTargets := append(append([]string{}, staticTargets...), corenode.AgentBinaryPath, corenode.SingBoxBinaryPath)
	if repair {
		allTargets = append(allTargets, corenode.ActiveCandidatePath, corenode.ActiveConfigPath)
	}
	// A co-located Line reuses the Hub-owned MeshMux runtime verbatim. The
	// shared binary is neither snapshotted nor rolled back, and it is never
	// rewritten by the Line.
	sharedAgent := ""
	if layout.CoLocated {
		sharedAgent = layout.SharedAgent
		allTargets = core.RemoveTarget(allTargets, sharedAgent)
	}
	snapshots, err := snapshotNodeTargets(opts.Root, allTargets, *state, hasState, backupDir)
	if err != nil {
		return nodeFailPartial(result, state, opts, layout, record, failures.backupSnapshot)
	}
	rollback := func(stage string, cause error) (nodeApplied, error) {
		res, err := rollbackNodeFailure(*result, *state, previous, hasState, *opts, layout, snapshots, record, stage, cause)
		*result = res
		return nodeApplied{}, err
	}
	applyFiles := map[string]string{
		corenode.SingBoxBinaryPath: kernelPath,
	}
	if sharedAgent == "" {
		applyFiles[corenode.AgentBinaryPath] = agentPath
	}
	for path, staged := range stagedManaged {
		applyFiles[path] = staged
	}
	if err := applyNodeFiles(ctx, *opts, layout, *state, managed, applyFiles, backupDir); err != nil {
		return rollback("apply", err)
	}
	if err := record("apply", "files_written", ""); err != nil {
		return rollback("apply", failures.journalFilesWrite)
	}

	unitPaths := nodeUnitPaths(opts.Root, cfg)
	if unitErr := core.ValidateStagedUnits(ctx, opts.Runner, unitPaths, failures.systemdUnit, failures.fail2banConfig); unitErr != nil {
		return rollback(unitErr.Stage, unitErr)
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return rollback("apply", failures.systemdReload)
	}

	if fail2banErr := core.EnsureFail2banRunning(ctx, opts.Runner, failures.fail2banStart, failures.fail2banReload); fail2banErr != nil {
		return nodeFailVerified(result, state, opts, layout, record, fail2banErr)
	}
	// The daemon answers fail2ban-client only after its socket exists and the
	// jail is loaded. Querying immediately after (re)start loses with exit
	// 255 on fast hosts, so wait for the jail to become queryable first.
	//
	// A standalone Line owns its own SSH jail. A co-located Line reuses the
	// Hub's jail: a second jail for the same listeners would duplicate the
	// ban rules, so the Line verifies the existing jail instead of
	// installing one.
	if layout.ReuseHubSSHJail {
		if err := waitFail2banJailNamed(ctx, opts.Runner, core.HubSSHJailName); err != nil {
			return nodeFailVerified(result, state, opts, layout, record, failures.fail2banWait)
		}
		if err := verifyFail2banJailPorts(ctx, opts.Runner, core.HubSSHJailName, sshPorts); err != nil {
			return nodeFailVerified(result, state, opts, layout, record, failures.hubJailReadback(err))
		}
	} else {
		if err := waitFail2banJail(ctx, opts.Runner); err != nil {
			return nodeFailVerified(result, state, opts, layout, record, failures.fail2banWait)
		}
		if err := verifyNodeSSHJail(ctx, opts.Runner, sshPorts...); err != nil {
			return nodeFailVerified(result, state, opts, layout, record, failures.standaloneJailReadback(err))
		}
	}
	return nodeApplied{backupDir: backupDir}, nil
}

func nodeFailPartial(result *core.InstallResult, state *core.InstallState, opts *core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, failure *core.InstallError) (nodeApplied, error) {
	res, err := failNodePartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
	*result = res
	return nodeApplied{}, err
}

func nodeFailVerified(result *core.InstallResult, state *core.InstallState, opts *core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, failure *core.InstallError) (nodeApplied, error) {
	res, err := failVerifiedPartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
	*result = res
	return nodeApplied{}, err
}
