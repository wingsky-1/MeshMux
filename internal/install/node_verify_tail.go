package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// nodeVerifyErrors carries the exact verify-tail failure templates. The Line
// recovery wording must stay verbatim and guard-checked, so InstallNode owns
// every literal and this phase only selects the applicable entry. Native
// readback keeps a format string because its recovery embeds the readback error.
type nodeVerifyErrors struct {
	runtimeBusy          *InstallError
	kernelConfigApply    *InstallError
	outACLApply          *InstallError
	outACLReadback       *InstallError
	kernelStart          *InstallError
	nativeReadbackFormat string
	journalDataPlane     *InstallError
	agentStart           *InstallError
	finalLedger          *InstallError
	journalVerifyPass    *InstallError
}

// nodeVerifyTail runs the Node verify tail: it acquires the shared runtime lock
// for a repair, installs the dynamic data plane, starts the ACL and kernel
// units, polls native readback, starts the Agent, and writes the terminal
// ledger. The lock's defer lives in this same function on purpose: it must
// cover Agent start and the terminal ledger, not be released when a stage
// helper returns.
func nodeVerifyTail(ctx context.Context, result *InstallResult, state *InstallState, opts *NodeApplyOptions, layout nodeLayout, record func(string, string, string) error, repair bool, cfg, installedCfg node.Config, activeCandidate node.CandidateDocument, candidateConfig []byte, checks []Check, artifacts []Artifact, stageDir, backupDir string, failures nodeVerifyErrors) error {
	fail := func(failure *InstallError) error {
		res, err := failVerifiedPartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
		*result = res
		return err
	}
	if repair {
		lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lock, lockErr := node.AcquireRuntimeLock(lockCtx, opts.Root)
		cancel()
		if lockErr != nil {
			return fail(failures.runtimeBusy)
		}
		defer lock.Close()
	}
	_, lkgOK := nodeValidLKG(opts.Root, installedCfg)
	if !repair || !lkgOK {
		if err := installNodeDynamic(ctx, *opts, activeCandidate, candidateConfig, installedCfg.Role); err != nil {
			return fail(failures.kernelConfigApply)
		}
	}
	if cfg.Role == node.RoleOut {
		// The ACL unit applies /var/lib/meshmux-agent/out.nft, which is
		// written by installNodeDynamic above. Starting it earlier fails on
		// a clean host where the file does not exist yet.
		if err := activateNodeUnit(ctx, opts.Runner, node.ACLUnit, repair); err != nil {
			return fail(failures.outACLApply)
		}
		if err := verifyNodeACLReadback(ctx, opts.Runner, installedCfg.VLESSPort); err != nil {
			return fail(failures.outACLReadback)
		}
	}
	if err := activateNodeUnit(ctx, opts.Runner, node.SingBoxUnit, repair); err != nil {
		return fail(failures.kernelStart)
	}
	nativeReadback, err := pollNodeReadback(ctx, *opts, installedCfg)
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
		return fail(&InstallError{Stage: "verify", Code: "NATIVE_READBACK_FAILED", Recovery: fmt.Sprintf(failures.nativeReadbackFormat, err)})
	}
	if err := record("verify", "data_plane_active", ""); err != nil {
		return fail(failures.journalDataPlane)
	}
	// The installer holds the shared runtime lock here. Do not restart an
	// already-running Agent: restart would make the new process wait on this
	// same lock. enable --now is idempotent and starts it only when inactive.
	if _, err := opts.Runner.Run(ctx, "systemctl", "enable", "--now", node.AgentUnit); err != nil {
		return fail(failures.agentStart)
	}
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.UpdatedAt = time.Now().UTC()
	if err := writeNodeState(opts.Root, layout, *state); err != nil {
		return fail(failures.finalLedger)
	}
	if err := record("verify", "pass", ""); err != nil {
		return fail(failures.journalVerifyPass)
	}
	_ = os.RemoveAll(stageDir)
	_ = os.RemoveAll(backupDir)
	result.Stage, result.Status, result.Checks = "verify", "installed", checks
	result.Artifacts = nodeComponents(artifacts)
	return nil
}
