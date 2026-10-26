package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// repairCandidateNotConverged is the stable code of the repair candidate
// notice. It is deliberately not an error code: a repair that keeps the
// recorded candidate has still done its job, so the code travels in
// next_action and in the operation journal instead of error_code.
const repairCandidateNotConverged = "REPAIR_CANDIDATE_NOT_CONVERGED"

// repairCandidateNotice returns the next_action of a repair that downloaded a
// candidate other than the recorded one, or "" when there is nothing to
// declare.
//
// The decision is fixed: a repair never reconciles the node to the candidate
// it downloads. It keeps the recorded active candidate and the compiled
// configuration it already verified, because candidate application belongs to
// the Agent's config.apply/readback chain and is anchored by the 11c-3
// confirm/revert records. An installer that silently moved a repair to another
// revision would leave those anchors naming a release the host does not run,
// and a later readback could not confirm or revert the chain that produced it.
// The notice exists so that the choice is visible instead of silent.
func repairCandidateNotice(repair bool, downloaded, recorded node.CandidateDocument) string {
	if !repair || downloaded.Schema == "" || sameNodeCandidate(downloaded, recorded) {
		return ""
	}
	offered := fmt.Sprintf("revision %d", downloaded.Revision)
	if downloaded.Revision == recorded.Revision {
		// Same revision, different bytes: the Hub re-rendered the document
		// (a route or user change) without minting a new one. Saying "did not
		// apply revision N" twice would hide that this is a content change.
		offered = fmt.Sprintf("the different document for revision %d", downloaded.Revision)
	}
	return fmt.Sprintf("%s: this repair kept the recorded active candidate (revision %d) and did not apply %s, which the Hub offered for this operation. Candidate application belongs to the Agent's config.apply/readback chain and its confirm/revert records; the installer never moves a repair to another candidate.",
		repairCandidateNotConverged, recorded.Revision, offered)
}

// sameNodeCandidate compares two documents the way the data plane sees them:
// they are the same candidate only when they encode to the same bytes.
func sameNodeCandidate(a, b node.CandidateDocument) bool {
	left, leftErr := jsonMarshal(a)
	right, rightErr := jsonMarshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

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
//
// repairNotice is the declared outcome of a repair that kept the recorded
// candidate instead of the one it downloaded. It is empty for a fresh install
// and for a repair that found the Hub candidate already recorded. It is
// reported through result.Recovery (next_action) only: the ledger keeps a clean
// "installed" record, and the recorded-state handoff decides on status and
// error_code, so a declared repair is never a failed unit.
func nodeVerifyTail(ctx context.Context, result *InstallResult, state *InstallState, opts *NodeApplyOptions, layout nodeLayout, record func(string, string, string) error, repair bool, cfg, installedCfg node.Config, activeCandidate node.CandidateDocument, candidateConfig []byte, repairNotice string, checks []Check, artifacts []Artifact, stageDir, backupDir string, failures nodeVerifyErrors) error {
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
	// The data plane is written from activeCandidate, never from the candidate
	// this operation downloaded. On a repair those differ when the recorded
	// candidate is still valid, and the divergence was already declared in the
	// journal and in next_action (REPAIR_CANDIDATE_NOT_CONVERGED); this branch
	// is the other half of that same fixed decision.
	_, lkgOK := nodeValidLKG(opts.Root, installedCfg)
	if !repair || !lkgOK {
		if err := installNodeDynamic(ctx, *opts, activeCandidate, candidateConfig, installedCfg.Role, repair); err != nil {
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
		if err := verifyNodeACLReadback(ctx, opts.Runner, opts.Root, installedCfg, activeCandidate.Candidate(), installedCfg.VLESSPort); err != nil {
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
	// The verified release is also the seed of the NEXT upgrade's rollback
	// source (11c-3 Task 4): a manifest-backed snapshot of everything this
	// operation installed. The Agent's live LKG/state bytes are deliberately
	// not part of this seed (they still belong to the previous release); the
	// post-confirm RefreshUpgradeSource captures them. A co-located Line never
	// owns the shared Hub runtime and has no Node upgrade path (11d owns the
	// Hub), so it keeps its previous behavior instead of failing on a snapshot
	// it cannot build.
	if !layout.CoLocated {
		if err := writeUpgradeSnapshot(opts.Root, layout, *state, installedCfg.Role, false); err != nil {
			var ie *InstallError
			if errors.As(err, &ie) {
				return fail(ie)
			}
			return fail(&InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "The verified release could not be recorded as the next upgrade's rollback source; check disk space and permissions."})
		}
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
	// The ledger records the release pair this operation actually installed.
	// A repair must not wipe the verified hashes (that is what the preflight
	// needs to recognize its own listener), and an upgrade must not leave the
	// old pair behind: the recorded-state handoff compares these two fields
	// with agent.json before it repairs, so a stale ledger would refuse every
	// later upgrade with CONFIG_CONFLICT.
	state.Node = cloneNodeConfig(&installedCfg)
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
	// A repair that kept the recorded candidate declares it here: the
	// operation succeeded, so this is next_action and never error_code, and
	// the ledger above stays a clean "installed" record. The recorded-state
	// handoff reads only status/error_code, so the notice never turns a
	// successful repair into a failed unit.
	result.Recovery = repairNotice
	result.Artifacts = nodeComponents(artifacts)
	return nil
}
