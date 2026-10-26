package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// nodeCandidateErrors carries the exact candidate-phase failure templates. The
// Line recovery wording must stay verbatim and guard-checked, so InstallNode
// owns every literal and this phase only selects the applicable entry.
type nodeCandidateErrors struct {
	marshalFailed      *InstallError
	compileFailed      *InstallError
	candidateInvalid   *InstallError
	configRenderFailed *InstallError
	stageTemporary     *InstallError
	operationLog       *InstallError
}

// nodeCandidateFinalized reports the read-only outputs that later apply phases
// consume. Mutable operation state is updated through the pointers
// nodeFinalizeCandidate receives, never returned for the caller to reassign.
type nodeCandidateFinalized struct {
	activeCandidate node.CandidateDocument
	candidateConfig []byte
	managed         map[string]nodeManagedFile
	stagedManaged   map[string]string
	// repairNotice is the declared outcome of a repair whose downloaded
	// candidate differs from the recorded one. It is empty when the repair
	// kept the candidate the Hub offered, and for every fresh install.
	repairNotice string
}

// nodeFinalizeCandidate selects the active candidate (the recorded one for a
// repair, the Hub-provided one otherwise), renders and locally validates it,
// stages every managed file under the operation stage, and records
// candidate_validated. The failure texts stay parameters so the call site keeps
// the exact Line wording.
func nodeFinalizeCandidate(ctx context.Context, result *InstallResult, state *InstallState, opts *NodeApplyOptions, layout nodeLayout, record func(string, string, string) error, repair bool, cfg node.Config, installedCfg node.Config, identity node.Identity, candidate node.CandidateDocument, sshPorts []int, stageDir, kernelPath string, failures nodeCandidateErrors) (nodeCandidateFinalized, error) {
	fail := func(failure *InstallError) (nodeCandidateFinalized, error) {
		res, err := failNodePartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
		*result = res
		return nodeCandidateFinalized{}, err
	}
	activeCandidate := candidate
	if repair {
		if existing, ok := currentNodeCandidate(opts.Root, installedCfg); ok {
			activeCandidate = existing
		}
	}
	// The repair decision is declared where it is taken: when the recorded
	// candidate wins over the downloaded one, the operation records that it
	// did not converge instead of leaving the divergence silent.
	repairNotice := repairCandidateNotice(repair, candidate, activeCandidate)
	if activeCandidate.Schema == "" {
		activeCandidate = node.NewCandidateDocument(node.Candidate{
			NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
			VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
		})
	}
	candidateBody, err := jsonMarshal(activeCandidate)
	if err != nil {
		return fail(failures.marshalFailed)
	}
	candidateConfig, err := node.CompileCandidate(activeCandidate.Candidate())
	if err != nil {
		return fail(failures.compileFailed)
	}
	if err := verifyNodeCandidate(ctx, *opts, kernelPath, candidateConfig, stageDir); err != nil {
		return fail(failures.candidateInvalid)
	}

	managed, err := nodeManagedFilesForLayout(installedCfg, sshPorts, identity, layout)
	if err != nil {
		return fail(failures.configRenderFailed)
	}
	stagedManaged := map[string]string{}
	for path, file := range managed {
		if !file.Static {
			continue
		}
		staged := filepath.Join(stageDir, "managed", strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_"))
		if err := writeBytesAtomic(staged, []byte(file.Body), os.FileMode(file.Mode)); err != nil {
			return fail(failures.stageTemporary)
		}
		stagedManaged[path] = staged
	}
	if err := writeBytesAtomic(filepath.Join(stageDir, "active-candidate.json"), candidateBody, 0600); err != nil {
		return fail(failures.stageTemporary)
	}
	if err := writeBytesAtomic(filepath.Join(stageDir, "config.json"), candidateConfig, 0640); err != nil {
		return fail(failures.stageTemporary)
	}
	if err := record("stage", "candidate_validated", ""); err != nil {
		return fail(failures.operationLog)
	}
	if repairNotice != "" {
		// The journal is the durable half of the declaration: an operator
		// reading this operation later can see that the repair deliberately
		// kept the recorded candidate, not that it forgot to apply one. The
		// status names the event and error_code stays empty, because this
		// repair succeeded; the stable code lives in the next_action prefix.
		if err := record("stage", "candidate_not_converged", ""); err != nil {
			return fail(failures.operationLog)
		}
	}
	return nodeCandidateFinalized{activeCandidate: activeCandidate, candidateConfig: candidateConfig, managed: managed, stagedManaged: stagedManaged, repairNotice: repairNotice}, nil
}
