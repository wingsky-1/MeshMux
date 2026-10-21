package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

func (r *Runtime) check(ctx context.Context, revision int64) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: currentOperation(ctx), Status: "failed"}
	_, candidate, _, err := r.validatedCandidate(ctx, revision)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	config, err := CompileCandidate(candidate)
	if err != nil {
		return failedResult(result, "CANDIDATE_RENDER_FAILED"), err
	}
	name, f, err := temporaryCandidatePath(r.root)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	defer os.Remove(name)
	if _, err = f.Write(config); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return failedResult(result, "CHECK_FILE_WRITE_FAILED"), err
	}
	binary, err := fixedBinary(r.root, SingBoxBinaryPath, r.cfg)
	if err == nil {
		err = checkSingBox(ctx, r.runner, binary, name)
	}
	if err == nil {
		err = checkOutACL(ctx, r.runner, r.root, candidate)
	}
	if err != nil {
		return failedResult(result, errorCodeOr(err, "CANDIDATE_CHECK_FAILED")), err
	}
	result.Status = "healthy"
	return result, nil
}

func (r *Runtime) stage(ctx context.Context, revision int64) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: currentOperation(ctx), Status: "failed"}
	document, candidate, config, err := r.validatedCandidate(ctx, revision)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	documentData, err := json.Marshal(document)
	if err != nil {
		return failedResult(result, "CANDIDATE_ENCODE_FAILED"), err
	}
	if err = writeStageAtomic(r.root, stagedCandidatePath(r.root, revision), documentData); err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if err = writeStageAtomic(r.root, stagedConfigPath(r.root, revision), config); err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if err = checkSingBox(ctx, r.runner, rootedOptionalBinary(r.root, SingBoxBinaryPath), stagedConfigPath(r.root, revision)); err != nil {
		return failedResult(result, "CANDIDATE_CHECK_FAILED"), err
	}
	if err = checkOutACL(ctx, r.runner, r.root, candidate); err != nil {
		return failedResult(result, "OUT_ACL_CHECK_FAILED"), err
	}
	result.Status = "healthy"
	return result, nil
}

func (r *Runtime) validatedCandidate(ctx context.Context, revision int64) (CandidateDocument, Candidate, []byte, error) {
	document, err := r.controller.Candidate(ctx, revision)
	if err != nil {
		return CandidateDocument{}, Candidate{}, nil, stableError("CANDIDATE_FETCH_FAILED")
	}
	if err = document.ValidateFor(r.cfg); err != nil {
		return CandidateDocument{}, Candidate{}, nil, err
	}
	if document.Revision != revision {
		return CandidateDocument{}, Candidate{}, nil, errors.New("CANDIDATE_REVISION_MISMATCH")
	}
	candidate := document.Candidate()
	config, err := CompileCandidate(candidate)
	if err != nil {
		return CandidateDocument{}, Candidate{}, nil, err
	}
	return document, candidate, config, nil
}

func rootedOptionalBinary(root, path string) string {
	if root == "/" {
		return path
	}
	return rooted(root, path)
}

func (r *Runtime) apply(ctx context.Context, task protocol.Task, payload string, revision int64, state runtimeState) protocol.TaskResult {
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	if state.Journal != nil {
		return failedResult(result, "RECOVERY_REQUIRED")
	}
	document, candidate, config, err := r.validatedCandidate(ctx, revision)
	if err != nil {
		return r.finishApply(ctx, &state, task, payload, failedResult(result, errorCode(err)))
	}
	documentData, err := json.Marshal(document)
	if err != nil {
		return r.finishApply(ctx, &state, task, payload, failedResult(result, "CANDIDATE_ENCODE_FAILED"))
	}
	if err = r.stageCandidateFiles(revision, documentData, config); err != nil {
		return r.finishApply(ctx, &state, task, payload, failedResult(result, errorCode(err)))
	}
	if err = r.validateStaged(ctx, revision, document, candidate); err != nil {
		return r.finishApply(ctx, &state, task, payload, failedResult(result, errorCode(err)))
	}
	digest := sha256Hex(config)
	journal := &applyJournal{
		Schema:       journalTXNSchema,
		OperationID:  task.OperationID,
		Idempotency:  task.IdempotencyKey,
		Payload:      payload,
		TaskRevision: task.Revision,
		Revision:     revision,
		Digest:       digest,
		Candidate:    documentData,
		Config:       config,
	}
	state.Journal = journal
	state.LastTaskRevision = task.Revision
	if err = r.saveState(&state); err != nil {
		return failedResult(result, "JOURNAL_WRITE_FAILED")
	}
	progress := protocol.TaskResult{OperationID: task.OperationID, Status: "applying"}
	if !applyAcknowledged(ctx) {
		if err = r.controller.Report(ctx, progress); err != nil {
			return r.finishApply(ctx, &state, task, payload, failedResult(result, "APPLYING_REPORT_FAILED"))
		}
	}
	journal.Reported = true
	if err = r.saveState(&state); err != nil {
		return r.finishApply(ctx, &state, task, payload, failedResult(result, "JOURNAL_WRITE_FAILED"))
	}
	if err = r.activate(ctx, &state, journal, candidate); err != nil {
		return r.finishApply(ctx, &state, task, payload, r.recoverFailedApply(ctx, &state, journal, err))
	}
	if err = r.controller.Report(ctx, protocol.TaskResult{
		OperationID: task.OperationID, Status: "verifying",
	}); err != nil {
		return r.finishApply(ctx, &state, task, payload, r.recoverFailedApply(ctx, &state, journal, errors.New("VERIFYING_REPORT_FAILED")))
	}
	expectedPID := ""
	if journal.ExpectedPID > 0 {
		expectedPID = strconv.Itoa(journal.ExpectedPID)
	}
	readback, err := r.readbackForProcess(ctx, r.cfg.Role, candidate, digest, expectedPID)
	if err != nil {
		return r.finishApply(ctx, &state, task, payload, r.recoverFailedApply(ctx, &state, journal, err))
	}
	detail, err := json.Marshal(readback)
	if err != nil {
		return r.finishApply(ctx, &state, task, payload, failedResult(result, "READBACK_DETAIL_FAILED"))
	}
	state.Revision = revision
	state.Digest = sha256Hex(documentData)
	state.LKG = append([]byte(nil), config...)
	state.LKGDigest = readback.ConfigSHA256
	state.Journal = nil
	result.Status = "healthy"
	result.Detail = boundedDetail(detail)
	return r.finishApply(ctx, &state, task, payload, result)
}

func (r *Runtime) stageCandidateFiles(revision int64, document, config []byte) error {
	if err := writeStageAtomic(r.root, stagedCandidatePath(r.root, revision), document); err != nil {
		return err
	}
	return writeStageAtomic(r.root, stagedConfigPath(r.root, revision), config)
}

func (r *Runtime) validateStaged(ctx context.Context, revision int64, document CandidateDocument, candidate Candidate) error {
	stagedCandidate, _, err := readPrivateFile(stagedCandidatePath(r.root, revision))
	if err != nil {
		return errors.New("STAGED_CANDIDATE_INVALID")
	}
	var decoded CandidateDocument
	if decodeStrictJSON(stagedCandidate, &decoded) != nil || !decoded.Equal(document) {
		return errors.New("STAGED_CANDIDATE_INVALID")
	}
	stagedConfig, _, err := readPrivateFile(stagedConfigPath(r.root, revision))
	if err != nil {
		return errors.New("STAGED_CONFIG_INVALID")
	}
	expected, err := CompileCandidate(candidate)
	if err != nil || !bytes.Equal(stagedConfig, expected) {
		return errors.New("STAGED_CONFIG_INVALID")
	}
	if err = checkSingBox(ctx, r.runner, rootedOptionalBinary(r.root, SingBoxBinaryPath), stagedConfigPath(r.root, revision)); err != nil {
		return errors.New("CANDIDATE_CHECK_FAILED")
	}
	if err = checkOutACL(ctx, r.runner, r.root, candidate); err != nil {
		return errors.New("OUT_ACL_CHECK_FAILED")
	}
	return nil
}

func (r *Runtime) activate(ctx context.Context, state *runtimeState, journal *applyJournal, candidate Candidate) error {
	before, beforeErr := r.systemdProperties(ctx)
	if beforeErr == nil && before.MainPID > 0 {
		journal.PreviousPID = before.MainPID
	}
	if err := prepareActiveConfig(r.root, journal.Config); err != nil {
		return err
	}
	if err := prepareCandidate(r.root, journal.Candidate); err != nil {
		return err
	}
	if candidate.Role == RoleOut {
		acl, err := CompileACL(candidate)
		if err != nil {
			return err
		}
		if err := prepareACL(r.root, acl); err != nil {
			return err
		}
		if _, err := r.runner.Run(ctx, nftPath, "-f", rooted(r.root, ACLPath)); err != nil {
			return errors.New("OUT_ACL_APPLY_FAILED")
		}
	}
	if _, err := r.runner.Run(ctx, systemctlPath, "restart", SingBoxUnit); err != nil {
		return errors.New("SINGBOX_RESTART_FAILED")
	}
	props, err := r.systemdProperties(ctx)
	if err != nil || props.ActiveState != "active" || props.SubState != "running" || props.MainPID < 1 {
		return errors.New("SINGBOX_NOT_RUNNING")
	}
	if journal.PreviousPID > 0 && props.MainPID == journal.PreviousPID {
		return errors.New("SINGBOX_PID_NOT_REPLACED")
	}
	journal.ExpectedPID = props.MainPID
	if err := r.saveState(state); err != nil {
		return errors.New("JOURNAL_WRITE_FAILED")
	}
	return nil
}

func (r *Runtime) recoverFailedApply(ctx context.Context, state *runtimeState, journal *applyJournal, cause error) protocol.TaskResult {
	result := protocol.TaskResult{OperationID: journal.OperationID, Status: "failed", ErrorCode: errorCode(cause)}
	restoreErr := r.restoreLKG(ctx, state)
	if restoreErr != nil {
		result.Status = "partial"
		result.ErrorCode = errorCode(restoreErr)
	} else {
		result.Status = "rolled_back"
		result.ErrorCode = errorCode(cause)
	}
	return result
}

func (r *Runtime) restoreLKG(ctx context.Context, state *runtimeState) error {
	if len(state.LKG) == 0 || state.Revision < 1 || state.LKGDigest == "" {
		return errors.New("LKG_UNAVAILABLE")
	}
	configPath := rooted(r.root, ActiveConfigPath)
	candidatePath := rooted(r.root, ActiveCandidatePath)
	currentConfig, _, configReadErr := readRegularFile(configPath, false)
	currentCandidate, _, candidateReadErr := readPrivateFile(candidatePath)
	restoreConfig := configReadErr != nil || !bytes.Equal(currentConfig, state.LKG)
	restoreCandidate := candidateReadErr != nil || sha256Hex(currentCandidate) != state.Digest
	if restoreConfig {
		if err := prepareActiveConfig(r.root, state.LKG); err != nil {
			return errors.New("LKG_CONFIG_RESTORE_FAILED")
		}
	}
	candidateData, err := r.loadLKGCandidate(state.Revision)
	if err != nil {
		return errors.New("LKG_CANDIDATE_RESTORE_FAILED")
	}
	if restoreCandidate {
		if err = prepareCandidate(r.root, candidateData); err != nil {
			return errors.New("LKG_CANDIDATE_RESTORE_FAILED")
		}
	}
	var previousPID int
	if props, err := r.systemdProperties(ctx); err == nil {
		previousPID = props.MainPID
	}
	if restoreConfig || restoreCandidate {
		if _, err := r.runner.Run(ctx, systemctlPath, "restart", SingBoxUnit); err != nil {
			return errors.New("LKG_RESTART_FAILED")
		}
		props, err := r.systemdProperties(ctx)
		if err != nil || props.MainPID < 1 || beforePIDEqual(previousPID, props.MainPID) {
			return errors.New("LKG_PID_NOT_REPLACED")
		}
	}
	candidate := candidateFromStaged(candidateData)
	if candidate == nil {
		return errors.New("LKG_CANDIDATE_INVALID")
	}
	if candidate.Role == RoleOut {
		acl, err := CompileACL(*candidate)
		if err != nil || prepareACL(r.root, acl) != nil {
			return errors.New("LKG_ACL_RESTORE_FAILED")
		}
		if _, err := r.runner.Run(ctx, nftPath, "-f", rooted(r.root, ACLPath)); err != nil {
			return errors.New("LKG_ACL_RESTORE_FAILED")
		}
	}
	if _, err := r.readbackFor(ctx, r.cfg.Role, *candidate, state.LKGDigest); err != nil {
		return errors.New("LKG_READBACK_FAILED")
	}
	state.Journal = nil
	return nil
}

func beforePIDEqual(before, after int) bool {
	return before > 0 && before == after
}

func (r *Runtime) loadLKGCandidate(revision int64) ([]byte, error) {
	data, _, err := readPrivateFile(stagedCandidatePath(r.root, revision))
	if err != nil {
		return nil, err
	}
	var document CandidateDocument
	if err = decodeStrictJSON(data, &document); err != nil || document.ValidateFor(r.cfg) != nil || document.Revision != revision {
		return nil, errors.New("LKG_CANDIDATE_INVALID")
	}
	return data, nil
}

func candidateFromStaged(data []byte) *Candidate {
	var document CandidateDocument
	if decodeStrictJSON(data, &document) != nil {
		return nil
	}
	candidate := document.Candidate()
	return &candidate
}

func (r *Runtime) recoverJournal(ctx context.Context, state *runtimeState) error {
	journal := state.Journal
	if journal == nil {
		return nil
	}
	if journal.Schema != journalTXNSchema || journal.OperationID == "" || journal.Revision < 1 ||
		sha256Hex(journal.Config) != journal.Digest {
		return errors.New("JOURNAL_INVALID")
	}
	if len(state.LKG) > 0 {
		if err := r.restoreLKG(ctx, state); err != nil {
			result := protocol.TaskResult{OperationID: journal.OperationID, Status: "partial", ErrorCode: errorCode(err)}
			state.Idempotency[journal.Idempotency] = idempotencyItem{
				PayloadDigest: journal.Payload, TaskRevision: journal.TaskRevision,
				OperationID: journal.OperationID, Result: result,
			}
			if journal.Reported {
				state.FinalResults[journal.OperationID] = result
			}
			return err
		}
	} else {
		return errors.New("JOURNAL_WITHOUT_LKG")
	}
	result := protocol.TaskResult{OperationID: journal.OperationID, Status: "rolled_back", ErrorCode: "RECOVERED_AFTER_CRASH"}
	state.Idempotency[journal.Idempotency] = idempotencyItem{
		PayloadDigest: journal.Payload, TaskRevision: journal.TaskRevision,
		OperationID: journal.OperationID, Result: result,
	}
	if journal.Reported {
		state.FinalResults[journal.OperationID] = result
	}
	state.Journal = nil
	return nil
}

func (r *Runtime) finishApply(ctx context.Context, state *runtimeState, task protocol.Task, payload string, result protocol.TaskResult) protocol.TaskResult {
	if err := protocol.ValidateTaskResult(result); err != nil {
		result = failedResult(result, "RESULT_INVALID")
	}
	state.Idempotency[task.IdempotencyKey] = idempotencyItem{
		PayloadDigest: payload, TaskRevision: task.Revision, OperationID: task.OperationID, Result: result,
	}
	if result.Status == "applying" || result.Status == "verifying" {
		state.LastTaskRevision = task.Revision
		state.FinalResults[task.OperationID] = result
		if err := r.saveState(state); err != nil {
			r.logger.ErrorContext(ctx, "persist progress result failed",
				"operation_id", task.OperationID, "error_code", errorCode(err))
			return failedResult(result, "STATE_PERSIST_FAILED")
		}
		return result
	}
	state.FinalResults[task.OperationID] = result
	state.LastTaskRevision = task.Revision
	if err := r.saveState(state); err != nil {
		r.logger.ErrorContext(ctx, "persist apply result failed", "operation_id", task.OperationID, "error_code", errorCode(err))
		if result.Status == "healthy" {
			result.Status = "partial"
		} else {
			result.Status = "failed"
		}
		result.ErrorCode = "STATE_PERSIST_FAILED"
		result.Detail = ""
	}
	return result
}
