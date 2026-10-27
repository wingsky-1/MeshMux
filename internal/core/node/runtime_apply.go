package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
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
	}
	if err != nil {
		return failedResult(result, errorCodeOr(err, "CANDIDATE_CHECK_FAILED")), err
	}
	result.Status = "healthy"
	return result, nil
}

func (r *Runtime) stage(ctx context.Context, revision int64) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: currentOperation(ctx), Status: "failed"}
	document, _, config, err := r.validatedCandidate(ctx, revision)
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
	previousRevision := state.Revision
	state.Revision = revision
	state.Digest = sha256Hex(documentData)
	state.LKG = append([]byte(nil), config...)
	state.LKGDigest = readback.ConfigSHA256
	// The retired allowlist fields are cleared so a state written by an older
	// Agent stops carrying them on its first successful apply.
	state.AllowedSources = nil
	state.AllowedSourcesRecorded = false
	state.Journal = nil
	result.Status = "healthy"
	result.Detail = boundedDetail(detail)
	result = r.finishApply(ctx, &state, task, payload, result)
	// The change set is now proven (apply + readback) AND its verdict is
	// durable, so the staged revisions behind the retention window are dead
	// weight. The GC runs only here: a failed or rolled-back apply still needs
	// every staged file it might restore from, a stage-only revision is pending
	// work, and a healthy verdict that could not be persisted must leave the
	// directory exactly as it was. It is best effort — a collection failure
	// never downgrades the verdict the readback just proved; the next healthy
	// apply retries it.
	if result.Status == "healthy" {
		if removed, gcErr := gcStagedRevisions(r.root, revision, previousRevision, stagedKeepRevisions); gcErr != nil {
			r.logger.WarnContext(ctx, "staged revision GC incomplete",
				"operation_id", task.OperationID, "error_code", errorCode(gcErr))
		} else if len(removed) > 0 {
			r.logger.InfoContext(ctx, "staged revisions collected",
				"operation_id", task.OperationID, "count", len(removed))
		}
	}
	return result
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
		acl, err := CompileACL(candidate, nil)
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
	candidate := candidateFromStaged(candidateData)
	if candidate == nil {
		return errors.New("LKG_CANDIDATE_INVALID")
	}
	// The retired Out table is re-applied before the kernel restart for the
	// same reason every LKG step is ordered: a host that is rolled back must
	// carry the neutral table, not a stale allowlist that would deny the
	// clients the restored configuration admits.
	if candidate.Role == RoleOut {
		acl, err := CompileACL(*candidate, nil)
		if err != nil || prepareACL(r.root, acl) != nil {
			return errors.New("LKG_ACL_RESTORE_FAILED")
		}
		if _, err := r.runner.Run(ctx, nftPath, "-f", rooted(r.root, ACLPath)); err != nil {
			return errors.New("LKG_ACL_RESTORE_FAILED")
		}
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
	if _, err := r.readbackFor(ctx, r.cfg.Role, *candidate, state.LKGDigest); err != nil {
		return &lkgRestoreError{code: "LKG_READBACK_FAILED", cause: err}
	}
	state.Journal = nil
	return nil
}

// lkgRestoreError names a failed LKG restore while keeping the underlying
// readback signal. Boot recovery must tell a kernel that has not finished
// starting (retry the restore) from a host that no longer matches the LKG
// (retrying cannot change the verdict). Error() is the stable code alone:
// errorCode must never see the cause.
type lkgRestoreError struct {
	code  string
	cause error
}

func (e *lkgRestoreError) Error() string { return e.code }

func (e *lkgRestoreError) Unwrap() error { return e.cause }

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

// validTransaction reports whether the journal can still name the interrupted
// transaction: its schema, operation, revision and config digest must agree. A
// journal that fails this check is corruption, never a guessable record.
func (j *applyJournal) validTransaction() bool {
	return j != nil && j.Schema == journalTXNSchema && protocol.ValidID(j.OperationID) &&
		j.Revision >= 1 && len(j.Config) > 0 && sha256Hex(j.Config) == j.Digest
}

// receiptable reports whether the journal can still answer a redelivery: the
// task envelope (revision, idempotency key, payload digest) survives even when
// the transaction digest does not. A corrupt envelope is not guessed at; the
// Hub row then ends through its own redelivery instead of a fabricated receipt.
func (j *applyJournal) receiptable() bool {
	return j != nil && protocol.ValidID(j.OperationID) && j.TaskRevision >= 1 &&
		j.Idempotency != "" && protocol.ValidSHA256(j.Payload)
}

// journalRecoveryRetryable reports whether a failed LKG restore may still
// succeed on a later attempt. Only a kernel that has not finished starting
// qualifies: the LKG was healthy before the interrupted apply, so its config
// bytes, ownership and ACL are deterministic on this host, and an ACL that no
// longer matches the recorded authorization will not fix itself between polls.
func journalRecoveryRetryable(err error) bool {
	if err == nil {
		return false
	}
	switch errorCode(err) {
	case "LKG_RESTART_FAILED", "LKG_PID_NOT_REPLACED":
		return true
	case "LKG_READBACK_FAILED":
		var restore *lkgRestoreError
		return errors.As(err, &restore) && TransientReadback(restore.cause)
	default:
		return false
	}
}

// recordJournalFailure makes one failed recovery attempt reportable. The
// receipt is partial: failure is explicit, and partial is legal from every Hub
// state an interrupted apply can leave behind. The idempotency entry answers a
// redelivery; the outbox entry exists only for an operation the Hub already saw
// as "applying" and is replayed by the next drain.
func (r *Runtime) recordJournalFailure(state *runtimeState, journal *applyJournal, code string) {
	if journal == nil || !protocol.ValidID(journal.OperationID) {
		return
	}
	result := protocol.TaskResult{OperationID: journal.OperationID, Status: "partial", ErrorCode: stableCode(code)}
	if journal.receiptable() {
		state.Idempotency[journal.Idempotency] = idempotencyItem{
			PayloadDigest: journal.Payload, TaskRevision: journal.TaskRevision,
			OperationID: journal.OperationID, Result: result,
		}
	}
	if journal.Reported {
		state.FinalResults[journal.OperationID] = result
	}
}

// recoverJournal settles one interrupted apply from the persisted journal.
//
// A proved restore records the rollback verdict and clears the journal. A failed
// restore records the terminal partial receipt in the state and reports whether
// another attempt can still change the outcome. The journal is retired when it
// cannot (corruption, a missing LKG, deterministic host drift); it is kept only
// while the failure is startup-transient, which is what makes check/stage/apply
// answer RECOVERY_REQUIRED instead of touching a data plane whose LKG was not
// proved.
//
// A successful restore is reported as rolled_back only when the Hub already saw
// the operation as "applying". A journal that was never reported leaves its row
// pending, and the Hub's frozen state machine refuses rolled_back there; partial
// is the status it accepts from both pending and applying, so a crash in the
// report window does not turn into a report the Agent can never deliver.
func (r *Runtime) recoverJournal(ctx context.Context, state *runtimeState) (retryable bool, err error) {
	journal := state.Journal
	if journal == nil {
		return false, nil
	}
	failure := ""
	// restore puts the last proved change set back. Its own success clears the
	// journal; a failure replaces the receipt's reason with the step that
	// actually refused and decides whether another attempt can change it.
	restore := func() {
		if len(state.LKG) == 0 {
			return
		}
		if restoreErr := r.restoreLKG(ctx, state); restoreErr != nil {
			failure = errorCode(restoreErr)
			retryable = journalRecoveryRetryable(restoreErr)
		}
	}
	switch {
	case !journal.validTransaction():
		// The transaction cannot be proven, but the LKG in the same state is
		// independent of it: put the last proved change set back when possible,
		// and still name the unprovable journal in the receipt.
		failure = "JOURNAL_INVALID"
		restore()
	case len(state.LKG) == 0:
		failure = "JOURNAL_WITHOUT_LKG"
	default:
		restore()
	}
	if failure != "" {
		r.recordJournalFailure(state, journal, failure)
		if !retryable {
			state.Journal = nil
		}
		return retryable, errors.New(failure)
	}
	status := "rolled_back"
	if !journal.Reported {
		status = "partial"
	}
	result := protocol.TaskResult{OperationID: journal.OperationID, Status: status, ErrorCode: "RECOVERED_AFTER_CRASH"}
	state.Idempotency[journal.Idempotency] = idempotencyItem{
		PayloadDigest: journal.Payload, TaskRevision: journal.TaskRevision,
		OperationID: journal.OperationID, Result: result,
	}
	if journal.Reported {
		state.FinalResults[journal.OperationID] = result
	}
	state.Journal = nil
	return false, nil
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
