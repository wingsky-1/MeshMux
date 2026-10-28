package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// Execute validates and executes exactly one frozen task.
func (r *Runtime) Execute(ctx context.Context, task protocol.Task) protocol.TaskResult {
	// The upgrade gate is answered before the runtime lock (spec §4.9). While
	// an install is in flight an apply/readback must return its non-terminal
	// receipt without waiting behind the lock the install/repair holds; the
	// lock is only needed by work that would touch the data plane.
	if gated, stop := r.preLockHandoffGate(ctx, task); stop {
		r.logger.InfoContext(withOperation(ctx, task.OperationID), "task stage",
			"operation_id", task.OperationID, "stage", "handoff", "error_code", gated.ErrorCode)
		return gated
	}
	lock, err := acquireRuntimeLock(ctx, r.root, true, r.lockTimeout)
	if err != nil {
		return failedResult(protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}, errorCode(err))
	}
	defer lock.Close()
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	payload, err := canonicalTaskPayload(task)
	if err != nil {
		return failedResult(result, "TASK_ENCODE_FAILED")
	}
	digest := sha256Hex(payload)
	if err = protocol.ValidateTask(task); err != nil {
		if task.OperationID == "" {
			result.OperationID = strings.Repeat("0", 32)
		}
		return failedResult(result, errorCode(err))
	}
	if task.NodeID != r.cfg.NodeID {
		return failedResult(result, "NODE_SCOPE_MISMATCH")
	}
	revision, err := taskRevision(task)
	if err != nil {
		return failedResult(result, errorCode(err))
	}
	state, err := r.loadStateForExecution()
	if err != nil {
		return failedResult(result, errorCode(err))
	}
	if item, ok := state.Idempotency[task.IdempotencyKey]; ok {
		if item.PayloadDigest != digest || item.TaskRevision != task.Revision || item.OperationID != task.OperationID {
			return failedResult(result, "IDEMPOTENCY_CONFLICT")
		}
		return item.Result
	}
	for _, item := range state.Idempotency {
		if item.OperationID == task.OperationID {
			return failedResult(result, "OPERATION_REUSE_CONFLICT")
		}
	}
	if task.Revision <= state.LastTaskRevision {
		return failedResult(result, "TASK_REVISION_STALE")
	}
	if len(state.FinalResults) >= maxFinalCache {
		return failedResult(result, "FINAL_OUTBOX_FULL")
	}
	taskContext := withOperation(ctx, task.OperationID)
	r.logger.InfoContext(taskContext, "task stage",
		"operation_id", task.OperationID, "stage", "validate", "error_code", "")
	// The upgrade handoff keeps the chain open: while an install is in flight,
	// apply and readback must not touch the data plane. They report a legal
	// non-terminal state instead, so TASKS_IN_PROGRESS still sees an unfinished
	// chain and no step claims work it did not do.
	var executeErr error
	gated := false
	if task.Kind == protocol.KindConfigReadback ||
		task.Kind == protocol.KindConfigApply && state.Journal == nil {
		gateResult, stop, gateErr := r.handoffGate(ctx, task.OperationID)
		if stop {
			result, executeErr, gated = gateResult, gateErr, true
		}
	}
	if !gated {
		switch task.Kind {
		case protocol.KindConfigCheck:
			if state.Journal != nil {
				result, executeErr = failedResult(result, "RECOVERY_REQUIRED"), errors.New("RECOVERY_REQUIRED")
				break
			}
			result, executeErr = r.check(taskContext, revision)
		case protocol.KindConfigStage:
			if state.Journal != nil {
				result, executeErr = failedResult(result, "RECOVERY_REQUIRED"), errors.New("RECOVERY_REQUIRED")
				break
			}
			result, executeErr = r.stageOrHandOff(taskContext, task, revision)
		case protocol.KindConfigApply:
			if state.Journal != nil {
				return failedResult(result, "RECOVERY_REQUIRED")
			}
			applyResult := r.apply(taskContext, task, digest, revision, state)
			return applyResult
		case protocol.KindConfigReadback:
			result, executeErr = r.readback(taskContext, revision)
		case protocol.KindHealthStatus, protocol.KindNodeStatus:
			result, executeErr = r.status(taskContext)
		default:
			executeErr = errors.New("TASK_KIND_REJECTED")
		}
	}
	if executeErr != nil && result.ErrorCode == "" {
		result = failedResult(result, errorCode(executeErr))
	}
	if result.Status == "partial" || result.Status == "failed" {
		result.Status = "failed"
	}
	if !terminalTaskResult(result.Status) {
		// A non-terminal receipt is not a final result: the step is redelivered
		// on the next poll and replays it while the handoff runs. Nothing is
		// cached and LastTaskRevision stays put, so the chain cannot be advanced
		// past a step that has not completed.
		r.logger.InfoContext(taskContext, "task stage",
			"operation_id", task.OperationID, "stage", "handoff", "error_code", result.ErrorCode)
		return result
	}
	final := result
	state.Idempotency[task.IdempotencyKey] = idempotencyItem{
		PayloadDigest: digest, TaskRevision: task.Revision, OperationID: task.OperationID, Result: final,
	}
	state.FinalResults[task.OperationID] = final
	state.LastTaskRevision = task.Revision
	if err := r.saveState(&state); err != nil {
		r.logger.ErrorContext(ctx, "persist final task result failed",
			"operation_id", task.OperationID, "error_code", errorCode(err))
		return failedResult(result, statePersistCode(err))
	}
	r.logger.InfoContext(taskContext, "task stage",
		"operation_id", task.OperationID, "stage", "final", "error_code", result.ErrorCode)
	return final
}

func (r *Runtime) cachedTaskResult(task protocol.Task) (protocol.TaskResult, bool) {
	result := protocol.TaskResult{OperationID: task.OperationID, Status: "failed"}
	if err := protocol.ValidateTask(task); err != nil || task.NodeID != r.cfg.NodeID {
		return failedResult(result, errorCode(err)), true
	}
	payload, err := canonicalTaskPayload(task)
	if err != nil {
		return failedResult(result, "TASK_ENCODE_FAILED"), true
	}
	state, err := r.loadStateForExecution()
	if err != nil {
		return failedResult(result, errorCode(err)), true
	}
	if item, ok := state.Idempotency[task.IdempotencyKey]; ok {
		if item.PayloadDigest != sha256Hex(payload) || item.TaskRevision != task.Revision || item.OperationID != task.OperationID {
			return failedResult(result, "IDEMPOTENCY_CONFLICT"), true
		}
		return item.Result, true
	}
	for _, item := range state.Idempotency {
		if item.OperationID == task.OperationID {
			return failedResult(result, "OPERATION_REUSE_CONFLICT"), true
		}
	}
	if task.Revision <= state.LastTaskRevision {
		return failedResult(result, "TASK_REVISION_STALE"), true
	}
	if len(state.FinalResults) >= maxFinalCache {
		return failedResult(result, "FINAL_OUTBOX_FULL"), true
	}
	return protocol.TaskResult{}, false
}

func terminalTaskResult(status string) bool {
	switch status {
	case "healthy", "partial", "failed", "rolled_back":
		return true
	default:
		return false
	}
}

func canonicalTaskPayload(task protocol.Task) ([]byte, error) {
	var params any
	decoder := json.NewDecoder(bytes.NewReader(task.Params))
	decoder.UseNumber()
	if len(task.Params) == 0 || decoder.Decode(&params) != nil {
		return nil, errors.New("PARAMS_INVALID")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("PARAMS_INVALID")
	}
	task.Params = nil
	normalized, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	const marker = `"params":null`
	index := bytes.LastIndex(normalized, []byte(marker))
	if index < 0 {
		return nil, errors.New("TASK_ENCODE_FAILED")
	}
	result := make([]byte, 0, len(normalized)+len(paramsJSON))
	result = append(result, normalized[:index]...)
	result = append(result, `"params":`...)
	result = append(result, paramsJSON...)
	result = append(result, normalized[index+len(marker):]...)
	return result, nil
}

func taskRevision(task protocol.Task) (int64, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(task.Params, &values); err != nil {
		return 0, errors.New("PARAMS_INVALID")
	}
	if len(values) == 0 {
		return task.Revision, nil
	}
	raw, ok := values["revision"]
	if !ok {
		return 0, errors.New("PARAMS_INVALID")
	}
	var revision int64
	if err := json.Unmarshal(raw, &revision); err != nil || revision < 1 {
		return 0, errors.New("REVISION_INVALID")
	}
	return revision, nil
}

// taskAllowedSources was retired with the Out source allowlist. A config task
// no longer carries a source set: the Out admits by link key, so the Agent has
// nothing to derive, stage or read back. Older task params may still contain
// `allowed_sources`; taskRevision ignores unknown keys.

func currentOperation(ctx context.Context) string {
	if value, ok := ctx.Value(operationContextKey{}).(string); ok {
		return value
	}
	return strings.Repeat("0", 32)
}

type operationContextKey struct{}
type applyAcknowledgedKey struct{}

func withOperation(ctx context.Context, operationID string) context.Context {
	return context.WithValue(ctx, operationContextKey{}, operationID)
}

func withApplyAcknowledged(ctx context.Context) context.Context {
	return context.WithValue(ctx, applyAcknowledgedKey{}, true)
}

func applyAcknowledged(ctx context.Context) bool {
	value, _ := ctx.Value(applyAcknowledgedKey{}).(bool)
	return value
}

func failedResult(result protocol.TaskResult, code string) protocol.TaskResult {
	result.Status = "failed"
	result.ErrorCode = stableCode(code)
	result.Detail = ""
	return result
}

// stableCode returns code when it is one of the registered runtime codes, and
// taskFailedCode otherwise. Only the registry decides what reaches a task
// result: a caller-supplied message, a wrapped error and a free-form value all
// collapse to taskFailedCode instead of becoming an ad-hoc code.
func stableCode(code string) string {
	if isRuntimeCode(code) {
		return code
	}
	return taskFailedCode
}

// errorCode extracts the stable code of err. Only the text before the first
// colon can name a code, and only a registered one is returned; the rest of the
// message (a path, a digest, a raw subprocess line) stays out of the contract.
func errorCode(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if index := strings.IndexByte(message, ':'); index > 0 {
		message = message[:index]
	}
	return stableCode(message)
}

func errorCodeOr(err error, fallback string) string {
	code := errorCode(err)
	if code == "" || code == taskFailedCode {
		return stableCode(fallback)
	}
	return code
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func boundedDetail(data []byte) string {
	if len(data) <= 512 {
		return string(data)
	}
	var full, compact map[string]json.RawMessage
	if json.Unmarshal(data, &full) != nil {
		return "{}"
	}
	compact = make(map[string]json.RawMessage)
	for _, key := range []string{
		"active_revision", "agent_sha256", "agent_version", "architecture",
		"config_sha256", "kernel_sha256", "kernel_version", "local_active",
		"out_default_deny",
	} {
		if value, ok := full[key]; ok {
			compact[key] = value
		}
	}
	shortened, err := json.Marshal(compact)
	if err != nil || len(shortened) > 512 {
		return "{}"
	}
	return string(shortened)
}
