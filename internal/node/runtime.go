package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

const (
	runtimeStateSchema = "meshmux-node-state/v1"
	journalTXNSchema   = "meshmux-node-journal/v1"
	maxIdempotency     = 1024
	maxFinalCache      = 1024
)

// errRuntimeStateTooLarge refuses a runtime state that does not fit the
// state size bound. The previous readable state stays untouched.
var errRuntimeStateTooLarge = errors.New("RUNTIME_STATE_TOO_LARGE")

// Controller is the narrow outbound Hub control-plane boundary.
type Controller interface {
	Candidate(context.Context, int64) (CandidateDocument, error)
	Heartbeat(context.Context, protocol.HeartbeatRequest) error
	Tasks(context.Context) ([]protocol.Task, error)
	Report(context.Context, protocol.TaskResult) error
}

// RuntimeOptions supplies the fixed host boundary and outbound controller.
type RuntimeOptions struct {
	Root         string
	Runner       CommandRunner
	Controller   Controller
	HTTPClient   *http.Client
	Logger       *slog.Logger
	PollInterval time.Duration
}

// Runtime executes the frozen task set against one installed node.
type Runtime struct {
	cfg             Config
	identity        Identity
	root            string
	runner          CommandRunner
	controller      Controller
	httpClient      *http.Client
	logger          *slog.Logger
	pollInterval    time.Duration
	now             func() time.Time
	procRoot        string
	writeState      func(*runtimeState) error
	enforceProcArgs bool
}

type runtimeState struct {
	Schema           string                         `json:"schema"`
	NodeID           string                         `json:"node_id"`
	Role             Role                           `json:"role"`
	Revision         int64                          `json:"revision,omitempty"`
	LastTaskRevision int64                          `json:"last_task_revision,omitempty"`
	Digest           string                         `json:"digest,omitempty"`
	LKG              []byte                         `json:"lkg,omitempty"`
	LKGDigest        string                         `json:"lkg_digest,omitempty"`
	Journal          *applyJournal                  `json:"journal,omitempty"`
	Idempotency      map[string]idempotencyItem     `json:"idempotency,omitempty"`
	FinalResults     map[string]protocol.TaskResult `json:"final_results,omitempty"`
}

type idempotencyItem struct {
	PayloadDigest string              `json:"payload_digest"`
	TaskRevision  int64               `json:"task_revision"`
	OperationID   string              `json:"operation_id"`
	Result        protocol.TaskResult `json:"result"`
}

type applyJournal struct {
	Schema       string `json:"schema"`
	OperationID  string `json:"operation_id"`
	Idempotency  string `json:"idempotency_key"`
	Payload      string `json:"payload_digest"`
	TaskRevision int64  `json:"task_revision"`
	Revision     int64  `json:"revision"`
	Digest       string `json:"digest"`
	Candidate    []byte `json:"candidate"`
	Config       []byte `json:"config"`
	Reported     bool   `json:"reported"`
	ExpectedPID  int    `json:"expected_pid,omitempty"`
	PreviousPID  int    `json:"previous_pid,omitempty"`
}

func emptyRuntimeState(cfg Config) runtimeState {
	return runtimeState{
		Schema:       runtimeStateSchema,
		NodeID:       cfg.NodeID,
		Role:         cfg.Role,
		Idempotency:  make(map[string]idempotencyItem),
		FinalResults: make(map[string]protocol.TaskResult),
	}
}

// NewRuntime validates all fixed paths and recovers an interrupted apply before
// returning a runtime that can execute new tasks.
func NewRuntime(cfg Config, identity Identity, opts RuntimeOptions) (*Runtime, error) {
	if err := cfg.ValidateInstalled(); err != nil {
		return nil, err
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return nil, err
	}
	if _, ok := KernelReleaseFor(runtime.GOARCH); !ok {
		return nil, errors.New("ARCHITECTURE_UNSUPPORTED")
	}
	root, err := trustedRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	if release, ok := KernelReleaseFor(runtime.GOARCH); !ok || root == "/" && cfg.KernelSHA256 != release.BinarySHA256 {
		return nil, errors.New("KERNEL_RELEASE_MISMATCH")
	}
	lock, err := acquireRuntimeLock(context.Background(), root, true)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Controller == nil {
		return nil, errors.New("CONTROLLER_REQUIRED")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	r := &Runtime{
		cfg:             cfg,
		identity:        identity,
		root:            root,
		runner:          opts.Runner,
		controller:      opts.Controller,
		httpClient:      opts.HTTPClient,
		logger:          opts.Logger,
		pollInterval:    defaultPollInterval(opts.PollInterval),
		now:             time.Now,
		procRoot:        rooted(root, "/proc"),
		enforceProcArgs: root == "/",
	}
	r.writeState = r.persistState
	if err := r.ensureLayout(); err != nil {
		return nil, err
	}
	state, err := r.loadOrInitializeState()
	if err != nil {
		return nil, err
	}
	if state.Journal != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err = r.recoverJournal(recoveryCtx, &state)
		cancel()
		if err != nil {
			r.logger.ErrorContext(context.Background(), "runtime recovery failed",
				"operation_id", state.Journal.OperationID, "error_code", errorCode(err))
			return nil, err
		}
	}
	if err := r.saveState(&state); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Runtime) ensureLayout() error {
	for _, dir := range []string{
		rooted(r.root, agentDataDir),
		rooted(r.root, stagedDir),
	} {
		if err := ensureNoSymlinkAncestors(r.root, dir); err != nil {
			return err
		}
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			if err = os.Mkdir(dir, 0700); err != nil {
				return errors.New("RUNTIME_DIRECTORY_CREATE_FAILED")
			}
			info, err = os.Lstat(dir)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("RUNTIME_DIRECTORY_UNSAFE")
		}
		if info.Mode().Perm() != 0700 {
			return errors.New("DATA_PERMISSIONS")
		}
	}
	return nil
}

func (r *Runtime) loadOrInitializeState() (runtimeState, error) {
	path := rooted(r.root, RuntimeStatePath)
	data, _, err := readRuntimeStateFile(path)
	if os.IsNotExist(err) {
		state := emptyRuntimeState(r.cfg)
		if err := r.bootstrapLKG(&state); err != nil {
			return state, err
		}
		if err := r.saveState(&state); err != nil {
			return state, err
		}
		return state, nil
	}
	if err != nil {
		return runtimeState{}, errors.New("RUNTIME_STATE_UNSAFE")
	}
	var state runtimeState
	if err := decodeStrictJSON(data, &state); err != nil || state.Schema != runtimeStateSchema ||
		state.NodeID != r.cfg.NodeID || state.Role != r.cfg.Role {
		return runtimeState{}, errors.New("RUNTIME_STATE_INVALID")
	}
	if state.Idempotency == nil {
		state.Idempotency = make(map[string]idempotencyItem)
	}
	for key, item := range state.Idempotency {
		if !terminalTaskResult(item.Result.Status) {
			delete(state.Idempotency, key)
		}
	}
	if state.FinalResults == nil {
		state.FinalResults = make(map[string]protocol.TaskResult)
	}
	return state, nil
}

func (r *Runtime) bootstrapLKG(state *runtimeState) error {
	candidateData, _, err := readRegularFile(rooted(r.root, ActiveCandidatePath), true)
	if err != nil {
		return errors.New("BOOTSTRAP_CANDIDATE_UNAVAILABLE")
	}
	var document CandidateDocument
	if err = decodeStrictJSON(candidateData, &document); err != nil {
		return errors.New("BOOTSTRAP_CANDIDATE_INVALID")
	}
	if err = document.ValidateFor(r.cfg); err != nil {
		return err
	}
	if err = writeStageAtomic(r.root, stagedCandidatePath(r.root, document.Revision), candidateData); err != nil {
		return err
	}
	configData, _, err := readRegularFile(rooted(r.root, ActiveConfigPath), false)
	if err != nil {
		return errors.New("BOOTSTRAP_CONFIG_UNAVAILABLE")
	}
	expected, err := CompileCandidate(document.Candidate())
	if err != nil || !bytes.Equal(configData, expected) {
		return errors.New("BOOTSTRAP_CONFIG_INVALID")
	}
	if err = writeStageAtomic(r.root, stagedConfigPath(r.root, document.Revision), configData); err != nil {
		return err
	}
	// The kernel may still be starting (systemd runs Agent and kernel
	// concurrently with no ordering between them). Poll a bounded number of
	// times for startup-transient signals; anything deterministic fails fast
	// so a broken data plane is never mistaken for a slow one.
	var readback Readback
	for i := 0; ; i++ {
		readback, err = r.readbackFor(context.Background(), r.cfg.Role, document.Candidate(), sha256Hex(configData))
		if err == nil || !TransientReadback(err) || i >= 29 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return err
	}
	state.Revision = document.Revision
	state.Digest = sha256Hex(candidateData)
	state.LKG = append([]byte(nil), configData...)
	state.LKGDigest = readback.ConfigSHA256
	return nil
}

func (r *Runtime) persistState(state *runtimeState) error {
	if len(state.Idempotency) > maxIdempotency {
		state.trimAcknowledged()
		if len(state.Idempotency) > maxIdempotency {
			return errors.New("IDEMPOTENCY_CACHE_FULL")
		}
	}
	if len(state.FinalResults) > maxFinalCache {
		return errors.New("FINAL_OUTBOX_FULL")
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("RUNTIME_STATE_ENCODE_FAILED")
	}
	data = append(data, '\n')
	// The size is checked before the atomic replace, so a state that does not
	// fit never reaches the disk and the previous readable state stays in
	// place for the next start.
	if len(data) > maxRuntimeStateSize {
		return errRuntimeStateTooLarge
	}
	path := rooted(r.root, RuntimeStatePath)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return writeAtomic(path, data, 0600, false)
	}
	return writeAtomic(path, data, 0600, true)
}

func (r *Runtime) saveState(state *runtimeState) error {
	if r.writeState != nil {
		return r.writeState(state)
	}
	return r.persistState(state)
}

// statePersistCode maps a state persistence failure to a stable error code.
// A state that does not fit the size bound keeps its own code, because the
// previous readable state is still in place and only the new state was
// refused.
func statePersistCode(err error) string {
	if errors.Is(err, errRuntimeStateTooLarge) {
		return "RUNTIME_STATE_TOO_LARGE"
	}
	return "STATE_PERSIST_FAILED"
}

func (s *runtimeState) trimAcknowledged() {
	for key, item := range s.Idempotency {
		if _, pending := s.FinalResults[item.OperationID]; !pending && terminalTaskResult(item.Result.Status) {
			delete(s.Idempotency, key)
			if len(s.Idempotency) <= maxIdempotency {
				return
			}
		}
	}
}

// Execute validates and executes exactly one frozen task.
func (r *Runtime) Execute(ctx context.Context, task protocol.Task) protocol.TaskResult {
	lock, err := acquireRuntimeLock(ctx, r.root, true)
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
	var executeErr error
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
		result, executeErr = r.stage(taskContext, revision)
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
	if executeErr != nil && result.ErrorCode == "" {
		result = failedResult(result, errorCode(executeErr))
	}
	if result.Status == "partial" || result.Status == "failed" {
		result.Status = "failed"
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

func (r *Runtime) loadStateForExecution() (runtimeState, error) {
	path := rooted(r.root, RuntimeStatePath)
	data, _, err := readRuntimeStateFile(path)
	if err != nil {
		return runtimeState{}, errors.New("RUNTIME_STATE_UNSAFE")
	}
	var state runtimeState
	if err = decodeStrictJSON(data, &state); err != nil || state.Schema != runtimeStateSchema ||
		state.NodeID != r.cfg.NodeID || state.Role != r.cfg.Role {
		return runtimeState{}, errors.New("RUNTIME_STATE_INVALID")
	}
	if state.Idempotency == nil {
		state.Idempotency = make(map[string]idempotencyItem)
	}
	if state.FinalResults == nil {
		state.FinalResults = make(map[string]protocol.TaskResult)
	}
	return state, nil
}

// Run heartbeats and drains tasks. Control-plane failures are logged and
// retried without touching an active data plane.
func (r *Runtime) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	r.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.cycle(ctx)
		}
	}
}

func (r *Runtime) cycle(ctx context.Context) {
	heartbeat := protocol.HeartbeatRequest{AgentVersion: r.cfg.AgentVersion, KernelVersion: KernelVersion}
	if err := heartbeat.Validate(); err != nil {
		r.logger.ErrorContext(ctx, "heartbeat invalid", "error_code", errorCode(err))
		return
	}
	if err := r.controller.Heartbeat(ctx, heartbeat); err != nil {
		r.logger.WarnContext(ctx, "heartbeat unavailable", "error_code", "CONTROL_PLANE_UNAVAILABLE")
	}
	if err := r.replayResults(ctx); err != nil {
		r.logger.WarnContext(ctx, "result replay unavailable", "error_code", errorCode(err))
		return
	}
	tasks, err := r.controller.Tasks(ctx)
	if err != nil {
		r.logger.WarnContext(ctx, "task poll unavailable", "error_code", "CONTROL_PLANE_UNAVAILABLE")
		return
	}
	for _, task := range tasks {
		if ctx.Err() != nil {
			return
		}
		var result protocol.TaskResult
		if task.Kind == protocol.KindConfigApply {
			if cached, ok := r.cachedTaskResult(task); ok {
				if reportErr := r.controller.Report(ctx, cached); reportErr != nil {
					if isAlreadyFinal(reportErr) {
						_ = r.removeOutbox(task.OperationID)
						continue
					}
					return
				}
				_ = r.removeOutbox(task.OperationID)
				continue
			}
			if reportErr := r.controller.Report(ctx, protocol.TaskResult{
				OperationID: task.OperationID, Status: "applying",
			}); reportErr != nil {
				if isAlreadyFinal(reportErr) {
					_ = r.removeOutbox(task.OperationID)
				}
				return
			}
			result = r.Execute(withApplyAcknowledged(ctx), task)
		} else {
			result = r.Execute(ctx, task)
		}
		if err := protocol.ValidateTaskResult(result); err != nil {
			result = failedResult(result, "RESULT_INVALID")
		}
		if err := r.controller.Report(ctx, result); err != nil {
			r.logger.WarnContext(ctx, "task report deferred",
				"operation_id", task.OperationID, "error_code", "RESULT_REPORT_UNAVAILABLE")
			if isAlreadyFinal(err) {
				_ = r.removeOutbox(task.OperationID)
				continue
			}
			return
		}
		if terminalTaskResult(result.Status) {
			_ = r.removeOutbox(task.OperationID)
		}
	}
}

func (r *Runtime) replayResults(ctx context.Context) error {
	state, err := r.loadStateForExecution()
	if err != nil {
		return err
	}
	for operationID, result := range state.FinalResults {
		if err = r.controller.Report(ctx, result); err != nil {
			if isAlreadyFinal(err) {
				r.logger.WarnContext(ctx, "report result already final",
					"operation_id", operationID, "error_code", "TASK_ALREADY_FINAL")
				delete(state.FinalResults, operationID)
				if err = r.saveState(&state); err != nil {
					return err
				}
				continue
			}
			return err
		}
		delete(state.FinalResults, operationID)
		if err = r.saveState(&state); err != nil {
			return err
		}
	}
	return nil
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

func (r *Runtime) removeOutbox(operationID string) error {
	state, err := r.loadStateForExecution()
	if err != nil {
		return err
	}
	delete(state.FinalResults, operationID)
	return r.saveState(&state)
}

func isAlreadyFinal(err error) bool {
	var clientErr *ClientError
	return errors.As(err, &clientErr) && clientErr.Code == "TASK_ALREADY_FINAL"
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

func stableCode(value string) string {
	if index := strings.IndexByte(value, ':'); index >= 0 {
		value = value[:index]
	}
	var b strings.Builder
	for _, char := range value {
		if char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' {
			b.WriteRune(char)
		}
	}
	code := b.String()
	if code == "" || code[0] < 'A' || code[0] > 'Z' {
		return "TASK_FAILED"
	}
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	return stableCode(err.Error())
}

func errorCodeOr(err error, fallback string) string {
	code := errorCode(err)
	if code == "" || code == "TASK_FAILED" {
		return fallback
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

func newRunLogger(writer io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey:
				return slog.Attr{}
			case slog.LevelKey:
				return slog.Attr{}
			}
			return attr
		},
	}))
}
