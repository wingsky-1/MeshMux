package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/node/render"
)

// errRuntimeStateTooLarge refuses a runtime state that does not fit the
// state size bound. The previous readable state stays untouched.
var errRuntimeStateTooLarge = errors.New("RUNTIME_STATE_TOO_LARGE")

type runtimeState struct {
	Schema           string   `json:"schema"`
	NodeID           string   `json:"node_id"`
	Role             Role     `json:"role"`
	Revision         int64    `json:"revision,omitempty"`
	LastTaskRevision int64    `json:"last_task_revision,omitempty"`
	Digest           string   `json:"digest,omitempty"`
	LKG              []byte   `json:"lkg,omitempty"`
	LKGDigest        string   `json:"lkg_digest,omitempty"`
	AllowedSources   []string `json:"allowed_sources,omitempty"`
	// AllowedSourcesRecorded kept the distinction between an applied empty
	// allowlist and no record at all. Both fields are retired with the Out
	// source allowlist: the Out admits by link key, so nothing reads them any
	// more. They stay in the struct so a state file written by an older Agent
	// still decodes strictly; the next save drops them.
	AllowedSourcesRecorded bool                           `json:"allowed_sources_recorded,omitempty"`
	Journal                *applyJournal                  `json:"journal,omitempty"`
	Idempotency            map[string]idempotencyItem     `json:"idempotency,omitempty"`
	FinalResults           map[string]protocol.TaskResult `json:"final_results,omitempty"`
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
	// AllowedSources is retired with the Out source allowlist and kept only so
	// a journal written by an older Agent still decodes. Nothing reads it.
	AllowedSources []string `json:"allowed_sources,omitempty"`
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

func (r *Runtime) loadOrInitializeState(ctx context.Context) (runtimeState, error) {
	path := rooted(r.root, RuntimeStatePath)
	data, _, err := readRuntimeStateFile(path)
	if os.IsNotExist(err) {
		state := emptyRuntimeState(r.cfg)
		if err := r.bootstrapLKG(ctx, &state); err != nil {
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

func (r *Runtime) bootstrapLKG(ctx context.Context, state *runtimeState) error {
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
	expected, err := render.CompileCandidate(document.Candidate())
	if err != nil || !bytes.Equal(configData, expected) {
		return errors.New("BOOTSTRAP_CONFIG_INVALID")
	}
	if err = writeStageAtomic(r.root, stagedConfigPath(r.root, document.Revision), configData); err != nil {
		return err
	}
	// No runtime state exists yet, so there is no trusted record of an applied
	// allowlist. The managed ACL file is deliberately not read here: a file
	// edited out of band would then authorize itself. The bootstrap readback
	// proves only the guard shape and both drops; the real authorization
	// arrives with the next Hub task and is recorded in state.json there.
	// The kernel may still be starting (systemd runs Agent and kernel
	// concurrently with no ordering between them). Poll for
	// startup-transient signals inside one bounded, cancellable budget;
	// anything deterministic fails fast so a broken data plane is never
	// mistaken for a slow one.
	readback, err := r.bootstrapReadback(ctx, document.Candidate(), sha256Hex(configData))
	if err != nil {
		return err
	}
	state.Revision = document.Revision
	state.Digest = sha256Hex(candidateData)
	state.LKG = append([]byte(nil), configData...)
	state.LKGDigest = readback.ConfigSHA256
	return nil
}

// bootstrapRetryInterval is the pause between startup readback attempts. The
// whole retry shares one bounded budget (BootstrapReadbackTimeout, agentLockTimeout
// by default), so the interval only decides how many chances fit inside it.
const bootstrapRetryInterval = 500 * time.Millisecond

// bootstrapReadback retries the first live readback while the failure still
// looks startup-transient. It is bounded and cancellable on purpose: the
// startup lock is held across it, so a slow kernel must cost the shared lock one
// agentLockTimeout budget at most (the same bound a contended poll cycle gets),
// and a stop request ends the wait at once instead of sleeping through it.
func (r *Runtime) bootstrapReadback(ctx context.Context, candidate Candidate, configHash string) (Readback, error) {
	budget := r.bootstrapTimeout
	if budget <= 0 {
		budget = agentLockTimeout
	}
	retryCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var lastTransient error
	for {
		readback, err := r.readbackFor(retryCtx, r.cfg.Role, candidate, configHash)
		if err == nil {
			return readback, nil
		}
		if ctx.Err() != nil {
			return Readback{}, errors.New("REQUEST_CANCELLED")
		}
		if !TransientReadback(err) {
			// The budget may have cut a live readback short (a killed systemctl
			// or ss). The last startup-transient signal is still the honest
			// verdict; a deterministic failure is reported as itself.
			if retryCtx.Err() != nil && lastTransient != nil {
				return Readback{}, lastTransient
			}
			return readback, err
		}
		lastTransient = err
		if retryCtx.Err() != nil {
			return Readback{}, lastTransient
		}
		timer := time.NewTimer(bootstrapRetryInterval)
		select {
		case <-retryCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return Readback{}, errors.New("REQUEST_CANCELLED")
			}
			return Readback{}, lastTransient
		case <-timer.C:
		}
	}
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
