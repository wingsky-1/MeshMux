package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/agent"
)

// testStateKey builds a deterministic 32-hex cache key for one cache entry.
func testStateKey(index int, salt byte) string {
	sum := sha256.Sum256([]byte{byte(index), byte(index >> 8), salt})
	return hex.EncodeToString(sum[:16])
}

// testStateUUID builds a deterministic, syntactically valid and unique UUIDv4
// for one of the 1024 candidate users.
func testStateUUID(index int) string {
	return fmt.Sprintf("%08x-0000-4%03x-8%03x-%012x", index, index%0x1000, index%0x1000, index)
}

// TestRuntimeStateTooLargeKeepsPreviousStateReadable pins the size boundary
// of the runtime state file. A state above the bound must be refused before
// the atomic replace, so the previous readable state stays on disk and the
// next start can still read it.
func TestRuntimeStateTooLargeKeepsPreviousStateReadable(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newTestRuntime(t, root, cfg, identity, runner, &runtimeTestController{candidate: testCandidate(7)})

	path := rooted(root, RuntimeStatePath)

	// Fill the state with the largest realistic cache entries: the protocol
	// allows a 512 byte detail per result.
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	filler := strings.Repeat("a", 512)
	for i := 0; i < maxIdempotency; i++ {
		key := testStateKey(i, 0x5a)
		state.Idempotency[key] = idempotencyItem{
			PayloadDigest: strings.Repeat("b", 64),
			TaskRevision:  int64(i + 1),
			OperationID:   key,
			Result:        agent.TaskResult{OperationID: key, Status: "failed", ErrorCode: "TEST_FAILURE", Detail: filler},
		}
	}
	if err := runtime.persistState(&state); err != nil {
		t.Fatalf("state below the bound was refused: %v", err)
	}

	// Capture the exact bytes of the last readable state. The refused write
	// must leave them untouched.
	accepted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) == 0 || len(accepted) > maxRuntimeStateSize {
		t.Fatalf("accepted state size = %d, want 1..%d", len(accepted), maxRuntimeStateSize)
	}

	// Now push the document above the bound and confirm the refusal.
	oversized := state
	oversized.Idempotency = make(map[string]idempotencyItem, len(state.Idempotency))
	for key, item := range state.Idempotency {
		oversized.Idempotency[key] = item
	}
	oversized.LKG = []byte(strings.Repeat("L", maxRuntimeStateSize+1))
	err = runtime.persistState(&oversized)
	if err == nil {
		t.Fatal("oversized runtime state was persisted")
	}
	if errorCode(err) != "RUNTIME_STATE_TOO_LARGE" {
		t.Fatalf("oversized state error = %v", err)
	}

	// The previous readable state must still be on disk byte for byte and
	// must still load.
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, accepted) {
		t.Fatalf("refused state changed the file on disk: %d bytes before, %d bytes after",
			len(accepted), len(current))
	}
	reloaded, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatalf("previous state is no longer readable: %v", err)
	}
	if reloaded.Schema != runtimeStateSchema || reloaded.NodeID != cfg.NodeID {
		t.Fatal("previous state lost its identity")
	}
	if len(reloaded.Idempotency) != len(state.Idempotency) {
		t.Fatalf("previous state lost entries: %d", len(reloaded.Idempotency))
	}
}

// TestRuntimeStateSizeBoundFitsFullCaches pins that the documented 4 MiB
// state bound actually fits the worst realistic runtime state: the LKG
// config, the apply journal with its base64 inflated candidate and config,
// and the full idempotency and final-result caches with 1024 entries each.
func TestRuntimeStateSizeBoundFitsFullCaches(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newTestRuntime(t, root, cfg, identity, runner, &runtimeTestController{candidate: testCandidate(7)})

	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}

	// A full v2 candidate with 1024 users: the journal stores it base64
	// inflated inside the JSON document.
	users := make([]VLESSUser, 0, maxCandidateUsers)
	for i := 0; i < maxCandidateUsers; i++ {
		users = append(users, VLESSUser{
			CredentialID: fmt.Sprintf("%032x", i+1),
			UUID:         testStateUUID(i),
		})
	}
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Users = users
	candidate.Reality = testReality(t)
	document := NewCandidateDocument(candidate)
	documentData, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	config, err := CompileCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	state.LKG = config
	state.LKGDigest = sha256Hex(config)
	state.Journal = &applyJournal{
		Schema:       journalTXNSchema,
		OperationID:  strings.Repeat("1", 32),
		Idempotency:  strings.Repeat("2", 32),
		Payload:      strings.Repeat("a", 64),
		TaskRevision: 12,
		Revision:     9,
		Digest:       sha256Hex(config),
		Candidate:    documentData,
		Config:       config,
		Reported:     true,
	}

	// Both caches are full. The 512 byte detail is the protocol maximum, so
	// this is the worst realistic cache size, not a semantic validation.
	for i := 0; i < maxIdempotency; i++ {
		key := testStateKey(i, 0x5a)
		state.Idempotency[key] = idempotencyItem{
			PayloadDigest: strings.Repeat("b", 64),
			TaskRevision:  int64(i + 1),
			OperationID:   key,
			Result: agent.TaskResult{
				OperationID: key, Status: "failed", ErrorCode: "TEST_FAILURE",
				Detail: strings.Repeat("c", 512),
			},
		}
		state.FinalResults[key] = agent.TaskResult{
			OperationID: key, Status: "failed", ErrorCode: "TEST_FAILURE",
			Detail: strings.Repeat("c", 512),
		}
	}
	if len(state.Idempotency) != maxIdempotency || len(state.FinalResults) != maxFinalCache {
		t.Fatalf("caches are not full: %d/%d", len(state.Idempotency), len(state.FinalResults))
	}

	encoded, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxRuntimeStateSize {
		t.Fatalf("full runtime state is %d bytes, above the %d byte bound", len(encoded), maxRuntimeStateSize)
	}
	// The worst realistic state is about 2.3 MiB, so the 4 MiB bound keeps a
	// wide margin for the state growth that a busy node can still reach.
	if len(encoded) > 3*maxRuntimeFileSize {
		t.Fatalf("full runtime state is %d bytes, above the %d byte margin", len(encoded), 3*maxRuntimeFileSize)
	}
	if err := runtime.persistState(&state); err != nil {
		t.Fatalf("full runtime state was refused: %v", err)
	}
	onDisk, err := os.ReadFile(rooted(root, RuntimeStatePath))
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) > maxRuntimeStateSize {
		t.Fatalf("persisted state is %d bytes, above the bound", len(onDisk))
	}
	// The written state must stay readable after the next start.
	if _, err := runtime.loadStateForExecution(); err != nil {
		t.Fatalf("full runtime state is no longer readable: %v", err)
	}
}

// TestRuntimeStateReadLimitKeepsSmallFilesTight pins that the larger state
// bound only applies to the runtime state. The identity, agent config,
// active candidate and staged revisions keep the 1 MiB runtime-file bound.
func TestRuntimeStateReadLimitKeepsSmallFilesTight(t *testing.T) {
	if maxRuntimeStateSize <= maxRuntimeFileSize {
		t.Fatalf("state bound %d must be above the file bound %d", maxRuntimeStateSize, maxRuntimeFileSize)
	}
	if maxRuntimeFileSize != 1<<20 {
		t.Fatalf("runtime file bound = %d, want 1 MiB", maxRuntimeFileSize)
	}
	if maxRuntimeStateSize != 4<<20 {
		t.Fatalf("runtime state bound = %d, want 4 MiB", maxRuntimeStateSize)
	}

	root := t.TempDir()
	if err := os.MkdirAll(rooted(root, agentDataDir), 0700); err != nil {
		t.Fatal(err)
	}
	small := rooted(root, IdentityPath)
	if err := os.WriteFile(small, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPrivateFile(small); err != nil {
		t.Fatalf("small private file was refused: %v", err)
	}

	// A file above the tight bound is refused by the small-file reader.
	oversized := make([]byte, maxRuntimeFileSize+1)
	if err := os.WriteFile(small, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPrivateFile(small); err == nil {
		t.Fatal("private file above the 1 MiB bound was read")
	}

	// The same bytes are accepted by the runtime state reader, which has its
	// own larger bound.
	statePath := rooted(root, RuntimeStatePath)
	if err := os.WriteFile(statePath, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRuntimeStateFile(statePath); err != nil {
		t.Fatalf("runtime state below the state bound was refused: %v", err)
	}
}

// TestRuntimeStateAboveBoundIsRefusedOnRead pins that a state file above the
// state bound is never parsed, so a corrupted or oversized state cannot
// brick the agent at startup.
func TestRuntimeStateAboveBoundIsRefusedOnRead(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newTestRuntime(t, root, cfg, identity, runner, &runtimeTestController{candidate: testCandidate(7)})

	path := rooted(root, RuntimeStatePath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	inflated := append(append([]byte(nil), body...), make([]byte, maxRuntimeStateSize+1)...)
	if err := os.WriteFile(path, inflated, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRuntimeStateFile(path); err == nil {
		t.Fatal("state above the bound was read")
	}
	if _, err := runtime.loadStateForExecution(); err == nil {
		t.Fatal("state above the bound was loaded")
	}
}
