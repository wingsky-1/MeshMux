package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

const (
	testPairingCode = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testIdentity    = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type testHub struct {
	t       *testing.T
	server  *httptest.Server
	mu      sync.Mutex
	pair    func(http.ResponseWriter, *http.Request)
	meta    func(http.ResponseWriter, *http.Request)
	config  func(http.ResponseWriter, *http.Request)
	heart   func(http.ResponseWriter, *http.Request)
	tasks   func(http.ResponseWriter, *http.Request)
	result  func(http.ResponseWriter, *http.Request)
	unknown func(http.ResponseWriter, *http.Request)
}

func newTestHub(t *testing.T) (*testHub, Config) {
	t.Helper()
	hub := &testHub{t: t}
	hub.server = httptest.NewTLSServer(http.HandlerFunc(hub.serveHTTP))
	t.Cleanup(hub.server.Close)
	config := validConfig()
	config.HubURL = hub.server.URL
	return hub, config
}

func (h *testHub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	pair, meta, config, heart := h.pair, h.meta, h.config, h.heart
	tasks, result, unknown := h.tasks, h.result, h.unknown
	h.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == agentPairPath && pair != nil:
		pair(w, r)
	case r.Method == http.MethodGet && r.URL.Path == agentMetadataPath && meta != nil:
		meta(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, agentConfigPrefix) && config != nil:
		config(w, r)
	case r.Method == http.MethodPost && r.URL.Path == agentHeartbeatPath && heart != nil:
		heart(w, r)
	case r.Method == http.MethodGet && r.URL.Path == agentTasksPath && tasks != nil:
		tasks(w, r)
	case r.Method == http.MethodPost && r.URL.Path == agentResultPath && result != nil:
		result(w, r)
	default:
		if unknown != nil {
			unknown(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func newTestClient(t *testing.T, hub *testHub, config Config, identity Identity) *Client {
	t.Helper()
	client, err := NewClient(config, identity, hub.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validIdentity(config Config) Identity {
	return Identity{NodeID: config.NodeID, IdentityToken: testIdentity}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Error(err)
	}
}

func writeRawJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := io.WriteString(w, body); err != nil {
		t.Error(err)
	}
}

func requireClientError(t *testing.T, err error, code string, status int) {
	t.Helper()
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("error = %v, want ClientError %s", err, code)
	}
	if clientErr.Code != code || clientErr.StatusCode != status {
		t.Fatalf("ClientError = %#v, want code=%s status=%d", clientErr, code, status)
	}
}

func candidateJSON(t *testing.T, config Config, revision int64) []byte {
	t.Helper()
	candidate := validCandidate()
	candidate.NodeID = config.NodeID
	candidate.Role = config.Role
	candidate.VLESSPort = config.VLESSPort
	candidate.Revision = revision
	body, err := json.Marshal(NewCandidateDocument(candidate))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func setCandidate(t *testing.T, w http.ResponseWriter, body []byte) {
	t.Helper()
	sum := sha256.Sum256(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(configSHA256Header, hex.EncodeToString(sum[:]))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		t.Error(err)
	}
}

func validTaskFor(config Config, revision int64) protocol.Task {
	return protocol.Task{
		Schema:         protocol.Schema,
		Version:        protocol.Version,
		OperationID:    strings.Repeat("d", 32),
		Revision:       revision,
		IdempotencyKey: strings.Repeat("e", 32),
		NodeID:         config.NodeID,
		Kind:           protocol.KindConfigStage,
		Params:         json.RawMessage(`{"revision":3}`),
	}
}

func TestClientPairPollReportAndReconnect(t *testing.T) {
	hub, config := newTestHub(t)
	var pairBody protocol.PairingRequest
	hub.pair = func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&pairBody); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("pairing request unexpectedly carried a bearer token")
		}
		writeJSON(t, w, http.StatusOK, map[string]string{
			"node_id": config.NodeID, "identity_token": testIdentity,
			"operation_id": "cccccccccccccccccccccc", "extra": "server-owned",
		})
	}
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentMetadataPath || r.Header.Get("Authorization") != "Bearer "+testIdentity {
			t.Errorf("metadata request path/auth mismatch")
		}
		writeJSON(t, w, http.StatusOK, Metadata{NodeID: config.NodeID, Role: config.Role, VLESSPort: config.VLESSPort, SSHPort: config.SSHPort})
	}
	hub.config = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentConfigPrefix+"9" {
			t.Errorf("candidate path = %q", r.URL.Path)
		}
		setCandidate(t, w, candidateJSON(t, config, 9))
	}
	hub.heart = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "paired", "operation_id": "cccccccccccccccccccccc"})
	}
	task := validTaskFor(config, 3)
	taskJSON, _ := json.Marshal(task)
	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"tasks":[`+string(taskJSON)+`],"operation_id":"cccccccccccccccccccccc"}`)
	}
	hub.result = func(w http.ResponseWriter, r *http.Request) {
		var got protocol.TaskResult
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		if got.OperationID != task.OperationID || got.Status != "applying" {
			t.Errorf("result body = %+v", got)
		}
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "recorded", "operation_id": "cccccccccccccccccccccc"})
	}

	client := newTestClient(t, hub, config, Identity{})
	pairingCode := testPairingCode
	identity, err := client.Pair(context.Background(), pairingCode)
	if err != nil || identity != validIdentity(config) {
		t.Fatalf("Pair = %+v, %v", identity, err)
	}
	if pairBody.NodeID != config.NodeID || pairBody.Role != string(config.Role) ||
		pairBody.PairingCode != testPairingCode || pairBody.AgentVersion != config.AgentVersion ||
		pairBody.KernelVersion != KernelVersion {
		t.Fatalf("pair body = %+v", pairBody)
	}

	metadata, err := client.Metadata(context.Background())
	if err != nil || metadata.ValidateFor(config) != nil {
		t.Fatalf("Metadata = %+v, %v", metadata, err)
	}
	candidate, err := client.Candidate(context.Background(), 9)
	if err != nil || candidate.Revision != 9 {
		t.Fatalf("Candidate = %+v, %v", candidate, err)
	}
	if err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{AgentVersion: config.AgentVersion, KernelVersion: KernelVersion}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	tasks, err := client.Tasks(context.Background())
	if err != nil || len(tasks) != 1 || tasks[0].OperationID != task.OperationID {
		t.Fatalf("Tasks = %+v, %v", tasks, err)
	}
	if err := client.Report(context.Background(), protocol.TaskResult{OperationID: task.OperationID, Status: "applying"}); err != nil {
		t.Fatalf("Report: %v", err)
	}

	// A new client can reconnect with the identity returned by Pair.
	reconnected := newTestClient(t, hub, config, identity)
	if _, err := reconnected.Tasks(context.Background()); err != nil {
		t.Fatalf("reconnect Tasks: %v", err)
	}
}

func TestClientTasksPreservesRawTaskDocument(t *testing.T) {
	hub, config := newTestHub(t)
	task := validTaskFor(config, 3)
	taskDocument, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	taskDocument = bytes.Replace(taskDocument, []byte(`"params":{"revision":3}`), []byte(`"params": {"revision":3}`), 1)
	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"tasks":[`+string(taskDocument)+`],"operation_id":"cccccccccccccccccccccc"}`)
	}

	client := newTestClient(t, hub, config, validIdentity(config))
	tasks, err := client.Tasks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || string(tasks[0].Params) != `{"revision":3}` {
		t.Fatalf("task params = %#v", tasks)
	}
	if _, err := json.Marshal(tasks); err != nil {
		t.Fatalf("decoded tasks cannot be re-encoded for strict Hub consumers: %v", err)
	}
}

func TestClientConstructorAndAuthenticationContract(t *testing.T) {
	hub, config := newTestHub(t)
	if _, err := NewClient(config, Identity{}, hub.server.Client()); err != nil {
		t.Fatalf("constructor with empty identity: %v", err)
	}
	client := newTestClient(t, hub, config, Identity{})
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("authenticated call without identity succeeded")
	} else {
		requireClientError(t, err, "IDENTITY_REQUIRED", 0)
	}
	if _, err := client.Pair(context.Background(), "short"); err == nil {
		t.Fatal("malformed pairing code accepted")
	} else {
		requireClientError(t, err, "PAIRING_CODE_INVALID", 0)
	}
	if _, err := client.Candidate(context.Background(), 0); err == nil {
		t.Fatal("zero candidate revision accepted")
	} else {
		requireClientError(t, err, "REVISION_INVALID", 0)
	}
	if err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{}); err == nil {
		t.Fatal("empty heartbeat accepted before auth")
	}
	if err := client.Report(context.Background(), protocol.TaskResult{}); err == nil {
		t.Fatal("empty result accepted")
	} else {
		requireClientError(t, err, "RESULT_INVALID", 0)
	}

	config.AgentVersion = ""
	if err := config.Validate(); err != nil {
		t.Fatalf("base validation must allow pre-stage empty AgentVersion: %v", err)
	}
	client = newTestClient(t, hub, config, Identity{})
	if _, err := client.Pair(context.Background(), testPairingCode); err == nil {
		t.Fatal("pairing with empty version succeeded")
	} else {
		requireClientError(t, err, "VERSION_INVALID", 0)
	}

	config.HubURL = "http://hub.example.invalid"
	if _, err := NewClient(config, validIdentity(validConfig()), hub.server.Client()); err == nil {
		t.Fatal("HTTP origin accepted")
	}
	config.HubURL = "https://hub.example.invalid/api"
	if _, err := NewClient(config, Identity{}, hub.server.Client()); err == nil {
		t.Fatal("Hub URL with a path accepted")
	}
	config = validConfig()
	badIdentity := validIdentity(validConfig())
	badIdentity.NodeID = strings.Repeat("f", 32)
	if _, err := NewClient(config, badIdentity, hub.server.Client()); err == nil {
		t.Fatal("identity for the wrong node accepted")
	}
}

func TestClientHonorsCancelledContextBeforeTransport(t *testing.T) {
	config := validConfig()
	transport := &recordingRoundTripper{}
	client, err := NewClient(config, validIdentity(config), &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Metadata(ctx); err == nil {
		t.Fatal("cancelled context accepted")
	} else {
		requireClientError(t, err, "REQUEST_CANCELLED", 0)
	}
	if transport.called {
		t.Fatal("cancelled request reached the transport")
	}
}

type recordingRoundTripper struct {
	called bool
}

func (r *recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.called = true
	return nil, context.Canceled
}

func TestClientRejectsRedirectWithoutForwardingCredentials(t *testing.T) {
	hub, config := newTestHub(t)
	var targetCalled bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		if r.Header.Get("Authorization") != "" {
			t.Error("redirect target saw Authorization")
		}
	}))
	defer target.Close()
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testIdentity {
			t.Error("origin request lacked bearer")
		}
		w.Header().Set("Location", target.URL+"/steal")
		w.WriteHeader(http.StatusFound)
	}
	client := newTestClient(t, hub, config, validIdentity(config))
	_, err := client.Metadata(context.Background())
	requireClientError(t, err, "REDIRECT_REJECTED", http.StatusFound)
	if targetCalled {
		t.Fatal("redirect target was contacted")
	}
}

func TestClientBoundsErrorBodies(t *testing.T) {
	hub, config := newTestHub(t)
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusUnauthorized,
			`{"error_code":"AGENT_UNAUTHORIZED","message":"`+strings.Repeat("secret", maxErrorBody)+`"}`)
	}
	client := newTestClient(t, hub, config, validIdentity(config))
	_, err := client.Metadata(context.Background())
	requireClientError(t, err, "AGENT_UNAUTHORIZED", http.StatusUnauthorized)
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), config.HubURL) {
		t.Fatal("bounded error body leaked sensitive data")
	}
}

func TestClientRejectsUntrustedOrMismatchedTLS(t *testing.T) {
	hub, config := newTestHub(t)
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, config.Metadata())
	}
	client := newTestClient(t, hub, config, validIdentity(config))
	if _, err := client.Metadata(context.Background()); err != nil {
		t.Fatalf("injected trusted test root with matching hostname should verify: %v", err)
	}
}

func TestClientRejectsWrongIdentityAndWrongPairNode(t *testing.T) {
	hub, config := newTestHub(t)
	wrong := validIdentity(config)
	wrong.NodeID = strings.Repeat("f", 32)

	called := false
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		called = true
	}
	client, err := NewClient(config, wrong, hub.server.Client())
	if err == nil {
		_ = client
		t.Fatal("constructor accepted an identity bound to another node")
	}
	requireClientError(t, err, "IDENTITY_INVALID", 0)
	if called {
		t.Fatal("wrong-node identity reached the Hub")
	}

	hub.pair = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"node_id": strings.Repeat("f", 32), "identity_token": testIdentity,
			"operation_id": "cccccccccccccccccccccc",
		})
	}
	client = newTestClient(t, hub, config, Identity{})
	if _, err := client.Pair(context.Background(), testPairingCode); err == nil {
		t.Fatal("pair response for another node accepted")
	} else {
		requireClientError(t, err, "IDENTITY_INVALID", http.StatusOK)
	}
}

func TestClientRejectsWrongRoleMetadataAndBadCandidate(t *testing.T) {
	hub, config := newTestHub(t)
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		m := config.Metadata()
		m.Role = RoleEdge
		writeJSON(t, w, http.StatusOK, m)
	}
	client := newTestClient(t, hub, config, validIdentity(config))
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("wrong-role metadata accepted")
	} else {
		requireClientError(t, err, "METADATA_INVALID", http.StatusOK)
	}

	hub.config = func(w http.ResponseWriter, r *http.Request) {
		body := candidateJSON(t, config, 9)
		w.Header().Set(configSHA256Header, strings.Repeat("0", 64))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}
	if _, err := client.Candidate(context.Background(), 9); err == nil {
		t.Fatal("candidate response with a forged hash succeeded")
	} else {
		requireClientError(t, err, "CANDIDATE_HASH_MISMATCH", http.StatusOK)
	}

	hub.config = func(w http.ResponseWriter, r *http.Request) {
		body := candidateJSON(t, config, 10)
		setCandidate(t, w, body)
	}
	if _, err := client.Candidate(context.Background(), 9); err == nil {
		t.Fatal("candidate revision mismatch accepted")
	} else {
		requireClientError(t, err, "CANDIDATE_REVISION_MISMATCH", http.StatusOK)
	}

	hub.config = func(w http.ResponseWriter, r *http.Request) {
		body := append(candidateJSON(t, config, 9), []byte(`{}`)...)
		setCandidate(t, w, body)
	}
	if _, err := client.Candidate(context.Background(), 9); err == nil {
		t.Fatal("candidate trailing JSON accepted")
	}
	hub.config = func(w http.ResponseWriter, r *http.Request) {
		body := candidateJSON(t, config, 9)
		body = append(body[:len(body)-1], []byte(`,"revision":9}`)...)
		setCandidate(t, w, body)
	}
	if _, err := client.Candidate(context.Background(), 9); err == nil {
		t.Fatal("candidate duplicate revision accepted")
	}

	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"node_id":"`+config.NodeID+`","role":"out","vless_port":8443,"ssh_port":2222,"extra":true}`)
	}
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("metadata with an unknown field accepted")
	} else {
		requireClientError(t, err, "SERVER_RESPONSE_INVALID", http.StatusOK)
	}
}

func TestClientRejectsMaliciousTasksAndBoundsBodies(t *testing.T) {
	hub, config := newTestHub(t)
	client := newTestClient(t, hub, config, validIdentity(config))
	task := validTaskFor(config, 3)
	task.Params = json.RawMessage(`{"url":"https://evil.example.invalid/payload"}`)
	taskJSON, _ := json.Marshal(task)
	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"tasks":[`+string(taskJSON)+`],"operation_id":"cccccccccccccccccccccc"}`)
	}
	if _, err := client.Tasks(context.Background()); err == nil {
		t.Fatal("task with URL parameter accepted")
	} else {
		requireClientError(t, err, "TASK_INVALID", http.StatusOK)
	}

	task = validTaskFor(config, 3)
	task.NodeID = strings.Repeat("f", 32)
	taskJSON, _ = json.Marshal(task)
	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"tasks":[`+string(taskJSON)+`],"operation_id":"cccccccccccccccccccccc"}`)
	}
	if _, err := client.Tasks(context.Background()); err == nil {
		t.Fatal("task for another node accepted")
	} else {
		requireClientError(t, err, "TASK_NODE_MISMATCH", http.StatusOK)
	}

	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tasks":[]`+strings.Repeat(" ", maxTasksBody)+`}`)
	}
	if _, err := client.Tasks(context.Background()); err == nil {
		t.Fatal("oversized task response accepted")
	} else {
		requireClientError(t, err, "RESPONSE_TOO_LARGE", http.StatusOK)
	}
	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"tasks":[],"operation_id":"cccccccccccccccccccccc","extra":true}`)
	}
	if tasks, err := client.Tasks(context.Background()); err != nil || len(tasks) != 0 {
		t.Fatalf("task wrapper with an unknown field was refused: %v, %v", tasks, err)
	}
	hub.tasks = func(w http.ResponseWriter, r *http.Request) {
		var taskList []string
		for index := 0; index <= maxTasks; index++ {
			taskList = append(taskList, `{}`)
		}
		writeRawJSON(t, w, http.StatusOK, `{"tasks":[`+strings.Join(taskList, ",")+`],"operation_id":"cccccccccccccccccccccc"}`)
	}
	if _, err := client.Tasks(context.Background()); err == nil {
		t.Fatal("task count over the fixed bound accepted")
	} else {
		requireClientError(t, err, "SERVER_RESPONSE_INVALID", http.StatusOK)
	}

	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusUnauthorized, `{"error_code":"AGENT_UNAUTHORIZED","message":"`+strings.Repeat("secret", 1000)+`"}`)
	}
	_, err := client.Metadata(context.Background())
	requireClientError(t, err, "AGENT_UNAUTHORIZED", http.StatusUnauthorized)
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("server response body leaked through ClientError")
	}
}

func TestClientErrorNeverContainsURLBodyOrIdentity(t *testing.T) {
	hub, config := newTestHub(t)
	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusBadRequest, `{"error_code":"METADATA_INVALID","message":"`+testIdentity+` at `+config.HubURL+`"}`)
	}
	client := newTestClient(t, hub, config, validIdentity(config))
	_, err := client.Metadata(context.Background())
	requireClientError(t, err, "METADATA_INVALID", http.StatusBadRequest)
	for _, secret := range []string{config.HubURL, testIdentity, "message"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error included forbidden data %q", secret)
		}
	}
}

func TestClientPairResponseAndCancellation(t *testing.T) {
	hub, config := newTestHub(t)
	hub.pair = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"node_id":"`+config.NodeID+`","identity_token":"`+testIdentity+`","operation_id":"cccccccccccccccccccccc","extra":true,"extra":false}`)
	}
	client := newTestClient(t, hub, config, Identity{})
	if _, err := client.Pair(context.Background(), testPairingCode); err == nil {
		t.Fatal("pair response with a duplicate extra field accepted")
	} else {
		requireClientError(t, err, "SERVER_RESPONSE_INVALID", http.StatusOK)
	}

	hub.pair = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"node_id":"short","identity_token":"`+testIdentity+`","operation_id":"cccccccccccccccccccccc"}`)
	}
	if _, err := client.Pair(context.Background(), testPairingCode); err == nil {
		t.Fatal("pair response with a malformed node ID accepted")
	} else {
		requireClientError(t, err, "IDENTITY_INVALID", http.StatusOK)
	}

	hub.meta = func(w http.ResponseWriter, r *http.Request) {
		writeRawJSON(t, w, http.StatusOK, `{"node_id":"`+config.NodeID+`","role":"out","vless_port":"8443","ssh_port":2222}`)
	}
	client = newTestClient(t, hub, config, validIdentity(config))
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("metadata with a string port accepted")
	} else {
		requireClientError(t, err, "SERVER_RESPONSE_INVALID", http.StatusOK)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Metadata(cancelled); err == nil {
		t.Fatal("cancelled context accepted")
	} else {
		requireClientError(t, err, "REQUEST_CANCELLED", 0)
	}
}
