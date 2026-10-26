package handler

import (
	"bytes"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

func pairedNode(t *testing.T, app *Server, name string) (store.Node, string) {
	t.Helper()
	node, code := createPendingNode(t, app, "edge", name, 8443, 2222)
	w := pairJSON(t, app, node.ID, "edge", code)
	requireStatus(t, w, 200)
	var issued struct {
		IdentityToken string `json:"identity_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || len(issued.IdentityToken) != 43 {
		t.Fatalf("pairing failed: %v %.200s", err, w.Body.String())
	}
	return node, issued.IdentityToken
}

func reportJSON(t *testing.T, app *Server, token string, res protocol.TaskResult) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(res)
	return bearerReq(app, "POST", "/api/agent/result", token, body)
}

func TestAgentEndpointsRequireSingleJSONObject(t *testing.T) {
	app, _ := testApp(t)
	node, code := createPendingNode(t, app, "edge", "strict-json", 8443, 2222)
	validPair, _ := json.Marshal(protocol.PairingRequest{NodeID: node.ID, Role: "edge", PairingCode: code, AgentVersion: "meshmux-agent test", KernelVersion: "6.1-test"})
	for _, body := range [][]byte{append(append([]byte(nil), validPair...), []byte(`{}`)...), append(append([]byte(nil), validPair[:len(validPair)-1]...), []byte(`,"extra":true}`)...)} {
		r := httptest.NewRequest("POST", testOrigin+"/api/agent/pair", bytes.NewReader(body))
		r.URL.Scheme, r.URL.Host = "", ""
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, r)
		requireStatus(t, w, 400)
		if !strings.Contains(w.Body.String(), "PAIRING_INVALID") {
			t.Fatalf("strict pairing rejection code missing: %.200s", w.Body.String())
		}
	}
	_, token := pairedNode(t, app, "strict-result")
	taskID, _ := protocol.NewID()
	if err := app.store.EnqueueTaskAt(protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: taskID, Revision: 1, IdempotencyKey: taskID, NodeID: node.ID, Kind: protocol.KindHealthStatus, Params: []byte(`{}`)}, app.now()); err != nil {
		t.Fatal(err)
	}
	res, _ := json.Marshal(protocol.TaskResult{OperationID: taskID, Status: "healthy"})
	w := bearerReq(app, "POST", "/api/agent/result", token, append(res, []byte(`{}`)...))
	requireStatus(t, w, 400)
	if !strings.Contains(w.Body.String(), "RESULT_INVALID") {
		t.Fatalf("strict result rejection code missing: %.200s", w.Body.String())
	}
}

func TestPairingFailureDoesNotConsumeCode(t *testing.T) {
	app, _ := testApp(t)
	node, code := createPendingNode(t, app, "edge", "pair-rollback", 8443, 2222)
	if _, err := app.store.DB.Exec(`CREATE TRIGGER pairing_issue_fail BEFORE INSERT ON node_identities BEGIN SELECT RAISE(ABORT, 'IDENTITY_ISSUE_FAILED'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.ConsumePairing(node.ID, "edge", code, "meshmux-agent test", "6.1-test", time.Now()); err == nil || !strings.Contains(err.Error(), "IDENTITY_ISSUE_FAILED") {
		t.Fatalf("identity issue failure not returned: %v", err)
	}
	var consumed int64
	var status string
	if err := app.store.DB.QueryRow(`SELECT consumed FROM node_pairing WHERE node_id=?`, node.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := app.store.DB.QueryRow(`SELECT status FROM nodes WHERE id=?`, node.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 || status != "pending" {
		t.Fatalf("pairing consumed or node finalized: consumed=%d status=%s", consumed, status)
	}
	var identities int
	if err := app.store.DB.QueryRow(`SELECT count(*) FROM node_identities`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if identities != 0 {
		t.Fatal("identity persisted after pairing failure")
	}
	if _, err := app.store.DB.Exec(`DROP TRIGGER pairing_issue_fail`); err != nil {
		t.Fatal(err)
	}
	w := pairJSON(t, app, node.ID, "edge", code)
	requireStatus(t, w, 200)
}

func TestEnqueueExactIdempotencyAndConflicts(t *testing.T) {
	app, _ := testApp(t)
	node, _ := createPendingNode(t, app, "edge", "queue-idem", 8443, 2222)
	id, _ := protocol.NewID()
	task := protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: id, Revision: 1, IdempotencyKey: id, NodeID: node.ID, Kind: protocol.KindHealthStatus, Params: []byte(`{}`)}
	if err := app.store.EnqueueTaskAt(task, app.now()); err != nil {
		t.Fatal(err)
	}
	if err := app.store.EnqueueTaskAt(task, app.now()); err != nil {
		t.Fatalf("exact replay must succeed: %v", err)
	}
	var count int
	if err := app.store.DB.QueryRow(`SELECT count(*) FROM agent_tasks`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("exact replay count=%d err=%v", count, err)
	}
	keyID, _ := protocol.NewID()
	otherOp, _ := protocol.NewID()
	keyed := task
	keyed.OperationID, keyed.IdempotencyKey, keyed.Revision = keyID, keyID, 2
	if err := app.store.EnqueueTaskAt(keyed, app.now()); err != nil {
		t.Fatal(err)
	}
	keyed.OperationID = otherOp
	if err := app.store.EnqueueTaskAt(keyed, app.now()); err == nil || !strings.Contains(err.Error(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("cross-operation exact idempotency key replay accepted: %v", err)
	}
	task.Revision = 2
	if err := app.store.EnqueueTaskAt(task, app.now()); err == nil || !strings.Contains(err.Error(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("operation content conflict accepted: %v", err)
	}
	other, _ := protocol.NewID()
	task.OperationID, task.Revision = other, 3
	if err := app.store.EnqueueTaskAt(task, app.now()); err == nil || !strings.Contains(err.Error(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("idempotency content conflict accepted: %v", err)
	}
}

func TestEnqueueConcurrentRevisionIsMonotonic(t *testing.T) {
	app, _ := testApp(t)
	node, _ := createPendingNode(t, app, "edge", "queue-race", 8443, 2222)
	const workers = 8
	tasks := make([]protocol.Task, workers)
	for i := range tasks {
		id, _ := protocol.NewID()
		tasks[i] = protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: id, Revision: 1, IdempotencyKey: id, NodeID: node.ID, Kind: protocol.KindHealthStatus, Params: []byte(`{}`)}
	}
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	now := app.now()
	for _, task := range tasks {
		wg.Go(func() {
			<-start
			errs <- app.store.EnqueueTaskAt(task, now)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	succeeded := 0
	for err := range errs {
		if err == nil {
			succeeded++
		} else if !strings.Contains(err.Error(), "REVISION_STALE") {
			t.Fatalf("unexpected concurrent enqueue error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("same revision inserted %d tasks", succeeded)
	}
	var count, distinct int
	if err := app.store.DB.QueryRow(`SELECT count(*), count(DISTINCT revision) FROM agent_tasks WHERE node_id=?`, node.ID).Scan(&count, &distinct); err != nil || count != 1 || distinct != 1 {
		t.Fatalf("revision invariant: count=%d distinct=%d err=%v", count, distinct, err)
	}
}

func TestAgentResultRejectsCrossNodeWrites(t *testing.T) {
	app, _ := testApp(t)
	nodeA, tokenA := pairedNode(t, app, "line-a")
	_, tokenB := pairedNode(t, app, "line-b")
	clearNodeTasks(t, app, nodeA.ID)
	task := protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Revision: 1, IdempotencyKey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NodeID: nodeA.ID, Kind: protocol.KindHealthStatus, Params: []byte("{}")}
	if err := app.store.EnqueueTaskAt(task, app.now()); err != nil {
		t.Fatal(err)
	}
	forge := protocol.TaskResult{OperationID: task.OperationID, Status: "healthy"}
	w := reportJSON(t, app, tokenB, forge)
	requireStatus(t, w, 404)
	if !strings.Contains(w.Body.String(), "TASK_NOT_FOUND") {
		t.Fatalf("cross-node result was not scoped: %.200s", w.Body.String())
	}
	var status string
	if err := app.store.DB.QueryRow(`SELECT status FROM agent_tasks WHERE operation_id=?`, task.OperationID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("cross-node result changed task: %s", status)
	}
	w = reportJSON(t, app, tokenA, protocol.TaskResult{OperationID: task.OperationID, Status: "applying"})
	requireStatus(t, w, 200)
	w = reportJSON(t, app, tokenA, forge)
	requireStatus(t, w, 200)
}

func TestAgentResultRejectsPendingAndIllegalTransitions(t *testing.T) {
	app, _ := testApp(t)
	node, token := pairedNode(t, app, "line-state")
	clearNodeTasks(t, app, node.ID)
	revision := int64(0)
	newTask := func(operation string) protocol.Task {
		revision++
		return protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: operation, Revision: revision, IdempotencyKey: operation, NodeID: node.ID, Kind: protocol.KindHealthStatus, Params: []byte("{}")}
	}
	backward, _ := protocol.NewID()
	if err := app.store.EnqueueTaskAt(newTask(backward), app.now()); err != nil {
		t.Fatal(err)
	}
	res := protocol.TaskResult{OperationID: backward, Status: "applying"}
	w := reportJSON(t, app, token, res)
	requireStatus(t, w, 200)
	res.Status = "pending"
	w = reportJSON(t, app, token, res)
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "TASK_STATE_INVALID") {
		t.Fatalf("pending regression accepted: %.200s", w.Body.String())
	}

	verify, _ := protocol.NewID()
	if err := app.store.EnqueueTaskAt(newTask(verify), app.now()); err != nil {
		t.Fatal(err)
	}
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: verify, Status: "applying"})
	requireStatus(t, w, 200)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: verify, Status: "verifying"})
	requireStatus(t, w, 200)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: verify, Status: "applying"})
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "TASK_STATE_INVALID") {
		t.Fatalf("backward nonterminal transition accepted: %.200s", w.Body.String())
	}

	partial, _ := protocol.NewID()
	if err := app.store.EnqueueTaskAt(newTask(partial), app.now()); err != nil {
		t.Fatal(err)
	}
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: partial, Status: "partial", ErrorCode: "APPLY_FAILED"})
	requireStatus(t, w, 200)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: partial, Status: "partial", ErrorCode: "APPLY_FAILED"})
	requireStatus(t, w, 200)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: partial, Status: "partial", ErrorCode: "OTHER_FAILED"})
	requireStatus(t, w, 409)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: partial, Status: "healthy"})
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "TASK_ALREADY_FINAL") {
		t.Fatalf("partial task was finalized: %.200s", w.Body.String())
	}

	rollback, _ := protocol.NewID()
	if err := app.store.EnqueueTaskAt(newTask(rollback), app.now()); err != nil {
		t.Fatal(err)
	}
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: rollback, Status: "applying"})
	requireStatus(t, w, 200)
	for _, res := range []protocol.TaskResult{{OperationID: rollback, Status: "applying"}, {OperationID: rollback, Status: "rolled_back"}} {
		w = reportJSON(t, app, token, res)
		requireStatus(t, w, 200)
	}

	nonterminal, _ := protocol.NewID()
	if err := app.store.EnqueueTaskAt(newTask(nonterminal), app.now()); err != nil {
		t.Fatal(err)
	}
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: nonterminal, Status: "applying"})
	requireStatus(t, w, 200)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: nonterminal, Status: "applying", ErrorCode: "APPLY_FAILED"})
	requireStatus(t, w, 409)
}

func TestPendingTasksIncludeRedeliveryStates(t *testing.T) {
	app, _ := testApp(t)
	node, token := pairedNode(t, app, "line-redeliver")
	clearNodeTasks(t, app, node.ID)
	statuses := []string{"pending", "applying", "verifying", "healthy"}
	for i, status := range statuses {
		id, _ := protocol.NewID()
		task := protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: id, Revision: int64(i + 1), IdempotencyKey: id, NodeID: node.ID, Kind: protocol.KindHealthStatus, Params: []byte(`{}`)}
		if err := app.store.EnqueueTaskAt(task, app.now()); err != nil {
			t.Fatal(err)
		}
		if status != "pending" {
			w := reportJSON(t, app, token, protocol.TaskResult{OperationID: id, Status: status})
			requireStatus(t, w, 200)
		}
	}
	tasks, err := app.store.PendingTasksAt(node.ID, 8, app.now())
	if err != nil || len(tasks) != 3 {
		t.Fatalf("pending task states = %d err=%v", len(tasks), err)
	}
}
