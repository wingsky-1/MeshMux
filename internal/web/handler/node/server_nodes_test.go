package node_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

func TestNodeCreateAndListOverWeb(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)
	w := b.Post("/nodes", url.Values{"role": {"edge"}, "display_name": {"line-hk-01"}, "vless_port": {"8443"}, "ssh_port": {"2222"}})
	handlertest.RequireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "配对码已签发") || !strings.Contains(w.Body.String(), "配对码 15 分钟过期") {
		t.Fatalf("nodes page missing pairing disclosure: %.300s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "8443") && !strings.Contains(w.Body.String(), "VLESS") {
		t.Fatal("ports not disclosed")
	}
	w = b.Req("GET", "/api/nodes", nil, nil)
	handlertest.RequireStatus(t, w, 200)
	var listed struct {
		Nodes []store.Node `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed.Nodes) != 1 {
		t.Fatalf("api nodes list failed: %v %.200s", err, w.Body.String())
	}
	n := listed.Nodes[0]
	if n.ID == "" || n.Role != "edge" || n.DisplayName != "line-hk-01" || n.VlessPort != 8443 || n.SSHPort != 2222 || n.Status != "pending" {
		t.Fatalf("node record wrong: %+v", n)
	}
	// Bad inputs fail closed without creating a second node.
	w = b.Post("/nodes", url.Values{"role": {"hub"}, "display_name": {"x"}, "vless_port": {"8443"}, "ssh_port": {"2222"}})
	handlertest.RequireStatus(t, w, 400)
	w = b.Req("GET", "/api/nodes", nil, nil)
	var relist struct {
		Nodes []store.Node `json:"nodes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &relist)
	if len(relist.Nodes) != 1 {
		t.Fatal("invalid node was persisted")
	}
}

func TestPairingSingleUseExpiryAndRole(t *testing.T) {
	app, logs := handlertest.TestApp(t)
	node, code := handlertest.CreatePendingNode(t, app, "edge", "line-01", 8443, 2222)
	// Success binds Node ID + role and returns a one-time identity.
	w := handlertest.PairJSON(t, app, node.ID, "edge", code)
	handlertest.RequireStatus(t, w, 200)
	var paired map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &paired); err != nil || len(paired["identity_token"]) != 43 {
		t.Fatalf("pairing did not issue identity: %.200s", w.Body.String())
	}
	token := paired["identity_token"]
	handlertest.ClearNodeTasks(t, app, node.ID)
	if w.Header().Get("X-Operation-ID") == "" {
		t.Fatal("missing operation id")
	}
	// Replay with the same one-time code is rejected. The body cannot say the
	// code was already spent: expired, unknown and consumed all look identical,
	// so the response is not an oracle for a code's history.
	w = handlertest.PairJSON(t, app, node.ID, "edge", code)
	handlertest.RequireStatus(t, w, 401)
	if !strings.Contains(w.Body.String(), "PAIRING_INVALID") {
		t.Fatalf("replay not refused as a generic rejection: %.200s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "PAIRING_CONSUMED") || strings.Contains(w.Body.String(), "PAIRING_EXPIRED") {
		t.Fatalf("replay body disclosed the code's history: %.200s", w.Body.String())
	}
	// The operator can still tell the two apart from the log, keyed by the
	// operation_id the response carries.
	if !strings.Contains(logs.String(), `"error_code":"PAIRING_CONSUMED"`) {
		t.Fatal("consumed replay was not recorded for the operator")
	}
	// Wrong role is an explicit rejection, not a silent bind.
	node2, code2 := handlertest.CreatePendingNode(t, app, "out", "out-01", 9443, 2223)
	w = handlertest.PairJSON(t, app, node2.ID, "edge", code2)
	handlertest.RequireStatus(t, w, 403)
	if !strings.Contains(w.Body.String(), "ROLE_MISMATCH") {
		t.Fatalf("wrong role not rejected: %.200s", w.Body.String())
	}
	// Expired codes cannot be revived, and their refusal is the same neutral
	// 401 as an unknown code.
	node3, code3 := handlertest.CreatePendingNode(t, app, "edge", "line-03", 8444, 2224)
	if _, err := app.Store.DB.Exec(`UPDATE node_pairing SET expires=0 WHERE node_id=?`, node3.ID); err != nil {
		t.Fatal(err)
	}
	w = handlertest.PairJSON(t, app, node3.ID, "edge", code3)
	handlertest.RequireStatus(t, w, 401)
	if !strings.Contains(w.Body.String(), "PAIRING_INVALID") {
		t.Fatalf("expiry not enforced: %.200s", w.Body.String())
	}
	if !strings.Contains(logs.String(), `"error_code":"PAIRING_EXPIRED"`) {
		t.Fatal("expired attempt was not recorded for the operator")
	}
	// Forged Hub identity (unknown token) fails closed on every agent call.
	w = handlertest.BearerReq(app, "GET", "/api/agent/tasks", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil)
	handlertest.RequireStatus(t, w, 401)
	if !strings.Contains(w.Body.String(), "AGENT_UNAUTHORIZED") {
		t.Fatal("forged identity not rejected")
	}
	// The real identity polls empty tasks and heartbeats in PR-A.
	w = handlertest.BearerReq(app, "GET", "/api/agent/tasks", token, nil)
	handlertest.RequireStatus(t, w, 200)
	hb, _ := json.Marshal(map[string]string{"agent_version": "meshmux-agent test", "kernel_version": "6.1-test"})
	w = handlertest.BearerReq(app, "POST", "/api/agent/heartbeat", token, hb)
	handlertest.RequireStatus(t, w, 200)
	// Secrets never reach logs; only operation_id and stable codes do.
	for _, secret := range []string{code, token, code2, code3} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("pairing or identity secret leaked in logs")
		}
	}
}

func TestTaskAllowlistIdempotencyAndResults(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	node, code := handlertest.CreatePendingNode(t, app, "edge", "line-01", 8443, 2222)
	w := handlertest.PairJSON(t, app, node.ID, "edge", code)
	var paired map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &paired)
	token := paired["identity_token"]
	handlertest.ClearNodeTasks(t, app, node.ID)
	newTask := func(kind string, rev int64, idem string, params string) protocol.Task {
		return protocol.Task{Schema: protocol.Schema, Version: protocol.Version, OperationID: idem, Revision: rev, IdempotencyKey: idem, NodeID: node.ID, Kind: kind, Params: json.RawMessage(params)}
	}
	id1, _ := protocol.NewID()
	if err := app.Store.EnqueueTaskAt(newTask(protocol.KindHealthStatus, 1, id1, `{}`), app.Now()); err != nil {
		t.Fatalf("valid status task rejected: %v", err)
	}
	// Duplicate idempotency key is a rejection, not a second execution.
	if err := app.Store.EnqueueTaskAt(newTask(protocol.KindHealthStatus, 2, id1, `{}`), app.Now()); err == nil || !strings.Contains(err.Error(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("duplicate idempotency accepted: %v", err)
	}
	// Stale revision cannot rewind the per-node monotonic chain.
	id2, _ := protocol.NewID()
	if err := app.Store.EnqueueTaskAt(newTask(protocol.KindHealthStatus, 1, id2, `{}`), app.Now()); err == nil || !strings.Contains(err.Error(), "REVISION_STALE") {
		t.Fatalf("stale revision accepted: %v", err)
	}
	// Malicious payloads never reach storage.
	for _, tc := range []struct{ kind, params string }{
		{"exec.shell", `{"cmd":"id"}`},
		{protocol.KindConfigApply, `{"url":"https://evil.example.invalid/x"}`},
		{protocol.KindConfigApply, `{"path":"/etc/passwd"}`},
		{"upgrade.agent", `{}`},
		{"rollback.config", `{}`},
	} {
		id, _ := protocol.NewID()
		if err := app.Store.EnqueueTaskAt(newTask(tc.kind, 5, id, tc.params), app.Now()); err == nil {
			t.Fatalf("malicious task accepted: %+v", tc)
		}
	}
	// Agent polls the one pending task and reports idempotently.
	w = handlertest.BearerReq(app, "GET", "/api/agent/tasks", token, nil)
	handlertest.RequireStatus(t, w, 200)
	var tasks struct {
		Tasks []protocol.Task `json:"tasks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tasks); err != nil || len(tasks.Tasks) != 1 || tasks.Tasks[0].OperationID != id1 {
		t.Fatalf("pending tasks wrong: %.300s", w.Body.String())
	}
	res, _ := json.Marshal(protocol.TaskResult{OperationID: id1, Status: "healthy"})
	w = handlertest.BearerReq(app, "POST", "/api/agent/result", token, res)
	handlertest.RequireStatus(t, w, 200)
	// Repeating the same terminal state is a no-op for reconnects.
	w = handlertest.BearerReq(app, "POST", "/api/agent/result", token, res)
	handlertest.RequireStatus(t, w, 200)
	// Unknown operation IDs and terminal rewrites are rejected.
	unknown, _ := protocol.NewID()
	bad, _ := json.Marshal(protocol.TaskResult{OperationID: unknown, Status: "healthy"})
	w = handlertest.BearerReq(app, "POST", "/api/agent/result", token, bad)
	handlertest.RequireStatus(t, w, 404)
	rewrite, _ := json.Marshal(protocol.TaskResult{OperationID: id1, Status: "failed", ErrorCode: "PROBE_FAILED"})
	w = handlertest.BearerReq(app, "POST", "/api/agent/result", token, rewrite)
	handlertest.RequireStatus(t, w, 409)
}
