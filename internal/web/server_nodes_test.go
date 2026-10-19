package web

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/agent"
)

func createPendingNode(t *testing.T, app *Server, role, name string, vless, ssh int) (Node, string) {
	t.Helper()
	node, code, err := app.store.createNode(role, name, vless, ssh, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 43 {
		t.Fatal("pairing code must be 43-char secret")
	}
	return node, code
}

func pairJSON(t *testing.T, app *Server, nodeID, role, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"node_id": nodeID, "role": role, "pairing_code": code, "agent_version": "meshmux-agent test", "kernel_version": "6.1-test"})
	r := httptest.NewRequest("POST", testOrigin+"/api/agent/pair", bytes.NewReader(body))
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	return w
}

func bearerReq(app *Server, method, path, token string, body []byte) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, testOrigin+path, reader)
	r.URL.Scheme = ""
	r.URL.Host = ""
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	return w
}

func TestNodeCreateAndListOverWeb(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.post("/nodes", url.Values{"role": {"edge"}, "display_name": {"line-hk-01"}, "vless_port": {"8443"}, "ssh_port": {"2222"}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "配对码已签发") || !strings.Contains(w.Body.String(), "节点安装尚未开放") {
		t.Fatalf("nodes page missing pairing disclosure: %.300s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "8443") && !strings.Contains(w.Body.String(), "VLESS") {
		t.Fatal("ports not disclosed")
	}
	w = b.req("GET", "/api/nodes", nil, nil)
	requireStatus(t, w, 200)
	var listed struct {
		Nodes []Node `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed.Nodes) != 1 {
		t.Fatalf("api nodes list failed: %v %.200s", err, w.Body.String())
	}
	n := listed.Nodes[0]
	if n.ID == "" || n.Role != "edge" || n.DisplayName != "line-hk-01" || n.VlessPort != 8443 || n.SSHPort != 2222 || n.Status != "pending" {
		t.Fatalf("node record wrong: %+v", n)
	}
	// Bad inputs fail closed without creating a second node.
	w = b.post("/nodes", url.Values{"role": {"hub"}, "display_name": {"x"}, "vless_port": {"8443"}, "ssh_port": {"2222"}})
	requireStatus(t, w, 400)
	w = b.req("GET", "/api/nodes", nil, nil)
	var relist struct {
		Nodes []Node `json:"nodes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &relist)
	if len(relist.Nodes) != 1 {
		t.Fatal("invalid node was persisted")
	}
}

func TestPairingSingleUseExpiryAndRole(t *testing.T) {
	app, logs := testApp(t)
	node, code := createPendingNode(t, app, "edge", "line-01", 8443, 2222)
	// Success binds Node ID + role and returns a one-time identity.
	w := pairJSON(t, app, node.ID, "edge", code)
	requireStatus(t, w, 200)
	var paired map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &paired); err != nil || len(paired["identity_token"]) != 43 {
		t.Fatalf("pairing did not issue identity: %.200s", w.Body.String())
	}
	token := paired["identity_token"]
	if w.Header().Get("X-Operation-ID") == "" {
		t.Fatal("missing operation id")
	}
	// Replay with the same one-time code is rejected.
	w = pairJSON(t, app, node.ID, "edge", code)
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "PAIRING_CONSUMED") {
		t.Fatalf("replay not marked consumed: %.200s", w.Body.String())
	}
	// Wrong role is an explicit rejection, not a silent bind.
	node2, code2 := createPendingNode(t, app, "out", "out-01", 9443, 2223)
	w = pairJSON(t, app, node2.ID, "edge", code2)
	requireStatus(t, w, 403)
	if !strings.Contains(w.Body.String(), "ROLE_MISMATCH") {
		t.Fatalf("wrong role not rejected: %.200s", w.Body.String())
	}
	// Expired codes cannot be revived.
	node3, code3 := createPendingNode(t, app, "edge", "line-03", 8444, 2224)
	if _, err := app.store.db.Exec(`UPDATE node_pairing SET expires=0 WHERE node_id=?`, node3.ID); err != nil {
		t.Fatal(err)
	}
	w = pairJSON(t, app, node3.ID, "edge", code3)
	requireStatus(t, w, 410)
	if !strings.Contains(w.Body.String(), "PAIRING_EXPIRED") {
		t.Fatalf("expiry not enforced: %.200s", w.Body.String())
	}
	// Forged Hub identity (unknown token) fails closed on every agent call.
	w = bearerReq(app, "GET", "/api/agent/tasks", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil)
	requireStatus(t, w, 401)
	if !strings.Contains(w.Body.String(), "AGENT_UNAUTHORIZED") {
		t.Fatal("forged identity not rejected")
	}
	// The real identity polls empty tasks and heartbeats in PR-A.
	w = bearerReq(app, "GET", "/api/agent/tasks", token, nil)
	requireStatus(t, w, 200)
	hb, _ := json.Marshal(map[string]string{"agent_version": "meshmux-agent test", "kernel_version": "6.1-test"})
	w = bearerReq(app, "POST", "/api/agent/heartbeat", token, hb)
	requireStatus(t, w, 200)
	// Secrets never reach logs; only operation_id and stable codes do.
	for _, secret := range []string{code, token, code2, code3} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("pairing or identity secret leaked in logs")
		}
	}
}

func TestTaskAllowlistIdempotencyAndResults(t *testing.T) {
	app, _ := testApp(t)
	node, code := createPendingNode(t, app, "edge", "line-01", 8443, 2222)
	w := pairJSON(t, app, node.ID, "edge", code)
	var paired map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &paired)
	token := paired["identity_token"]
	newTask := func(kind string, rev int64, idem string, params string) agent.Task {
		return agent.Task{Schema: agent.Schema, Version: agent.Version, OperationID: idem, Revision: rev, IdempotencyKey: idem, NodeID: node.ID, Kind: kind, Params: json.RawMessage(params)}
	}
	id1, _ := agent.NewID()
	if err := app.store.enqueueTask(newTask(agent.KindHealthStatus, 1, id1, `{}`)); err != nil {
		t.Fatalf("valid status task rejected: %v", err)
	}
	// Duplicate idempotency key is a rejection, not a second execution.
	if err := app.store.enqueueTask(newTask(agent.KindHealthStatus, 2, id1, `{}`)); err == nil || !strings.Contains(err.Error(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("duplicate idempotency accepted: %v", err)
	}
	// Stale revision cannot rewind the per-node monotonic chain.
	id2, _ := agent.NewID()
	if err := app.store.enqueueTask(newTask(agent.KindHealthStatus, 1, id2, `{}`)); err == nil || !strings.Contains(err.Error(), "REVISION_STALE") {
		t.Fatalf("stale revision accepted: %v", err)
	}
	// Malicious payloads never reach storage.
	for _, tc := range []struct{ kind, params string }{
		{"exec.shell", `{"cmd":"id"}`},
		{agent.KindConfigApply, `{"url":"https://evil.example.invalid/x"}`},
		{agent.KindConfigApply, `{"path":"/etc/passwd"}`},
		{"upgrade.agent", `{}`},
		{"rollback.config", `{}`},
	} {
		id, _ := agent.NewID()
		if err := app.store.enqueueTask(newTask(tc.kind, 5, id, tc.params)); err == nil {
			t.Fatalf("malicious task accepted: %+v", tc)
		}
	}
	// Agent polls the one pending task and reports idempotently.
	w = bearerReq(app, "GET", "/api/agent/tasks", token, nil)
	requireStatus(t, w, 200)
	var tasks struct {
		Tasks []agent.Task `json:"tasks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tasks); err != nil || len(tasks.Tasks) != 1 || tasks.Tasks[0].OperationID != id1 {
		t.Fatalf("pending tasks wrong: %.300s", w.Body.String())
	}
	res, _ := json.Marshal(agent.TaskResult{OperationID: id1, Status: "healthy"})
	w = bearerReq(app, "POST", "/api/agent/result", token, res)
	requireStatus(t, w, 200)
	// Repeating the same terminal state is a no-op for reconnects.
	w = bearerReq(app, "POST", "/api/agent/result", token, res)
	requireStatus(t, w, 200)
	// Unknown operation IDs and terminal rewrites are rejected.
	unknown, _ := agent.NewID()
	bad, _ := json.Marshal(agent.TaskResult{OperationID: unknown, Status: "healthy"})
	w = bearerReq(app, "POST", "/api/agent/result", token, bad)
	requireStatus(t, w, 404)
	rewrite, _ := json.Marshal(agent.TaskResult{OperationID: id1, Status: "failed", ErrorCode: "PROBE_FAILED"})
	w = bearerReq(app, "POST", "/api/agent/result", token, rewrite)
	requireStatus(t, w, 409)
}
