package web

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// requireBindingError asserts the shared management error contract:
// {error_code, operation_id, stage:"web", next_action}.
func requireBindingError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	requireStatus(t, w, status)
	var body struct {
		ErrorCode   string `json:"error_code"`
		OperationID string `json:"operation_id"`
		Stage       string `json:"stage"`
		NextAction  string `json:"next_action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v %.300s", err, w.Body.String())
	}
	if body.ErrorCode != code || body.Stage != "web" || body.OperationID == "" || body.NextAction == "" {
		t.Fatalf("error contract wrong: %+v", body)
	}
}

// createPairedWebNode drives the real pairing endpoint so a handler test uses
// a node with the same non-revoked identity the production flow issues.
func createPairedWebNode(t *testing.T, app *Server, role, name string, vless, ssh int) Node {
	t.Helper()
	node, code := createPendingNode(t, app, role, name, vless, ssh)
	w := pairJSON(t, app, node.ID, role, code)
	requireStatus(t, w, 200)
	clearNodeTasks(t, app, node.ID)
	paired, err := app.store.getNodeAt(node.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return paired
}

type outBindingAPIResponse struct {
	Status      string `json:"status"`
	OutID       string `json:"out_id"`
	LineID      string `json:"line_id"`
	Enabled     bool   `json:"enabled"`
	UpdatedAt   int64  `json:"updated_at"`
	OperationID string `json:"operation_id"`
}

type outPreviewAPIResponse struct {
	Mode                string `json:"mode"`
	OutID               string `json:"out_id"`
	LineID              string `json:"line_id"`
	Enabled             bool   `json:"enabled"`
	AffectedLines       int    `json:"affected_lines"`
	AffectedPolicies    int    `json:"affected_policies"`
	AffectedSubscribers int    `json:"affected_subscribers"`
	OperationID         string `json:"operation_id"`
}

func TestOutBindingManagementAPI(t *testing.T) {
	app, logs := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	// No Out at all: the Hub previews direct Line egress.
	w := b.post("/nodes/out/preview", nil)
	requireStatus(t, w, 200)
	var preview outPreviewAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatalf("preview body: %v %.300s", err, w.Body.String())
	}
	if preview.Mode != "no-out-direct" || preview.AffectedLines != 0 || preview.OperationID == "" {
		t.Fatalf("empty preview wrong: %+v", preview)
	}

	line := createPairedWebNode(t, app, "edge", "line-api", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-api", 9443, 2223)
	now := time.Now()
	configureLine(t, app.store, line.ID, "line-api", now)
	subscriber, _, err := app.store.createSubscriber("alice", []string{line.ID}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Bind enables the Out; the response is a flat readback of the stored row.
	w = b.post("/nodes/out/bind", url.Values{"out_id": {out.ID}, "line_id": {line.ID}})
	requireStatus(t, w, 200)
	var bound outBindingAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &bound); err != nil {
		t.Fatalf("bind body: %v %.300s", err, w.Body.String())
	}
	if bound.Status != "bound" || bound.OutID != out.ID || bound.LineID != line.ID ||
		!bound.Enabled || bound.UpdatedAt <= 0 || bound.OperationID == "" {
		t.Fatalf("bind response wrong: %+v", bound)
	}
	stored, err := app.store.GetOutBinding(out.ID)
	if err != nil || stored.LineID != line.ID || !stored.Enabled {
		t.Fatalf("stored binding wrong: %+v err=%v", stored, err)
	}

	// Preview reports the affected Line and its one active policy without
	// exposing the subscriber identity or credential.
	w = b.post("/nodes/out/preview", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatalf("preview body: %v %.300s", err, w.Body.String())
	}
	if preview.Mode != "out-bound" || preview.OutID != out.ID || preview.LineID != line.ID ||
		!preview.Enabled || preview.AffectedLines != 1 || preview.AffectedPolicies != 1 || preview.AffectedSubscribers != 1 {
		t.Fatalf("bound preview wrong: %+v", preview)
	}
	if strings.Contains(w.Body.String(), subscriber.ID) {
		t.Fatal("preview leaked a subscriber identity")
	}
	var credentialUUID string
	if err = app.store.db.QueryRow(`SELECT uuid FROM proxy_credentials WHERE subscriber_id=? AND node_id=?`,
		subscriber.ID, line.ID).Scan(&credentialUUID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), credentialUUID) {
		t.Fatal("preview leaked a credential UUID")
	}

	// Unbind keeps the audit row and returns the Out to direct egress.
	w = b.post("/nodes/out/unbind", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	var unbound outBindingAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &unbound); err != nil {
		t.Fatalf("unbind body: %v %.300s", err, w.Body.String())
	}
	if unbound.Status != "unbound" || unbound.OutID != out.ID || unbound.LineID != "" ||
		unbound.Enabled || unbound.OperationID == "" {
		t.Fatalf("unbind response wrong: %+v", unbound)
	}
	stored, err = app.store.GetOutBinding(out.ID)
	if err != nil || stored.LineID != "" || stored.Enabled {
		t.Fatalf("unbound row wrong: %+v err=%v", stored, err)
	}

	// The audit events are logged by stable code only.
	for _, code := range []string{"OUT_BOUND", "OUT_UNBOUND"} {
		if !strings.Contains(logs.String(), `"error_code":"`+code+`"`) {
			t.Fatalf("missing audit event %s", code)
		}
	}
}

func TestOutBindingManagementAPIRejections(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-reject", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-reject", 9443, 2223)
	unpairedLine, _ := createPendingNode(t, app, "edge", "line-unpaired", 8444, 2224)
	unpairedOut, _ := createPendingNode(t, app, "out", "out-unpaired", 9444, 2223)

	// Missing session and missing CSRF never reach the handler; both failures
	// still use the same JSON contract.
	anon := &browser{app: app}
	requireBindingError(t, anon.req("POST", "/nodes/out/bind", url.Values{"out_id": {out.ID}, "line_id": {line.ID}}, nil), 401, "SESSION_INVALID")
	requireBindingError(t, b.req("POST", "/nodes/out/bind", url.Values{"out_id": {out.ID}, "line_id": {line.ID}}, nil), 403, "CSRF_REJECTED")

	cases := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"unknown out", url.Values{"out_id": {strings.Repeat("a", 32)}, "line_id": {line.ID}}, 404, "OUT_NOT_FOUND"},
		{"unknown line", url.Values{"out_id": {out.ID}, "line_id": {strings.Repeat("b", 32)}}, 404, "LINE_NOT_FOUND"},
		{"edge as out", url.Values{"out_id": {line.ID}, "line_id": {line.ID}}, 409, "OUT_ROLE_INVALID"},
		{"out as line", url.Values{"out_id": {out.ID}, "line_id": {out.ID}}, 409, "LINE_ROLE_INVALID"},
		{"out unpaired", url.Values{"out_id": {unpairedOut.ID}, "line_id": {line.ID}}, 409, "OUT_NOT_AUTHORIZED"},
		{"line unpaired", url.Values{"out_id": {out.ID}, "line_id": {unpairedLine.ID}}, 409, "OUT_NOT_AUTHORIZED"},
		{"bad enabled", url.Values{"out_id": {out.ID}, "line_id": {line.ID}, "enabled": {"maybe"}}, 400, "OUT_BINDING_INVALID"},
		{"bad out id", url.Values{"out_id": {"out"}, "line_id": {line.ID}}, 400, "OUT_BINDING_INVALID"},
		{"missing line", url.Values{"out_id": {out.ID}}, 400, "OUT_BINDING_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireBindingError(t, b.post("/nodes/out/bind", tc.form), tc.status, tc.code)
		})
	}
	// Failures never create a live binding.
	var enabled int
	if err := app.store.db.QueryRow(`SELECT count(*) FROM out_bindings WHERE enabled=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("rejected binds created enabled rows: %d err=%v", enabled, err)
	}
	// A disabled bind is allowed for a role-correct, unpaired Out.
	w := b.post("/nodes/out/bind", url.Values{"out_id": {unpairedOut.ID}, "line_id": {line.ID}, "enabled": {"0"}})
	requireStatus(t, w, 200)
	stored, err := app.store.GetOutBinding(unpairedOut.ID)
	if err != nil || stored.Enabled || stored.LineID != line.ID {
		t.Fatalf("disabled bind wrong: %+v err=%v", stored, err)
	}

	// Unbind and preview reject the same invalid inputs.
	requireBindingError(t, b.post("/nodes/out/unbind", url.Values{"out_id": {line.ID}}), 409, "OUT_ROLE_INVALID")
	requireBindingError(t, b.post("/nodes/out/preview", url.Values{"out_id": {strings.Repeat("c", 32)}}), 404, "OUT_NOT_FOUND")
	requireBindingError(t, b.post("/nodes/out/preview", url.Values{"out_id": {out.ID}, "line_id": {out.ID}}), 409, "LINE_ROLE_INVALID")
}
