package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
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
func createPairedWebNode(t *testing.T, app *Server, role, name string, vless, ssh int) store.Node {
	t.Helper()
	node, code := createPendingNode(t, app, role, name, vless, ssh)
	w := pairJSON(t, app, node.ID, role, code)
	requireStatus(t, w, 200)
	clearNodeTasks(t, app, node.ID)
	paired, err := app.store.GetNodeAt(node.ID, time.Now())
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
	subscriber, _, err := app.store.CreateSubscriber("alice", []string{line.ID}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Unbinding an Out that was never bound is a no-op: the Hub must stay at
	// no-out-direct instead of gaining a fabricated audit row.
	w = b.post("/nodes/out/unbind", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	var noop outBindingAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &noop); err != nil {
		t.Fatalf("no-op unbind body: %v %.300s", err, w.Body.String())
	}
	if noop.OutID != out.ID || noop.LineID != "" || noop.Enabled {
		t.Fatalf("no-op unbind response wrong: %+v", noop)
	}
	if _, err := app.store.GetOutBinding(out.ID); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("no-op unbind created a row: %v", err)
	}
	w = b.post("/nodes/out/preview", nil)
	requireStatus(t, w, 200)
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatalf("preview body: %v %.300s", err, w.Body.String())
	}
	if preview.Mode != "no-out-direct" {
		t.Fatalf("hub preview after no-op unbind = %s, want no-out-direct", preview.Mode)
	}

	// Bind enables the Out; the response is a flat readback of the stored row
	// and both readback timestamps come from the one request clock.
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
	if stored.UpdatedAt != bound.UpdatedAt {
		t.Fatalf("response UpdatedAt %d != stored %d (request used two clocks)", bound.UpdatedAt, stored.UpdatedAt)
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
	if err = app.store.DB.QueryRow(`SELECT uuid FROM proxy_credentials WHERE subscriber_id=? AND node_id=?`,
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

// TestOutDeleteManagementAPICleansTheRoute drives the real endpoint: a deleted
// Out leaves no route, publishes the explicit empty authorization and returns
// the operation id; an unreachable Out reports the pending cleanup instead of a
// fabricated success.
func TestOutDeleteManagementAPICleansTheRoute(t *testing.T) {
	app, logs := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-del", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-del", 9443, 2223)
	now := time.Now()
	configureLine(t, app.store, line.ID, "line-del", now)
	if err := app.store.SetOutBindingAt(store.OutBinding{OutID: out.ID, LineID: line.ID, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, app.store, out.ID)
	confirmChain(t, app.store, out.ID, now)

	// Missing session / CSRF never reach the handler.
	anon := &browser{app: app}
	requireBindingError(t, anon.req("POST", "/nodes/out/delete", url.Values{"out_id": {out.ID}}, nil), 401, "SESSION_INVALID")
	requireBindingError(t, b.req("POST", "/nodes/out/delete", url.Values{"out_id": {out.ID}}, nil), 403, "CSRF_REJECTED")

	w := b.post("/nodes/out/delete", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	var deleted struct {
		Status      string `json:"status"`
		OutID       string `json:"out_id"`
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &deleted); err != nil {
		t.Fatalf("delete body: %v %.300s", err, w.Body.String())
	}
	if deleted.Status != "deleted" || deleted.OutID != out.ID || deleted.OperationID == "" {
		t.Fatalf("delete response wrong: %+v", deleted)
	}
	if _, err := app.store.GetOutBinding(out.ID); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("binding after delete = %v, want none", err)
	}
	// The cleanup chain carries the explicit empty list.
	latest, err := app.store.LatestCandidate(out.ID)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, present, err := outReadbackAllowlist(app.store, out.ID, latest.Revision)
	if err != nil || !present || len(reclaimed) != 0 {
		t.Fatalf("cleanup chain = %v present=%v err=%v, want an explicit empty allowlist", reclaimed, present, err)
	}
	// The audit event carries the stable code only.
	if !strings.Contains(logs.String(), `"error_code":"OUT_DELETED"`) {
		t.Fatal("missing the OUT_DELETED audit event")
	}

	// A wrong role and an unknown node use the shared error contract.
	requireBindingError(t, b.post("/nodes/out/delete", url.Values{"out_id": {line.ID}}), 409, "OUT_ROLE_INVALID")
	requireBindingError(t, b.post("/nodes/out/delete", url.Values{"out_id": {strings.Repeat("d", 32)}}), 404, "OUT_NOT_FOUND")
	requireBindingError(t, b.post("/nodes/out/delete", url.Values{"out_id": {"nope"}}), 400, "OUT_BINDING_INVALID")
}

// TestOutDeleteReportsPendingCleanupWithoutClaimingSuccess pins the 202 shape:
// the route is gone, but the host cleanup is explicitly pending and names only
// stable codes.
func TestOutDeleteReportsPendingCleanupWithoutClaimingSuccess(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-del-pending", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-del-pending", 9443, 2223)
	now := time.Now()
	configureLine(t, app.store, line.ID, "line-del-pending", now)
	if err := app.store.SetOutBindingAt(store.OutBinding{OutID: out.ID, LineID: line.ID, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, app.store, out.ID)
	confirmChain(t, app.store, out.ID, now)
	// The Out stops reporting after it confirmed the last chain, so the cleanup
	// cannot be delivered.
	if _, err := app.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out.ID); err != nil {
		t.Fatal(err)
	}

	w := b.post("/nodes/out/delete", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 202)
	var pending struct {
		Status      string `json:"status"`
		ErrorCode   string `json:"error_code"`
		Detail      string `json:"detail"`
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
		t.Fatalf("pending body: %v %.300s", err, w.Body.String())
	}
	if pending.Status != "cleanup_pending" || pending.ErrorCode != store.CodeOutSyncPending ||
		!strings.Contains(pending.Detail, "OUT_OFFLINE") || pending.OperationID == "" {
		t.Fatalf("pending response wrong: %+v", pending)
	}
	// The detail is codes only: no SQL, no transport text, no identifiers.
	for _, field := range strings.Fields(pending.Detail) {
		if !store.SyncErrorCodePattern.MatchString(field) {
			t.Fatalf("pending detail field %q is not a stable code", field)
		}
	}
	if _, err := app.store.GetOutBinding(out.ID); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("route after pending delete = %v, want none", err)
	}
}

func TestOutBindingManagementAPIRejections(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-reject", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-reject", 9443, 2223)
	unpairedLine, _ := createPendingNode(t, app, "edge", "line-unpaired", 8443, 2224)
	unpairedOut, _ := createPendingNode(t, app, "out", "out-unpaired", 9444, 2223)
	// The paired Line has a stored transport; an unconfigured paired edge is
	// added separately so the enable gate is distinguishable from the
	// identity gate.
	configureLine(t, app.store, line.ID, "line-reject", time.Now())
	unconfiguredLine := createPairedWebNode(t, app, "edge", "line-no-transport", 8445, 2225)
	configureLine(t, app.store, unpairedLine.ID, "line-unpaired", time.Now())

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
		{"line unconfigured", url.Values{"out_id": {out.ID}, "line_id": {unconfiguredLine.ID}}, 409, "LINE_NOT_CONFIGURED"},
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
	if err := app.store.DB.QueryRow(`SELECT count(*) FROM out_bindings WHERE enabled=1`).Scan(&enabled); err != nil || enabled != 0 {
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
