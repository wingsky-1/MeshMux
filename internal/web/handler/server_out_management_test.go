package handler

// The Out management API after the authorization migration (Task 5).
//
// The binding endpoints are gone and answer one stable "retired" code; delete and
// preview remain. The tests here pin the parts of the surface that survived plus
// the retirement contract, and the authorization semantics themselves live in
// store_out_acl_derivation_test.go (store level) and store_out_sync_test.go.

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler/node"
)

// outTransportConfigured reports whether one Out still has dial parameters.
// The former GetOutTransport convenience wrapper was removed in Task 6; the row
// itself is the fact these delete tests care about.
func outTransportConfigured(t *testing.T, s *store.Store, outID string) bool {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM out_settings WHERE node_id=?`, outID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count > 0
}

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

// createPairedWebNode drives the real pairing endpoint so a handler test uses a
// node with the same non-revoked identity the production flow issues.
func createPairedWebNode(t *testing.T, app *Server, role, name string, vless, ssh int) store.Node {
	t.Helper()
	node, code := createPendingNode(t, app, role, name, vless, ssh)
	w := pairJSON(t, app, node.ID, role, code)
	requireStatus(t, w, 200)
	clearNodeTasks(t, app, node.ID)
	paired, err := app.Store.GetNodeAt(node.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return paired
}

type outAuthorizationPreviewResponse struct {
	Mode                string   `json:"mode"`
	OutID               string   `json:"out_id"`
	LineIDs             []string `json:"line_ids"`
	Subscribers         []string `json:"subscribers"`
	Sources             []string `json:"sources"`
	AffectedLines       int      `json:"affected_lines"`
	AffectedPolicies    int      `json:"affected_policies"`
	AffectedSubscribers int      `json:"affected_subscribers"`
	EgressState         string   `json:"egress_state"`
	EgressCode          string   `json:"egress_code"`
	SyncState           string   `json:"sync_state"`
	SyncCode            string   `json:"sync_code"`
	OperationID         string   `json:"operation_id"`
}

// TestOutBindingEndpointsAreRetired pins the retirement contract: the two deleted
// routes answer one stable code that names the replacement action, so an old client
// learns where the action moved instead of reading a bare 404 as a typo.
func TestOutBindingEndpointsAreRetired(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-retired", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-retired", 9443, 2223)
	now := time.Now()
	storetest.ConfigureLine(t, app.Store, line.ID, "line-retired", now)
	storetest.ConfigureOut(t, app.Store, out.ID, now)

	// Session and CSRF boundaries are unchanged: the routes are still mutations, so
	// an anonymous or unmarked request never reaches the handler.
	anon := &browser{app: app}
	for _, path := range []string{"/nodes/out/bind", "/nodes/out/unbind"} {
		requireBindingError(t, anon.req("POST", path, url.Values{"out_id": {out.ID}, "line_id": {line.ID}}, nil), 401, "SESSION_INVALID")
		requireBindingError(t, b.req("POST", path, url.Values{"out_id": {out.ID}, "line_id": {line.ID}}, nil), 403, "CSRF_REJECTED")
	}

	for _, path := range []string{"/nodes/out/bind", "/nodes/out/unbind"} {
		w := b.post(path, url.Values{"out_id": {out.ID}, "line_id": {line.ID}})
		requireBindingError(t, w, 410, node.CodeBindingAPIRetired)
		var body struct {
			NextAction string `json:"next_action"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body.NextAction, "订阅") {
			t.Fatalf("%s next_action does not name the replacement: %q", path, body.NextAction)
		}
	}
	// The refused calls changed nothing: selecting an Out is still the
	// subscription's decision, and the retired route cannot write it.
	if subscribers, err := app.Store.OutAuthorizedSubscribers(out.ID); err != nil || len(subscribers) != 0 {
		t.Fatalf("a retired endpoint selected an out: %v err=%v", subscribers, err)
	}
}

// TestOutPreviewDerivesFromTheSubscription pins the surviving read-only preview:
// its answer is the subscription projection, so it can never describe an egress
// the wizard would not produce.
func TestOutPreviewDerivesFromTheSubscription(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	// No Out at all: the Hub previews the Out-free direct deployment.
	w := b.post("/nodes/out/preview", nil)
	requireStatus(t, w, 200)
	var preview outAuthorizationPreviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatalf("preview body: %v %.300s", err, w.Body.String())
	}
	if preview.Mode != store.OutPoolNoOutDirect || preview.AffectedLines != 0 || preview.OperationID == "" {
		t.Fatalf("empty preview wrong: %+v", preview)
	}

	line := createPairedWebNode(t, app, "edge", "line-preview", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-preview", 9443, 2223)
	now := time.Now()
	storetest.ConfigureLine(t, app.Store, line.ID, "line-preview", now)
	storetest.ConfigureOut(t, app.Store, out.ID, now)
	subscriber, _, err := app.Store.CreateSubscriber("alice", []string{line.ID}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Membership is the authorization (Ruling R10): the Out accepts the enrolled Line
	// whether or not any subscription selects it. No subscription exists yet, so the
	// preview reports a pool of one accepted Line and no affected policy.
	w = b.post("/nodes/out/preview", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Mode != store.OutPoolBound || len(preview.LineIDs) != 1 || preview.LineIDs[0] != line.ID {
		t.Fatalf("membership preview wrong: %+v", preview)
	}
	// The default fixture Line is addressed by a DNS name, which the Hub refuses to
	// authorize, so the projection reports the same refusal the publication would.
	if preview.EgressCode != store.CodeLineEgressUnverified || len(preview.Sources) != 0 {
		t.Fatalf("DNS-named line preview = %+v, want LINE_EGRESS_UNVERIFIED and no source", preview)
	}
	if len(preview.Subscribers) != 0 {
		t.Fatalf("preview reports subscribers nobody created: %v", preview.Subscribers)
	}

	// A single-Line projection narrows the answer to that Line and reports its real
	// state. The derivation still refuses the DNS-named address, so this is a refusal
	// rather than a fabricated pending transition.
	w = b.post("/nodes/out/preview", url.Values{"out_id": {out.ID}, "line_id": {line.ID}})
	requireStatus(t, w, 200)
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Mode != store.OutPoolLineDirect || len(preview.LineIDs) != 1 {
		t.Fatalf("single-line preview wrong: %+v", preview)
	}
	if preview.EgressCode != store.CodeLineEgressUnverified {
		t.Fatalf("single-line preview code = %q, want LINE_EGRESS_UNVERIFIED", preview.EgressCode)
	}

	// A subscribable Line address makes the derived set non-empty, and the affected
	// counts then describe the credentials membership covers.
	settings := storetest.TestLine(line.ID, "line-preview")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.Store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	w = b.post("/nodes/out/preview", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Mode != store.OutPoolBound || preview.AffectedLines != 1 ||
		preview.AffectedPolicies != 1 || preview.AffectedSubscribers != 1 {
		t.Fatalf("membership preview wrong: %+v", preview)
	}
	if len(preview.Sources) != 1 || preview.Sources[0] != "203.0.113.7/32" {
		t.Fatalf("membership sources = %v, want the line address", preview.Sources)
	}
	// The subscription does not authorize anything; it appears only as a used-by name
	// for the delete guard, while the source set stays the membership set.
	storetest.EnableOutForLine(t, app.Store, out.ID, line.ID, now)
	w = b.post("/nodes/out/preview", url.Values{"out_id": {out.ID}})
	requireStatus(t, w, 200)
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if len(preview.Sources) != 1 || preview.Sources[0] != "203.0.113.7/32" {
		t.Fatalf("selecting a subscriber changed the authorization: %v", preview.Sources)
	}
	if len(preview.Subscribers) != 1 || preview.Subscribers[0] != "alice" {
		t.Fatalf("selected preview subscribers = %v, want the subscription name", preview.Subscribers)
	}
	if strings.Contains(w.Body.String(), subscriber.ID) {
		t.Fatal("preview leaked a subscriber identity")
	}
	var credentialUUID string
	if err = app.Store.DB.QueryRow(`SELECT uuid FROM proxy_credentials WHERE subscriber_id=? AND node_id=?`,
		subscriber.ID, line.ID).Scan(&credentialUUID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), credentialUUID) {
		t.Fatal("preview leaked a credential UUID")
	}
	if strings.Contains(w.Body.String(), "line-preview") || strings.Contains(w.Body.String(), "out-preview") {
		t.Fatal("preview leaked a node display name")
	}
}

// TestOutDeleteManagementAPICleansTheRoute drives the real endpoint: a deleted Out
// publishes the explicit empty authorization, then the node row and its dial
// parameters are gone (Ruling R9: delete means delete).
func TestOutDeleteManagementAPICleansTheRoute(t *testing.T) {
	app, logs := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-del", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-del", 9443, 2223)
	now := time.Now()
	storetest.ConfigureLine(t, app.Store, line.ID, "line-del", now)
	storetest.ConfigureOut(t, app.Store, out.ID, now)
	storetest.EnableOutForLine(t, app.Store, out.ID, line.ID, now)
	storetest.SettleTasks(t, app.Store, out.ID)
	storetest.ConfirmChain(t, app.Store, out.ID, now)
	// The delete is refused while the subscription selects the Out, so the fixture
	// releases it first: that is the operator migration the refusal asks for.
	storetest.ClearOutForLine(t, app.Store, line.ID, now)
	storetest.SettleTasks(t, app.Store, out.ID)

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
	// Ruling R9: the delete is total. The node row, its dial parameters (address +
	// link key) and every row keyed to it are gone, so a later selection cannot
	// resurrect a stale endpoint.
	if _, err := app.Store.GetNodeAt(out.ID, now); err == nil {
		t.Fatal("the delete left the out node behind")
	}
	if outTransportConfigured(t, app.Store, out.ID) {
		t.Fatal("the delete left the dial parameters behind")
	}
	if storetest.TableExists(t, app.Store, "out_settings") {
		var settings int
		if err := app.Store.DB.QueryRow(`SELECT count(*) FROM out_settings WHERE node_id=?`, out.ID).Scan(&settings); err != nil {
			t.Fatal(err)
		}
		if settings != 0 {
			t.Fatalf("the delete left %d out_settings rows", settings)
		}
	}
	var tasks, candidates int
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=?`, out.ID).Scan(&tasks); err != nil {
		t.Fatal(err)
	}
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, out.ID).Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if tasks != 0 || candidates != 0 {
		t.Fatalf("the delete left tasks=%d candidates=%d behind", tasks, candidates)
	}
	// The cleanup is proven by the store-level test: the empty authorization is
	// published and read back inside the delete transaction, before the row goes, so
	// a host that applied it ends in default-deny. The chain rows themselves are
	// deleted with the node, which is why the endpoint cannot re-read them here.
	// The audit event carries the stable code only.
	if !strings.Contains(logs.String(), `"error_code":"OUT_DELETED"`) {
		t.Fatal("missing the OUT_DELETED audit event")
	}

	// A wrong role and an unknown node use the shared error contract.
	requireBindingError(t, b.post("/nodes/out/delete", url.Values{"out_id": {line.ID}}), 409, "OUT_ROLE_INVALID")
	requireBindingError(t, b.post("/nodes/out/delete", url.Values{"out_id": {strings.Repeat("d", 32)}}), 404, "OUT_NOT_FOUND")
	requireBindingError(t, b.post("/nodes/out/delete", url.Values{"out_id": {"nope"}}), 400, "OUT_BINDING_INVALID")
}

// TestOutDeleteRefusesALiveSubscriptionReference keeps the used-by guard: an Out a
// subscription still selects is a live egress, and the refusal names the
// subscription so the operator can migrate it first.
func TestOutDeleteRefusesALiveSubscriptionReference(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-live", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-live", 9443, 2223)
	now := time.Now()
	storetest.ConfigureLine(t, app.Store, line.ID, "line-live", now)
	storetest.ConfigureOut(t, app.Store, out.ID, now)
	storetest.EnableOutForLine(t, app.Store, out.ID, line.ID, now)
	storetest.SettleTasks(t, app.Store, out.ID)
	storetest.ConfirmChain(t, app.Store, out.ID, now)

	// The Out must be authorizable for the reference to be the reason the delete is
	// refused: a DNS-named Line never authorizes, and the delete would succeed.
	settings := storetest.TestLine(line.ID, "line-live")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.Store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	storetest.SettleTasks(t, app.Store, out.ID)

	w := b.post("/nodes/out/delete", url.Values{"out_id": {out.ID}})
	requireBindingError(t, w, 409, store.CodeOutReferenced)
	if !strings.Contains(w.Body.String(), "owner-") && !strings.Contains(w.Body.String(), "alice") {
		t.Fatalf("the refusal does not name the subscription: %.300s", w.Body.String())
	}
	// The Out is untouched: its transport, its ACK chain and its selection survive.
	if !outTransportConfigured(t, app.Store, out.ID) {
		t.Fatal("a refused delete removed the transport")
	}
	if subscribers, err := app.Store.OutAuthorizedSubscribers(out.ID); err != nil || len(subscribers) != 1 {
		t.Fatalf("a refused delete dropped the selection: %v err=%v", subscribers, err)
	}

	// Once the subscription releases it, the delete succeeds and — Ruling R9 — takes
	// the node and its dial parameters with it. Getting the Out back means enrolling
	// a node again, which is the point of "delete means delete".
	storetest.ClearOutForLine(t, app.Store, line.ID, now)
	// The release queued an empty-authorization chain; the delete refuses until the host
	// has confirmed it, so the fixture settles it the way a reachable Out would.
	storetest.SettleTasks(t, app.Store, out.ID)
	if err := app.Store.RetryOutSync(out.ID, now); err != nil {
		t.Fatalf("republish the empty authorization: %v", err)
	}
	storetest.SettleTasks(t, app.Store, out.ID)
	storetest.ConfirmChain(t, app.Store, out.ID, now)
	// A confirmed, non-empty membership still has to be emptied before the row can go,
	// so the delete publishes that empty guard and the host confirms it. Here the Line
	// carries a literal address, so the membership is a real source.
	w = b.post("/nodes/out/delete", url.Values{"out_id": {out.ID}})
	if w.Code == 202 {
		storetest.SettleTasks(t, app.Store, out.ID)
		if err := app.Store.RetryOutSync(out.ID, now); err != nil {
			t.Fatalf("republish the cleanup chain: %v", err)
		}
		storetest.SettleTasks(t, app.Store, out.ID)
		storetest.ConfirmChain(t, app.Store, out.ID, now)
		w = b.post("/nodes/out/delete", url.Values{"out_id": {out.ID}})
	}
	requireStatus(t, w, 200)
	if _, err := app.Store.GetNodeAt(out.ID, now); err == nil {
		t.Fatal("the delete kept the node row")
	}
	if outTransportConfigured(t, app.Store, out.ID) {
		t.Fatal("the delete kept the dial parameters")
	}
}

// TestOutDeleteRefusesWhenTheHostCannotDropItsGuard keeps the fail-closed half of
// Ruling R9: the delete publishes the empty guard first, so an Out that cannot
// receive it (offline) is REFUSED rather than deleted. Deleting anyway would leave an
// unreachable host accepting the old sources with no node row left to retry from.
func TestOutDeleteRefusesWhenTheHostCannotDropItsGuard(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	line := createPairedWebNode(t, app, "edge", "line-del-offline", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-del-offline", 9443, 2223)
	now := time.Now()
	storetest.ConfigureLine(t, app.Store, line.ID, "line-del-offline", now)
	storetest.ConfigureOut(t, app.Store, out.ID, now)
	// A subscribable address makes the Out authorize a real source, so the empty
	// authorization it has to publish on delete is a genuine change.
	settings := storetest.TestLine(line.ID, "line-del-offline")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.Store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	storetest.SettleTasks(t, app.Store, out.ID)
	storetest.ConfirmChain(t, app.Store, out.ID, now)
	// The Out stops reporting after it confirmed the last chain, so the empty
	// authorization cannot be delivered.
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out.ID); err != nil {
		t.Fatal(err)
	}

	w := b.post("/nodes/out/delete", url.Values{"out_id": {out.ID}})
	requireBindingError(t, w, 409, store.CodeOutSyncPending)
	// Nothing was destroyed: the node, its dial address and its authorization survive,
	// so the operator can bring the host back and retry.
	if _, err := app.Store.GetNodeAt(out.ID, now); err != nil {
		t.Fatalf("a refused delete removed the node: %v", err)
	}
	if !outTransportConfigured(t, app.Store, out.ID) {
		t.Fatal("a refused delete removed the dial parameters")
	}
	if allowed, err := app.Store.DeriveOutAllowlist(out.ID); err != nil || len(allowed) != 1 {
		t.Fatalf("a refused delete changed the authorization: %v err=%v", allowed, err)
	}
}
