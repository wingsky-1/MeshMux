package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// This file pins the four final-review findings of PR #8. Each test names the
// behaviour that was missing, so a regression cannot pass by compiling.

// TestOutReadbackRetryPointerBoundaries pins the retry pointer of the two
// independent projections after the client-chain rebuild:
//
//   - a direct Line egress has nothing to retry;
//   - a terminal Out chain failure sets retry_pending on the Out projection;
//   - the Line projection no longer waits for the Out: a confirmed Line inbound
//     is healthy and not retry-pending even while its selected Out chain failed;
//   - the confirmed revision/digest are the rollback target and are only
//     reported when the Line really confirmed that revision.
func TestOutReadbackRetryPointerBoundaries(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	// Direct egress: nothing to retry.
	direct, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.RetryPending {
		t.Fatalf("direct egress reported retry_pending: %+v", direct)
	}

	enableOutForLine(t, s, out, line, now)
	// Terminal Out failure: retry is the only way forward for the Out chain.
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_SYNC_FAILED' WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	failed, err := s.NodeCoordinationReadback(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if failed.FinalEgress != store.OutSyncPartial {
		t.Fatalf("failed out readback = %+v, want partial", failed)
	}
	if !failed.RetryPending {
		t.Fatalf("terminal out failure did not set retry_pending: %+v", failed)
	}

	// The Line projection is independent: confirm its inbound and it is
	// healthy even though the selected Out chain is still failed.
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	healthy, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.FinalEgress != store.LineEgressHealthy {
		t.Fatalf("line readback = %+v, want healthy independently of the out chain", healthy)
	}
	if healthy.RetryPending {
		t.Fatalf("healthy line readback reported retry_pending: %+v", healthy)
	}
	lineCandidate, err := s.LatestCandidate(line)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.ConfirmedRevision != lineCandidate.Revision || healthy.ConfirmedDigest != lineCandidate.ConfigSHA256 {
		t.Fatalf("confirmed pointer = %d/%s, want %d/%s", healthy.ConfirmedRevision, healthy.ConfirmedDigest,
			lineCandidate.Revision, lineCandidate.ConfigSHA256)
	}

	// The rollback pointer never claims a revision the node did not confirm.
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0 WHERE id=?`, line); err != nil {
		t.Fatal(err)
	}
	unconfirmed, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if unconfirmed.ConfirmedRevision != 0 || unconfirmed.ConfirmedDigest != "" {
		t.Fatalf("unconfirmed readback reported a rollback target: %+v", unconfirmed)
	}
}

// TestRetryPointerIsLoggedForTheRetryAffordance proves the pointer reaches the
// operator-facing event, which is the affordance the node retry route acts on.
// A field that is computed but never emitted cannot guide a retry.
//
// The fixture runs at Debug because the heartbeat's readback line is Debug: a
// 1s heartbeat cannot write an Info line per tick, so the same projection is
// only visible in a debug-level journal. The payload itself is unchanged.
func TestRetryPointerIsLoggedForTheRetryAffordance(t *testing.T) {
	f := newPairedWebOutSyncAppWithLevel(t, slog.LevelDebug)
	app := f.app
	now := time.Now()

	// The Out is a member and its guard is confirmed (Ruling R10: enrollment publishes
	// it), and the Line routes through it because the subscription selected it.
	app.Store.RepublishOutAuthorizations(now)
	settleTasks(t, app.Store, f.outID)
	confirmChain(t, app.Store, f.outID, now)
	enableOutForLine(t, app.Store, f.outID, f.lineID, now)
	if err := app.Store.PrepareSubscriberSync(f.subscriberIDForTest(t), now); err != nil {
		t.Fatalf("publish the line: %v", err)
	}
	settleTasks(t, app.Store, f.lineID)
	confirmChain(t, app.Store, f.lineID, now)
	// Fail the Out chain, then heartbeat: the readback event must carry
	// retry_pending=true together with the stable failure code.
	if _, err := app.Store.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_SYNC_FAILED' WHERE node_id=?`, f.outID); err != nil {
		t.Fatal(err)
	}
	w := heartbeatJSON(t, app, f.outToken)
	requireStatus(t, w, 200)

	failureEvent := outReadbackEvents(f.logsForTest())
	if len(failureEvent) != 1 {
		t.Fatalf("out_readback events after the failure = %d, want 1", len(failureEvent))
	}
	if !strings.Contains(failureEvent[0], `"retry_pending":true`) {
		t.Fatalf("retry_pending was not emitted for a retryable failure: %.600s", failureEvent[0])
	}
	if !strings.Contains(failureEvent[0], `"allowlist":"partial"`) {
		t.Fatalf("the failure state was not emitted: %.600s", failureEvent[0])
	}
	if !strings.Contains(failureEvent[0], `"allowlist_code":"OUT_SYNC_FAILED"`) {
		t.Fatalf("the stable failure code was not emitted: %.600s", failureEvent[0])
	}

	// A converged pair emits retry_pending=false, so the flag is meaningful in
	// both directions and not a constant.
	confirmChain(t, app.Store, f.outID, now)
	if err := prepareSubscriberSyncForLine(app.Store, f.lineID, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, app.Store, f.lineID, now)
	before := len(outReadbackEvents(f.logsForTest()))
	requireStatus(t, heartbeatJSON(t, app, f.lineToken), 200)
	events := outReadbackEvents(f.logsForTest())
	if len(events) != before+1 {
		t.Fatalf("out_readback events after the converged heartbeat = %d, want %d", len(events), before+1)
	}
	if strings.Contains(events[len(events)-1], `"retry_pending":true`) {
		t.Fatalf("a converged pair still reported retry_pending: %.600s", events[len(events)-1])
	}
	if !strings.Contains(events[len(events)-1], `"final_egress":"healthy"`) {
		t.Fatalf("a converged pair did not report a healthy egress: %.600s", events[len(events)-1])
	}
}

// outReadbackEvents returns the audit lines of the coordination readback, in
// order, so a test can assert one event at a time instead of the whole buffer.
func outReadbackEvents(logs string) []string {
	var events []string
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, `"msg":"out_readback"`) {
			events = append(events, line)
		}
	}
	return events
}

// TestJSONFailureBodyIsDeclaredByTheRoute is the M1 regression: the failure
// representation belongs to the route, not to a path prefix the error writer
// recognises.
//
// The decisive case is a JSON route whose URL does not look like an API: it must
// still answer JSON. And a page route whose URL happens to contain an API-ish
// segment must still answer HTML.
func TestJSONFailureBodyIsDeclaredByTheRoute(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	// A JSON management route under /nodes answers the JSON envelope.
	w := b.post("/nodes/out/preview", url.Values{"out_id": {"out"}})
	requireStatus(t, w, 400)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("out preview failure Content-Type = %q, want JSON", ct)
	}
	var envelope struct {
		ErrorCode   string `json:"error_code"`
		OperationID string `json:"operation_id"`
		Stage       string `json:"stage"`
		NextAction  string `json:"next_action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("out preview failure is not JSON: %v %.200s", err, w.Body.String())
	}
	if envelope.ErrorCode != "OUT_BINDING_INVALID" || envelope.Stage != "web" ||
		envelope.OperationID == "" || envelope.NextAction == "" {
		t.Fatalf("out preview failure envelope wrong: %+v", envelope)
	}

	// The writer itself must be path-independent. This is the decisive check:
	// a marked route whose URL is NOT in any JSON namespace still answers JSON,
	// and an unmarked route whose URL IS in a JSON namespace still answers HTML.
	// Without it, every real route coincidentally lives under /api/ or
	// /nodes/out/, so a reinstated path heuristic would go unnoticed.
	probeRouter := chi.NewRouter()
	probeRouter.Post("/opaque/endpoint", infra.JSONAPI(func(w http.ResponseWriter, r *http.Request) {
		app.Fail(w, r, 400, "PROBE_JSON", "probe", "probe")
	}))
	probeRouter.Post("/api/opaque-page", func(w http.ResponseWriter, r *http.Request) {
		app.Fail(w, r, 400, "PROBE_HTML", "probe", "probe")
	})

	jsonProbe := httptest.NewRecorder()
	probeRouter.ServeHTTP(jsonProbe, httptest.NewRequest("POST", testOrigin+"/opaque/endpoint", nil))
	if ct := jsonProbe.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("a marked route outside the JSON namespaces answered %q, want JSON: the writer still infers the shape from the path", ct)
	}
	if !strings.Contains(jsonProbe.Body.String(), "PROBE_JSON") {
		t.Fatalf("marked route body is not the JSON envelope: %.200s", jsonProbe.Body.String())
	}
	htmlProbe := httptest.NewRecorder()
	probeRouter.ServeHTTP(htmlProbe, httptest.NewRequest("POST", testOrigin+"/api/opaque-page", nil))
	if ct := htmlProbe.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("an unmarked route inside a JSON namespace answered %q, want HTML: the writer still infers the shape from the path", ct)
	}
	if strings.Contains(htmlProbe.Body.String(), `"error_code"`) {
		t.Fatalf("unmarked route emitted the JSON envelope: %.200s", htmlProbe.Body.String())
	}

	// An unmarked page route keeps the HTML error page even though another JSON
	// namespace exists. This is the direction that a path-prefix check used to
	// decide on its own.
	page := b.req("POST", "/subscribers", url.Values{"csrf": {b.csrf}, "display_name": {""}}, nil)
	requireStatus(t, page, 400)
	if ct := page.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("page failure Content-Type = %q, want HTML", ct)
	}
	if strings.Contains(page.Body.String(), `"error_code"`) {
		t.Fatalf("page failure leaked the JSON envelope: %.200s", page.Body.String())
	}

	// An unmatched path inside a declared JSON namespace keeps JSON, because the
	// fallback has no handler to declare anything.
	unknown := b.req("GET", "/api/nope", nil, nil)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown api path status = %d, want 404", unknown.Code)
	}
	if ct := unknown.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("unknown api path Content-Type = %q, want JSON", ct)
	}
	if !strings.Contains(unknown.Body.String(), "NOT_FOUND") {
		t.Fatalf("unknown api path body lacks the stable code: %.200s", unknown.Body.String())
	}
	// An unmatched page path keeps the HTML error page.
	missing := b.req("GET", "/no-such-page", nil, nil)
	requireStatus(t, missing, 404)
	if ct := missing.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("unknown page path Content-Type = %q, want HTML", ct)
	}
}
