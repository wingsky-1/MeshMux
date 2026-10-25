package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
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

// TestLineSaveRepublishesBoundOut is the I1 regression: a Line transport change
// is also an Out authorization change, so saving the Line has to republish every
// Out that serves it.
//
// The decisive assertion is the *set*: the Out chain must carry the new address
// and must not carry the old one. A republish that merely enqueues another chain
// with the stale allowlist would leave the Out accepting a source the Hub no
// longer owns.
func TestLineSaveRepublishesBoundOut(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	now := time.Now()

	out := createPairedWebNode(t, app, "out", "out-line-save", 9443, 2223)
	line := createPairedWebNode(t, app, "edge", "line-line-save", 8443, 2222)
	configureOut(t, app.store, out.ID, now)
	// The Line starts at one documentation address and both nodes are online
	// with settled chains, so every later chain is attributable.
	lineSettings := testLine(line.ID, "line-line-save")
	lineSettings.Server = "203.0.113.7"
	lineSettings.ServerName = "line.example.invalid"
	if _, err := app.store.SetLine(lineSettings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, app.store, line.ID, now)
	markLineOnline(t, app.store, out.ID, now)
	for _, nodeID := range []string{out.ID, line.ID} {
		settleTasks(t, app.store, nodeID)
		confirmChain(t, app.store, nodeID, now)
	}
	if _, _, err := app.store.CreateSubscriber("alice", []string{line.ID}, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, app.store, line.ID)
	confirmChain(t, app.store, line.ID, now)

	if err := app.store.SetOutBindingAt(store.OutBinding{OutID: out.ID, LineID: line.ID, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, app.store, out.ID)
	confirmChain(t, app.store, out.ID, now)
	if allowed, err := app.store.DeriveOutAllowlist(out.ID); err != nil || len(allowed) != 1 || allowed[0] != "203.0.113.7/32" {
		t.Fatalf("allowlist before the save = %v err=%v", allowed, err)
	}
	outRevisionsBefore := candidateCount(t, app.store, out.ID)

	// The save changes the Line's server address, which is exactly the value the
	// Out allowlist is derived from.
	w := b.post("/lines", url.Values{
		"node_id": {line.ID}, "display_name": {"line-line-save"}, "sort_order": {"1"},
		"server": {"198.51.100.9"}, "port": {"8443"},
		"server_name":      {"line.example.invalid"},
		"handshake_server": {"handshake.example.invalid"}, "handshake_port": {"443"},
	})
	require2xx(t, w)

	// The Out derived a new authorization...
	if allowed, err := app.store.DeriveOutAllowlist(out.ID); err != nil || len(allowed) != 1 || allowed[0] != "198.51.100.9/32" {
		t.Fatalf("allowlist after the save = %v err=%v, want the new line address", allowed, err)
	}
	// ...and the save itself republished it, without a second trigger.
	if got := candidateCount(t, app.store, out.ID); got != outRevisionsBefore+1 {
		t.Fatalf("out revisions after the save = %d, want exactly one more than %d", got, outRevisionsBefore)
	}
	latest, err := app.store.LatestCandidate(out.ID)
	if err != nil {
		t.Fatal(err)
	}
	published, present, err := outReadbackAllowlist(app.store, out.ID, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("the republished out chain omitted allowed_sources")
	}
	if len(published) != 1 || published[0] != "198.51.100.9/32" {
		t.Fatalf("republished allowlist = %v, want only the new line address", published)
	}
	for _, stale := range []string{"203.0.113.7", "203.0.113.7/32"} {
		for _, entry := range published {
			if strings.Contains(entry, stale) {
				t.Fatalf("republished allowlist still accepts the retired source: %v", published)
			}
		}
	}
}

// TestLineSaveWithoutBindingKeepsOutFreeDeployment is the I1 guard rail: the new
// Out fan-out must not create an Out chain when no Out is bound.
func TestLineSaveWithoutBindingKeepsOutFreeDeployment(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	now := time.Now()

	out := createPairedWebNode(t, app, "out", "out-unbound", 9443, 2223)
	line := createPairedWebNode(t, app, "edge", "line-unbound", 8443, 2222)
	lineSettings := testLine(line.ID, "line-unbound")
	lineSettings.Server = "203.0.113.7"
	lineSettings.ServerName = "line.example.invalid"
	if _, err := app.store.SetLine(lineSettings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, app.store, line.ID, now)
	markLineOnline(t, app.store, out.ID, now)
	settleTasks(t, app.store, out.ID)
	confirmChain(t, app.store, out.ID, now)
	before := candidateCount(t, app.store, out.ID)

	w := b.post("/lines", url.Values{
		"node_id": {line.ID}, "display_name": {"line-unbound"}, "sort_order": {"1"},
		"server": {"198.51.100.9"}, "port": {"8443"},
		"server_name":      {"line.example.invalid"},
		"handshake_server": {"handshake.example.invalid"}, "handshake_port": {"443"},
	})
	require2xx(t, w)

	if got := candidateCount(t, app.store, out.ID); got != before {
		t.Fatalf("unbound out received %d revisions (was %d): the fan-out must only touch bound outs", got, before)
	}
	if allowed, err := app.store.DeriveOutAllowlist(out.ID); err != nil || len(allowed) != 0 {
		t.Fatalf("unbound out authorization = %v err=%v, want empty", allowed, err)
	}
}

// TestOutReadbackRetryPointerBoundaries is the I2 regression. It pins which
// states set the retry pointer, because an operator action is gated on it:
//
//   - a terminal failure is retry-pending;
//   - a transition in progress is NOT (its own chain still has to finish);
//   - a healthy pair is NOT;
//   - a direct egress is NOT (there is no Out path to retry).
//
// It also pins that the confirmed revision/digest are only reported when the
// node really confirmed that revision: they are the rollback target, so a
// fabricated one would point a rollback at a revision nobody applied.
func TestOutReadbackRetryPointerBoundaries(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	// Direct egress: nothing to retry.
	direct, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.RetryPending {
		t.Fatalf("direct egress reported retry_pending: %+v", direct)
	}

	if err := s.SetOutBindingAt(store.OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	// In flight: a chain exists and has not settled. Retry must stay false.
	inflight, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if inflight.FinalEgress != store.LineEgressVerifying {
		t.Fatalf("setup: in-flight readback = %+v, want verifying", inflight)
	}
	if inflight.RetryPending {
		t.Fatalf("verifying readback reported retry_pending: %+v", inflight)
	}

	// Terminal failure: retry is the only way forward, so the pointer is set and
	// the rollback target is still the last confirmed revision.
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_ACL_RULE_INVALID' WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	failed, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if failed.FinalEgress != store.LineEgressPartial {
		t.Fatalf("failed readback = %+v, want partial", failed)
	}
	if !failed.RetryPending {
		t.Fatalf("terminal failure did not set retry_pending: %+v", failed)
	}

	// A confirmed pair: healthy and not retryable, with a real rollback target.
	confirmChain(t, s, out, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	healthy, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.FinalEgress != store.LineEgressHealthy {
		t.Fatalf("setup: confirmed readback = %+v, want healthy", healthy)
	}
	if healthy.RetryPending {
		t.Fatalf("healthy readback reported retry_pending: %+v", healthy)
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
	unconfirmed, err := s.OutEgressReadback(line, now)
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
func TestRetryPointerIsLoggedForTheRetryAffordance(t *testing.T) {
	f := newPairedWebOutSyncApp(t)
	app := f.app
	now := time.Now()

	if err := app.store.SetOutBindingAt(store.OutBinding{OutID: f.outID, LineID: f.lineID, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	// Fail the Out chain, then heartbeat: the readback event must carry
	// retry_pending=true together with the stable failure code.
	if _, err := app.store.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_ACL_RULE_INVALID' WHERE node_id=?`, f.outID); err != nil {
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
	if !strings.Contains(failureEvent[0], `"allowlist_code":"OUT_ACL_RULE_INVALID"`) {
		t.Fatalf("the stable failure code was not emitted: %.600s", failureEvent[0])
	}

	// A converged pair emits retry_pending=false, so the flag is meaningful in
	// both directions and not a constant.
	confirmChain(t, app.store, f.outID, now)
	if err := prepareSubscriberSyncForLine(app.store, f.lineID, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, app.store, f.lineID, now)
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

// TestReissueDisablesOutAuthorization is the M2 regression. Re-pairing is
// deliberately NOT a retirement: the derivation already excludes a Line without
// a current identity, so an Out event during the re-pair window republishes an
// empty allowlist (fail-closed) and the Line's own post-re-pair event restores
// it. That decision was untested; a regression here would either keep a
// revoked source authorized or break every re-pair.
func TestReissueDisablesOutAuthorization(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.SetOutBindingAt(store.OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, s, out)
	confirmChain(t, s, out, now)
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 1 {
		t.Fatalf("allowlist before the reissue = %v err=%v", allowed, err)
	}

	// Re-pairing revokes the current identity. The Out must stop authorizing the
	// Line on its very next event, because the Hub can no longer vouch for the
	// source address.
	if _, err := s.ReissuePairing(line, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("allowlist after the reissue = %v err=%v, want empty (fail-closed)", allowed, err)
	}
	// An Out event in the window publishes that empty authorization...
	drainOut(t, s, out, now)
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := outReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("chain after the reissue = %v present=%v, want an explicit empty list", revoked, present)
	}
	// ...and the pair is not reported healthy while the source is unproven.
	state, _, err := lineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state == store.LineEgressHealthy {
		t.Fatalf("reissued line still reported a healthy out egress")
	}

	// Re-pairing restores the authorization: the Line event is what brings the
	// source back, not a manual store edit.
	code, err := s.ReissuePairing(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumePairing(line, "edge", code, "meshmux-agent test", "6.1-test", now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, s, line, now)
	settleTasks(t, s, out)
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("restoring the authorization failed: %v", err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 1 || allowed[0] != "203.0.113.7/32" {
		t.Fatalf("allowlist after re-pairing = %v err=%v, want the line address restored", allowed, err)
	}
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
	probeRouter.Post("/opaque/endpoint", jsonAPI(func(w http.ResponseWriter, r *http.Request) {
		app.fail(w, r, 400, "PROBE_JSON", "probe", "probe")
	}))
	probeRouter.Post("/api/opaque-page", func(w http.ResponseWriter, r *http.Request) {
		app.fail(w, r, 400, "PROBE_HTML", "probe", "probe")
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
