package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

var subscriberTokenPattern = regexp.MustCompile(`<pre class="sub-secret">([^<]+)</pre>`)

func require2xx(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code < 200 || w.Code > 299 {
		t.Fatalf("status %d want 2xx (operation_id %q)", w.Code, w.Header().Get("X-Operation-ID"))
	}
}

func TestSubscriberRoutesRequireAuthentication(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}

	w := b.req("GET", "/subscribers", nil, http.Header{"Accept": {"text/html"}})
	requireStatus(t, w, http.StatusUnauthorized)
	if !strings.Contains(w.Body.String(), "AUTH_REQUIRED") {
		t.Fatal("unauthenticated page did not require authentication")
	}

	w = b.req("POST", "/subscribers", url.Values{"csrf": {"x"}, "display_name": {"anonymous"}}, nil)
	requireStatus(t, w, http.StatusUnauthorized)
	if !strings.Contains(w.Body.String(), "SESSION_INVALID") {
		t.Fatal("unauthenticated mutation did not report SESSION_INVALID")
	}
	subs, err := app.Store.ListSubscribers()
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("unauthenticated request created %d subscribers", len(subs))
	}
}

func TestSubscriberMutationsRejectWrongCSRFAndOrigin(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	w := b.req("POST", "/subscribers", url.Values{"csrf": {"wrong"}, "display_name": {"mallory"}}, nil)
	requireStatus(t, w, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "CSRF_REJECTED") {
		t.Fatal("wrong CSRF was not rejected")
	}

	w = b.req("POST", "/subscribers", url.Values{"csrf": {b.csrf}, "display_name": {"mallory"}},
		http.Header{"Origin": {"https://evil.example.invalid"}})
	requireStatus(t, w, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "ORIGIN_REJECTED") {
		t.Fatal("wrong Origin was not rejected")
	}

	subs, err := app.Store.ListSubscribers()
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("rejected requests created %d subscribers", len(subs))
	}
}

func TestLineAndSubscriberCreationDiscloseSecretsOnlyOnce(t *testing.T) {
	app, logs := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	node, _ := createPendingNode(t, app, "edge", "line-hk-01", 8443, 2222)

	w := b.post("/lines", url.Values{
		"node_id": {node.ID}, "display_name": {"香港 01"}, "sort_order": {"1"},
		"server": {"line.example.invalid"}, "port": {"8443"},
		"server_name":      {"handshake.example.invalid"},
		"handshake_server": {"handshake.example.invalid"}, "handshake_port": {"443"},
	})
	require2xx(t, w)
	line, err := readStoredLine(t, app.Store, node.ID)
	if err != nil {
		t.Fatal("Line was not stored")
	}
	if line.Port != 8443 || line.Port != node.VlessPort {
		t.Fatalf("Line port = %d, node VLESS port = %d, want 8443", line.Port, node.VlessPort)
	}
	if line.PrivateKey == "" {
		t.Fatal("Line key was not generated")
	}
	linePage := w.Body.String()
	for _, key := range []string{line.PrivateKey, line.PublicKey} {
		if strings.Contains(linePage, key) {
			t.Fatal("Line key disclosed in HTML")
		}
	}

	w = b.post("/subscribers", url.Values{"display_name": {"alice"}, "line_" + node.ID: {"1"}})
	require2xx(t, w)
	createBody := w.Body.String()
	match := subscriberTokenPattern.FindStringSubmatch(createBody)
	if len(match) != 2 {
		t.Fatal("create response lacks the one-time token disclosure")
	}
	token := match[1]
	if err := subscription.ValidateToken(token); err != nil {
		t.Fatal("disclosed token is not canonical")
	}
	subs, err := app.Store.ListSubscribers()
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 {
		t.Fatalf("subscriber count = %d, want 1", len(subs))
	}
	creds, err := app.Store.ListSubscriberCredentials(subs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].NodeID != node.ID {
		t.Fatal("unique line_<node_id> checkbox did not select the Line")
	}

	page := b.req("GET", "/subscribers", nil, nil)
	requireStatus(t, page, http.StatusOK)
	api := b.req("GET", "/api/subscribers", nil, nil)
	requireStatus(t, api, http.StatusOK)
	for name, body := range map[string]string{"create": createBody, "page": page.Body.String(), "api": api.Body.String()} {
		for _, secret := range []string{creds[0].UUID, line.PrivateKey, line.PublicKey, line.ShortID} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s response disclosed a subscriber or Line secret", name)
			}
		}
	}
	for name, body := range map[string]string{"page": page.Body.String(), "api": api.Body.String()} {
		if strings.Contains(body, token) {
			t.Fatalf("%s re-disclosed the raw subscription token", name)
		}
	}
	for _, secret := range []string{token, creds[0].UUID, line.PrivateKey, line.PublicKey, line.ShortID} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("web log contains a subscriber or Line secret")
		}
	}
}

func TestSubscriberStateRejectsManualCompletion(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	node, _ := createPendingNode(t, app, "edge", "line-01", 8443, 2222)
	configureLine(t, app.Store, node.ID, "line-a", time.Now())

	w := b.post("/subscribers", url.Values{"display_name": {"alice"}, "line_" + node.ID: {"1"}})
	require2xx(t, w)
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscriber setup failed: %v", err)
	}
	id := subs[0].ID

	w = b.post("/subscribers/state", url.Values{"subscriber_id": {id}, "action": {"complete"}})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), "SUBSCRIBER_ACTION_INVALID") {
		t.Fatal("complete action was not rejected")
	}
	sub, err := app.Store.GetSubscriber(id)
	if err != nil || sub.State != subscription.StateActive {
		t.Fatalf("state = %q after rejected complete, want active (err %v)", sub.State, err)
	}

	w = b.post("/subscribers/state", url.Values{"subscriber_id": {id}, "action": {"delete"}})
	require2xx(t, w)
	sub, err = app.Store.GetSubscriber(id)
	if err != nil || sub.State != subscription.StateDeleting {
		t.Fatalf("state = %q after delete, want deleting (err %v)", sub.State, err)
	}

	w = b.post("/subscribers/state", url.Values{"subscriber_id": {id}, "action": {"complete"}})
	requireStatus(t, w, http.StatusBadRequest)
	sub, err = app.Store.GetSubscriber(id)
	if err != nil || sub.State != subscription.StateDeleting {
		t.Fatalf("manual complete changed deleting to %q (err %v)", sub.State, err)
	}
}

// TestSubscriberPageShowsServingDownloadOrigin pins the fix for a wrong-origin
// regression: the page used to render subscription addresses with the
// management origin even when downloads were served by a dedicated
// subscription host, whose management address answers 404. The view origin
// must follow the same serving origin the download routes use.
func TestSubscriberPageShowsServingDownloadOrigin(t *testing.T) {
	app, _ := subscriptionAppWithOrigin(t, testSubscriptionOrigin)
	view, err := app.subscriberServer.SubscriberViewModel()
	if err != nil {
		t.Fatal(err)
	}
	if view.Origin != testSubscriptionOrigin {
		t.Fatalf("page origin = %q, want dedicated %q", view.Origin, testSubscriptionOrigin)
	}

	management, _ := subscriptionAppWithOrigin(t, "")
	managementView, err := management.subscriberServer.SubscriberViewModel()
	if err != nil {
		t.Fatal(err)
	}
	if managementView.Origin != testOrigin {
		t.Fatalf("single-host page origin = %q, want management %q", managementView.Origin, testOrigin)
	}
}
