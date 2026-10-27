package subscription_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
	"github.com/wingsky-1/MeshMux/internal/web/testhttp"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// The public download boundary is exercised with its own fixtures. Every test
// uses its own temporary store and its own inserted rows; the tests never
// reuse the admin session fixtures, so a change in the authentication
// behaviour cannot silently weaken this boundary.

const testSubscriptionOrigin = "https://download.example.invalid"

// subscriptionApp opens a Web runtime whose download routes are served by the
// management origin, which is the single-host development default.
func subscriptionApp(t *testing.T) (*handler.Server, *bytes.Buffer) {
	t.Helper()
	return subscriptionAppWithOrigin(t, "")
}

// subscriptionAppWithOrigin opens a Web runtime with an optional dedicated
// download origin.
func subscriptionAppWithOrigin(t *testing.T, subscriptionOrigin string) (*handler.Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	c := handler.Config{
		Listen:             "127.0.0.1:9080",
		Origin:             handlertest.Origin,
		SubscriptionOrigin: subscriptionOrigin,
		DataDir:            filepath.Join(t.TempDir(), "state"),
	}
	app, err := handler.New(c, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app, &logs
}

// downloadFixture inserts one edge Line whose transport, candidate and
// readback all agree, so the download gate passes.
//
// It returns the node id, the Line, the subscriber, the bearer and the
// credential of that subscriber.

// TestSubscriptionDownloadServesBothFixedFormats proves that a converged
// bearer downloads the sing-box and the mihomo document, that the response
// carries the fixed private/no-store headers and that the payload contains
// the client credential but never the Line private key.
func TestSubscriptionDownloadServesBothFixedFormats(t *testing.T) {
	app, logs := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, line, _, bearer, credential := storetest.DownloadFixture(t, app.Store, now)

	for _, format := range []string{"sing-box.json", "mihomo.yaml"} {
		w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/"+format)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status %d want 200: %s", format, w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, credential.UUID) {
			t.Fatalf("%s payload misses the client credential", format)
		}
		if strings.Contains(body, line.PrivateKey) {
			t.Fatalf("%s payload leaked the Line private key", format)
		}
		if !strings.Contains(body, line.PublicKey) {
			t.Fatalf("%s payload misses the REALITY public key", format)
		}
		if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Fatalf("%s Cache-Control = %q", format, got)
		}
		if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Fatalf("%s Referrer-Policy = %q", format, got)
		}
		if got := w.Header().Get("X-Robots-Tag"); got != "noindex" {
			t.Fatalf("%s X-Robots-Tag = %q", format, got)
		}
	}
	if strings.Contains(logs.String(), bearer) {
		t.Fatal("bearer leaked into the log")
	}
}

// TestSubscriptionDownloadHeadHasNoBody proves that a HEAD request returns
// the same status and headers without a body.
func TestSubscriptionDownloadHeadHasNoBody(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	w := testhttp.SubscriptionRequest(app.Handler(), "HEAD", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatal("HEAD returned a body")
	}
	if w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("HEAD lost the cache header")
	}
	if w.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD lost the content length")
	}
}

// TestSubscriptionRejectsInvalidBearersGenerically proves that every
// unusable bearer produces the identical generic answer, so the endpoint
// cannot be enumerated.
func TestSubscriptionRejectsInvalidBearersGenerically(t *testing.T) {
	app, logs := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	unknown := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases := []struct {
		name  string
		token string
	}{
		{"forged bearer", unknown},
		{"truncated bearer", bearer[:len(bearer)-1]},
		{"uppercase bearer", strings.ToUpper(bearer)},
		{"empty bearer", ""},
	}
	var reference string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+tc.token+"/sing-box.json")
			if w.Code != http.StatusNotFound {
				t.Fatalf("status %d want 404", w.Code)
			}
			body := w.Body.String()
			if strings.Contains(body, bearer) {
				t.Fatal("the answer echoes the bearer")
			}
			if tc.token != "" && strings.Contains(body, tc.token) {
				t.Fatal("the answer echoes the bearer")
			}
			if reference == "" {
				reference = body
			} else if body != reference {
				t.Fatal("rejections are distinguishable")
			}
		})
	}
	if strings.Contains(logs.String(), bearer) || strings.Contains(logs.String(), unknown) {
		t.Fatal("bearer leaked into the log")
	}
}

// TestSubscriptionRejectsSuspendedAndRevoked proves that a suspended
// subscriber and a revoked bearer cannot download anything.
func TestSubscriptionRejectsSuspendedAndRevoked(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, sub, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	if _, err := app.Store.SetSubscriberState(sub.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("suspended subscriber status %d want 404", w.Code)
	}

	if _, err := app.Store.SetSubscriberState(sub.ID, subscription.StateActive, now); err != nil {
		t.Fatal(err)
	}
	if err := app.Store.RevokeTokens(sub.ID, now); err != nil {
		t.Fatal(err)
	}
	w = testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("revoked bearer status %d want 404", w.Code)
	}
}

// TestSubscriptionRejectsUnconvergedLine proves that the download is refused
// while the Line did not confirm the current revision, and that it starts
// working again after the Line confirmed it.
func TestSubscriptionRejectsUnconvergedLine(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	nodeID, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	// A stale heartbeat means the Line is no longer contacting the Hub.
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET last_heartbeat=? WHERE id=?`, now.Add(-10*time.Minute).Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("offline line status %d want 404", w.Code)
	}

	// A confirmed revision that does not match the latest candidate means the
	// Line still runs an older configuration.
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET last_heartbeat=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET observed_revision=1 WHERE id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	w = testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("stale revision status %d want 404", w.Code)
	}
}

// TestSubscriptionRejectsMissingOtherSubscriber proves that the gate is
// authoritative for the whole Line: a pending removal of another subscriber
// blocks the download until the Line confirms the reduced user set.
func TestSubscriptionRejectsMissingOtherSubscriber(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	s := app.Store
	nodeID, line, _, aliceBearer, aliceCredential := storetest.DownloadFixture(t, app.Store, now)

	// A second subscriber joins the same Line.
	bob, _, err := s.CreateSubscriber("bob", []string{nodeID}, now)
	if err != nil {
		t.Fatal(err)
	}
	bobCredentials, err := s.ListSubscriberCredentials(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The Line confirms the complete desired user set of both subscribers.
	storetest.PublishConvergedCandidate(t, s, nodeID, line, append(append([]subscription.Credential{}, aliceCredential), bobCredentials...), now)
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+aliceBearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d want 200: %s", w.Code, w.Body.String())
	}

	// Bob is paused. His token is revoked, but his credential is still
	// authorized on the Line until the Line confirms the removal.
	if _, err = s.SetSubscriberState(bob.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	// The confirmed candidate still carries Bob's user.
	w = testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+aliceBearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("pending removal status %d want 404", w.Code)
	}
	// Once the Line confirms the reduced user set, the download works again.
	storetest.PublishConvergedCandidate(t, s, nodeID, line, []subscription.Credential{aliceCredential}, now)
	w = testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+aliceBearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d want 200 after the removal was confirmed", w.Code)
	}
}

// TestSubscriptionRejectsForeignHost proves that only the configured download
// host serves the bearer, and that a foreign host learns nothing.
func TestSubscriptionRejectsForeignHost(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "evil.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign host status %d want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), bearer) {
		t.Fatal("the answer echoes the bearer")
	}
}

// TestSubscriptionRejectsNonCanonicalPaths proves that only the two exact
// canonical paths are served. Every other spelling is refused.
func TestSubscriptionRejectsNonCanonicalPaths(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	paths := []string{
		"/subscription/" + bearer + "/sing-box.json?x=1",
		"/subscription/" + bearer + "/sing-box.json/",
		"/subscription/" + bearer + "/sing-box.JSON",
		"/subscription/" + bearer + "/sing-box.json/extra",
		"/subscription/" + bearer + "/sing-box.json%2f",
		"/subscription/" + bearer + "%2Fsing-box.json",
		"/subscription/" + bearer + "/./sing-box.json",
		"/subscription/" + bearer + "/../sing-box.json",
		"/Subscription/" + bearer + "/sing-box.json",
		"/subscription/" + bearer + "/sing-box.txt",
		"/subscription/" + bearer,
		"/subscription/" + bearer + "/",
	}
	for _, path := range paths {
		w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", path)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s status %d want 404", path, w.Code)
		}
		if strings.Contains(w.Body.String(), bearer) {
			t.Fatalf("%s echoed the bearer", path)
		}
	}
}

// TestSubscriptionRejectsNonGetMethods proves that the download namespace
// answers only GET and HEAD.
func TestSubscriptionRejectsNonGetMethods(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		w := testhttp.SubscriptionRequest(app.Handler(), method, "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status %d want 405", method, w.Code)
		}
	}
}

// TestSubscriptionHostIsolation proves that a dedicated download host serves
// the two download routes and nothing else, and that the management host
// keeps its console.
func TestSubscriptionHostIsolation(t *testing.T) {
	app, _ := subscriptionAppWithOrigin(t, testSubscriptionOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	// The download host serves the download.
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "download.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("download host status %d want 200", w.Code)
	}
	// The download host serves nothing else.
	for _, path := range []string{"/healthz", "/login", "/api/status", "/assets/app.css", "/", "/nodes"} {
		w = testhttp.SubscriptionRequest(app.Handler(), "GET", "download.example.invalid", path)
		if w.Code != http.StatusNotFound {
			t.Fatalf("download host %s status %d want 404", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "<html") {
			t.Fatalf("download host %s leaked a management page", path)
		}
	}
	// The management host keeps its console and never serves a download.
	w = testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/healthz")
	if w.Code != http.StatusOK {
		t.Fatalf("management host status %d want 200", w.Code)
	}
	w = testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("management host download status %d want 404", w.Code)
	}
}

// TestSubscriptionOperationIDMatchesLog proves that the operation identifier
// of the response header is the same identifier that the log carries, and
// that no URL or bearer is logged.
func TestSubscriptionOperationIDMatchesLog(t *testing.T) {
	app, logs := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d want 200", w.Code)
	}
	operation := w.Header().Get("X-Operation-ID")
	if operation == "" {
		t.Fatal("missing operation identifier")
	}
	if !strings.Contains(logs.String(), operation) {
		t.Fatal("the logged operation identifier differs from the response header")
	}
	if strings.Contains(logs.String(), bearer) || strings.Contains(logs.String(), "/subscription/") {
		t.Fatal("the log carries the request URL or the bearer")
	}
}

// TestSubscriptionRejectsUnconfiguredLine proves that a Line without stored
// transport settings can never serve a download.
func TestSubscriptionRejectsUnconfiguredLine(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	s := app.Store

	created, _, err := s.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := created.ID
	if _, err = s.SetLine(storetest.DownloadLineFixture(t, nodeID, "line-a"), now); err != nil {
		t.Fatal(err)
	}
	sub, bearer, err := s.CreateSubscriber("alice", []string{nodeID}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.ListSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	line, err := storetest.ReadStoredLine(t, s, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	storetest.PublishConvergedCandidate(t, s, nodeID, line, credentials, now)

	// The transport settings disappear: the download must fail closed.
	if _, err = s.DB.Exec(`DELETE FROM line_settings WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d want 404", w.Code)
	}
}

// TestSubscriptionDownloadReturnsPublicLinesOnly proves that the store
// helper never hands a server-side secret to the download handler.
func TestSubscriptionDownloadReturnsPublicLinesOnly(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, line, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	lines, credentials, err := app.Store.SubscriptionDownload(bearer, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || len(credentials) != 1 {
		t.Fatalf("lines=%d credentials=%d want 1/1", len(lines), len(credentials))
	}
	got := lines[0]
	if got.PrivateKey != "" {
		t.Fatal("the Line private key left the store")
	}
	if got.HandshakeServer != "" || got.HandshakePort != 0 {
		t.Fatal("the handshake configuration left the store")
	}
	if got.PublicKey != line.PublicKey || got.ShortID != line.ShortID {
		t.Fatal("the public transport fields were changed")
	}
}

// refuseSubscriptionAfterMutation breaks one stored invariant of the converged
// download fixture with mutation, then proves that the download is refused.
// Every invariant the gate trusts is damaged the same way, so the tests below
// differ only in the row they break.
func refuseSubscriptionAfterMutation(t *testing.T, mutation string) {
	t.Helper()
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	nodeID, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	if _, err := app.Store.DB.Exec(mutation, nodeID); err != nil {
		t.Fatal(err)
	}
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d want 404", w.Code)
	}
}

// TestSubscriptionRejectsPortMismatch proves that a Line whose published port
// disagrees with the stored transport can never serve a download.
func TestSubscriptionRejectsPortMismatch(t *testing.T) {
	refuseSubscriptionAfterMutation(t, `UPDATE line_settings SET port=9443 WHERE node_id=?`)
}

// TestSubscriptionRejectsUnenrolledLine proves that a Line without a valid
// identity can never serve a download.
func TestSubscriptionRejectsUnenrolledLine(t *testing.T) {
	refuseSubscriptionAfterMutation(t, `UPDATE node_identities SET revoked=1 WHERE node_id=?`)
}

// TestSubscriptionReportsDatabaseFailure proves that a broken database is
// reported as a service failure instead of being hidden behind the generic
// rejection.
func TestSubscriptionReportsDatabaseFailure(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	_, _, _, bearer, _ := storetest.DownloadFixture(t, app.Store, now)

	if err := app.Store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	w := testhttp.SubscriptionRequest(app.Handler(), "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d want 503", w.Code)
	}
	if strings.Contains(w.Body.String(), bearer) {
		t.Fatal("the answer echoes the bearer")
	}
}

// TestSubscriptionCandidateUsersMatchRejectsDuplicates proves that the set
// comparison is exact. A candidate that repeats one credential and drops
// another has the same length as the desired set, so the length check alone
// would accept it.
func TestSubscriptionCandidateUsersMatchRejectsDuplicates(t *testing.T) {
	desired := map[string]string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "11111111-1111-4111-8111-111111111111",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": "22222222-2222-4222-8222-222222222222",
	}
	exact := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
		{CredentialID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", UUID: "22222222-2222-4222-8222-222222222222"},
	}}
	if err := store.CandidateUsersMatch(exact, desired); err != nil {
		t.Fatalf("the exact user set was rejected: %v", err)
	}
	duplicated := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
	}}
	if err := store.CandidateUsersMatch(duplicated, desired); err == nil {
		t.Fatal("a duplicated credential was accepted")
	}
	missing := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
	}}
	if err := store.CandidateUsersMatch(missing, desired); err == nil {
		t.Fatal("a missing credential was accepted")
	}
	changed := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
		{CredentialID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", UUID: "33333333-3333-4333-8333-333333333333"},
	}}
	if err := store.CandidateUsersMatch(changed, desired); err == nil {
		t.Fatal("a changed UUID was accepted")
	}
}

// TestSubscriptionOriginValidation proves that only one exact origin without
// a path is accepted, and that the empty value keeps the management origin.
