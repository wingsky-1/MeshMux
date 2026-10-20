package web

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The public download boundary is exercised with its own fixtures. Every test
// uses its own temporary store and its own inserted rows; the tests never
// reuse the admin session fixtures, so a change in the authentication
// behaviour cannot silently weaken this boundary.

const testSubscriptionOrigin = "https://download.example.invalid"

// subscriptionApp opens a Web runtime whose download routes are served by the
// management origin, which is the single-host development default.
func subscriptionApp(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	return subscriptionAppWithOrigin(t, "")
}

// subscriptionAppWithOrigin opens a Web runtime with an optional dedicated
// download origin.
func subscriptionAppWithOrigin(t *testing.T, subscriptionOrigin string) (*Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	c := Config{
		Listen:             "127.0.0.1:9080",
		Origin:             testOrigin,
		SubscriptionOrigin: subscriptionOrigin,
		DataDir:            filepath.Join(t.TempDir(), "state"),
	}
	app, err := newServer(c, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app, &logs
}

// subscriptionRequest sends one raw request to the Web runtime. The target is
// written exactly as given, so percent escapes and dot segments survive.
func subscriptionRequest(app *Server, method, host, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	r.RemoteAddr = "127.0.0.1:40000"
	r.URL.Scheme = ""
	r.URL.Host = ""
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	return w
}

// downloadLineFixture returns a valid Line transport for one node. The port
// matches the VLESS port of the fixture nodes.
func downloadLineFixture(t *testing.T, nodeID, name string) subscription.Line {
	t.Helper()
	pair, err := subscription.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := subscription.NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	return subscription.Line{
		NodeID:          nodeID,
		DisplayName:     name,
		Server:          "line.example.invalid",
		Port:            8443,
		SortOrder:       1,
		ServerName:      "line.example.invalid",
		HandshakeServer: "handshake.example.invalid",
		HandshakePort:   443,
		PrivateKey:      pair.PrivateKey,
		PublicKey:       pair.PublicKey,
		ShortID:         shortID,
	}
}

// publishConvergedCandidate writes the next candidate revision of one Line
// and records the matching readback evidence on the node.
func publishConvergedCandidate(t *testing.T, s *store, nodeID string, line subscription.Line, credentials []subscription.Credential, now time.Time) {
	t.Helper()
	users := make([]node.VLESSUser, 0, len(credentials))
	for _, credential := range credentials {
		users = append(users, node.VLESSUser{CredentialID: credential.ID, UUID: credential.UUID})
	}
	reality := &node.RealityConfig{
		ServerName:      line.ServerName,
		HandshakeServer: line.HandshakeServer,
		HandshakePort:   line.HandshakePort,
		PrivateKey:      line.PrivateKey,
		ShortID:         line.ShortID,
	}
	var revision int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	candidate := node.Candidate{
		NodeID:        nodeID,
		Role:          node.RoleEdge,
		Revision:      revision,
		VLESSPort:     8443,
		KernelVersion: node.KernelVersion,
		Users:         users,
		Reality:       reality,
	}
	document, err := json.Marshal(node.NewCandidateDocument(candidate))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := candidateSHA256(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO node_candidates(node_id, revision, candidate_json, config_sha256, created_at) VALUES(?,?,?,?,?)`,
		nodeID, candidate.Revision, document, digest, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE nodes SET status='paired', last_heartbeat=?, observed_revision=?, observed_config_sha256=?,
	 observed_at=?, updated_at=? WHERE id=?`, now.Unix(), candidate.Revision, digest, now.Unix(), now.Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
}

// enrollNodeIdentity records a valid, unrevoked Agent identity for one node.
// A Line without an identity is not enrolled and can never serve a
// credential.
func enrollNodeIdentity(t *testing.T, s *store, nodeID string, now time.Time) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`,
		nodeID, tokenHash(randomToken()), now.Unix()); err != nil {
		t.Fatal(err)
	}
}

// downloadFixture inserts one edge Line whose transport, candidate and
// readback all agree, so the download gate passes.
//
// It returns the node id, the Line, the subscriber, the bearer and the
// credential of that subscriber.
func downloadFixture(t *testing.T, app *Server, now time.Time) (string, subscription.Line, subscription.Subscriber, string, subscription.Credential) {
	t.Helper()
	s := app.store
	created, _, err := s.createNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := created.ID
	enrollNodeIdentity(t, s, nodeID, now)
	line, err := s.setLine(downloadLineFixture(t, nodeID, "line-a"), now)
	if err != nil {
		t.Fatal(err)
	}
	sub, bearer, err := s.createSubscriber("alice", []string{nodeID}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("expected one credential, got %d", len(credentials))
	}
	publishConvergedCandidate(t, s, nodeID, line, credentials, now)
	return nodeID, line, sub, bearer, credentials[0]
}

// TestSubscriptionDownloadServesBothFixedFormats proves that a converged
// bearer downloads the sing-box and the mihomo document, that the response
// carries the fixed private/no-store headers and that the payload contains
// the client credential but never the Line private key.
func TestSubscriptionDownloadServesBothFixedFormats(t *testing.T) {
	app, logs := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	_, line, _, bearer, credential := downloadFixture(t, app, now)

	for _, format := range []string{"sing-box.json", "mihomo.yaml"} {
		w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/"+format)
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
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

	w := subscriptionRequest(app, "HEAD", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

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
			w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+tc.token+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	_, _, sub, bearer, _ := downloadFixture(t, app, now)

	if _, err := app.store.setSubscriberState(sub.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("suspended subscriber status %d want 404", w.Code)
	}

	if _, err := app.store.setSubscriberState(sub.ID, subscription.StateActive, now); err != nil {
		t.Fatal(err)
	}
	if err := app.store.revokeTokens(sub.ID, now); err != nil {
		t.Fatal(err)
	}
	w = subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	nodeID, _, _, bearer, _ := downloadFixture(t, app, now)

	// A stale heartbeat means the Line is no longer contacting the Hub.
	if _, err := app.store.db.Exec(`UPDATE nodes SET last_heartbeat=? WHERE id=?`, now.Add(-10*time.Minute).Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("offline line status %d want 404", w.Code)
	}

	// A confirmed revision that does not match the latest candidate means the
	// Line still runs an older configuration.
	if _, err := app.store.db.Exec(`UPDATE nodes SET last_heartbeat=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.db.Exec(`UPDATE nodes SET observed_revision=1 WHERE id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	w = subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	s := app.store
	nodeID, line, _, aliceBearer, aliceCredential := downloadFixture(t, app, now)

	// A second subscriber joins the same Line.
	bob, _, err := s.createSubscriber("bob", []string{nodeID}, now)
	if err != nil {
		t.Fatal(err)
	}
	bobCredentials, err := s.listSubscriberCredentials(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The Line confirms the complete desired user set of both subscribers.
	publishConvergedCandidate(t, s, nodeID, line, append(append([]subscription.Credential{}, aliceCredential), bobCredentials...), now)
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+aliceBearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d want 200: %s", w.Code, w.Body.String())
	}

	// Bob is paused. His token is revoked, but his credential is still
	// authorized on the Line until the Line confirms the removal.
	if _, err = s.setSubscriberState(bob.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	// The confirmed candidate still carries Bob's user.
	w = subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+aliceBearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("pending removal status %d want 404", w.Code)
	}
	// Once the Line confirms the reduced user set, the download works again.
	publishConvergedCandidate(t, s, nodeID, line, []subscription.Credential{aliceCredential}, now)
	w = subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+aliceBearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d want 200 after the removal was confirmed", w.Code)
	}
}

// TestSubscriptionRejectsForeignHost proves that only the configured download
// host serves the bearer, and that a foreign host learns nothing.
func TestSubscriptionRejectsForeignHost(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

	w := subscriptionRequest(app, "GET", "evil.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

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
		w := subscriptionRequest(app, "GET", "admin.example.invalid", path)
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
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		w := subscriptionRequest(app, method, "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

	// The download host serves the download.
	w := subscriptionRequest(app, "GET", "download.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusOK {
		t.Fatalf("download host status %d want 200", w.Code)
	}
	// The download host serves nothing else.
	for _, path := range []string{"/healthz", "/login", "/api/status", "/assets/app.css", "/", "/nodes"} {
		w = subscriptionRequest(app, "GET", "download.example.invalid", path)
		if w.Code != http.StatusNotFound {
			t.Fatalf("download host %s status %d want 404", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "<html") {
			t.Fatalf("download host %s leaked a management page", path)
		}
	}
	// The management host keeps its console and never serves a download.
	w = subscriptionRequest(app, "GET", "admin.example.invalid", "/healthz")
	if w.Code != http.StatusOK {
		t.Fatalf("management host status %d want 200", w.Code)
	}
	w = subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	app.now = func() time.Time { return now }
	s := app.store

	created, _, err := s.createNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := created.ID
	if _, err = s.setLine(downloadLineFixture(t, nodeID, "line-a"), now); err != nil {
		t.Fatal(err)
	}
	sub, bearer, err := s.createSubscriber("alice", []string{nodeID}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	line, err := s.getLine(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	publishConvergedCandidate(t, s, nodeID, line, credentials, now)

	// The transport settings disappear: the download must fail closed.
	if _, err = s.db.Exec(`DELETE FROM line_settings WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d want 404", w.Code)
	}
}

// TestSubscriptionDownloadReturnsPublicLinesOnly proves that the store
// helper never hands a server-side secret to the download handler.
func TestSubscriptionDownloadReturnsPublicLinesOnly(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	_, line, _, bearer, _ := downloadFixture(t, app, now)

	lines, credentials, err := app.store.subscriptionDownload(bearer, now)
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

// TestSubscriptionRejectsPortMismatch proves that a Line whose published port
// disagrees with the stored transport can never serve a download.
func TestSubscriptionRejectsPortMismatch(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	nodeID, _, _, bearer, _ := downloadFixture(t, app, now)

	if _, err := app.store.db.Exec(`UPDATE line_settings SET port=9443 WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d want 404", w.Code)
	}
}

// TestSubscriptionRejectsUnenrolledLine proves that a Line without a valid
// identity can never serve a download.
func TestSubscriptionRejectsUnenrolledLine(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	nodeID, _, _, bearer, _ := downloadFixture(t, app, now)

	if _, err := app.store.db.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d want 404", w.Code)
	}
}

// TestSubscriptionReportsDatabaseFailure proves that a broken database is
// reported as a service failure instead of being hidden behind the generic
// rejection.
func TestSubscriptionReportsDatabaseFailure(t *testing.T) {
	app, _ := subscriptionApp(t)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	_, _, _, bearer, _ := downloadFixture(t, app, now)

	if err := app.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json")
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
	if err := candidateUsersMatch(exact, desired); err != nil {
		t.Fatalf("the exact user set was rejected: %v", err)
	}
	duplicated := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
	}}
	if err := candidateUsersMatch(duplicated, desired); err == nil {
		t.Fatal("a duplicated credential was accepted")
	}
	missing := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
	}}
	if err := candidateUsersMatch(missing, desired); err == nil {
		t.Fatal("a missing credential was accepted")
	}
	changed := node.CandidateDocument{Users: []node.VLESSUser{
		{CredentialID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UUID: "11111111-1111-4111-8111-111111111111"},
		{CredentialID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", UUID: "33333333-3333-4333-8333-333333333333"},
	}}
	if err := candidateUsersMatch(changed, desired); err == nil {
		t.Fatal("a changed UUID was accepted")
	}
}

// TestSubscriptionOriginValidation proves that only one exact origin without
// a path is accepted, and that the empty value keeps the management origin.
func TestSubscriptionOriginValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		origin    string
		subscribe string
		dev       bool
		valid     bool
	}{
		{"empty keeps the management origin", testOrigin, "", false, true},
		{"distinct HTTPS origin", testOrigin, "https://download.example.invalid", false, true},
		{"same origin spelled exactly", testOrigin, testOrigin, false, true},
		{"path", testOrigin, "https://download.example.invalid/sub", false, false},
		{"query", testOrigin, "https://download.example.invalid?a=b", false, false},
		{"fragment", testOrigin, "https://download.example.invalid#x", false, false},
		{"credentials", testOrigin, "https://user@download.example.invalid", false, false},
		{"no host", testOrigin, "https://", false, false},
		{"plain HTTP", testOrigin, "http://download.example.invalid", false, false},
		{"not a url", testOrigin, "download.example.invalid", false, false},
		{"development HTTP", "http://127.0.0.1:9080", "http://127.0.0.1:9080", true, true},
		{"development HTTP on another port", "http://127.0.0.1:9080", "http://127.0.0.1:9081", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{
				Listen:             "127.0.0.1:9080",
				Origin:             tc.origin,
				SubscriptionOrigin: tc.subscribe,
				DevHTTP:            tc.dev,
				DataDir:            filepath.Join(t.TempDir(), "state"),
			}
			err := c.Validate(1000)
			if tc.valid && err != nil {
				t.Fatalf("origin %q was rejected: %v", tc.subscribe, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("origin %q was accepted", tc.subscribe)
			}
		})
	}
}
