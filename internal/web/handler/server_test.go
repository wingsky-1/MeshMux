package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/logging"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testOrigin = "https://admin.example.invalid"
const testPassword = "test-only-long-password-47!"

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// kdfSlotOf exposes the runtime's password-KDF slot to this package's tests.
// It is the one seam a test needs from infra's unexported guard state.
func (s *Server) kdfSlotOf() chan struct{} { return s.Runtime.KDFSlotForTest() }

type browser struct {
	app    *Server
	cookie *http.Cookie
	form   *http.Cookie
	csrf   string
}

func testApp(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	// The production floor, not a test-only one: a test that asserts a log line
	// must see exactly what journald would. A test inspecting a deliberately
	// demoted line asks for that level with testAppWithLevel.
	return testAppWithLevel(t, logging.Default)
}

// testAppWithLevel builds the fixture with an explicit handler level. Most tests
// want logging.Default, because that is what journald shows. A test that inspects
// a demoted line (the per-poll heartbeat audit) asks for Debug here.
func testAppWithLevel(t *testing.T, level slog.Level) (*Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	c := Config{Listen: "127.0.0.1:9080", Origin: testOrigin, DataDir: filepath.Join(t.TempDir(), "state")}
	app, err := newServer(c, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: level})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app, &logs
}
func (b *browser) req(method, path string, form url.Values, headers http.Header) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, testOrigin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40000"
	// httptest's absolute target is a convenient constructor, not proxy request form.
	r.URL.Scheme = ""
	r.URL.Host = ""
	if b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	if b.form != nil {
		r.AddCookie(b.form)
	}
	if method == "POST" {
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, values := range headers {
		r.Header[http.CanonicalHeaderKey(key)] = values
	}
	w := httptest.NewRecorder()
	b.app.Handler().ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == b.app.CookieName() {
			b.cookie = c
		}
		if c.Name == b.app.FormCookieName() {
			if c.MaxAge < 0 {
				b.form = nil
			} else {
				b.form = c
			}
		}
	}
	if m := csrfPattern.FindStringSubmatch(w.Body.String()); len(m) > 1 {
		b.csrf = m[1]
	}
	return w
}
func (b *browser) post(path string, fields url.Values) *httptest.ResponseRecorder {
	if fields == nil {
		fields = url.Values{}
	}
	fields.Set("csrf", b.csrf)
	return b.req("POST", path, fields, nil)
}
func requireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d want %d: %.300s", w.Code, status, w.Body.String())
	}
}
func initialize(t *testing.T, b *browser) {
	t.Helper()
	requireStatus(t, b.req("GET", "/setup", nil, nil), 200)
	token, err := os.ReadFile(filepath.Join(b.app.Store.Dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, b.post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {testPassword}}), 303)
	if _, err = os.Stat(filepath.Join(b.app.Store.Dir, "bootstrap.token")); !os.IsNotExist(err) {
		t.Fatal("bootstrap secret was not removed")
	}
}
func loginAs(t *testing.T, b *browser, password string) {
	t.Helper()
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	requireStatus(t, b.post("/login", url.Values{"password": {password}}), 303)
	requireStatus(t, b.req("GET", "/", nil, nil), 200)
}

func TestAuthenticationLifecycleAndRestart(t *testing.T) {
	app, logs := testApp(t)
	b := &browser{app: app}
	requireStatus(t, b.req("GET", "/api/status", nil, nil), 401)
	requireStatus(t, b.req("GET", "/nodes", nil, nil), 401)
	initialize(t, b)
	requireStatus(t, b.req("GET", "/setup", nil, nil), 403)
	loginAs(t, b, testPassword)
	old := *b.cookie
	oldCSRF := b.csrf
	if !old.Secure || !old.HttpOnly || old.SameSite != http.SameSiteStrictMode || old.Path != "/" || old.Domain != "" || old.Name != "__Host-meshmux" {
		t.Fatal("insecure cookie attributes")
	}
	var saved []byte
	if err := app.Store.DB.QueryRow("SELECT token_hash FROM sessions WHERE authenticated=1").Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(saved, []byte(old.Value)) || len(saved) != 32 {
		t.Fatal("session must be hashed")
	}
	// A real close/open performs the migration again and keeps a valid session.
	c := app.Cfg
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(c, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b.app = reopened
	requireStatus(t, b.req("GET", "/api/status", nil, nil), 200)
	requireStatus(t, b.req("GET", "/settings", nil, nil), 200)
	newPassword := "new-test-only-password-96!"
	requireStatus(t, b.post("/password", url.Values{"current_password": {testPassword}, "password": {newPassword}}), 303)
	stale := &browser{app: reopened, cookie: &old, csrf: oldCSRF}
	requireStatus(t, stale.req("GET", "/api/status", nil, nil), 401)
	requireStatus(t, stale.post("/logout", nil), 401)
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	requireStatus(t, b.post("/login", url.Values{"password": {testPassword}}), 401)
	loginAs(t, b, newPassword)
	revoked := *b.cookie
	revokedCSRF := b.csrf
	requireStatus(t, b.post("/logout", nil), 303)
	stale.cookie = &revoked
	stale.csrf = revokedCSRF
	requireStatus(t, stale.req("GET", "/api/status", nil, nil), 401)
	for _, secret := range []string{testPassword, newPassword, old.Value, oldCSRF, revoked.Value} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("secret leaked in logs")
		}
	}
}

func TestCSRFOriginAndMalformedRequests(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	cases := []struct {
		name, path string
		form       url.Values
		headers    http.Header
		want       int
		code       string
	}{
		{"missing csrf", "/logout", url.Values{}, nil, 403, "CSRF_REJECTED"},
		{"wrong csrf", "/logout", url.Values{"csrf": {"bad"}}, nil, 403, "CSRF_REJECTED"},
		{"wrong origin", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Origin": {"https://evil.example.invalid"}}, 403, "ORIGIN_REJECTED"},
		{"missing origin", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Origin": {}}, 403, "ORIGIN_REJECTED"},
		{"null origin", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Origin": {"null"}}, 403, "ORIGIN_REJECTED"},
		{"duplicate origin", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Origin": {testOrigin, testOrigin}}, 403, "ORIGIN_REJECTED"},
		{"cross site", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Sec-Fetch-Site": {"cross-site"}}, 403, "ORIGIN_REJECTED"},
		{"duplicate csrf", "/logout", url.Values{"csrf": {b.csrf, b.csrf}}, nil, 400, "FORM_INVALID"},
		{"query csrf", "/logout?csrf=x", url.Values{"csrf": {b.csrf}}, nil, 400, "FORM_INVALID"},
		{"duplicate content type", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Content-Type": {"application/x-www-form-urlencoded", "application/json"}}, 415, "FORM_REQUIRED"},
		{"json", "/logout", url.Values{"csrf": {b.csrf}}, http.Header{"Content-Type": {"application/json"}}, 415, "FORM_REQUIRED"},
		{"large body", "/password", url.Values{"csrf": {b.csrf}, "password": {strings.Repeat("x", 5000)}}, nil, 400, "FORM_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := b.req("POST", tc.path, tc.form, tc.headers)
			requireStatus(t, w, tc.want)
			if !strings.Contains(w.Body.String(), tc.code) {
				t.Fatal("missing stable code")
			}
		})
	}
	requireStatus(t, b.req("GET", "/logout", nil, nil), 405)
	requireStatus(t, b.req("GET", "/api/status", nil, nil), 200)
	// Duplicate cookies and invalid random sessions fail closed.
	dup := http.Header{"Cookie": {b.cookie.String() + "; " + b.cookie.Name + "=forged"}}
	requireStatus(t, b.req("GET", "/api/status", nil, dup), 401)
	invalid := &browser{app: app, cookie: &http.Cookie{Name: app.CookieName(), Value: store.RandomToken()}}
	requireStatus(t, invalid.req("GET", "/api/status", nil, nil), 401)
	r := httptest.NewRequest("GET", "https://evil.example.invalid/api/status", nil)
	r.AddCookie(b.cookie)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	requireStatus(t, w, 403)
}

func TestSessionRotationExpiryAndNoFixation(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	anonymous := *b.cookie
	csrf := b.csrf
	requireStatus(t, b.post("/login", url.Values{"password": {testPassword}}), 303)
	if b.cookie.Value == anonymous.Value {
		t.Fatal("session fixation")
	}
	stale := &browser{app: app, cookie: &anonymous, csrf: csrf}
	requireStatus(t, stale.post("/login", url.Values{"password": {testPassword}}), 401)
	requireStatus(t, b.req("GET", "/", nil, nil), 200)
	old := *b.cookie
	other := &browser{app: app}
	loginAs(t, other, testPassword)
	stale.cookie = &old
	requireStatus(t, stale.req("GET", "/api/status", nil, nil), 401)
	now := time.Now()
	app.Now = func() time.Time { return now.Add(31 * time.Minute) }
	requireStatus(t, other.req("GET", "/api/status", nil, nil), 401)
	// Refreshing seen cannot extend the absolute lifetime.
	app.Now = time.Now
	requireStatus(t, other.req("GET", "/api/status", nil, nil), 401)
	other.cookie = nil
	loginAs(t, other, testPassword)
	if _, err := app.Store.DB.Exec("UPDATE sessions SET expires=? WHERE authenticated=1", time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, other.req("GET", "/api/status", nil, nil), 401)
}

func TestBootstrapExpiryAndConcurrentInitialization(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	requireStatus(t, b.req("GET", "/setup", nil, nil), 200)
	requireStatus(t, b.post("/setup", url.Values{"bootstrap": {"wrong"}, "password": {testPassword}}), 401)
	token, _ := os.ReadFile(filepath.Join(app.Store.Dir, "bootstrap.token"))
	if _, err := app.Store.DB.Exec("UPDATE bootstrap SET expires=0"); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, b.post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {testPassword}}), 401)
	if err := app.Store.PrepareBootstrap(time.Now()); err != nil {
		t.Fatal(err)
	}
	token, _ = os.ReadFile(filepath.Join(app.Store.Dir, "bootstrap.token"))
	requireStatus(t, b.post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {"short"}}), 400)
	// Simulate a second already-open setup tab; its form token is still valid,
	// but the initialization entry is closed and the bootstrap secret is gone,
	// so it can never create the admin.
	other := &browser{app: app}
	requireStatus(t, other.req("GET", "/setup", nil, nil), 200)
	initialize(t, b)
	w := other.post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {testPassword}})
	requireStatus(t, w, 403)
	if !strings.Contains(w.Body.String(), "SETUP_CLOSED") {
		t.Fatalf("second setup tab was not refused as closed: %.200s", w.Body.String())
	}
	// The password slot is taken after the session/form/CSRF checks, so only a
	// well-formed login is refused while another hash holds it; a forged or
	// session-less request is refused earlier with its own code.
	anon := &browser{app: app}
	requireStatus(t, anon.req("GET", "/login", nil, nil), 200)
	app.kdfSlotOf() <- struct{}{}
	requireStatus(t, anon.post("/login", url.Values{"password": {testPassword}}), 429)
	<-app.kdfSlotOf()
	requireStatus(t, anon.post("/login", url.Values{"password": {testPassword}}), 303)
}

func TestDurableRateLimitAndProxyLog(t *testing.T) {
	app, logs := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	// Initialization proved the bootstrap secret and cleared the shared budget,
	// so ten wrong attempts now exhaust it. Forwarded headers must not affect it.
	for range 10 {
		requireStatus(t, b.req("POST", "/login", url.Values{"csrf": {b.csrf}, "password": {"wrong"}}, http.Header{"X-Forwarded-For": {"192.0.2.5"}, "X-MeshMux-Client-Ip": {"192.0.2.6"}}), 401)
	}
	requireStatus(t, b.post("/login", url.Values{"password": {testPassword}}), 429)
	if strings.Contains(logs.String(), `"ban_candidate":true`) || strings.Contains(logs.String(), "192.0.2.") {
		t.Fatal("untrusted proxy address logged as candidate")
	}
	c := app.Cfg
	app.Close()
	again, err := New(c, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	b.app = again
	// The form token is process-local, so the restart invalidates the open form
	// (a page reload) while the durable budget survives it. Re-open the page to
	// show that the persisted limit, not the form, is what refuses.
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	requireStatus(t, b.post("/login", url.Values{"password": {testPassword}}), 429)
	again.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	again.Cfg.DirectProxy = true
	requireStatus(t, b.req("POST", "/login", url.Values{"csrf": {b.csrf}, "password": {"wrong"}}, http.Header{"X-MeshMux-Client-Ip": {"192.0.2.8"}}), 401)
	var found bool
	for line := range strings.SplitSeq(logs.String(), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["ban_candidate"] == true && event["client_ip"] == "192.0.2.8" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing explicit direct-Caddy candidate")
	}
}

func TestSuccessfulLoginsResetTheGlobalBudget(t *testing.T) {
	app, _ := testApp(t)
	initialize(t, &browser{app: app})
	// Ten routine logins inside one window must never lock the only
	// administrator out: every proven password clears the shared budget, so the
	// run below keeps succeeding past the nominal limit.
	for i := range 12 {
		b := &browser{app: app}
		requireStatus(t, b.req("GET", "/login", nil, nil), 200)
		if w := b.post("/login", url.Values{"password": {testPassword}}); w.Code != 303 {
			t.Fatalf("login %d status %d want 303: %.200s", i+1, w.Code, w.Body.String())
		}
	}
	var attempts int
	if err := app.Store.DB.QueryRow("SELECT attempts FROM auth_limit WHERE id=1").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("attempts after a successful login = %d, want 0", attempts)
	}
}

func TestOnlyAProvenPasswordResetsTheBudget(t *testing.T) {
	app, _ := testApp(t)
	initialize(t, &browser{app: app})
	attempt := func(password string) *httptest.ResponseRecorder {
		t.Helper()
		b := &browser{app: app}
		requireStatus(t, b.req("GET", "/login", nil, nil), 200)
		return b.post("/login", url.Values{"password": {password}})
	}
	// Nine failures leave exactly one slot; the proven password may spend it.
	for range 9 {
		requireStatus(t, attempt("wrong"), 401)
	}
	requireStatus(t, attempt(testPassword), 303)
	// A failed attempt never refills the budget: ten fresh failures are again
	// needed before the next refusal, which proves the reset followed the
	// successful proof rather than the mere passage of requests.
	for range 10 {
		requireStatus(t, attempt("wrong"), 401)
	}
	requireStatus(t, attempt(testPassword), 429)
}

func TestRateLimitRefusalStatesWhenToRetry(t *testing.T) {
	app, _ := testApp(t)
	base := time.Now()
	app.Now = func() time.Time { return base }
	initialize(t, &browser{app: app})
	b := &browser{app: app}
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	wrong := func() *httptest.ResponseRecorder {
		return b.req("POST", "/login", url.Values{"csrf": {b.csrf}, "password": {"wrong"}}, nil)
	}
	for range 10 {
		requireStatus(t, wrong(), 401)
	}
	w := wrong()
	requireStatus(t, w, 429)
	// A constant "600" would be wrong after four minutes: the refusal must state
	// the remainder of the window that already started.
	if got := w.Header().Get("Retry-After"); got != "600" {
		t.Fatalf("Retry-After at the start of the window = %q, want 600", got)
	}
	for _, want := range []string{"AUTH_RATE_LIMITED", "约 10 分钟后", "成功认证会立即清零", "只读页面与退出不受"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("refusal page lacks %q", want)
		}
	}
	app.Now = func() time.Time { return base.Add(4 * time.Minute) }
	w = wrong()
	requireStatus(t, w, 429)
	if got := w.Header().Get("Retry-After"); got != "360" {
		t.Fatalf("Retry-After four minutes in = %q, want 360", got)
	}
	if !strings.Contains(w.Body.String(), "约 6 分钟后") {
		t.Fatal("refusal page does not state the remaining wait")
	}
	// The window reopens on its own; a failed attempt does not slide it.
	app.Now = func() time.Time { return base.Add(11 * time.Minute) }
	requireStatus(t, wrong(), 401)
}

func TestDatabaseFailureClosedAndHeaders(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	w := b.req("GET", "/healthz", nil, nil)
	requireStatus(t, w, 200)
	for _, header := range []string{"Content-Security-Policy", "X-Operation-ID", "X-Content-Type-Options", "Referrer-Policy"} {
		if w.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache enabled")
	}
	app.Store.DB.Close()
	requireStatus(t, b.req("GET", "/healthz", nil, nil), 503)
	requireStatus(t, b.req("GET", "/login", nil, nil), 503)
	// Missing/invalid session is unauthorized even when the DB is unavailable;
	// a syntactically valid session must report DB failure, never authenticate.
	b.cookie = &http.Cookie{Name: app.CookieName(), Value: store.RandomToken()}
	requireStatus(t, b.req("GET", "/api/status", nil, nil), 503)
}

func TestMigrationRollback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "broken")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "meshmux.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE sessions(existing TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := store.OpenStore(dir); err == nil {
		s.Close()
		t.Fatal("broken migration accepted")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count, version int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='admin'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if count != 0 || version != 0 {
		t.Fatal("migration failed to roll back")
	}
}

func TestPageCoverage(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	for _, nav := range view.Navigation {
		w := b.req("GET", nav.Path, nil, nil)
		requireStatus(t, w, 200)
		if !strings.Contains(w.Body.String(), nav.Title) {
			t.Fatal("missing page title")
		}
	}
	requireStatus(t, b.req("GET", "/status", nil, nil), 200)
	requireStatus(t, b.req("GET", "/assets/app.css", nil, nil), 200)
	requireStatus(t, b.req("GET", "/assets/htmx.min.js", nil, nil), 200)
}
