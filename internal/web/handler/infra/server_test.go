package infra_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

func TestAuthenticationLifecycleAndRestart(t *testing.T) {
	app, logs := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, b.Req("GET", "/api/status", nil, nil), 401)
	handlertest.RequireStatus(t, b.Req("GET", "/nodes", nil, nil), 401)
	handlertest.Initialize(t, b)
	handlertest.RequireStatus(t, b.Req("GET", "/setup", nil, nil), 403)
	handlertest.LoginAs(t, b, handlertest.Password)
	old := *b.Cookie
	oldCSRF := b.CSRF
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
	reopened, err := handler.New(c, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b.App = reopened
	handlertest.RequireStatus(t, b.Req("GET", "/api/status", nil, nil), 200)
	handlertest.RequireStatus(t, b.Req("GET", "/settings", nil, nil), 200)
	newPassword := "new-test-only-password-96!"
	handlertest.RequireStatus(t, b.Post("/password", url.Values{"current_password": {handlertest.Password}, "password": {newPassword}}), 303)
	stale := &handlertest.Browser{App: reopened, Cookie: &old, CSRF: oldCSRF}
	handlertest.RequireStatus(t, stale.Req("GET", "/api/status", nil, nil), 401)
	handlertest.RequireStatus(t, stale.Post("/logout", nil), 401)
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	handlertest.RequireStatus(t, b.Post("/login", url.Values{"password": {handlertest.Password}}), 401)
	handlertest.LoginAs(t, b, newPassword)
	revoked := *b.Cookie
	revokedCSRF := b.CSRF
	handlertest.RequireStatus(t, b.Post("/logout", nil), 303)
	stale.Cookie = &revoked
	stale.CSRF = revokedCSRF
	handlertest.RequireStatus(t, stale.Req("GET", "/api/status", nil, nil), 401)
	for _, secret := range []string{handlertest.Password, newPassword, old.Value, oldCSRF, revoked.Value} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("secret leaked in logs")
		}
	}
}

func TestCSRFOriginAndMalformedRequests(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)
	cases := []struct {
		name, path string
		form       url.Values
		headers    http.Header
		want       int
		code       string
	}{
		{"missing csrf", "/logout", url.Values{}, nil, 403, "CSRF_REJECTED"},
		{"wrong csrf", "/logout", url.Values{"csrf": {"bad"}}, nil, 403, "CSRF_REJECTED"},
		{"wrong origin", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Origin": {"https://evil.example.invalid"}}, 403, "ORIGIN_REJECTED"},
		{"missing origin", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Origin": {}}, 403, "ORIGIN_REJECTED"},
		{"null origin", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Origin": {"null"}}, 403, "ORIGIN_REJECTED"},
		{"duplicate origin", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Origin": {handlertest.Origin, handlertest.Origin}}, 403, "ORIGIN_REJECTED"},
		{"cross site", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Sec-Fetch-Site": {"cross-site"}}, 403, "ORIGIN_REJECTED"},
		{"duplicate csrf", "/logout", url.Values{"csrf": {b.CSRF, b.CSRF}}, nil, 400, "FORM_INVALID"},
		{"query csrf", "/logout?csrf=x", url.Values{"csrf": {b.CSRF}}, nil, 400, "FORM_INVALID"},
		{"duplicate content type", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Content-Type": {"application/x-www-form-urlencoded", "application/json"}}, 415, "FORM_REQUIRED"},
		{"json", "/logout", url.Values{"csrf": {b.CSRF}}, http.Header{"Content-Type": {"application/json"}}, 415, "FORM_REQUIRED"},
		{"large body", "/password", url.Values{"csrf": {b.CSRF}, "password": {strings.Repeat("x", 5000)}}, nil, 400, "FORM_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := b.Req("POST", tc.path, tc.form, tc.headers)
			handlertest.RequireStatus(t, w, tc.want)
			if !strings.Contains(w.Body.String(), tc.code) {
				t.Fatal("missing stable code")
			}
		})
	}
	handlertest.RequireStatus(t, b.Req("GET", "/logout", nil, nil), 405)
	handlertest.RequireStatus(t, b.Req("GET", "/api/status", nil, nil), 200)
	// Duplicate cookies and invalid random sessions fail closed.
	dup := http.Header{"Cookie": {b.Cookie.String() + "; " + b.Cookie.Name + "=forged"}}
	handlertest.RequireStatus(t, b.Req("GET", "/api/status", nil, dup), 401)
	invalid := &handlertest.Browser{App: app, Cookie: &http.Cookie{Name: app.CookieName(), Value: store.RandomToken()}}
	handlertest.RequireStatus(t, invalid.Req("GET", "/api/status", nil, nil), 401)
	r := httptest.NewRequest("GET", "https://evil.example.invalid/api/status", nil)
	r.AddCookie(b.Cookie)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	handlertest.RequireStatus(t, w, 403)
}

func TestSessionRotationExpiryAndNoFixation(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	anonymous := *b.Cookie
	csrf := b.CSRF
	handlertest.RequireStatus(t, b.Post("/login", url.Values{"password": {handlertest.Password}}), 303)
	if b.Cookie.Value == anonymous.Value {
		t.Fatal("session fixation")
	}
	stale := &handlertest.Browser{App: app, Cookie: &anonymous, CSRF: csrf}
	handlertest.RequireStatus(t, stale.Post("/login", url.Values{"password": {handlertest.Password}}), 401)
	handlertest.RequireStatus(t, b.Req("GET", "/", nil, nil), 200)
	old := *b.Cookie
	other := &handlertest.Browser{App: app}
	handlertest.LoginAs(t, other, handlertest.Password)
	stale.Cookie = &old
	handlertest.RequireStatus(t, stale.Req("GET", "/api/status", nil, nil), 401)
	now := time.Now()
	app.Now = func() time.Time { return now.Add(31 * time.Minute) }
	handlertest.RequireStatus(t, other.Req("GET", "/api/status", nil, nil), 401)
	// Refreshing seen cannot extend the absolute lifetime.
	app.Now = time.Now
	handlertest.RequireStatus(t, other.Req("GET", "/api/status", nil, nil), 401)
	other.Cookie = nil
	handlertest.LoginAs(t, other, handlertest.Password)
	if _, err := app.Store.DB.Exec("UPDATE sessions SET expires=? WHERE authenticated=1", time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	handlertest.RequireStatus(t, other.Req("GET", "/api/status", nil, nil), 401)
}

func TestBootstrapExpiryAndConcurrentInitialization(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, b.Req("GET", "/setup", nil, nil), 200)
	handlertest.RequireStatus(t, b.Post("/setup", url.Values{"bootstrap": {"wrong"}, "password": {handlertest.Password}}), 401)
	token, _ := os.ReadFile(filepath.Join(app.Store.Dir, "bootstrap.token"))
	if _, err := app.Store.DB.Exec("UPDATE bootstrap SET expires=0"); err != nil {
		t.Fatal(err)
	}
	handlertest.RequireStatus(t, b.Post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {handlertest.Password}}), 401)
	if err := app.Store.PrepareBootstrap(time.Now()); err != nil {
		t.Fatal(err)
	}
	token, _ = os.ReadFile(filepath.Join(app.Store.Dir, "bootstrap.token"))
	handlertest.RequireStatus(t, b.Post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {"short"}}), 400)
	// Simulate a second already-open setup tab; its form token is still valid,
	// but the initialization entry is closed and the bootstrap secret is gone,
	// so it can never create the admin.
	other := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, other.Req("GET", "/setup", nil, nil), 200)
	handlertest.Initialize(t, b)
	w := other.Post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {handlertest.Password}})
	handlertest.RequireStatus(t, w, 403)
	if !strings.Contains(w.Body.String(), "SETUP_CLOSED") {
		t.Fatalf("second setup tab was not refused as closed: %.200s", w.Body.String())
	}
	// The password slot is taken after the session/form/CSRF checks, so only a
	// well-formed login is refused while another hash holds it; a forged or
	// session-less request is refused earlier with its own code.
	anon := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, anon.Req("GET", "/login", nil, nil), 200)
	app.Runtime.KDFSlotForTest() <- struct{}{}
	handlertest.RequireStatus(t, anon.Post("/login", url.Values{"password": {handlertest.Password}}), 429)
	<-app.Runtime.KDFSlotForTest()
	handlertest.RequireStatus(t, anon.Post("/login", url.Values{"password": {handlertest.Password}}), 303)
}

func TestDurableRateLimitAndProxyLog(t *testing.T) {
	app, logs := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	// Initialization proved the bootstrap secret and cleared the shared budget,
	// so ten wrong attempts now exhaust it. Forwarded headers must not affect it.
	for range 10 {
		handlertest.RequireStatus(t, b.Req("POST", "/login", url.Values{"csrf": {b.CSRF}, "password": {"wrong"}}, http.Header{"X-Forwarded-For": {"192.0.2.5"}, "X-MeshMux-Client-Ip": {"192.0.2.6"}}), 401)
	}
	handlertest.RequireStatus(t, b.Post("/login", url.Values{"password": {handlertest.Password}}), 429)
	if strings.Contains(logs.String(), `"ban_candidate":true`) || strings.Contains(logs.String(), "192.0.2.") {
		t.Fatal("untrusted proxy address logged as candidate")
	}
	c := app.Cfg
	app.Close()
	again, err := handler.New(c, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	b.App = again
	// The form token is process-local, so the restart invalidates the open form
	// (a page reload) while the durable budget survives it. Re-open the page to
	// show that the persisted limit, not the form, is what refuses.
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	handlertest.RequireStatus(t, b.Post("/login", url.Values{"password": {handlertest.Password}}), 429)
	again.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	again.Cfg.DirectProxy = true
	handlertest.RequireStatus(t, b.Req("POST", "/login", url.Values{"csrf": {b.CSRF}, "password": {"wrong"}}, http.Header{"X-MeshMux-Client-Ip": {"192.0.2.8"}}), 401)
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
	app, _ := handlertest.TestApp(t)
	handlertest.Initialize(t, &handlertest.Browser{App: app})
	// Ten routine logins inside one window must never lock the only
	// administrator out: every proven password clears the shared budget, so the
	// run below keeps succeeding past the nominal limit.
	for i := range 12 {
		b := &handlertest.Browser{App: app}
		handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
		if w := b.Post("/login", url.Values{"password": {handlertest.Password}}); w.Code != 303 {
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
	app, _ := handlertest.TestApp(t)
	handlertest.Initialize(t, &handlertest.Browser{App: app})
	attempt := func(password string) *httptest.ResponseRecorder {
		t.Helper()
		b := &handlertest.Browser{App: app}
		handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
		return b.Post("/login", url.Values{"password": {password}})
	}
	// Nine failures leave exactly one slot; the proven password may spend it.
	for range 9 {
		handlertest.RequireStatus(t, attempt("wrong"), 401)
	}
	handlertest.RequireStatus(t, attempt(handlertest.Password), 303)
	// A failed attempt never refills the budget: ten fresh failures are again
	// needed before the next refusal, which proves the reset followed the
	// successful proof rather than the mere passage of requests.
	for range 10 {
		handlertest.RequireStatus(t, attempt("wrong"), 401)
	}
	handlertest.RequireStatus(t, attempt(handlertest.Password), 429)
}

func TestRateLimitRefusalStatesWhenToRetry(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	base := time.Now()
	app.Now = func() time.Time { return base }
	handlertest.Initialize(t, &handlertest.Browser{App: app})
	b := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	wrong := func() *httptest.ResponseRecorder {
		return b.Req("POST", "/login", url.Values{"csrf": {b.CSRF}, "password": {"wrong"}}, nil)
	}
	for range 10 {
		handlertest.RequireStatus(t, wrong(), 401)
	}
	w := wrong()
	handlertest.RequireStatus(t, w, 429)
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
	handlertest.RequireStatus(t, w, 429)
	if got := w.Header().Get("Retry-After"); got != "360" {
		t.Fatalf("Retry-After four minutes in = %q, want 360", got)
	}
	if !strings.Contains(w.Body.String(), "约 6 分钟后") {
		t.Fatal("refusal page does not state the remaining wait")
	}
	// The window reopens on its own; a failed attempt does not slide it.
	app.Now = func() time.Time { return base.Add(11 * time.Minute) }
	handlertest.RequireStatus(t, wrong(), 401)
}

func TestDatabaseFailureClosedAndHeaders(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	w := b.Req("GET", "/healthz", nil, nil)
	handlertest.RequireStatus(t, w, 200)
	for _, header := range []string{"Content-Security-Policy", "X-Operation-ID", "X-Content-Type-Options", "Referrer-Policy"} {
		if w.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache enabled")
	}
	app.Store.DB.Close()
	handlertest.RequireStatus(t, b.Req("GET", "/healthz", nil, nil), 503)
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 503)
	// Missing/invalid session is unauthorized even when the DB is unavailable;
	// a syntactically valid session must report DB failure, never authenticate.
	b.Cookie = &http.Cookie{Name: app.CookieName(), Value: store.RandomToken()}
	handlertest.RequireStatus(t, b.Req("GET", "/api/status", nil, nil), 503)
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
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)
	for _, nav := range view.Navigation {
		w := b.Req("GET", nav.Path, nil, nil)
		handlertest.RequireStatus(t, w, 200)
		if !strings.Contains(w.Body.String(), nav.Title) {
			t.Fatal("missing page title")
		}
	}
	handlertest.RequireStatus(t, b.Req("GET", "/status", nil, nil), 200)
	handlertest.RequireStatus(t, b.Req("GET", "/assets/app.css", nil, nil), 200)
	handlertest.RequireStatus(t, b.Req("GET", "/assets/htmx.min.js", nil, nil), 200)
}
