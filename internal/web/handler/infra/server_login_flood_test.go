package infra_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
)

// TestAnonymousFloodCannotLockTheLoginPage is the regression for #113 3-3. The
// login page used to mint an anonymous session row to hold its CSRF value, and
// a 256-row cap refused further rows with 503 SESSION_UNAVAILABLE. Requests
// that never authenticate could therefore take away the one page that restores
// access. The page now carries a stateless token, so 256 cookie-less requests
// change nothing and the administrator's next page load still renders.
func TestAnonymousFloodCannotLockTheLoginPage(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	handlertest.Initialize(t, &handlertest.Browser{App: app})

	// Every request is a fresh handlertest.Browser that will discard the form cookie, which
	// is exactly the pattern the old cap punished.
	for i := range 256 {
		b := &handlertest.Browser{App: app}
		w := b.Req("GET", "/login", nil, nil)
		handlertest.RequireStatus(t, w, 200)
		if !handlertest.CSRFPattern.MatchString(w.Body.String()) {
			t.Fatalf("request %d rendered no CSRF field", i+1)
		}
		if b.Form == nil {
			t.Fatalf("request %d issued no form cookie", i+1)
		}
	}
	var rows int
	if err := app.Store.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("anonymous requests stored %d session rows, want 0", rows)
	}
	// Past the old cap the page is still a working login form: it renders, it
	// carries a usable token, and the credential path still accepts it.
	admin := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, admin.Req("GET", "/login", nil, nil), 200)
	handlertest.RequireStatus(t, admin.Post("/login", url.Values{"password": {handlertest.Password}}), 303)
	handlertest.RequireStatus(t, admin.Req("GET", "/api/status", nil, nil), 200)
}

// TestLoginFormTokenIsStillEnforced pins the boundary the anonymous session
// used to provide: the form only posts with the exact Origin, one cookie and a
// matching, unexpired token. Removing the stored row must not remove CSRF.
func TestLoginFormTokenIsStillEnforced(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	base := time.Now()
	app.Now = func() time.Time { return base }
	handlertest.Initialize(t, &handlertest.Browser{App: app})

	// No form cookie: the CSRF value in the body proves nothing on its own.
	page := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, page.Req("GET", "/login", nil, nil), 200)
	bodyOnly := &handlertest.Browser{App: app, CSRF: page.CSRF}
	handlertest.RequireStatus(t, bodyOnly.Req("POST", "/login", url.Values{"csrf": {page.CSRF}, "password": {handlertest.Password}}, nil), 401)

	// A token that was never signed by this process is refused.
	planted := &handlertest.Browser{App: app, Form: &http.Cookie{Name: app.FormCookieName(), Value: store.RandomToken()}, CSRF: store.RandomToken()}
	handlertest.RequireStatus(t, planted.Req("POST", "/login", url.Values{"csrf": {planted.CSRF}, "password": {handlertest.Password}}, nil), 401)

	// Cookie and body must carry the same value.
	mismatch := &handlertest.Browser{App: app, Form: page.Form, CSRF: store.RandomToken()}
	handlertest.RequireStatus(t, mismatch.Req("POST", "/login", url.Values{"csrf": {mismatch.CSRF}, "password": {handlertest.Password}}, nil), 403)

	// Duplicate form cookies fail closed rather than picking one.
	dup := &handlertest.Browser{App: app, Form: page.Form, CSRF: page.CSRF}
	header := http.Header{"Cookie": {page.Form.String() + "; " + app.FormCookieName() + "=" + store.RandomToken()}}
	handlertest.RequireStatus(t, dup.Req("POST", "/login", url.Values{"csrf": {page.CSRF}, "password": {handlertest.Password}}, header), 401)

	// The token expires on its own after the anonymous-form window.
	app.Now = func() time.Time { return base.Add(infra.FormTokenLifetime + time.Minute) }
	handlertest.RequireStatus(t, page.Req("POST", "/login", url.Values{"csrf": {page.CSRF}, "password": {handlertest.Password}}, nil), 401)
	// The page reloads with a fresh token and the login works.
	handlertest.RequireStatus(t, page.Req("GET", "/login", nil, nil), 200)
	handlertest.RequireStatus(t, page.Post("/login", url.Values{"password": {handlertest.Password}}), 303)
}

// TestSetupFormUsesTheSameStatelessToken covers the other unauthenticated form:
// a cookie-less setup request must not create a session row either, and the
// first-run flow still works end to end.
func TestSetupFormUsesTheSameStatelessToken(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, b.Req("GET", "/setup", nil, nil), 200)
	if b.Form == nil {
		t.Fatal("setup page issued no form cookie")
	}
	var rows int
	if err := app.Store.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("setup page stored %d session rows, want 0", rows)
	}
	token, err := os.ReadFile(filepath.Join(app.Store.Dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	handlertest.RequireStatus(t, b.Post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {handlertest.Password}}), 303)
	// The spent form cookie is cleared with the successful setup.
	if b.Form != nil {
		t.Fatal("setup left the form cookie behind")
	}
	login := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, login.Req("GET", "/login", nil, nil), 200)
	handlertest.RequireStatus(t, login.Post("/login", url.Values{"password": {handlertest.Password}}), 303)
}

// TestLoginPageRendersWithLegacyAnonymousRowsFull reproduces the original
// failure on an upgraded database: rows that an older build minted for the
// login form are already at the old 256 cap. The page must still render, and a
// successful login must clear them, because they never authorized anything.
func TestLoginPageRendersWithLegacyAnonymousRowsFull(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	handlertest.Initialize(t, &handlertest.Browser{App: app})
	now := time.Now()
	for range 256 {
		if _, err := app.Store.DB.Exec("INSERT INTO sessions VALUES(?,?,0,?,?)", store.TokenHash(store.RandomToken()), store.RandomToken(), now.Add(10*time.Minute).Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	admin := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, admin.Req("GET", "/login", nil, nil), 200)
	handlertest.RequireStatus(t, admin.Post("/login", url.Values{"password": {handlertest.Password}}), 303)
	var legacy int
	if err := app.Store.DB.QueryRow("SELECT count(*) FROM sessions WHERE authenticated=0").Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatalf("%d legacy anonymous rows survived the login, want 0", legacy)
	}
}

// TestFormCookieIsHostOnlyAndHttpOnly keeps the double-submit cookie inside the
// same boundary as the session cookie, so a sibling host cannot plant or read
// the value that pairs with a forged form field.
func TestFormCookieIsHostOnlyAndHttpOnly(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	handlertest.Initialize(t, &handlertest.Browser{App: app})
	b := &handlertest.Browser{App: app}
	handlertest.RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	if b.Form == nil {
		t.Fatal("no form cookie")
	}
	if !strings.HasPrefix(b.Form.Name, "__Host-") || !b.Form.Secure || !b.Form.HttpOnly || b.Form.SameSite != http.SameSiteStrictMode || b.Form.Path != "/" || b.Form.Domain != "" {
		t.Fatalf("unsafe form cookie attributes: %+v", b.Form)
	}
}
