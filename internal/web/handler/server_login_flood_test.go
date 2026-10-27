package handler

import (
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAnonymousFloodCannotLockTheLoginPage is the regression for #113 3-3. The
// login page used to mint an anonymous session row to hold its CSRF value, and
// a 256-row cap refused further rows with 503 SESSION_UNAVAILABLE. Requests
// that never authenticate could therefore take away the one page that restores
// access. The page now carries a stateless token, so 256 cookie-less requests
// change nothing and the administrator's next page load still renders.
func TestAnonymousFloodCannotLockTheLoginPage(t *testing.T) {
	app, _ := testApp(t)
	initialize(t, &browser{app: app})

	// Every request is a fresh browser that will discard the form cookie, which
	// is exactly the pattern the old cap punished.
	for i := range 256 {
		b := &browser{app: app}
		w := b.req("GET", "/login", nil, nil)
		requireStatus(t, w, 200)
		if !csrfPattern.MatchString(w.Body.String()) {
			t.Fatalf("request %d rendered no CSRF field", i+1)
		}
		if b.form == nil {
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
	admin := &browser{app: app}
	requireStatus(t, admin.req("GET", "/login", nil, nil), 200)
	requireStatus(t, admin.post("/login", url.Values{"password": {testPassword}}), 303)
	requireStatus(t, admin.req("GET", "/api/status", nil, nil), 200)
}

// TestLoginFormTokenIsStillEnforced pins the boundary the anonymous session
// used to provide: the form only posts with the exact Origin, one cookie and a
// matching, unexpired token. Removing the stored row must not remove CSRF.
func TestLoginFormTokenIsStillEnforced(t *testing.T) {
	app, _ := testApp(t)
	base := time.Now()
	app.Now = func() time.Time { return base }
	initialize(t, &browser{app: app})

	// No form cookie: the CSRF value in the body proves nothing on its own.
	page := &browser{app: app}
	requireStatus(t, page.req("GET", "/login", nil, nil), 200)
	bodyOnly := &browser{app: app, csrf: page.csrf}
	requireStatus(t, bodyOnly.req("POST", "/login", url.Values{"csrf": {page.csrf}, "password": {testPassword}}, nil), 401)

	// A token that was never signed by this process is refused.
	planted := &browser{app: app, form: &http.Cookie{Name: app.FormCookieName(), Value: store.RandomToken()}, csrf: store.RandomToken()}
	requireStatus(t, planted.req("POST", "/login", url.Values{"csrf": {planted.csrf}, "password": {testPassword}}, nil), 401)

	// Cookie and body must carry the same value.
	mismatch := &browser{app: app, form: page.form, csrf: store.RandomToken()}
	requireStatus(t, mismatch.req("POST", "/login", url.Values{"csrf": {mismatch.csrf}, "password": {testPassword}}, nil), 403)

	// Duplicate form cookies fail closed rather than picking one.
	dup := &browser{app: app, form: page.form, csrf: page.csrf}
	header := http.Header{"Cookie": {page.form.String() + "; " + app.FormCookieName() + "=" + store.RandomToken()}}
	requireStatus(t, dup.req("POST", "/login", url.Values{"csrf": {page.csrf}, "password": {testPassword}}, header), 401)

	// The token expires on its own after the anonymous-form window.
	app.Now = func() time.Time { return base.Add(infra.FormTokenLifetime + time.Minute) }
	requireStatus(t, page.req("POST", "/login", url.Values{"csrf": {page.csrf}, "password": {testPassword}}, nil), 401)
	// The page reloads with a fresh token and the login works.
	requireStatus(t, page.req("GET", "/login", nil, nil), 200)
	requireStatus(t, page.post("/login", url.Values{"password": {testPassword}}), 303)
}

// TestSetupFormUsesTheSameStatelessToken covers the other unauthenticated form:
// a cookie-less setup request must not create a session row either, and the
// first-run flow still works end to end.
func TestSetupFormUsesTheSameStatelessToken(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	requireStatus(t, b.req("GET", "/setup", nil, nil), 200)
	if b.form == nil {
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
	requireStatus(t, b.post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {testPassword}}), 303)
	// The spent form cookie is cleared with the successful setup.
	if b.form != nil {
		t.Fatal("setup left the form cookie behind")
	}
	login := &browser{app: app}
	requireStatus(t, login.req("GET", "/login", nil, nil), 200)
	requireStatus(t, login.post("/login", url.Values{"password": {testPassword}}), 303)
}

// TestLoginPageRendersWithLegacyAnonymousRowsFull reproduces the original
// failure on an upgraded database: rows that an older build minted for the
// login form are already at the old 256 cap. The page must still render, and a
// successful login must clear them, because they never authorized anything.
func TestLoginPageRendersWithLegacyAnonymousRowsFull(t *testing.T) {
	app, _ := testApp(t)
	initialize(t, &browser{app: app})
	now := time.Now()
	for range 256 {
		if _, err := app.Store.DB.Exec("INSERT INTO sessions VALUES(?,?,0,?,?)", store.TokenHash(store.RandomToken()), store.RandomToken(), now.Add(10*time.Minute).Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	admin := &browser{app: app}
	requireStatus(t, admin.req("GET", "/login", nil, nil), 200)
	requireStatus(t, admin.post("/login", url.Values{"password": {testPassword}}), 303)
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
	app, _ := testApp(t)
	initialize(t, &browser{app: app})
	b := &browser{app: app}
	requireStatus(t, b.req("GET", "/login", nil, nil), 200)
	if b.form == nil {
		t.Fatal("no form cookie")
	}
	if !strings.HasPrefix(b.form.Name, "__Host-") || !b.form.Secure || !b.form.HttpOnly || b.form.SameSite != http.SameSiteStrictMode || b.form.Path != "/" || b.form.Domain != "" {
		t.Fatalf("unsafe form cookie attributes: %+v", b.form)
	}
}
