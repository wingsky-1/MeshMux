package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/web/testhttp"
)

const testOrigin = testhttp.Origin
const testPassword = testhttp.Password

var csrfPattern = testhttp.CSRFPattern

// kdfSlotOf exposes the runtime's password-KDF slot to this package's tests.
// It is the one seam a test needs from infra's unexported guard state.
func (s *Server) kdfSlotOf() chan struct{} { return s.Runtime.KDFSlotForTest() }

// browser is the in-package view of one admin session. The cookie, form-token
// and CSRF rules live in testhttp, which the domain packages share; only the
// assembled *Server handle is added here, because those packages cannot import
// this one's fixtures.
type browser struct {
	app    *Server
	cookie *http.Cookie
	form   *http.Cookie
	csrf   string
}

func testApp(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	c := Config{Listen: "127.0.0.1:9080", Origin: testOrigin, DataDir: filepath.Join(t.TempDir(), "state")}
	app, err := newServer(c, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app, &logs
}

func (b *browser) Req(method, path string, form url.Values, headers http.Header) *httptest.ResponseRecorder {
	core := &testhttp.Browser{Handler: b.app.Handler(), Origin: testOrigin, SessionName: b.app.CookieName(), FormName: b.app.FormCookieName(), Cookie: b.cookie, Form: b.form, CSRF: b.csrf}
	w := core.Req(method, path, form, headers)
	b.cookie, b.form, b.csrf = core.Cookie, core.Form, core.CSRF
	return w
}

func (b *browser) Post(path string, fields url.Values) *httptest.ResponseRecorder {
	core := &testhttp.Browser{Handler: b.app.Handler(), Origin: testOrigin, SessionName: b.app.CookieName(), FormName: b.app.FormCookieName(), Cookie: b.cookie, Form: b.form, CSRF: b.csrf}
	w := core.Post(path, fields)
	b.cookie, b.form, b.csrf = core.Cookie, core.Form, core.CSRF
	return w
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	testhttp.RequireStatus(t, w, status)
}

func initialize(t *testing.T, b *browser) {
	t.Helper()
	testhttp.Initialize(t, b, b.app.Store.Dir, testPassword)
}

func loginAs(t *testing.T, b *browser, password string) {
	t.Helper()
	testhttp.LoginAs(t, b, password)
}
