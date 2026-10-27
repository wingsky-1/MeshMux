package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/testhttp"
)

const testOrigin = testhttp.Origin
const testPassword = testhttp.Password

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

// createPairedWebNode drives the real pairing endpoint so a handler test uses a
// node with the same non-revoked identity the production flow issues.
func createPairedWebNode(t *testing.T, app *Server, role, name string, vless, ssh int) store.Node {
	t.Helper()
	return testhttp.CreatePairedWebNode(t, app.Handler(), app.Store, role, name, vless, ssh)
}

func require2xx(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	testhttp.Require2xx(t, w)
}

// rootOutSyncApp pairs the shared Agent fixture with the assembled Server, so an
// in-package test can keep calling the root's own helpers.
type rootOutSyncApp struct {
	testhttp.OutSyncApp
	app *Server
}

// outSyncApp builds one Hub with a paired Out, a paired Line and one subscriber
// through the real Agent endpoints.
func outSyncApp(t *testing.T) rootOutSyncApp {
	t.Helper()
	app, logs := testApp(t)
	return rootOutSyncApp{OutSyncApp: testhttp.NewOutSyncApp(t, app.Handler(), app.Store, logs), app: app}
}

func heartbeatJSON(t *testing.T, app *Server, token string) *httptest.ResponseRecorder {
	t.Helper()
	return testhttp.HeartbeatJSON(t, app.Handler(), token)
}
