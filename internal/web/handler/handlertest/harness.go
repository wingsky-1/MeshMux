// Package handlertest is the assembled-handler fixture the handler domain test
// packages share.
//
// It builds the real handler through handler.New — the constructor the
// executable uses — and wraps testhttp.Browser so a domain package can log in
// and drive the routes without importing the handler root's in-package
// fixtures. It is test support, not production code: the handler root's own
// in-package tests use testhttp directly and must not import this package (it
// would close an import cycle).
package handlertest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	handlerpolicy "github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	"github.com/wingsky-1/MeshMux/internal/web/testhttp"
)

// Origin is the management origin every request uses.
const Origin = testhttp.Origin

// Password is the administrator password the fixtures set up.
const Password = testhttp.Password

// CSRFPattern finds the form token rendered into a page.
var CSRFPattern = testhttp.CSRFPattern

// Browser is one admin session against the assembled handler. The explicit
// fields keep composite literals readable; Req and Post copy them through
// testhttp.Browser, which owns the cookie and token rules.
type Browser struct {
	App    *handler.Server
	Cookie *http.Cookie
	Form   *http.Cookie
	CSRF   string
}

// NewBrowser starts an anonymous browser against app.
func NewBrowser(app *handler.Server) *Browser { return &Browser{App: app} }

// core builds the generic browser view of this session.
func (b *Browser) core() *testhttp.Browser {
	return &testhttp.Browser{Handler: b.App.Handler(), Origin: Origin, SessionName: b.App.CookieName(), FormName: b.App.FormCookieName(), Cookie: b.Cookie, Form: b.Form, CSRF: b.CSRF}
}

// Req sends one request and records the cookies and form token the response set.
func (b *Browser) Req(method, path string, form url.Values, headers http.Header) *httptest.ResponseRecorder {
	c := b.core()
	w := c.Req(method, path, form, headers)
	b.Cookie, b.Form, b.CSRF = c.Cookie, c.Form, c.CSRF
	return w
}

// Post sends one mutation with the current form token.
func (b *Browser) Post(path string, fields url.Values) *httptest.ResponseRecorder {
	c := b.core()
	w := c.Post(path, fields)
	b.Cookie, b.Form, b.CSRF = c.Cookie, c.Form, c.CSRF
	return w
}

// TestApp opens the assembled handler over a private data directory and returns
// it with the JSON log buffer.
func TestApp(t *testing.T) (*handler.Server, *bytes.Buffer) {
	t.Helper()
	return TestAppWithConfig(t, handler.Config{
		Listen:  "127.0.0.1:9080",
		Origin:  Origin,
		DataDir: t.TempDir() + "/state",
	})
}

// TestAppWithConfig opens the assembled handler over an explicit configuration.
func TestAppWithConfig(t *testing.T, c handler.Config) (*handler.Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	app, err := handler.New(c, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app, &logs
}

// RequireStatus fails unless the response carries the wanted status.
func RequireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	testhttp.RequireStatus(t, w, status)
}

// Initialize runs the first-run setup with the bootstrap secret.
func Initialize(t *testing.T, b *Browser) {
	t.Helper()
	testhttp.Initialize(t, b, b.App.Store.Dir, Password)
}

// LoginAs logs the browser in with password.
func LoginAs(t *testing.T, b *Browser, password string) {
	t.Helper()
	testhttp.LoginAs(t, b, password)
}

// DatabaseMigrationBrowser opens one logged-in console for the irreversible
// database-migration confirmation and the Hub backup/restore routes.
func DatabaseMigrationBrowser(t *testing.T) (*Browser, *handler.Server) {
	t.Helper()
	app, _ := TestApp(t)
	b := NewBrowser(app)
	Initialize(t, b)
	LoginAs(t, b, Password)
	return b, app
}

// DecodeDatabaseMigration decodes one database-migration receipt.
func DecodeDatabaseMigration(t *testing.T, w *httptest.ResponseRecorder, status int) handlerpolicy.DatabaseMigrationReceipt {
	t.Helper()
	RequireStatus(t, w, status)
	var receipt handlerpolicy.DatabaseMigrationReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("database migration receipt: %v %.300s", err, w.Body.String())
	}
	return receipt
}

// SeedLegacyClientPolicy inserts one active legacy client revision directly and
// returns its id.
func SeedLegacyClientPolicy(t *testing.T, b *Browser, payload string) string {
	t.Helper()
	return storetest.SeedLegacyClientPolicyStore(t, b.App.Store, json.RawMessage(payload), b.App.Now())
}

// CreatePendingNode creates one node through the store and returns its pairing
// code.
func CreatePendingNode(t *testing.T, app *handler.Server, role, name string, vless, ssh int) (store.Node, string) {
	t.Helper()
	return testhttp.CreatePendingNode(t, app.Store, role, name, vless, ssh)
}

// ClearNodeTasks removes every queued task of one node.
func ClearNodeTasks(t *testing.T, app *handler.Server, nodeID string) {
	t.Helper()
	testhttp.ClearNodeTasks(t, app.Store, nodeID)
}

// PairJSON posts one pairing request through the Agent channel.
func PairJSON(t *testing.T, app *handler.Server, nodeID, role, code string) *httptest.ResponseRecorder {
	t.Helper()
	return testhttp.PairJSON(t, app.Handler(), nodeID, role, code)
}

// BearerReq sends one Agent request with an optional bearer identity.
func BearerReq(app *handler.Server, method, path, token string, body []byte) *httptest.ResponseRecorder {
	return testhttp.BearerReq(app.Handler(), method, path, token, body)
}

// ReportJSON posts one task result over the Agent channel.
func ReportJSON(t *testing.T, app *handler.Server, token string, result protocol.TaskResult) *httptest.ResponseRecorder {
	t.Helper()
	return testhttp.ReportJSON(t, app.Handler(), token, result)
}

// FixedTasksForRevision returns the pending Agent tasks of one candidate revision.
func FixedTasksForRevision(t *testing.T, app *handler.Server, nodeID string, revision int64) []protocol.Task {
	t.Helper()
	return testhttp.FixedTasksForRevision(t, app.Store, nodeID, revision)
}
