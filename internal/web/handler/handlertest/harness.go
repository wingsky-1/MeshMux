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
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	handlerpolicy "github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	handlerupgrade "github.com/wingsky-1/MeshMux/internal/web/handler/upgrade"
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

// SubscriptionAppWithOrigin opens a Web runtime with an optional dedicated
// download origin, the single-host development default when it is empty.
func SubscriptionAppWithOrigin(t *testing.T, subscriptionOrigin string) (*handler.Server, *bytes.Buffer) {
	t.Helper()
	return TestAppWithConfig(t, handler.Config{
		Listen:             "127.0.0.1:9080",
		Origin:             Origin,
		SubscriptionOrigin: subscriptionOrigin,
		DataDir:            t.TempDir() + "/state",
	})
}

// PostPolicy posts one route-policy payload.
func PostPolicy(t *testing.T, b *Browser, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return b.Post(path, url.Values{"policy": {body}})
}

// PolicyReceipt decodes one route-policy write receipt.
func PolicyReceipt(t *testing.T, w *httptest.ResponseRecorder, status int) handlerpolicy.PolicyWriteResponse {
	t.Helper()
	RequireStatus(t, w, status)
	var out handlerpolicy.PolicyWriteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("write response: %v %.300s", err, w.Body.String())
	}
	return out
}

// NodesPageBody renders the Nodes page through the assembled handler.
func NodesPageBody(t *testing.T, b *Browser) string {
	t.Helper()
	w := b.Req("GET", "/nodes", nil, nil)
	RequireStatus(t, w, 200)
	return w.Body.String()
}

// HeartbeatJSON posts one Agent heartbeat.
func HeartbeatJSON(t *testing.T, app *handler.Server, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(protocol.HeartbeatRequest{AgentVersion: "meshmux-agent test", KernelVersion: node.KernelVersion})
	if err != nil {
		t.Fatal(err)
	}
	return BearerReq(app, "POST", "/api/agent/heartbeat", token, body)
}

// DatabaseMigrationApprovePath is the irreversible-confirmation route.
const DatabaseMigrationApprovePath = "/tasks/db-migration/approve"

// CreatePairedWebNode creates one node and drives the real pairing endpoint, so
// a test uses a node with the same non-revoked identity production issues.
func CreatePairedWebNode(t *testing.T, app *handler.Server, role, name string, vless, ssh int) store.Node {
	t.Helper()
	return testhttp.CreatePairedWebNode(t, app.Handler(), app.Store, role, name, vless, ssh)
}

// Require2xx fails unless the response carries a success status.
func Require2xx(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code < 200 || w.Code > 299 {
		t.Fatalf("status %d want 2xx (operation_id %q)", w.Code, w.Header().Get("X-Operation-ID"))
	}
}

// UpgradeApproveFixture builds one paired edge node whose observed agent version
// is observed, with a logged-in console.
func UpgradeApproveFixture(t *testing.T, observed string) (b *Browser, app *handler.Server, nodeID, token string) {
	t.Helper()
	app, _ = TestApp(t)
	created, code := CreatePendingNode(t, app, "edge", "upgrade-approve", 8443, 2222)
	pairing := PairJSON(t, app, created.ID, "edge", code)
	RequireStatus(t, pairing, http.StatusOK)
	var paired struct {
		IdentityToken string `json:"identity_token"`
	}
	if err := json.Unmarshal(pairing.Body.Bytes(), &paired); err != nil || paired.IdentityToken == "" {
		t.Fatalf("pairing did not issue an identity: %.200s", pairing.Body.String())
	}
	storetest.ConfirmChain(t, app.Store, created.ID, app.Now())
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET observed_agent_version=?, observed_at=? WHERE id=?`,
		observed, app.Now().Unix(), created.ID); err != nil {
		t.Fatal(err)
	}
	b = &Browser{App: app}
	Initialize(t, b)
	LoginAs(t, b, Password)
	return b, app, created.ID, paired.IdentityToken
}

// LatestRevision returns the newest stored candidate revision of one node.
func LatestRevision(t *testing.T, app *handler.Server, nodeID string) int64 {
	t.Helper()
	stored, err := app.Store.LatestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return stored.Revision
}

// CountStamped counts the Agent tasks of one node that carry a target version.
func CountStamped(t *testing.T, app *handler.Server, nodeID string) int {
	t.Helper()
	var count int
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND target_version<>''`,
		nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// DecodeApprove decodes one upgrade approval receipt.
func DecodeApprove(t *testing.T, w *httptest.ResponseRecorder, status int) handlerupgrade.ApproveReceipt {
	t.Helper()
	RequireStatus(t, w, status)
	var receipt handlerupgrade.ApproveReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("approval receipt: %v %.300s", err, w.Body.String())
	}
	return receipt
}

// ApproveUpgrade posts one node upgrade approval.
func ApproveUpgrade(t *testing.T, b *Browser, nodeID, version string) *httptest.ResponseRecorder {
	t.Helper()
	return b.Post("/tasks/approve", url.Values{"node_id": {nodeID}, "version": {version}})
}
