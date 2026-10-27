package handler

// The in-package forms of the Agent fixtures. The moved domain tests use
// handlertest, which wraps the same testhttp helpers; the root keeps these
// thin wrappers because its package tests cannot import handlertest without
// closing an import cycle.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	handlerpolicy "github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	"github.com/wingsky-1/MeshMux/internal/web/testhttp"
)

const testSubscriptionOrigin = "https://download.example.invalid"

const databaseMigrationApprovePath = "/tasks/db-migration/approve"

func createPendingNode(t *testing.T, app *Server, role, name string, vless, ssh int) (store.Node, string) {
	t.Helper()
	return testhttp.CreatePendingNode(t, app.Store, role, name, vless, ssh)
}

func clearNodeTasks(t *testing.T, app *Server, nodeID string) {
	t.Helper()
	testhttp.ClearNodeTasks(t, app.Store, nodeID)
}

func pairJSON(t *testing.T, app *Server, nodeID, role, code string) *httptest.ResponseRecorder {
	t.Helper()
	return testhttp.PairJSON(t, app.Handler(), nodeID, role, code)
}

func bearerReq(app *Server, method, path, token string, body []byte) *httptest.ResponseRecorder {
	return testhttp.BearerReq(app.Handler(), method, path, token, body)
}

func reportJSON(t *testing.T, app *Server, token string, res protocol.TaskResult) *httptest.ResponseRecorder {
	t.Helper()
	return testhttp.ReportJSON(t, app.Handler(), token, res)
}

func fixedTasksForRevision(t *testing.T, app *Server, nodeID string, revision int64) []protocol.Task {
	t.Helper()
	return testhttp.FixedTasksForRevision(t, app.Store, nodeID, revision)
}

func createPairedWebNode(t *testing.T, app *Server, role, name string, vless, ssh int) store.Node {
	t.Helper()
	return testhttp.CreatePairedWebNode(t, app.Handler(), app.Store, role, name, vless, ssh)
}

func databaseMigrationBrowser(t *testing.T) (*browser, *Server) {
	t.Helper()
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return b, app
}

func decodeDatabaseMigration(t *testing.T, w *httptest.ResponseRecorder, status int) handlerpolicy.DatabaseMigrationReceipt {
	t.Helper()
	requireStatus(t, w, status)
	var receipt handlerpolicy.DatabaseMigrationReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("database migration receipt: %v %.300s", err, w.Body.String())
	}
	return receipt
}

var _ = time.Now

func nodesPageBody(t *testing.T, b *browser) string {
	t.Helper()
	w := b.Req("GET", "/nodes", nil, nil)
	requireStatus(t, w, 200)
	return w.Body.String()
}

func postPolicy(t *testing.T, b *browser, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return b.Post(path, url.Values{"policy": {body}})
}

func policyReceipt(t *testing.T, w *httptest.ResponseRecorder, status int) handlerpolicy.PolicyWriteResponse {
	t.Helper()
	requireStatus(t, w, status)
	var out handlerpolicy.PolicyWriteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("write response: %v %.300s", err, w.Body.String())
	}
	return out
}

func subscriptionAppWithOrigin(t *testing.T, subscriptionOrigin string) (*Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	c := Config{Listen: "127.0.0.1:9080", Origin: testOrigin, SubscriptionOrigin: subscriptionOrigin, DataDir: filepath.Join(t.TempDir(), "state")}
	app, err := New(c, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app, &logs
}

func policyWriteApp(t *testing.T) *browser {
	t.Helper()
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return b
}
