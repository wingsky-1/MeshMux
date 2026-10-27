// Package testhttp is the HTTP fixture shared by the handler tests.
//
// It knows only http.Handler, a store handle and the Agent protocol, never the
// handler package itself: the handler root's in-package tests import it without
// the import cycle a handler-importing fixture would create, and
// handler/handlertest wraps it for the domain packages. It is test support, not
// production code.
package testhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// Origin is the management origin every request uses.
const Origin = "https://admin.example.invalid"

// Password is the administrator password the fixtures set up.
const Password = "test-only-long-password-47!"

// CSRFPattern finds the form token rendered into a page.
var CSRFPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// Browser is one admin session against one assembled handler. SessionName and
// FormName are the cookie names the handler publishes, so this package never
// needs the handler type to read them back.
type Browser struct {
	Handler     http.Handler
	Origin      string
	SessionName string
	FormName    string
	Cookie      *http.Cookie
	Form        *http.Cookie
	CSRF        string
}

// Req sends one request and records the cookies and form token the response set.
func (b *Browser) Req(method, path string, form url.Values, headers http.Header) *httptest.ResponseRecorder {
	origin := b.Origin
	if origin == "" {
		origin = Origin
	}
	body := ""
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40000"
	// httptest's absolute target is a convenient constructor, not proxy request form.
	r.URL.Scheme = ""
	r.URL.Host = ""
	if b.Cookie != nil {
		r.AddCookie(b.Cookie)
	}
	if b.Form != nil {
		r.AddCookie(b.Form)
	}
	if method == "POST" {
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, values := range headers {
		r.Header[http.CanonicalHeaderKey(key)] = values
	}
	w := httptest.NewRecorder()
	b.Handler.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == b.SessionName {
			b.Cookie = c
		}
		if c.Name == b.FormName {
			if c.MaxAge < 0 {
				b.Form = nil
			} else {
				b.Form = c
			}
		}
	}
	if m := CSRFPattern.FindStringSubmatch(w.Body.String()); len(m) > 1 {
		b.CSRF = m[1]
	}
	return w
}

// Post sends one mutation with the current form token.
func (b *Browser) Post(path string, fields url.Values) *httptest.ResponseRecorder {
	if fields == nil {
		fields = url.Values{}
	}
	fields.Set("csrf", b.CSRF)
	return b.Req("POST", path, fields, nil)
}

// Requester is the pair of request helpers Initialize and LoginAs drive.
type Requester interface {
	Req(method, path string, form url.Values, headers http.Header) *httptest.ResponseRecorder
	Post(path string, fields url.Values) *httptest.ResponseRecorder
}

// RequireStatus fails unless the response carries the wanted status.
func RequireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d want %d: %.300s", w.Code, status, w.Body.String())
	}
}

// Initialize runs the first-run setup with the bootstrap secret in dir.
func Initialize(t *testing.T, b Requester, dir, password string) {
	t.Helper()
	RequireStatus(t, b.Req("GET", "/setup", nil, nil), 200)
	token, err := os.ReadFile(filepath.Join(dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	RequireStatus(t, b.Post("/setup", url.Values{"bootstrap": {strings.TrimSpace(string(token))}, "password": {password}}), 303)
	if _, err = os.Stat(filepath.Join(dir, "bootstrap.token")); !os.IsNotExist(err) {
		t.Fatal("bootstrap secret was not removed")
	}
}

// LoginAs logs the browser in with password.
func LoginAs(t *testing.T, b Requester, password string) {
	t.Helper()
	RequireStatus(t, b.Req("GET", "/login", nil, nil), 200)
	RequireStatus(t, b.Post("/login", url.Values{"password": {password}}), 303)
	RequireStatus(t, b.Req("GET", "/", nil, nil), 200)
}

// CreatePendingNode creates one node through the store and returns its pairing
// code, exactly as the Nodes page receives it.
func CreatePendingNode(t *testing.T, s *store.Store, role, name string, vless, ssh int) (store.Node, string) {
	t.Helper()
	node, code, err := s.CreateNode(role, name, vless, ssh, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 43 {
		t.Fatal("pairing code must be 43-char secret")
	}
	return node, code
}

// ClearNodeTasks removes every queued task of one node.
func ClearNodeTasks(t *testing.T, s *store.Store, nodeID string) {
	t.Helper()
	if _, err := s.DB.Exec(`DELETE FROM agent_tasks WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
}

// PairJSON posts one pairing request through the Agent channel.
func PairJSON(t *testing.T, h http.Handler, nodeID, role, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"node_id": nodeID, "role": role, "pairing_code": code, "agent_version": "meshmux-agent test", "kernel_version": "6.1-test"})
	r := httptest.NewRequest("POST", Origin+"/api/agent/pair", bytes.NewReader(body))
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// BearerReq sends one Agent request with an optional bearer identity.
func BearerReq(h http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, Origin+path, reader)
	r.URL.Scheme = ""
	r.URL.Host = ""
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// ReportJSON posts one task result over the Agent channel.
func ReportJSON(t *testing.T, h http.Handler, token string, result protocol.TaskResult) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return BearerReq(h, "POST", "/api/agent/result", token, body)
}

// FixedTasksForRevision returns the pending Agent tasks of one node whose params
// point at exactly one candidate revision.
func FixedTasksForRevision(t *testing.T, s *store.Store, nodeID string, revision int64) []protocol.Task {
	t.Helper()
	rows, err := s.DB.Query(`SELECT operation_id, revision, idempotency_key, kind, params
 FROM agent_tasks WHERE node_id=? AND status='pending' ORDER BY revision`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tasks []protocol.Task
	for rows.Next() {
		task := protocol.Task{Schema: protocol.Schema, Version: protocol.Version, NodeID: nodeID}
		var params string
		if err := rows.Scan(&task.OperationID, &task.Revision, &task.IdempotencyKey, &task.Kind, &params); err != nil {
			t.Fatal(err)
		}
		task.Params = json.RawMessage(params)
		var p struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal(task.Params, &p) == nil && p.Revision == revision {
			tasks = append(tasks, task)
		}
	}
	return tasks
}

// CreatePairedWebNode creates one node and drives the real pairing endpoint, so a
// test uses a node with the same non-revoked identity the production flow issues.
func CreatePairedWebNode(t *testing.T, h http.Handler, s *store.Store, role, name string, vless, ssh int) store.Node {
	t.Helper()
	node, code := CreatePendingNode(t, s, role, name, vless, ssh)
	w := PairJSON(t, h, node.ID, role, code)
	RequireStatus(t, w, 200)
	ClearNodeTasks(t, s, node.ID)
	paired, err := s.GetNodeAt(node.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return paired
}

// SubscriptionRequest sends one raw request to the Web runtime. The target is
// written exactly as given, so percent escapes and dot segments survive.
func SubscriptionRequest(h http.Handler, method, host, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	r.RemoteAddr = "127.0.0.1:40000"
	r.URL.Scheme = ""
	r.URL.Host = ""
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// WritePrivateJSON writes value as 0600 JSON through WriteAtomicFile.
func WritePrivateJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return WriteAtomicFile(path, append(data, '\n'), 0600)
}

// WriteAtomicFile replaces path with data through a synced temporary file.
func WriteAtomicFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fixture-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace fixture file: %w", err)
	}
	return nil
}
