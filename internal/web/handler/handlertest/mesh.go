// Package-level Mesh fixtures shared by the Mesh and policy test packages.

package handlertest

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
)

// fakeHeadscale is a narrow in-memory control plane. It records every call so a
// test can assert what the Web layer asked Headscale to do, and it can refuse a
// chosen operation with one stable adapter code.
type FakeHeadscale struct {
	mu       sync.Mutex
	Users    []meshnet.User
	Nodes    []meshnet.Node
	Calls    []string
	FailWith map[string]string
	NextID   uint64
}

// RecordCall records one adapter call under the fake's lock. A wrapper that
// overrides a method uses it to keep the call log truthful without reaching the
// fake's own fields.
func (f *FakeHeadscale) RecordCall(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Record(call)
}

func (f *FakeHeadscale) Record(call string) error {
	f.Calls = append(f.Calls, call)
	if code, ok := f.FailWith[call]; ok {
		return &meshnet.Error{Code: code}
	}
	return nil
}

func (f *FakeHeadscale) ResetCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.Calls
	f.Calls = nil
	return calls
}

func (f *FakeHeadscale) CallsOf(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, call := range f.Calls {
		if call == name {
			n++
		}
	}
	return n
}

func (f *FakeHeadscale) ListUsers(context.Context) ([]meshnet.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("users.list"); err != nil {
		return nil, err
	}
	return append([]meshnet.User(nil), f.Users...), nil
}

func (f *FakeHeadscale) CreateUser(_ context.Context, name string) (meshnet.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("users.create"); err != nil {
		return meshnet.User{}, err
	}
	for _, user := range f.Users {
		if user.Name == name {
			return meshnet.User{}, &meshnet.Error{Code: meshnet.CodeAlreadyExists}
		}
	}
	f.NextID++
	user := meshnet.User{ID: f.NextID, Name: name, DisplayName: name}
	f.Users = append(f.Users, user)
	return user, nil
}

func (f *FakeHeadscale) ListNodes(context.Context, string) ([]meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("nodes.list"); err != nil {
		return nil, err
	}
	return append([]meshnet.Node(nil), f.Nodes...), nil
}

func (f *FakeHeadscale) CreatePreAuthKey(_ context.Context, req meshnet.PreAuthKeyRequest) (meshnet.PreAuthKey, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("preauthkeys.create"); err != nil {
		return meshnet.PreAuthKey{}, "", err
	}
	f.NextID++
	return meshnet.PreAuthKey{ID: f.NextID, UserID: req.UserID}, "headscale-preauth-example-once", nil
}

func (f *FakeHeadscale) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Record("preauthkeys.expire")
}

func (f *FakeHeadscale) ExpireNode(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Record("nodes.expire")
}

func (f *FakeHeadscale) DeleteNode(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("nodes.delete"); err != nil {
		return err
	}
	kept := f.Nodes[:0]
	for _, node := range f.Nodes {
		if node.ID != id {
			kept = append(kept, node)
		}
	}
	f.Nodes = kept
	return nil
}

func (f *FakeHeadscale) SetApprovedRoutes(_ context.Context, id uint64, prefixes []string) (meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("nodes.approve-routes"); err != nil {
		return meshnet.Node{}, err
	}
	for i, node := range f.Nodes {
		if node.ID == id {
			f.Nodes[i].ApprovedRoutes = append([]string(nil), prefixes...)
			return f.Nodes[i], nil
		}
	}
	return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeNotFound}
}

func (f *FakeHeadscale) ClearApprovedRoutes(_ context.Context, id uint64) (meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Record("nodes.clear-routes"); err != nil {
		return meshnet.Node{}, err
	}
	for i, node := range f.Nodes {
		if node.ID == id {
			f.Nodes[i].ApprovedRoutes = nil
			return f.Nodes[i], nil
		}
	}
	return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeNotFound}
}

// meshTestApp returns an initialized, logged-in console with a fake control
// plane that already holds the shared default Headscale user.
func MeshTestApp(t *testing.T) (*handler.Server, *Browser, *FakeHeadscale, *bytes.Buffer) {
	t.Helper()
	app, logs := TestApp(t)
	fake := &FakeHeadscale{FailWith: map[string]string{}, Users: []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}}
	app.MeshDomainForTest().SetClient(fake)
	b := &Browser{App: app}
	Initialize(t, b)
	LoginAs(t, b, Password)
	return app, b, fake, logs
}

// meshCreateDevice creates one device through the page form and returns its
// record plus the one-time key shown in that response.
func MeshCreateDevice(t *testing.T, b *Browser, fake *FakeHeadscale, displayName, purpose, platform, subscriberID string) (store.MeshDeviceRecord, string) {
	t.Helper()
	fields := url.Values{
		"display_name": {displayName}, "purpose": {purpose},
		"platform": {platform}, "subscriber_id": {subscriberID},
	}
	w := b.Post("/mesh", fields)
	RequireStatus(t, w, http.StatusOK)
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("response did not disclose a one-time key: %.400s", w.Body.String())
	}
	devices, err := b.App.Store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	var created *store.MeshDeviceRecord
	for i := range devices {
		if devices[i].DisplayName == displayName {
			created = &devices[i]
		}
	}
	if created == nil {
		t.Fatalf("no device named %q was created", displayName)
	}
	return *created, match[1]
}

// meshKeyPattern finds the one-time key the Mesh page discloses.
var meshKeyPattern = regexp.MustCompile(`<pre class="sub-secret">([^<]+)</pre>`)

const TestHeadscaleOrigin = "https://headscale.example.invalid"

func MeshEndpointTestApp(t *testing.T, headscaleOrigin string) (*handler.Server, *Browser, *FakeHeadscale, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	c := handler.Config{
		Listen:          "127.0.0.1:9080",
		Origin:          Origin,
		HeadscaleOrigin: headscaleOrigin,
		DataDir:         filepath.Join(t.TempDir(), "state"),
	}
	app, err := handler.New(c, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	fake := &FakeHeadscale{FailWith: map[string]string{}, Users: []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}}
	app.MeshDomainForTest().SetClient(fake)
	b := &Browser{App: app}
	Initialize(t, b)
	LoginAs(t, b, Password)
	return app, b, fake, &logs
}

func MeshConvergedSubscriber(t *testing.T, app *handler.Server, now time.Time) (subscription.Subscriber, subscription.Line) {
	t.Helper()
	created, _, err := app.Store.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	storetest.EnrollNodeIdentity(t, app.Store, created.ID, now)
	line := storetest.ConfigureLine(t, app.Store, created.ID, "line-a", now)
	sub, _, err := app.Store.CreateSubscriber("alice", []string{created.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := app.Store.ListSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("credentials = %d", len(credentials))
	}
	storetest.PublishConvergedCandidate(t, app.Store, created.ID, line, credentials, now)
	return sub, line
}
