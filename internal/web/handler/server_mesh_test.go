package handler

import (
	"bytes"
	"context"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
)

var meshKeyPattern = regexp.MustCompile(`<pre class="sub-secret">([^<]+)</pre>`)

// fakeHeadscale is a narrow in-memory control plane. It records every call so a
// test can assert what the Web layer asked Headscale to do, and it can refuse a
// chosen operation with one stable adapter code.
type fakeHeadscale struct {
	mu       sync.Mutex
	users    []meshnet.User
	nodes    []meshnet.Node
	calls    []string
	failWith map[string]string
	nextID   uint64
}

func (f *fakeHeadscale) record(call string) error {
	f.calls = append(f.calls, call)
	if code, ok := f.failWith[call]; ok {
		return &meshnet.Error{Code: code}
	}
	return nil
}

func (f *fakeHeadscale) resetCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

func (f *fakeHeadscale) callsOf(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, call := range f.calls {
		if call == name {
			n++
		}
	}
	return n
}

func (f *fakeHeadscale) ListUsers(context.Context) ([]meshnet.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("users.list"); err != nil {
		return nil, err
	}
	return append([]meshnet.User(nil), f.users...), nil
}

func (f *fakeHeadscale) CreateUser(_ context.Context, name string) (meshnet.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("users.create"); err != nil {
		return meshnet.User{}, err
	}
	for _, user := range f.users {
		if user.Name == name {
			return meshnet.User{}, &meshnet.Error{Code: meshnet.CodeAlreadyExists}
		}
	}
	f.nextID++
	user := meshnet.User{ID: f.nextID, Name: name, DisplayName: name}
	f.users = append(f.users, user)
	return user, nil
}

func (f *fakeHeadscale) ListNodes(context.Context, string) ([]meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("nodes.list"); err != nil {
		return nil, err
	}
	return append([]meshnet.Node(nil), f.nodes...), nil
}

func (f *fakeHeadscale) CreatePreAuthKey(_ context.Context, req meshnet.PreAuthKeyRequest) (meshnet.PreAuthKey, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("preauthkeys.create"); err != nil {
		return meshnet.PreAuthKey{}, "", err
	}
	f.nextID++
	return meshnet.PreAuthKey{ID: f.nextID, UserID: req.UserID}, "headscale-preauth-example-once", nil
}

func (f *fakeHeadscale) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.record("preauthkeys.expire")
}

func (f *fakeHeadscale) ExpireNode(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.record("nodes.expire")
}

func (f *fakeHeadscale) DeleteNode(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("nodes.delete"); err != nil {
		return err
	}
	kept := f.nodes[:0]
	for _, node := range f.nodes {
		if node.ID != id {
			kept = append(kept, node)
		}
	}
	f.nodes = kept
	return nil
}

func (f *fakeHeadscale) SetApprovedRoutes(_ context.Context, id uint64, prefixes []string) (meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("nodes.approve-routes"); err != nil {
		return meshnet.Node{}, err
	}
	for i, node := range f.nodes {
		if node.ID == id {
			f.nodes[i].ApprovedRoutes = append([]string(nil), prefixes...)
			return f.nodes[i], nil
		}
	}
	return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeNotFound}
}

func (f *fakeHeadscale) ClearApprovedRoutes(_ context.Context, id uint64) (meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("nodes.clear-routes"); err != nil {
		return meshnet.Node{}, err
	}
	for i, node := range f.nodes {
		if node.ID == id {
			f.nodes[i].ApprovedRoutes = nil
			return f.nodes[i], nil
		}
	}
	return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeNotFound}
}

// meshTestApp returns an initialized, logged-in console with a fake control
// plane that already holds the shared default Headscale user.
func meshTestApp(t *testing.T) (*Server, *browser, *fakeHeadscale, *bytes.Buffer) {
	t.Helper()
	app, logs := testApp(t)
	fake := &fakeHeadscale{failWith: map[string]string{}, users: []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}}
	app.mesh = fake
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return app, b, fake, logs
}

// meshCreateDevice creates one device through the page form and returns its
// record plus the one-time key shown in that response.
func meshCreateDevice(t *testing.T, b *browser, fake *fakeHeadscale, displayName, purpose, platform, subscriberID string) (store.MeshDeviceRecord, string) {
	t.Helper()
	fields := url.Values{
		"display_name": {displayName}, "purpose": {purpose},
		"platform": {platform}, "subscriber_id": {subscriberID},
	}
	w := b.post("/mesh", fields)
	requireStatus(t, w, http.StatusOK)
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("response did not disclose a one-time key: %.400s", w.Body.String())
	}
	devices, err := b.app.store.ListMeshDevices()
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

func TestMeshRoutesRequireAuthentication(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	for _, path := range []string{"/mesh"} {
		w := b.req("GET", path, nil, http.Header{"Accept": {"text/html"}})
		requireStatus(t, w, http.StatusUnauthorized)
		if !strings.Contains(w.Body.String(), "AUTH_REQUIRED") {
			t.Fatalf("%s did not require authentication", path)
		}
	}
	for _, path := range []string{"/mesh", "/mesh/rekey", "/mesh/reconcile", "/mesh/revoke", "/mesh/retry"} {
		w := b.req("POST", path, url.Values{"csrf": {"x"}, "device_id": {"ffffffffffffffffffffffffffffffff"}}, nil)
		requireStatus(t, w, http.StatusUnauthorized)
		if !strings.Contains(w.Body.String(), "SESSION_INVALID") {
			t.Fatalf("%s did not report SESSION_INVALID", path)
		}
	}
	devices, err := app.store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("unauthenticated request created %d devices", len(devices))
	}
}

func TestMeshPageRequiresCSRFOnMutations(t *testing.T) {
	app, b, _, _ := meshTestApp(t)
	w := b.req("POST", "/mesh", url.Values{"csrf": {"wrong"}, "display_name": {"phone"}, "purpose": {"mesh_only"}, "platform": {"ios"}}, nil)
	requireStatus(t, w, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "CSRF_REJECTED") {
		t.Fatal("wrong CSRF was not rejected")
	}
	devices, err := app.store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("rejected request created %d devices", len(devices))
	}
}

// TestMeshPageOwnsNavigationRoute proves the placeholder navigation page no
// longer competes with the real mesh page: the response is the device
// workspace, not the "尚未实现" filler.
func TestMeshPageOwnsNavigationRoute(t *testing.T) {
	_, b, _, _ := meshTestApp(t)
	w := b.req("GET", "/mesh", nil, nil)
	requireStatus(t, w, 200)
	body := w.Body.String()
	if !strings.Contains(body, "新增 Mesh 设备") || !strings.Contains(body, "重新核对全部设备") {
		t.Fatalf("mesh page missing its own controls: %.400s", body)
	}
	if strings.Contains(body, "将在后续开发阶段开放") {
		t.Fatal("placeholder page still owns /mesh")
	}
	if !strings.Contains(body, "尚未创建 Mesh 设备") {
		t.Fatal("empty state is not shown honestly")
	}
	if !strings.Contains(body, "0 台") {
		t.Fatal("device count badge missing")
	}
	if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	// The page's own stylesheet is embedded with the rest of the assets, so the
	// page never depends on a remote stylesheet (the CSP forbids one).
	requireStatus(t, b.req("GET", "/assets/mesh.css", nil, nil), 200)
}

// TestMeshCreateShowsKeyOnceAndNeverLeaksIt covers the disclosure contract: the
// plaintext appears in the POST body exactly once, the response is not cacheable
// or reusable, and the key stays out of the URL, the following page and the
// service log.
func TestMeshCreateShowsKeyOnceAndNeverLeaksIt(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)

	w := b.post("/mesh", url.Values{"display_name": {"alice-iphone"}, "purpose": {"mesh_only"}, "platform": {"ios"}, "subscriber_id": {""}})
	requireStatus(t, w, http.StatusOK)
	if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want private, no-store", got)
	}
	if got := w.Header().Get("Location"); got != "" {
		t.Fatalf("key response redirected to %q; a redirect would put state in a URL", got)
	}
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("no one-time key in the response: %.400s", w.Body.String())
	}
	secret := match[1]
	if len(secret) != 43 {
		t.Fatalf("disclosed secret has %d characters, want 43", len(secret))
	}
	// The plaintext is never reflected into a header (a Location or a cookie
	// would move it into a URL or a browser store).
	for name, values := range w.Header() {
		for _, value := range values {
			if strings.Contains(value, secret) {
				t.Fatalf("the plaintext key leaked into header %q", name)
			}
		}
	}
	// The key exists only in that one response body, exactly once: a second
	// occurrence would mean it was also reflected into a URL, a hidden field or
	// a data attribute.
	if got := strings.Count(w.Body.String(), secret); got != 1 {
		t.Fatalf("the plaintext key appears %d times in the response, want 1", got)
	}
	next := b.req("GET", "/mesh", nil, nil)
	requireStatus(t, next, 200)
	if strings.Contains(next.Body.String(), secret) {
		t.Fatal("the following page rendered the plaintext key again")
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("the plaintext key reached the service log")
	}
	// No log line carries a key-shaped value at all: the 43-character base64url
	// form is the only shape a key has, so a pass here is the sentinel that the
	// enrollment boundary is not logged.
	if keyShaped := regexp.MustCompile(`[A-Za-z0-9_-]{43,}`).FindString(logs.String()); keyShaped != "" {
		t.Fatalf("a key-shaped value reached the log: %q", keyShaped)
	}
	if !strings.Contains(logs.String(), "MESH_DEVICE_ENROLLMENT_KEY_ISSUED") {
		t.Fatal("the key issue audit event was not recorded")
	}
	// Only the digest is stored; the plaintext column does not exist.
	var digests int
	if err := app.store.DB.QueryRow(`SELECT count(*) FROM mesh_enrollment_keys WHERE secret_hash IS NOT NULL`).Scan(&digests); err != nil {
		t.Fatal(err)
	}
	if digests != 1 {
		t.Fatalf("stored %d key digests, want 1", digests)
	}
	// The user was resolved through the fixed default user, and no pre-auth key
	// was minted: this slice issues Hub-side keys only.
	if fake.callsOf("preauthkeys.create") != 0 {
		t.Fatal("web handlers minted a Headscale pre-auth key")
	}
}

// TestMeshOnlyDisclosureShowsStandardJoinCommand proves a mesh-only device gets
// a concrete Tailscale join command (login-server + auth-key placeholder +
// no invented routes), while the secret itself still appears exactly once.
func TestMeshOnlyDisclosureShowsStandardJoinCommand(t *testing.T) {
	app, b, _, _ := meshTestApp(t)
	app.cfg.HeadscaleOrigin = "https://headscale.example.invalid"

	w := b.post("/mesh", url.Values{"display_name": {"carol-nas"}, "purpose": {"mesh_only"}, "platform": {"linux"}, "subscriber_id": {""}})
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, "tailscale up --login-server=https://headscale.example.invalid --auth-key=") {
		t.Fatalf("standard join command missing: %.600s", body)
	}
	if strings.Contains(body, "--advertise-routes=") {
		t.Fatal("mesh-only join command must not advertise routes")
	}
}

// TestMeshDisclosureWithoutOriginAsksForConfiguration proves the page says plainly
// that the join command needs --headscale-origin instead of inventing a control
// plane (never the SaaS default).
func TestMeshDisclosureWithoutOriginAsksForConfiguration(t *testing.T) {
	app, b, _, _ := meshTestApp(t)
	app.cfg.HeadscaleOrigin = ""

	w := b.post("/mesh", url.Values{"display_name": {"dave-phone"}, "purpose": {"mesh_only"}, "platform": {"android"}, "subscriber_id": {""}})
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, "--headscale-origin") {
		t.Fatalf("missing-origin hint absent: %.600s", body)
	}
	if strings.Contains(body, "controlplane.tailscale.com") {
		t.Fatal("must never fall back to the SaaS control plane")
	}
}

// TestMeshReconcilePersistsOnlyOnExplicitAction proves a page render is not a
// reconciliation: the observation timestamp moves only when the operator asks.
func TestMeshReconcilePersistsOnlyOnExplicitAction(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	device, _ := meshCreateDevice(t, b, fake, "nas", "mesh_only", "nas", "")
	if device.ObservedAt != 0 {
		t.Fatalf("creation already recorded an observation: %+v", device)
	}
	// A device that never registered carries no node id, so a live Headscale
	// node with a matching name is not evidence: the row stays "未注册" and no
	// address is attributed to it.
	fake.nodes = []meshnet.Node{{ID: 77, Name: device.NodeName, Online: true, IPAddresses: []string{"100.64.0.7"}}}
	page := b.req("GET", "/mesh", nil, nil)
	requireStatus(t, page, 200)
	afterRender, err := b.app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterRender.ObservedAt != 0 || afterRender.Status != mesh.StatusPending {
		t.Fatalf("a page render recorded an observation: %+v", afterRender)
	}
	if !strings.Contains(page.Body.String(), "尚未观测到") {
		t.Fatal("an unobserved device was not shown as unobserved")
	}
	if strings.Contains(page.Body.String(), "100.64.0.7") {
		t.Fatal("a hostname match was rendered as this device's Tailnet address")
	}

	// The explicit action records an observation. A device with no node id is
	// still not registered by it, because no Headscale node id was observed.
	w := b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, 200)
	reconciled, err := b.app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.ObservedAt == 0 {
		t.Fatal("explicit reconcile did not persist an observation")
	}
	if reconciled.Status != mesh.StatusPending {
		t.Fatalf("reconcile invented a registration: %+v", reconciled)
	}

	// A registered device is annotated with the live address on a plain render,
	// and the render still writes nothing.
	measured, err := b.app.store.RecordMeshObservation(device.ID, 77, app.now())
	if err != nil {
		t.Fatal(err)
	}
	before := measured.ObservedAt
	page = b.req("GET", "/mesh", nil, nil)
	requireStatus(t, page, 200)
	if !strings.Contains(page.Body.String(), "100.64.0.7") {
		t.Fatal("the live Tailnet address was not shown even though Headscale reported it")
	}
	if !strings.Contains(page.Body.String(), "在线") {
		t.Fatal("the live online evidence was not shown")
	}
	after, err := b.app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ObservedAt != before || after.Status != mesh.StatusRegistered {
		t.Fatalf("a page render changed the record: %+v", after)
	}
}

func TestMeshReconcileSettlesDisappearedNode(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	fake.users = []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}
	records, err := app.store.CreateMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), app.now())
	if err != nil {
		t.Fatal(err)
	}
	registered, err := app.store.RecordMeshObservation(records.ID, 42, app.now())
	if err != nil {
		t.Fatal(err)
	}
	if registered.Status != mesh.StatusRegistered {
		t.Fatalf("fixture not registered: %+v", registered)
	}
	// Headscale reports nothing, so the confirmed disappearance moves the device
	// to expired instead of leaving a stale "registered".
	fake.nodes = nil
	w := b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, 200)
	expired, err := app.store.GetMeshDevice(records.ID)
	if err != nil {
		t.Fatal(err)
	}
	if expired.Status != mesh.StatusExpired {
		t.Fatalf("disappearance not recorded: %+v", expired)
	}
	// A Headscale outage is reported, never rendered as "expired".
	fake.failWith["nodes.list"] = meshnet.CodeUnavailable
	w = b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), meshnet.CodeUnavailable) {
		t.Fatalf("outage lost its stable code: %.300s", w.Body.String())
	}
}

// TestMeshReconcileConsumesLingeringKey proves the one-time key is settled by
// the path that proves registration: a database written before keys were spent
// on registration keeps a live issued row for an already registered device, and
// the next explicit reconcile turns it into the terminal consumed state with its
// digest cleared. Nothing accepts the secret back, so the observation is what
// retires it.
func TestMeshReconcileConsumesLingeringKey(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	now := app.now()
	device, err := app.store.CreateMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.store.RecordMeshObservation(device.ID, 42, now); err != nil {
		t.Fatal(err)
	}
	secret, err := mesh.NewEnrollmentSecret()
	if err != nil {
		t.Fatal(err)
	}
	keyID := strings.Repeat("a", 32)
	if _, err = app.store.DB.Exec(`INSERT INTO mesh_enrollment_keys(id, device_id, secret_hash, state, issued_at, expires_at, consumed_at)
 VALUES(?,?,?,'issued',?,?,0)`, keyID, device.ID, mesh.EnrollmentKeyHash(secret), now.Unix(), now.Add(mesh.KeyTTL).Unix()); err != nil {
		t.Fatal(err)
	}

	fake.nodes = []meshnet.Node{{ID: 42, Name: device.NodeName, UserName: mesh.DefaultHeadscaleUser}}
	w := b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, 200)

	var (
		state      string
		hash       []byte
		consumedAt int64
	)
	if err = app.store.DB.QueryRow(`SELECT state, secret_hash, consumed_at FROM mesh_enrollment_keys WHERE id=?`, keyID).
		Scan(&state, &hash, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if state != string(mesh.KeyConsumed) || hash != nil || consumedAt == 0 {
		t.Fatalf("reconcile left the key %q hash=%v consumed_at=%d, want consumed/NULL/set", state, hash, consumedAt)
	}
	// A second check finds no issued row and changes nothing.
	w = b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, 200)
	if err = app.store.DB.QueryRow(`SELECT state, consumed_at FROM mesh_enrollment_keys WHERE id=?`, keyID).
		Scan(&state, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if state != string(mesh.KeyConsumed) || consumedAt == 0 {
		t.Fatalf("repeat reconcile rewrote the consumed key: state %q consumed_at %d", state, consumedAt)
	}
}

// TestMeshRevokeIsIdempotentAndIsolated covers the two guarantees a device
// deletion must keep: repeating it is a no-op, and it never disables the bound
// subscriber, its credentials or its subscription token.
func TestMeshRevokeIsIdempotentAndIsolated(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	fake.users = []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}
	now := app.now()
	line := createEdgeNode(t, app.store, now)
	configureLine(t, app.store, line, "line-a", now)
	subscriber, token, err := app.store.CreateSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}
	device, _ := meshCreateDevice(t, b, fake, "alice-iphone", "proxy_mesh", "ios", subscriber.ID)
	if device.SubscriberID != subscriber.ID {
		t.Fatalf("subscriber binding = %q, want %q", device.SubscriberID, subscriber.ID)
	}
	// A second device of the same subscriber must survive the first one's
	// deletion: one device is one identity, not the whole subscription.
	second, _ := meshCreateDevice(t, b, fake, "alice-ipad", "proxy_mesh", "ios", subscriber.ID)
	registered, err := app.store.RecordMeshObservation(device.ID, 42, now)
	if err != nil {
		t.Fatal(err)
	}
	if registered.Status != mesh.StatusRegistered {
		t.Fatalf("fixture not registered: %+v", registered)
	}
	fake.nodes = []meshnet.Node{{ID: 42, Name: device.NodeName, Online: true, IPAddresses: []string{"100.64.0.9"}}}
	fake.resetCalls()

	w := b.post("/mesh/revoke", url.Values{"device_id": {device.ID}})
	requireStatus(t, w, 200)
	revoked, err := app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != mesh.StatusRevoked {
		t.Fatalf("revoke did not settle the device: %+v", revoked)
	}
	if revoked.RevokeReason != "USER_DELETE" || revoked.RevokeRequestedAt == 0 {
		t.Fatalf("revoke intent not audited: %+v", revoked)
	}
	// The removal expired and deleted the node in that order. The list render
	// that follows reads users and nodes, which write nothing.
	calls := fake.resetCalls()
	want := []string{"nodes.expire", "nodes.delete"}
	if len(calls) < len(want) {
		t.Fatalf("remote calls = %v, want at least %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("remote calls = %v, want %v first", calls, want)
		}
	}

	// Repeating the deletion is a success and performs no remote change: the
	// page render that follows reads users and nodes only.
	w = b.post("/mesh/revoke", url.Values{"device_id": {device.ID}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "无需再次操作") {
		t.Fatalf("repeat revoke was not reported as a no-op: %.300s", w.Body.String())
	}
	for _, call := range fake.resetCalls() {
		if call != "users.list" && call != "nodes.list" {
			t.Fatalf("repeat revoke performed a remote change: %v", call)
		}
	}
	again, err := app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != mesh.StatusRevoked || again.RevokeRequestedAt != revoked.RevokeRequestedAt {
		t.Fatalf("repeat revoke rewrote the audit record: %+v", again)
	}

	// The subscriber and every credential/token of it survive untouched.
	stored, err := app.store.GetSubscriber(subscriber.ID)
	if err != nil {
		t.Fatalf("subscriber lost: %v", err)
	}
	if stored.State != "active" {
		t.Fatalf("subscriber state = %q, want active", stored.State)
	}
	credentials, err := app.store.ListSubscriberCredentials(subscriber.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) == 0 {
		t.Fatal("subscriber credentials disappeared with the mesh device")
	}
	if _, err = resolveBearer(t, app.store, token); err != nil {
		t.Fatalf("subscription token stopped working: %v", err)
	}
	// The sibling device of the same subscriber is untouched.
	sibling, err := app.store.GetMeshDevice(second.ID)
	if err != nil {
		t.Fatalf("sibling device lost: %v", err)
	}
	if sibling.Status != mesh.StatusPending || sibling.RevokeReason != "" || sibling.SubscriberID != subscriber.ID {
		t.Fatalf("sibling device changed: %+v", sibling)
	}
}

// TestMeshRevokeRetriesRemoteFailure proves a Headscale refusal leaves a
// retryable intent instead of a settled record with a live node.
func TestMeshRevokeRetriesRemoteFailure(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	fake.users = []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}
	device, _ := meshCreateDevice(t, b, fake, "tablet", "mesh_only", "android", "")
	if _, err := app.store.RecordMeshObservation(device.ID, 55, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.failWith["nodes.delete"] = meshnet.CodeCommandFailed

	w := b.post("/mesh/revoke", url.Values{"device_id": {device.ID}})
	requireStatus(t, w, 200)
	pending, err := app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != mesh.StatusRevoking {
		t.Fatalf("failed remote removal settled the device: %+v", pending)
	}
	if !strings.Contains(w.Body.String(), meshnet.CodeCommandFailed) {
		t.Fatalf("failure code not reported: %.300s", w.Body.String())
	}

	// The retry button is the same intent route; once Headscale answers, the
	// device settles.
	delete(fake.failWith, "nodes.delete")
	w = b.post("/mesh/retry", url.Values{"device_id": {device.ID}})
	requireStatus(t, w, 200)
	settled, err := app.store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Status != mesh.StatusRevoked {
		t.Fatalf("retry did not settle the device: %+v", settled)
	}
}

func TestMeshUnknownDeviceIs404(t *testing.T) {
	_, b, _, _ := meshTestApp(t)
	missing := "ffffffffffffffffffffffffffffffff"
	for _, path := range []string{"/mesh/revoke", "/mesh/retry", "/mesh/rekey"} {
		w := b.post(path, url.Values{"device_id": {missing}})
		requireStatus(t, w, http.StatusNotFound)
		if !strings.Contains(w.Body.String(), "MESH_DEVICE_NOT_FOUND") {
			t.Fatalf("%s did not report MESH_DEVICE_NOT_FOUND: %.300s", path, w.Body.String())
		}
		// Every failure carries the operation id the audit log uses.
		if !strings.Contains(w.Body.String(), w.Header().Get("X-Operation-ID")) {
			t.Fatalf("%s failure page lost its operation id", path)
		}
	}
	// A malformed identifier is a client error, not a missing record.
	w := b.post("/mesh/revoke", url.Values{"device_id": {"not-an-id"}})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), mesh.CodeDeviceIDInvalid) {
		t.Fatalf("malformed id lost its code: %.300s", w.Body.String())
	}
}

// TestMeshRekeyWithdrawsOldKey proves a reissue never leaves two live secrets:
// the swap installs the new key and revokes the previous issued one in the same
// transaction, so after the response exactly one row is live.
func TestMeshRekeyWithdrawsOldKey(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	device, firstSecret := meshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	firstKeys, err := app.store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstKeys) != 1 || firstKeys[0].State != mesh.KeyIssued {
		t.Fatalf("unexpected initial keys: %+v", firstKeys)
	}

	w := b.post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	requireStatus(t, w, 200)
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 || match[1] == firstSecret {
		t.Fatal("reissue did not disclose a fresh key")
	}
	keys, err := app.store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	var issued, revoked int
	for _, key := range keys {
		switch key.State {
		case mesh.KeyIssued:
			issued++
		case mesh.KeyRevoked:
			revoked++
		}
	}
	if issued != 1 || revoked != 1 {
		t.Fatalf("after reissue: issued=%d revoked=%d, want 1/1", issued, revoked)
	}
	// The live key is the one the list reports; an older revoked record does not
	// hide it.
	if label, _, _ := meshKeyState(keys, app.now()); label != "已签发 · 未使用" {
		t.Fatalf("key column rendered %q after reissue", label)
	}
	// Registration spends only the live key: the withdrawn row stays revoked in
	// the audit trail and is never rewired into a consumption.
	if _, err = app.store.RecordMeshObservation(device.ID, 42, app.now()); err != nil {
		t.Fatal(err)
	}
	keys, err = app.store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	issued, revoked = 0, 0
	var consumed int
	for _, key := range keys {
		switch key.State {
		case mesh.KeyIssued:
			issued++
		case mesh.KeyConsumed:
			consumed++
		case mesh.KeyRevoked:
			revoked++
		}
	}
	if issued != 0 || consumed != 1 || revoked != 1 {
		t.Fatalf("after registration: issued=%d consumed=%d revoked=%d, want 0/1/1", issued, consumed, revoked)
	}
	// Rekeying a revoked device is refused with its own stable code.
	if _, _, err = app.store.RequestMeshDeviceRevocation(device.ID, "USER_DELETE", app.now()); err != nil {
		t.Fatal(err)
	}
	w = b.post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "MESH_DEVICE_NOT_REENROLLABLE") {
		t.Fatalf("revoked device accepted a reissue: %.300s", w.Body.String())
	}
}

func TestMeshCreateRejectsBindingMismatch(t *testing.T) {
	_, b, fake, _ := meshTestApp(t)
	fake.users = []meshnet.User{{ID: 1, Name: mesh.DefaultHeadscaleUser}}
	w := b.post("/mesh", url.Values{"display_name": {"phone"}, "purpose": {"proxy_mesh"}, "platform": {"ios"}, "subscriber_id": {""}})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), mesh.CodeSubscriberBindingInvalid) {
		t.Fatalf("binding mismatch lost its code: %.300s", w.Body.String())
	}
	devices, err := b.app.store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("rejected binding created %d devices", len(devices))
	}
}

// TestMeshCreateCreatesDefaultUserIdempotently covers D2: the shared default
// user is created when missing and an "already exists" answer is success, so a
// repeated creation is not an error.
func TestMeshCreateCreatesDefaultUserIdempotently(t *testing.T) {
	_, b, fake, _ := meshTestApp(t)
	fake.users = nil
	device, _ := meshCreateDevice(t, b, fake, "smoke", "mesh_only", "other", "")
	if device.HeadscaleUser != mesh.DefaultHeadscaleUser {
		t.Fatalf("headscale user = %q, want %q", device.HeadscaleUser, mesh.DefaultHeadscaleUser)
	}
	if fake.callsOf("users.create") != 1 {
		t.Fatalf("default user was not created once: %v", fake.calls)
	}
	fake.resetCalls()
	// A second creation finds the user and does not create it again.
	meshCreateDevice(t, b, fake, "smoke2", "mesh_only", "other", "")
	if fake.callsOf("users.create") != 0 {
		t.Fatalf("default user was created again: %v", fake.calls)
	}
	// Creating the user again because Headscale raced the list is still success.
	fake.users = nil
	fake.failWith["users.create"] = meshnet.CodeAlreadyExists
	if _, err := b.app.ensureMeshUser(context.Background(), mesh.DefaultHeadscaleUser); err != nil {
		t.Fatalf("already-exists user creation failed: %v", err)
	}
	// A name other than the shared default is never minted from a form field.
	if _, err := b.app.ensureMeshUser(context.Background(), "someone-else"); err == nil || !strings.Contains(err.Error(), codeMeshHeadscaleUserUnknown) {
		t.Fatalf("an arbitrary headscale user was created: %v", err)
	}
	if fake.callsOf("users.create") != 1 {
		t.Fatalf("unexpected user creations: %v", fake.resetCalls())
	}
}

// TestMeshNodeNameFallsBackForNonLatinLabels proves the assigned node name is
// canonical even when the display label has no ASCII characters, and that it is
// unique per Headscale user.
func TestMeshNodeNameFallsBackForNonLatinLabels(t *testing.T) {
	if got := meshNodeName("客厅 NAS"); got != "mesh-nas" {
		t.Fatalf("node name = %q, want mesh-nas", got)
	}
	if got := meshNodeName("客厅"); got != "mesh" {
		t.Fatalf("node name = %q, want mesh", got)
	}
	if got := meshNodeName(strings.Repeat("a", 200)); len(got) > 63 {
		t.Fatalf("node name length = %d", len(got))
	}
	if err := mesh.ValidateNodeName(meshNodeName("  -- ")); err != nil {
		t.Fatalf("fallback node name invalid: %v", err)
	}
}

// TestMeshKeyStateLabels keeps the key column honest about a lapsed key that was
// never retired.
func TestMeshKeyStateLabels(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	lapsed := store.MeshEnrollmentKeyRecord{State: mesh.KeyIssued, IssuedAt: now.Unix(), ExpiresAt: now.Add(-time.Minute).Unix()}
	label, class, _ := meshKeyState([]store.MeshEnrollmentKeyRecord{lapsed}, now)
	if label != "已过期 · 待回收" || class != "badge" {
		t.Fatalf("lapsed key rendered as %q/%q", label, class)
	}
	live := store.MeshEnrollmentKeyRecord{State: mesh.KeyIssued, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	if label, _, _ = meshKeyState([]store.MeshEnrollmentKeyRecord{live}, now); label != "已签发 · 未使用" {
		t.Fatalf("live key rendered as %q", label)
	}
	if label, _, _ = meshKeyState(nil, now); label != "尚无 Key" {
		t.Fatalf("missing key rendered as %q", label)
	}
}
