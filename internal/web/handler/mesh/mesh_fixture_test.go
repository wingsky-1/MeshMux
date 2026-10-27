package mesh_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
	"github.com/wingsky-1/MeshMux/internal/web/testhttp"
)

const meshFixtureListen = "127.0.0.1:19444"

// meshFixtureMetadata is the archived, secret-free outcome of one fixture run.
// It records only what the run proved; it carries no device key, no Headscale
// pre-auth key and no node key.
type meshFixtureMetadata struct {
	HubOrigin        string `json:"hub_origin"`
	HeadscaleBinary  string `json:"headscale_binary"`
	HeadscaleConfig  string `json:"headscale_config"`
	HeadscaleVersion string `json:"headscale_version"`
	Users            int    `json:"users"`
	Devices          int    `json:"devices"`
	Revoked          int    `json:"revoked"`
	Routes           int    `json:"routes"`
	ApprovedRoutes   int    `json:"approved_routes"`
}

// TestMeshHubFixture is a disposable-Hub fixture, not a normal unit test: it
// runs the real Web handler against the pinned Headscale binary over the fixed
// local unix socket, with persistent SQLite. It therefore proves the 9a-4
// boundary that unit tests cannot: the Web account really reaches the 0770
// socket, `users list` / `nodes list` answer, a device can be created through
// the page and settled again.
//
// The fixture is skipped by default. Run it inside a disposable Debian 13 Hub
// VM (never a production Hub), as the unprivileged Web account so the
// supplementary group membership of `meshmux-headscale` is the one under test:
//
//	sudo -u meshmux env MESHMUX_MESH_HUB_FIXTURE_DIR=/tmp/meshmux-mesh-fixture \
//	  /tmp/web-handler.test -test.run '^TestMeshHubFixture$' -test.v
//
// The directory must be fresh (it holds SQLite and the event log) and is owned
// by that account. No real tailnet client registers a node here, so this run
// cannot delete or expire a node; device registration and online evidence stay
// outside this slice.
func TestMeshHubFixture(t *testing.T) {
	dir := os.Getenv("MESHMUX_MESH_HUB_FIXTURE_DIR")
	if dir == "" {
		t.Skip("MESHMUX_MESH_HUB_FIXTURE_DIR is not set: set it inside a disposable Debian 13 Hub VM to run the Web/Headscale fixture")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as the unprivileged Web account (for example sudo -u meshmux): root would not prove the socket group boundary")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareMeshFixtureDir(dir); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	if _, err = os.Stat(filepath.Join(stateDir, "meshmux.db")); err == nil {
		t.Fatal("fixture state already exists: use a fresh MESHMUX_MESH_HUB_FIXTURE_DIR for every archived run")
	}
	eventsPath := filepath.Join(dir, "events.jsonl")
	metadataPath := filepath.Join(dir, "mesh-fixture.json")
	readyPath := filepath.Join(dir, "fixture-ready")
	_ = os.Remove(readyPath)

	// The fixture refuses to guess the host layout: the pinned binary and the
	// Hub-generated configuration are the same paths the adapter and installer
	// use, and neither may be redirected by an environment variable.
	for _, path := range []string{meshnet.BinaryPath, meshnet.ConfigPath} {
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("pinned Headscale host layout is incomplete (%s): %v", path, statErr)
		}
	}
	runner := meshnet.NewCLIRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = runner.VerifyVersion(ctx); err != nil {
		t.Fatalf("Headscale version handshake: %v", err)
	}
	// This read is the acceptance of the 9a-4 socket boundary: a HEADSCALE_*
	// code here means the group membership, the socket or the service is wrong.
	nodesBefore, err := runner.ListNodes(ctx, "")
	if err != nil {
		t.Fatalf("nodes list over the local socket: %v (the fixture account must be in meshmux-headscale and the service active)", err)
	}

	eventFile, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = eventFile.Chmod(0600); err != nil {
		eventFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eventFile.Close() })
	eventLogger := slog.New(slog.NewJSONHandler(eventFile, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey, "operation_id", "stage", "error_code":
				return attr
			default:
				return slog.Attr{}
			}
		},
	}))
	app, err := handler.New(handler.Config{Listen: meshFixtureListen, Origin: handlertest.Origin, DataDir: stateDir}, eventLogger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	// The production wiring is the pinned local CLI runner; the fixture keeps
	// it instead of substituting a fake control plane.
	requirePinnedHeadscaleWiring(t, app)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)

	empty := b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, empty, http.StatusOK)
	if strings.Contains(empty.Body.String(), "Headscale 用户读取失败") || strings.Contains(empty.Body.String(), "Headscale 节点读取失败") {
		t.Fatalf("a live Headscale read was reported as failed: %.600s", empty.Body.String())
	}
	if !strings.Contains(empty.Body.String(), "尚未创建 Mesh 设备") {
		t.Fatal("empty fixture page is not the honest empty state")
	}

	device, secret := handlertest.MeshCreateDevice(t, b, nil, "fixture-nas", "mesh_only", "nas", "")
	if len(secret) != 43 {
		t.Fatalf("disclosed key has %d characters, want 43", len(secret))
	}
	users, err := runner.ListUsers(ctx)
	if err != nil {
		t.Fatalf("users list after creation: %v", err)
	}
	var sharedUser bool
	for _, user := range users {
		if user.Name == mesh.DefaultHeadscaleUser {
			sharedUser = true
		}
	}
	if !sharedUser {
		t.Fatalf("the shared default Headscale user was not created in the fixture instance: %+v", users)
	}
	if device.HeadscaleNodeID != 0 || device.Status != mesh.StatusPending {
		t.Fatalf("a device without an observed node became %+v", device)
	}

	listed := b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, listed, http.StatusOK)
	for _, want := range []string{"fixture-nas", "未注册", "已签发 · 未使用"} {
		if !strings.Contains(listed.Body.String(), want) {
			t.Fatalf("device page lost %q after creation", want)
		}
	}
	if strings.Contains(listed.Body.String(), secret) {
		t.Fatal("the following page rendered the plaintext key again")
	}

	// Reconcile is the only path that persists an observation, and a real
	// `nodes list` must not invent a registration for an unregistered device.
	reconciled := b.Post("/mesh/reconcile", url.Values{})
	handlertest.RequireStatus(t, reconciled, http.StatusOK)
	if !strings.Contains(reconciled.Body.String(), "已核对 1 台设备") || strings.Contains(reconciled.Body.String(), "无法核对") {
		t.Fatalf("reconcile did not report a clean single-device check: %.600s", reconciled.Body.String())
	}
	stored, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != mesh.StatusPending || stored.HeadscaleNodeID != 0 || stored.ObservedAt == 0 {
		t.Fatalf("reconcile misrepresented an unregistered device: %+v", stored)
	}

	// A device with no observed node has nothing to remove remotely, so the
	// deletion settles locally and never touches another node in the tailnet.
	revoked := b.Post("/mesh/revoke", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, revoked, http.StatusOK)
	settled, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Status != mesh.StatusRevoked || settled.RevokeReason != "USER_DELETE" {
		t.Fatalf("revocation did not settle the device: %+v", settled)
	}
	nodesAfter, err := runner.ListNodes(ctx, "")
	if err != nil {
		t.Fatalf("nodes list after revocation: %v", err)
	}
	if len(nodesAfter) != len(nodesBefore) {
		t.Fatalf("revoking an unregistered device changed the tailnet: %d -> %d nodes", len(nodesBefore), len(nodesAfter))
	}

	if err = eventFile.Sync(); err != nil {
		t.Fatal(err)
	}
	events, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(events), secret) {
		t.Fatal("the plaintext key reached the fixture event log")
	}
	if !strings.Contains(string(events), "MESH_DEVICE_ENROLLMENT_KEY_ISSUED") {
		t.Fatal("the fixture event log lacks the key issue audit event")
	}
	// Route counts are part of the archived evidence even when this fixture
	// creates no subnet_router: a zero must be a measured zero, not a missing
	// field that hides a route the run actually wrote.
	routes, routeErr := app.Store.ListMeshRoutes(device.ID)
	if routeErr != nil {
		t.Fatal(routeErr)
	}
	approvedRoutes := 0
	for _, route := range routes {
		if route.Desired == mesh.RouteDesiredApproved {
			approvedRoutes++
		}
	}
	if err = testhttp.WritePrivateJSON(metadataPath, meshFixtureMetadata{
		HubOrigin:        handlertest.Origin,
		HeadscaleBinary:  meshnet.BinaryPath,
		HeadscaleConfig:  meshnet.ConfigPath,
		HeadscaleVersion: meshnet.HeadscaleVersion,
		Users:            len(users),
		Devices:          1,
		Revoked:          1,
		Routes:           len(routes),
		ApprovedRoutes:   approvedRoutes,
	}); err != nil {
		t.Fatal(err)
	}
	if err = testhttp.WriteAtomicFile(readyPath, []byte("mesh-hub-fixture-ready\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Log("Mesh Hub fixture PASS: real users/nodes read, device created, reconciled and revoked")
}

// prepareMeshFixtureDir keeps the archived fixture output private: the
// directory holds a SQLite database and the event log, and a symlinked or
// group-readable directory would let another local account read both.
func prepareMeshFixtureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return os.ErrPermission
	}
	return nil
}

// TestMeshHeadscaleWiringIsPinned proves the production page is wired to the
// pinned local CLI adapter, not to an injectable command or a remote client.
// The adapter's own argv table is covered in internal/core/meshnet; this is the
// Web-side half of the command-assembly contract.
func TestMeshHeadscaleWiringIsPinned(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	requirePinnedHeadscaleWiring(t, app)
}

// requirePinnedHeadscaleWiring pins the concrete adapter without spelling its
// type name: the only production implementation of meshnet.Client is the
// value NewCLIRunner returns, so the runtime types must be identical.
func requirePinnedHeadscaleWiring(t *testing.T, app *handler.Server) {
	t.Helper()
	if app.MeshDomainForTest().Client() == nil {
		t.Fatal("app.MeshDomainForTest().Client() is nil")
	}
	if got, want := fmt.Sprintf("%T", app.MeshDomainForTest().Client()), fmt.Sprintf("%T", meshnet.NewCLIRunner()); got != want {
		t.Fatalf("wired %s, want the fixed-layout %s", got, want)
	}
}

// TestMeshWithoutHeadscaleRefusesBeforeWrites covers the ordinary test host:
// there is no pinned binary at all, so every control-plane read must fail with
// its stable code and no device, key or observation may be written. It is
// skipped when the pinned binary exists so it can never reach a live service.
func TestMeshWithoutHeadscaleRefusesBeforeWrites(t *testing.T) {
	if _, err := os.Stat(meshnet.BinaryPath); err == nil {
		t.Skip("pinned Headscale binary is installed on this host; refusing to exercise a live control plane")
	}
	app, _ := handlertest.TestApp(t)
	app.MeshDomainForTest().SetClient(meshnet.NewCLIRunner())
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)

	// The page reports the adapter's stable code instead of rendering "offline",
	// and it still renders the honest empty state: a failed read is not a device.
	page := b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, page, http.StatusOK)
	body := page.Body.String()
	if code := headscaleErrorCodeIn(body); code == "" {
		t.Fatalf("page hid the control-plane refusal: %.800s", body)
	}
	if !strings.Contains(body, "尚未创建 Mesh 设备") {
		t.Fatal("a failed Headscale read invented device rows")
	}
	if strings.Contains(body, "在线") && !strings.Contains(body, "未核对") {
		t.Fatal("a failed read was rendered as a live snapshot")
	}

	w := b.Post("/mesh", url.Values{"display_name": {"phone"}, "purpose": {"mesh_only"}, "platform": {"ios"}})
	handlertest.RequireStatus(t, w, http.StatusServiceUnavailable)
	if code := headscaleErrorCodeIn(w.Body.String()); code == "" {
		t.Fatalf("create lost its stable code: %.400s", w.Body.String())
	}
	devices, err := app.Store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("a refused create stored %d devices", len(devices))
	}

	w = b.Post("/mesh/reconcile", url.Values{})
	handlertest.RequireStatus(t, w, http.StatusServiceUnavailable)
	if code := headscaleErrorCodeIn(w.Body.String()); code == "" {
		t.Fatalf("reconcile lost its stable code: %.400s", w.Body.String())
	}
}

// headscaleErrorCodeIn returns the first HEADSCALE_* code rendered into a
// response. A missing pinned binary is a host-layout defect, and Headscale's own
// 0.29.5 error text is classified into one of these codes rather than exposed
// verbatim; the test only requires that the refusal keeps a stable code.
func headscaleErrorCodeIn(body string) string {
	for _, code := range []string{
		meshnet.CodeUnavailable, meshnet.CodeSocketUnavailable, meshnet.CodeTimeout,
		meshnet.CodeCommandFailed, meshnet.CodeOutputInvalid, meshnet.CodeVersionMismatch,
	} {
		if strings.Contains(body, code) {
			return code
		}
	}
	return ""
}

// TestMeshPageRenderOnlyReadsControlPlane pins the read shape of one page
// render: users and nodes only. A render that called a mutation would make
// opening a page an unaudited change.
func TestMeshPageRenderOnlyReadsControlPlane(t *testing.T) {
	_, b, fake, _ := handlertest.MeshTestApp(t)
	handlertest.MeshCreateDevice(t, b, fake, "nas", "mesh_only", "nas", "")
	fake.ResetCalls()
	handlertest.RequireStatus(t, b.Req("GET", "/mesh", nil, nil), http.StatusOK)
	calls := fake.ResetCalls()
	want := []string{"users.list", "nodes.list"}
	if len(calls) != len(want) {
		t.Fatalf("page render called %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("page render called %v, want %v", calls, want)
		}
	}
}
