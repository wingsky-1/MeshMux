package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/mesh"
)

// policiesLiveApp returns a console whose mesh model can be built from one
// converged subscriber and one proxy_mesh device.
func policiesLiveApp(t *testing.T) (*Server, *browser) {
	t.Helper()
	app, b, _, _ := meshEndpointTestApp(t, testHeadscaleOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.now = func() time.Time { return now }
	sub, _ := meshConvergedSubscriber(t, app, now)
	if _, err := app.store.createMeshDevice(meshSpec("policy-phone", mesh.PurposeProxyMesh, sub.ID), now); err != nil {
		t.Fatal(err)
	}
	return app, b
}

func TestPoliciesPageUsesLiveSnapshot(t *testing.T) {
	_, b := policiesLiveApp(t)
	w := b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"Tailnet / 指定网段", "地区规则（cn）", "走 Line", "兜底（未命中任何规则）", "当前生效的客户端策略通过"} {
		if !strings.Contains(body, want) {
			t.Fatalf("live snapshot missing %q: %.500s", want, body)
		}
	}
	if strings.Contains(body, "当前没有可用的真实策略数据") || strings.Contains(body, "示例") {
		t.Fatal("live snapshot still showed the design sample")
	}
	if !strings.Contains(body, "Out 未配置") {
		t.Fatal("out-free deployment was not reported as the optional absent state")
	}
}

func TestPoliciesPageWithoutMeshDataFallsBackToDraft(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "当前没有可用的真实策略数据") || !strings.Contains(w.Body.String(), "示例") {
		t.Fatalf("no-data fallback is not explicit: %.400s", w.Body.String())
	}
}

// policiesOutFixture attaches the Out synchronization fixture to a real
// console, then creates the proxy_mesh device the live snapshot needs.
func policiesOutFixture(t *testing.T) (*Server, *browser, outSyncFixture) {
	t.Helper()
	f := newOutSyncFixture(t)
	app, _ := testApp(t)
	if err := app.store.Close(); err != nil {
		t.Fatal(err)
	}
	app.store = f.store
	app.cfg.HeadscaleOrigin = testHeadscaleOrigin
	app.now = func() time.Time { return f.now }
	if err := app.store.prepareBootstrap(f.now); err != nil {
		t.Fatal(err)
	}
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	subscribers, err := app.store.listSubscribers()
	if err != nil || len(subscribers) == 0 {
		t.Fatalf("subscribers = %v err=%v", subscribers, err)
	}
	if _, err = app.store.createMeshDevice(meshSpec("policy-phone", mesh.PurposeProxyMesh, subscribers[0].ID), f.now); err != nil {
		t.Fatal(err)
	}
	return app, b, f
}

func TestPoliciesOutTriStateSnapshot(t *testing.T) {
	app, b, f := policiesOutFixture(t)
	w := b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Out 未配置") {
		t.Fatalf("absent state missing: %.400s", w.Body.String())
	}

	if err := f.store.setOutBindingAt(OutBinding{OutID: f.out, LineID: f.line, Enabled: true}, f.now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, f.store, f.out, f.now)
	markLineOnline(t, f.store, f.line, f.now)
	if err := f.store.prepareSubscriberSyncForLine(f.line, f.now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, f.store, f.line, f.now)
	w = b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Out 已接入") {
		t.Fatalf("active state missing: %.400s", w.Body.String())
	}

	if _, err := app.store.db.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, f.out); err != nil {
		t.Fatal(err)
	}
	w = b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Out 故障 · fail-closed") {
		t.Fatalf("degraded state missing: %.400s", w.Body.String())
	}
}
