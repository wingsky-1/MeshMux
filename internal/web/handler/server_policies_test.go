package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	corepolicy "github.com/wingsky-1/MeshMux/internal/core/policy"
	policy "github.com/wingsky-1/MeshMux/internal/web/handler/policy"
)

// policiesLiveApp returns a console whose mesh model can be built from one
// converged subscriber and one proxy_mesh device.
func policiesLiveApp(t *testing.T) (*Server, *browser) {
	t.Helper()
	app, b, _, _ := meshEndpointTestApp(t, testHeadscaleOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	sub, _ := meshConvergedSubscriber(t, app, now)
	if _, err := app.Store.CreateMeshDevice(meshSpec("policy-phone", mesh.PurposeProxyMesh, sub.ID), now); err != nil {
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
	if !strings.Contains(body, "Line 直出") || strings.Contains(body, "Out 直出（可选）") {
		t.Fatalf("out-free server section promised an Out: %.500s", body)
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
	if err := app.Store.Close(); err != nil {
		t.Fatal(err)
	}
	app.Store = f.store
	app.Cfg.HeadscaleOrigin = testHeadscaleOrigin
	app.Now = func() time.Time { return f.now }
	if err := app.Store.PrepareBootstrap(f.now); err != nil {
		t.Fatal(err)
	}
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	subscribers, err := app.Store.ListSubscribers()
	if err != nil || len(subscribers) == 0 {
		t.Fatalf("subscribers = %v err=%v", subscribers, err)
	}
	if _, err = app.Store.CreateMeshDevice(meshSpec("policy-phone", mesh.PurposeProxyMesh, subscribers[0].ID), f.now); err != nil {
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

	enableOutForLine(t, f.store, f.out, f.line, f.now)
	confirmChain(t, f.store, f.out, f.now)
	markLineOnline(t, f.store, f.line, f.now)
	if err := prepareSubscriberSyncForLine(f.store, f.line, f.now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, f.store, f.line, f.now)
	w = b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Out 已接入") || !strings.Contains(w.Body.String(), "Out 直出（可选）") {
		t.Fatalf("active state missing: %.400s", w.Body.String())
	}

	if _, err := app.Store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, f.out); err != nil {
		t.Fatal(err)
	}
	w = b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Out 故障 · fail-closed") {
		t.Fatalf("degraded state missing: %.400s", w.Body.String())
	}
}

func TestPoliciesValidateDryRun(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	pass := `{"default":"proxy","rules":[
		{"Priority":100,"Match":{"IPCIDRs":["100.64.0.0/10"]},"Action":"tailscale"},
		{"Priority":200,"Match":{"Domains":["news.example.invalid"]},"Action":"direct"}]}`
	w := b.post("/policies/validate", url.Values{"rules": {pass}})
	requireStatus(t, w, http.StatusOK)
	var ok policy.PolicyValidationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ok); err != nil || !ok.OK || ok.Rules != 2 || ok.OperationID == "" {
		t.Fatalf("validate pass body = %+v err=%v: %.300s", ok, err, w.Body.String())
	}

	conflict := `{"default":"proxy","rules":[
		{"Priority":100,"Match":{"Domains":["news.example.invalid"]},"Action":"direct"},
		{"Priority":200,"Match":{"Domains":["news.example.invalid"]},"Action":"proxy"}]}`
	w = b.post("/policies/validate", url.Values{"rules": {conflict}})
	requireStatus(t, w, http.StatusUnprocessableEntity)
	var refused policy.PolicyValidationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &refused); err != nil {
		t.Fatalf("validate refusal body: %v %.300s", err, w.Body.String())
	}
	if refused.OK || refused.ErrorCode != corepolicy.CodePolicyConflict || !strings.Contains(refused.Detail, "priority 100 shadows") {
		t.Fatalf("validate refusal = %+v", refused)
	}

	w = b.post("/policies/validate", url.Values{"rules": {"not json"}})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), corepolicy.CodePolicyInvalid) {
		t.Fatalf("malformed rules lost POLICY_INVALID: %.300s", w.Body.String())
	}
}

func TestPoliciesExplainHitAndFallback(t *testing.T) {
	_, b := policiesLiveApp(t)
	w := b.req("GET", "/policies/explain?target=100.100.100.100", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"命中说明：100.100.100.100", "优先级 100", "直连（Tailnet）", "meshmux-ts", "规则", "动作", "实际出口", "DNS", "geo 与远端 ruleset 需要锁定数据"} {
		if !strings.Contains(body, want) {
			t.Fatalf("explain hit missing %q: %.500s", want, body)
		}
	}

	w = b.req("GET", "/policies/explain?target=news.example.invalid", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body = w.Body.String()
	if !strings.Contains(body, "兜底路径：news.example.invalid") || !strings.Contains(body, "meshmux-selector (selected Line)") {
		t.Fatalf("explain fallback missing: %.500s", body)
	}
}

func TestPoliciesExplainWithoutDataStaysDraft(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.req("GET", "/policies/explain?target=news.example.invalid", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "当前没有可用的真实策略数据") || strings.Contains(w.Body.String(), "命中说明：") {
		t.Fatalf("explain invented a chain without data: %.400s", w.Body.String())
	}
}
