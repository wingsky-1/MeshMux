package handler

// Ruling R11 at the Web boundary: the node onboarding radio can create an
// external HTTP proxy (URL instead of ports, no pairing code), the subscription
// wizard offers it as an egress with an 外部 state, and the delete is the same
// used-by interlocked thorough delete the Out path uses.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPProxyCreateThroughNodesPage(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	w := b.post("/nodes", url.Values{
		"role":         {"http"},
		"display_name": {"办公室代理"},
		"proxy_url":    {"http://alice:s3cret@proxy.example.invalid:8080"},
	})
	requireStatus(t, w, 200)
	body := w.Body.String()
	for _, want := range []string{"外部声明", "proxy.example.invalid:8080", "HTTP 代理节点已创建", "无需配对", `value="http"`, `name="proxy_url"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("nodes page missing %q: %.600s", want, body)
		}
	}
	if strings.Contains(body, "s3cret") || strings.Contains(body, "http://alice") {
		t.Fatal("the nodes page echoed the proxy credentials")
	}
	if strings.Contains(body, "配对码已签发") {
		t.Fatal("an external HTTP proxy was issued a pairing code")
	}

	w = b.req("GET", "/api/nodes", nil, nil)
	requireStatus(t, w, 200)
	var listed struct {
		Nodes []struct {
			ID      string `json:"id"`
			Role    string `json:"role"`
			Status  string `json:"status"`
			Offline bool   `json:"offline"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed.Nodes) != 1 {
		t.Fatalf("api nodes list: %v %.300s", err, w.Body.String())
	}
	n := listed.Nodes[0]
	if n.Role != "http" || n.Status != "external" || n.Offline {
		t.Fatalf("http proxy node projection = %+v", n)
	}
	for table, want := range map[string]int{"node_pairing": 0, "node_identities": 0, "node_candidates": 0, "agent_tasks": 0} {
		var count int
		if err := app.Store.DB.QueryRow(`SELECT count(*) FROM `+table+` WHERE node_id=?`, n.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s rows = %d, want %d", table, count, want)
		}
	}
}

func TestHTTPProxyCreateRejectsBadURL(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	w := b.post("/nodes", url.Values{
		"role":         {"http"},
		"display_name": {"办公室代理"},
		"proxy_url":    {"https://proxy.example.invalid:8080"},
	})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), "HTTP_PROXY_INVALID") {
		t.Fatalf("bad URL refusal = %.300s", w.Body.String())
	}
	var nodes int
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM nodes`).Scan(&nodes); err != nil || nodes != 0 {
		t.Fatalf("rejected creation wrote %d nodes (err=%v)", nodes, err)
	}
}

func TestWizardOffersHTTPProxyAsExternalEgress(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	proxy, err := app.Store.CreateHTTPProxyNode("办公室代理", "http://proxy.example.invalid:8080", app.Now())
	if err != nil {
		t.Fatal(err)
	}

	w := b.req("GET", "/subscribers/wizard", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{proxy.ID, "办公室代理", "proxy.example.invalid:8080", "外部声明 · HTTP 代理"} {
		if !strings.Contains(body, want) {
			t.Fatalf("wizard page missing %q", want)
		}
	}
	// The egress slot stays one radio group: selecting the HTTP proxy is the
	// same single-choice control the Out uses.
	if strings.Count(body, `name="out_id"`) < 2 {
		t.Fatal("the egress radio group is missing")
	}
	if !strings.Contains(body, `name="line_`+lineID+`"`) {
		t.Fatal("the Line checkbox is missing")
	}
}

func TestHTTPProxyDeleteIsUsedByInterlockedOnNodesPage(t *testing.T) {
	app, _ := testApp(t)
	browserState := &browser{app: app}
	initialize(t, browserState)
	loginAs(t, browserState, testPassword)

	lineNode, _, err := app.Store.CreateNode("edge", "line", 8443, 2222, app.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.SetLine(testLine(lineNode.ID, "line"), app.Now()); err != nil {
		t.Fatal(err)
	}
	proxy, err := app.Store.CreateHTTPProxyNode("办公室代理", "http://proxy.example.invalid:8080", app.Now())
	if err != nil {
		t.Fatal(err)
	}
	enableOutForLine(t, app.Store, proxy.ID, lineNode.ID, app.Now())

	w := browserState.post("/nodes/out-delete", url.Values{"out_id": {proxy.ID}, "confirm": {"1"}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "SUBSCRIPTION_OUT_CONFLICT") && !strings.Contains(w.Body.String(), "OUT_REFERENCED_BY_SUBSCRIPTIONS") {
		t.Fatalf("referenced http proxy delete = %.300s", w.Body.String())
	}
	if _, err := app.Store.GetNodeAt(proxy.ID, app.Now()); err != nil {
		t.Fatal("refused delete destroyed the proxy")
	}

	clearOutForLine(t, app.Store, lineNode.ID, app.Now())
	w = browserState.post("/nodes/out-delete", url.Values{"out_id": {proxy.ID}, "confirm": {"1"}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "HTTP 代理节点已彻底删除") {
		t.Fatalf("http proxy delete notice = %.300s", w.Body.String())
	}
	if _, err := app.Store.GetNodeAt(proxy.ID, app.Now()); err == nil {
		t.Fatal("http proxy node survived the delete")
	}
}

// TestHTTPProxyUpdateThroughNodesPage pins the twin of the Out transport form:
// the proxy URL is editable in place, the page never echoes its credentials and
// the success notice says the egress is a declaration, not a readback.
func TestHTTPProxyUpdateThroughNodesPage(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	proxy, err := app.Store.CreateHTTPProxyNode("办公室代理", "http://proxy.example.invalid:8080", app.Now())
	if err != nil {
		t.Fatal(err)
	}

	body := nodesPageBody(t, b)
	for _, want := range []string{`action="/nodes/http-proxy"`, `name="proxy_url"`, "外部声明", proxy.ID} {
		if !strings.Contains(body, want) {
			t.Fatalf("nodes page misses %q", want)
		}
	}

	w := b.post("/nodes/http-proxy", url.Values{
		"out_id":    {proxy.ID},
		"proxy_url": {"http://bob:n3w@edge.example.invalid:3128"},
	})
	requireStatus(t, w, 200)
	updated := w.Body.String()
	for _, want := range []string{"HTTP 代理已更新", "edge.example.invalid:3128", "外部声明"} {
		if !strings.Contains(updated, want) {
			t.Fatalf("proxy update notice misses %q: %.400s", want, updated)
		}
	}
	if strings.Contains(updated, "n3w") || strings.Contains(updated, "http://bob") {
		t.Fatal("the proxy update echoed the submitted credentials")
	}

	// A malformed URL is refused with the stable proxy code and writes nothing.
	w = b.post("/nodes/http-proxy", url.Values{"out_id": {proxy.ID}, "proxy_url": {"https://edge.example.invalid:3128"}})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), "HTTP_PROXY_INVALID") {
		t.Fatalf("bad proxy URL refusal = %.300s", w.Body.String())
	}
	var rawURL string
	if err := app.Store.DB.QueryRow(`SELECT url FROM node_http_proxy WHERE node_id=?`, proxy.ID).Scan(&rawURL); err != nil {
		t.Fatal(err)
	}
	if rawURL != "http://edge.example.invalid:3128" {
		t.Fatalf("refused update changed the stored URL to %q", rawURL)
	}

	// A managed Out id is refused as the wrong role: the two egress forms have
	// separate dial bodies.
	outNode, _, err := app.Store.CreateNode("out", "out", 9443, 2223, app.Now())
	if err != nil {
		t.Fatal(err)
	}
	w = b.post("/nodes/http-proxy", url.Values{"out_id": {outNode.ID}, "proxy_url": {"http://edge.example.invalid:3128"}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "OUT_ROLE_INVALID") {
		t.Fatalf("proxy update on a managed out = %.300s", w.Body.String())
	}
}

// TestHTTPProxyUnbindIsAnExplicitNoop pins the release action for an external
// proxy: there is no ACL, no chain and no readback, so the page must report
// OUT_SYNC_NOT_APPLICABLE instead of a silent "已解除" that implies a
// publication happened.
func TestHTTPProxyUnbindIsAnExplicitNoop(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	proxy, err := app.Store.CreateHTTPProxyNode("办公室代理", "http://proxy.example.invalid:8080", app.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := b.post("/nodes/out-unbind", url.Values{"out_id": {proxy.ID}})
	requireStatus(t, w, 200)
	body := w.Body.String()
	if !strings.Contains(body, "OUT_SYNC_NOT_APPLICABLE") {
		t.Fatalf("proxy release was a silent no-op: %.400s", body)
	}
	var candidates int
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, proxy.ID).Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if candidates != 0 {
		t.Fatalf("proxy release published %d candidates", candidates)
	}
}
