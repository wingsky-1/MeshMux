package handler

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/web/store"
)

// nodesOutTestApp opens one authenticated browser on a Hub with a paired Out
// and a paired, configured Line.
func nodesOutTestApp(t *testing.T) (*Server, *browser, string, string) {
	t.Helper()
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	now := time.Now()
	line := createPairedWebNode(t, app, "edge", "line-pool-ui", 8443, 2222)
	out := createPairedWebNode(t, app, "out", "out-pool-ui", 9443, 2223)
	settings := testLine(line.ID, "line-pool-ui")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	return app, b, line.ID, out.ID
}

func nodesPageBody(t *testing.T, b *browser) string {
	t.Helper()
	w := b.req("GET", "/nodes", nil, nil)
	requireStatus(t, w, 200)
	return w.Body.String()
}

// TestNodesPageShowsOutPoolStrip pins the Task 2 list UI: the Out pool strip
// with its counts, the enrollment modal with a role radio and three fields,
// and the per-Out transport form.
func TestNodesPageShowsOutPoolStrip(t *testing.T) {
	_, b, _, outID := nodesOutTestApp(t)
	body := nodesPageBody(t, b)
	for _, want := range []string{
		"Out 池", "1 个已纳管", "1 个未配置出口地址",
		`href="#enroll"`, `id="enroll"`,
		`name="role"`, `value="edge"`, `value="out"`,
		`name="display_name"`, `name="vless_port"`, `name="ssh_port"`,
		`action="/nodes/out-transport"`, `name="out_id"`, `value="` + outID + `"`,
		"未配置出口地址",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("nodes page misses %q", want)
		}
	}
}

// TestOutTransportSetFlow pins the HTML transport mutation: saving renders
// the address back with a notice, and a bad address is refused with its
// stable code.
func TestOutTransportSetFlow(t *testing.T) {
	app, b, _, outID := nodesOutTestApp(t)

	w := b.post("/nodes/out-transport", url.Values{"out_id": {outID}, "server": {"out.example.invalid"}})
	requireStatus(t, w, 200)
	body := w.Body.String()
	if !strings.Contains(body, "出口地址已保存") || !strings.Contains(body, "out.example.invalid") {
		t.Fatalf("transport save did not render back: %.300s", body)
	}
	transport, err := app.store.GetOutTransport(outID)
	if err != nil || transport.Server != "out.example.invalid" || transport.Port != 9443 {
		t.Fatalf("stored transport wrong: %+v err=%v", transport, err)
	}
	storedBody := nodesPageBody(t, b)
	if !strings.Contains(storedBody, "0 个未配置出口地址") {
		t.Fatalf("strip did not converge after transport set: %.300s", storedBody)
	}

	w = b.post("/nodes/out-transport", url.Values{"out_id": {outID}, "server": {"https://out.example.invalid"}})
	requireStatus(t, w, 400)
	if !strings.Contains(w.Body.String(), "OUT_TRANSPORT_INVALID") {
		t.Fatalf("bad server body: %.200s", w.Body.String())
	}

	w = b.post("/nodes/out-transport", url.Values{"out_id": {strings.Repeat("c", 32)}, "server": {"out.example.invalid"}})
	requireStatus(t, w, 404)
}

// TestOutDeleteConfirmFlow pins the delete protection: the first POST only
// shows the used-by impact, the confirmed POST deletes the route, and unbind
// releases the Line.
func TestOutDeleteConfirmFlow(t *testing.T) {
	app, b, lineID, outID := nodesOutTestApp(t)
	now := time.Now()
	configureOut(t, app.store, outID, now)
	markLineOnline(t, app.store, lineID, now)
	markLineOnline(t, app.store, outID, now)
	if err := app.store.SetOutBindingAt(store.OutBinding{OutID: outID, LineID: lineID, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, app.store, outID)
	confirmChain(t, app.store, outID, now)

	body := nodesPageBody(t, b)
	if !strings.Contains(body, "1 个已绑定") || !strings.Contains(body, lineID) {
		t.Fatalf("bound state not shown on nodes page: %.500s", body)
	}

	// First POST: no deletion, only the used-by confirm.
	w := b.post("/nodes/out-delete", url.Values{"out_id": {outID}})
	requireStatus(t, w, 200)
	body = w.Body.String()
	if !strings.Contains(body, "确认删除出口") || !strings.Contains(body, lineID) || !strings.Contains(body, "恢复直连") {
		t.Fatalf("delete confirm does not name the used-by Line: %.500s", body)
	}
	if _, err := app.store.GetOutBinding(outID); err != nil {
		t.Fatalf("unconfirmed delete removed the binding: %v", err)
	}

	// Confirmed POST: the route is gone and the Line is direct again.
	w = b.post("/nodes/out-delete", url.Values{"out_id": {outID}, "confirm": {"1"}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "出口已删除") {
		t.Fatalf("delete success notice missing: %.300s", w.Body.String())
	}
	if _, err := app.store.GetOutBinding(outID); err == nil {
		t.Fatal("confirmed delete kept the binding")
	}

	// Unbind path: bind again, then release through the page.
	configureOut(t, app.store, outID, now)
	if err := app.store.SetOutBindingAt(store.OutBinding{OutID: outID, LineID: lineID, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	w = b.post("/nodes/out-unbind", url.Values{"out_id": {outID}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "已解绑") {
		t.Fatalf("unbind notice missing: %.300s", w.Body.String())
	}
	stored, err := app.store.GetOutBinding(outID)
	if err != nil || stored.LineID != "" || stored.Enabled {
		t.Fatalf("unbind did not release the Line: %+v err=%v", stored, err)
	}
}
