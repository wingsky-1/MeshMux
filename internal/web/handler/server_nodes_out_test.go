package handler

import (
	"net/url"
	"strings"
	"testing"
	"time"
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
	if _, err := app.Store.SetLine(settings, now); err != nil {
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
	pool, err := app.Store.OutPool(app.Now())
	if err != nil || len(pool) != 1 || pool[0].Server != "out.example.invalid" || pool[0].Port != 9443 {
		t.Fatalf("stored transport wrong: %+v err=%v", pool, err)
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
	configureOut(t, app.Store, outID, now)
	markLineOnline(t, app.Store, lineID, now)
	markLineOnline(t, app.Store, outID, now)
	enableOutForLine(t, app.Store, outID, lineID, now)
	settleTasks(t, app.Store, outID)
	confirmChain(t, app.Store, outID, now)

	body := nodesPageBody(t, b)
	if !strings.Contains(body, "1 个被订阅选中") || !strings.Contains(body, lineID) {
		t.Fatalf("selected state not shown on nodes page: %.500s", body)
	}

	// First POST: no deletion, only the used-by confirm. The Line is named
	// because the subscription selects the Out for it.
	w := b.post("/nodes/out-delete", url.Values{"out_id": {outID}})
	requireStatus(t, w, 200)
	body = w.Body.String()
	if !strings.Contains(body, "确认删除出口") || !strings.Contains(body, lineID) {
		t.Fatalf("delete confirm does not name the used-by Line: %.500s", body)
	}
	if tables := tableExists(t, app.Store, "out_bindings"); tables {
		t.Fatal("the nodes page still projects a binding table the schema dropped")
	}

	// A confirmed delete is refused while a subscription still selects the Out:
	// the operator has to migrate the subscription first, and the refusal names
	// it. This is the same protection the retired /nodes/out/bind pair used to
	// provide, now enforced by the edge itself.
	w = b.post("/nodes/out-delete", url.Values{"out_id": {outID}, "confirm": {"1"}})
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "仍被订阅选中") {
		t.Fatalf("delete of a selected out = %.300s", w.Body.String())
	}

	// Unbind path: the page reports the live reference instead of silently
	// rewriting a subscription the operator did not open.
	w = b.post("/nodes/out-unbind", url.Values{"out_id": {outID}})
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "仍被订阅选中") {
		t.Fatalf("unbind of a selected out = %.300s", w.Body.String())
	}

	// Once the subscription stops selecting it, the release action succeeds. It does
	// NOT empty the ACL: the published set is the node membership (Ruling R10), so the
	// page only reports that the hub-side publication was refreshed.
	clearOutForLine(t, app.Store, lineID, now)
	w = b.post("/nodes/out-unbind", url.Values{"out_id": {outID}})
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "已解除") {
		t.Fatalf("unbind notice missing: %.300s", w.Body.String())
	}
	if subscribers, err := app.Store.OutAuthorizedSubscribers(outID); err != nil || len(subscribers) != 0 {
		t.Fatalf("unbind kept the out selected: %v err=%v", subscribers, err)
	}
	// The release is not a revocation: the Out chain still publishes the same
	// link key, so a client holding it stays admitted.
	preview, err := app.Store.PreviewOutAuthorization(outID, "")
	if err != nil || len(preview.LineIDs) != 0 {
		t.Fatalf("preview still names a selecting Line: %+v err=%v", preview, err)
	}
}

// TestOutUnbindCopyNamesLinkKeyAccess pins the copy of the release action after
// the source allowlist is retired: it must describe link-key access, never the
// deleted node-membership authorization or an ACL recompute.
func TestOutUnbindCopyNamesLinkKeyAccess(t *testing.T) {
	app, b, lineID, outID := nodesOutTestApp(t)
	now := time.Now()
	configureOut(t, app.Store, outID, now)
	markLineOnline(t, app.Store, lineID, now)
	markLineOnline(t, app.Store, outID, now)
	enableOutForLine(t, app.Store, outID, lineID, now)
	settleTasks(t, app.Store, outID)
	confirmChain(t, app.Store, outID, now)

	w := b.post("/nodes/out-unbind", url.Values{"out_id": {outID}})
	requireStatus(t, w, 409)
	refusal := w.Body.String()
	for _, stale := range []string{"节点成员制", "ACL 会随订阅自动重算", "随订阅自动重算", "ACL 已按空授权"} {
		if strings.Contains(refusal, stale) {
			t.Fatalf("the refusal still promises %q: %.500s", stale, refusal)
		}
	}
	if !strings.Contains(refusal, "link key") {
		t.Fatalf("the refusal does not name link-key access: %.500s", refusal)
	}

	clearOutForLine(t, app.Store, lineID, now)
	w = b.post("/nodes/out-unbind", url.Values{"out_id": {outID}})
	requireStatus(t, w, 200)
	notice := w.Body.String()
	for _, stale := range []string{"节点成员制", "空授权重算", "空授权下发", "ACL 会随订阅", "随订阅自动重算"} {
		if strings.Contains(notice, stale) {
			t.Fatalf("the release notice still claims %q: %.500s", stale, notice)
		}
	}
	if !strings.Contains(notice, "link key") {
		t.Fatalf("the release notice does not name link-key access: %.500s", notice)
	}
	if subscribers, err := app.Store.OutAuthorizedSubscribers(outID); err != nil || len(subscribers) != 0 {
		t.Fatalf("the release kept the out selected: %v err=%v", subscribers, err)
	}
}
