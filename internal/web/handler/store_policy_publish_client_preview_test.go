package handler

// Issue #113 1-2: the client policy layer has no consumer. The publication
// truth is the server route; the client documents are a rendered, gated
// preview. These tests pin the two halves of that contract:
//
//   - the receipt of a client publication never claims that a download follows
//     the active client revision, and
//   - publishing a legacy client revision leaves the subscription bytes
//     byte-identical, even after a server publication is applied. The client
//     layer is read-only since Task 6, so the fixture seeds a legacy row
//     directly instead of writing through the retired API.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/web/handler/subscription"
)

// previewSeed stores one converged Line whose confirmed candidate carries
// exactly the subscriber's credential, so the public download gate passes. It
// reuses the subscription fixture verbatim and returns the Line and bearer.
func previewSeed(t *testing.T, app *Server) (string, string) {
	t.Helper()
	lineID, _, _, bearer, _ := downloadFixture(t, app, app.Now())
	return lineID, bearer
}

// subscriptionBytes downloads one fixed format and returns the body.
func subscriptionBytes(t *testing.T, app *Server, bearer, format string) string {
	t.Helper()
	w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/"+format)
	if w.Code != http.StatusOK {
		t.Fatalf("%s download = %d: %s", format, w.Code, w.Body.String())
	}
	return w.Body.String()
}

// TestClientPolicyPublishIsPreviewAndKeepsDownloadBytes proves the honest
// boundary end to end: a client publication is reported as a gated preview,
// and no client policy revision ever reaches the standard export.
func TestClientPolicyPublishIsPreviewAndKeepsDownloadBytes(t *testing.T) {
	b, _ := publishApp(t)
	line, bearer := previewSeed(t, b.app)
	singBoxBefore := subscriptionBytes(t, b.app, bearer, subscription.SingBoxFormat)
	mihomoBefore := subscriptionBytes(t, b.app, bearer, subscription.MihomoFormat)
	// The baseline must be a real export, not an empty body: otherwise
	// "unchanged" would prove nothing.
	if !strings.Contains(singBoxBefore, `"meshmux-selector"`) || !strings.Contains(mihomoBefore, "PROXY") {
		t.Fatal("the baseline download is not the standard export")
	}

	activateViaAPI(t, b, "client",
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)
	receipt := publishReceipt(t, postPublish(t, b, `{"layer":"client","operation_id":"op-publish-client"}`), http.StatusOK)
	if !receipt.OK || receipt.Status != "gated" {
		t.Fatalf("client-only receipt = %+v", receipt)
	}
	if receipt.Candidate != nil || receipt.Revision != 1 {
		t.Fatalf("client-only receipt invented a candidate: %+v", receipt)
	}
	// The old text claimed the download renders the active revision. The
	// client layer has no consumer, so the receipt must say the opposite.
	if !strings.Contains(receipt.NextAction, "不改变订阅下载内容") {
		t.Fatalf("client-only next_action does not mark the preview: %q", receipt.NextAction)
	}
	if strings.Contains(receipt.NextAction, "订阅下载时按当前 active 版本渲染") {
		t.Fatalf("client-only next_action still claims a download follows the revision: %q", receipt.NextAction)
	}
	if len(receipt.Checks) != 2 {
		t.Fatalf("client-only checks = %+v, want both kernels", receipt.Checks)
	}

	// A second legacy client revision is seeded (the layer is read-only, so the
	// fixture is the only writer) and published. It still must not move a byte
	// of either download.
	activateViaAPI(t, b, "client",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["other.example.invalid"]},"action":"proxy"}]}`)
	second := publishReceipt(t, postPublish(t, b, `{"layer":"client","operation_id":"op-publish-client-2"}`), http.StatusOK)
	if second.Status != "gated" || second.Candidate != nil {
		t.Fatalf("second client receipt = %+v", second)
	}
	if got := subscriptionBytes(t, b.app, bearer, subscription.SingBoxFormat); got != singBoxBefore {
		t.Fatalf("a client publication changed the sing-box download:\n%s\n---\n%s", singBoxBefore, got)
	}
	if got := subscriptionBytes(t, b.app, bearer, subscription.MihomoFormat); got != mihomoBefore {
		t.Fatal("a client publication changed the mihomo download")
	}

	// A mixed publication stores the server candidate and gates the client
	// preview next to it. Its receipt must name both halves honestly: queued
	// server work, and a client preview that still changes no download.
	activateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`)
	mixed := publishReceipt(t, postPublish(t, b, `{"operation_id":"op-publish-both"}`), http.StatusOK)
	if !mixed.OK || mixed.Status != "queued" || mixed.Candidate == nil {
		t.Fatalf("mixed receipt = %+v", mixed)
	}
	if !strings.Contains(mixed.NextAction, "客户端层不写节点候选") {
		t.Fatalf("mixed next_action hides the client preview: %q", mixed.NextAction)
	}
	// The queued server candidate needs its own readback before the download
	// gate reopens; the client layer is not what unblocks it.
	settleTasks(t, b.app.Store, line)
	confirmChain(t, b.app.Store, line, b.app.Now())
	if got := subscriptionBytes(t, b.app, bearer, subscription.SingBoxFormat); got != singBoxBefore {
		t.Fatal("the applied server publication changed the sing-box download")
	}
	if got := subscriptionBytes(t, b.app, bearer, subscription.MihomoFormat); got != mihomoBefore {
		t.Fatal("the applied server publication changed the mihomo download")
	}
}

// TestPoliciesPageMarksClientLayerAsPreview proves the operator reads the same
// boundary on the page: the client panel is labelled as a preview that does not
// change the subscription, and no client row claims to be in effect.
func TestPoliciesPageMarksClientLayerAsPreview(t *testing.T) {
	b := policyWriteApp(t)
	activateViaAPI(t, b, "client",
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)
	w := b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"预览 · 不改变订阅", "没有消费者", "不读取客户端层", "不包含这些规则"} {
		if !strings.Contains(body, want) {
			t.Fatalf("client preview is not labelled on /policies (%q missing): %.600s", want, body)
		}
	}
	if strings.Contains(body, "订阅下载时按同一 active 版本渲染") {
		t.Fatalf("/policies still promises the client layer reaches the download: %.400s", body)
	}
}
