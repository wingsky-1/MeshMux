package handler

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	corepolicy "github.com/wingsky-1/MeshMux/internal/core/policy"
	handlerpolicy "github.com/wingsky-1/MeshMux/internal/web/handler/policy"
)

func previewServerPolicy(t *testing.T, b *browser, body string) (handlerpolicy.PolicyServerPreviewResponse, int) {
	t.Helper()
	w := b.post("/policies/server/preview", url.Values{"preview": {body}})
	var response handlerpolicy.PolicyServerPreviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.OperationID == "" {
		t.Fatalf("preview body = %.300s err=%v", w.Body.String(), err)
	}
	return response, w.Code
}

func TestPoliciesServerPreview(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	cases := []struct {
		body     string
		status   int
		state    string
		code     string
		fragment string
	}{
		{`{"domains":["chat.example.invalid"],"out":{"configured":false}}`, 200, corepolicy.AIEgressLine, "", `"outbound": "direct"`},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"available":true}}`, 200, corepolicy.AIEgressOut, "", `"outbound": "out"`},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"available":true,"external_declared":true}}`, 200, corepolicy.AIEgressOut, "LINE_EGRESS_EXTERNAL_DECLARED", `"outbound": "out"`},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true}}`, 409, "", corepolicy.CodeOutOfflineFailClosed, ""},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"fallback_to_line":true}}`, 409, "", corepolicy.CodeOutFallbackUnaudited, ""},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"fallback_to_line":true,"operation_id":"preview-op"}}`, 200, corepolicy.AIEgressLineFallback, corepolicy.CodeOutOfflineFailClosed, `"outbound": "direct"`},
		{`{"ai_ruleset":"ai"}`, 422, "", corepolicy.CodeRulesetUnpinned, ""},
		{`not json`, 400, "", corepolicy.CodePolicyInvalid, ""},
	}
	for _, tc := range cases {
		response, status := previewServerPolicy(t, b, tc.body)
		code := response.ErrorCode
		if response.OK {
			code = response.EgressCode
		}
		if status != tc.status || response.OK != (tc.status == 200) || response.EgressState != tc.state ||
			code != tc.code || !strings.Contains(response.RouteFragmentPreview, tc.fragment) {
			t.Fatalf("preview %s = %+v status=%d", tc.body, response, status)
		}
	}
}
