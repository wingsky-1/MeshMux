package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/route"
)

func previewServerPolicy(t *testing.T, b *browser, body string) (policyServerPreviewResponse, int) {
	t.Helper()
	w := b.post("/policies/server/preview", url.Values{"preview": {body}})
	var response policyServerPreviewResponse
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
		{`{"domains":["chat.example.invalid"],"out":{"configured":false}}`, 200, route.AIEgressLine, "", `"outbound": "direct"`},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"available":true}}`, 200, route.AIEgressOut, "", `"outbound": "out"`},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true}}`, 409, "", route.CodeOutOfflineFailClosed, ""},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"fallback_to_line":true}}`, 409, "", route.CodeOutFallbackUnaudited, ""},
		{`{"domains":["chat.example.invalid"],"out":{"configured":true,"fallback_to_line":true,"operation_id":"preview-op"}}`, 200, route.AIEgressLineFallback, route.CodeOutOfflineFailClosed, `"outbound": "direct"`},
		{`{"ai_ruleset":"ai"}`, 422, "", compiler.CodeRulesetUnpinned, ""},
		{`not json`, 400, "", compiler.CodePolicyInvalid, ""},
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

func TestPolicyServerPreviewEgressStateMatchesDecision(t *testing.T) {
	pin, fetch := aiRulesetFixture(t)
	line, out := strings.Repeat("a", 32), strings.Repeat("b", 32)
	cases := []struct {
		out  policyServerPreviewOut
		req  route.AIEgressRequest
		want string
	}{
		{policyServerPreviewOut{}, route.AIEgressRequest{LineID: line}, route.AIEgressLine},
		{policyServerPreviewOut{Configured: true, Available: true},
			route.AIEgressRequest{LineID: line, OutID: out, OutConfigured: true, OutAvailable: true, Pin: pin}, route.AIEgressOut},
		{policyServerPreviewOut{Configured: true},
			route.AIEgressRequest{LineID: line, OutID: out, OutConfigured: true, OutCode: "OUT_OFFLINE"}, "fail-closed"},
	}
	for _, tc := range cases {
		if state, _ := previewEgressState(tc.out); state != tc.want {
			t.Fatalf("preview state = %s, want %s", state, tc.want)
		}
		decision, err := route.DecideAIEgressWithFetcher(context.Background(), fetch, tc.req)
		if tc.want == "fail-closed" {
			var blocked *route.BlockedError
			if !errors.As(err, &blocked) || blocked.Code != route.CodeOutOfflineFailClosed {
				t.Fatalf("decision error = %v, want fail-closed", err)
			}
		} else if err != nil || decision.Mode != tc.want {
			t.Fatalf("decision = %+v err=%v, want %s", decision, err, tc.want)
		}
	}
}
