package handler

import (
	"encoding/json"
	"fmt"
	"github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func policyWriteApp(t *testing.T) *browser {
	t.Helper()
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return b
}

func postPolicy(t *testing.T, b *browser, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return b.post(path, url.Values{"policy": {body}})
}

func policyReceipt(t *testing.T, w *httptest.ResponseRecorder, status int) policy.PolicyWriteResponse {
	t.Helper()
	requireStatus(t, w, status)
	var out policy.PolicyWriteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("write response: %v %.300s", err, w.Body.String())
	}
	return out
}

func TestPolicyWriteAPILifecycle(t *testing.T) {
	b := policyWriteApp(t)
	_, server, pins := policyFixtures()
	created := policyReceipt(t, postPolicy(t, b, "/policies",
		fmt.Sprintf(`{"layer":"server","name":"服务端默认策略","payload":%s,"pins":%s,"operation_id":"op-create"}`, server, pins)), http.StatusCreated)
	if !created.OK || created.ID == "" || created.Revision != 1 || created.Status != "draft" || created.OperationID == "" {
		t.Fatalf("create = %+v", created)
	}
	revised := policyReceipt(t, postPolicy(t, b, "/policies/revise",
		fmt.Sprintf(`{"id":%q,"payload":%s,"pins":%s,"operation_id":"op-revise"}`, created.ID, server, pins)), http.StatusOK)
	if revised.Revision != 2 || revised.Status != "draft" {
		t.Fatalf("revise = %+v", revised)
	}
	active := policyReceipt(t, postPolicy(t, b, "/policies/activate",
		fmt.Sprintf(`{"id":%q,"revision":2,"operation_id":"op-activate"}`, created.ID)), http.StatusOK)
	if active.Revision != 2 || active.Status != "active" {
		t.Fatalf("activate = %+v", active)
	}
	// Activating a superseded revision must be refused, not silently revived.
	refused := policyReceipt(t, postPolicy(t, b, "/policies/activate",
		fmt.Sprintf(`{"id":%q,"revision":1,"operation_id":"op-old"}`, created.ID)), http.StatusConflict)
	if refused.ErrorCode != "POLICY_STATE_INVALID" || refused.OperationID == "" {
		t.Fatalf("old revision activation = %+v", refused)
	}
	revoked := policyReceipt(t, postPolicy(t, b, "/policies/revoke",
		fmt.Sprintf(`{"id":%q,"revision":2,"operation_id":"op-revoke"}`, created.ID)), http.StatusOK)
	if revoked.Status != "revoked" {
		t.Fatalf("revoke = %+v", revoked)
	}
	// The client layer stays readable but is closed to the write API.
	clientID := seedLegacyClientPolicy(t, b,
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)
	for _, request := range []struct {
		path, body string
	}{
		{"/policies/revise", fmt.Sprintf(`{"id":%q,"payload":%s,"operation_id":"op-client"}`, clientID, server)},
		{"/policies/activate", fmt.Sprintf(`{"id":%q,"revision":1,"operation_id":"op-client"}`, clientID)},
		{"/policies/revoke", fmt.Sprintf(`{"id":%q,"revision":1,"operation_id":"op-client"}`, clientID)},
		{"/policies", fmt.Sprintf(`{"layer":"client","name":"客户端默认策略","payload":%s,"operation_id":"op-client"}`, server)},
	} {
		w := postPolicy(t, b, request.path, request.body)
		got := policyReceipt(t, w, http.StatusConflict)
		if got.ErrorCode != "POLICY_LAYER_RETIRED" {
			t.Fatalf("%s client write = %+v, want POLICY_LAYER_RETIRED", request.path, got)
		}
		if !strings.Contains(w.Body.String(), "规则库") {
			t.Fatalf("%s client write does not point at the rule library: %.300s", request.path, w.Body.String())
		}
	}
}

func TestPolicyWriteAPIRejectsBadRequests(t *testing.T) {
	b := policyWriteApp(t)
	_, server, _ := policyFixtures()
	for _, tc := range []struct {
		name, path, body string
		status           int
		code             string
	}{
		{"missing operation id", "/policies", fmt.Sprintf(`{"layer":"server","name":"x","payload":%s}`, server), http.StatusBadRequest, "POLICY_OPERATION_REQUIRED"},
		{"illegal layer", "/policies", fmt.Sprintf(`{"layer":"mesh","name":"x","payload":%s,"operation_id":"op"}`, server), http.StatusBadRequest, "POLICY_LAYER_INVALID"},
		{"retired exceptions", "/policies", `{"layer":"server","name":"x","payload":{"default":"direct","rules":[],"exceptions":["news.example.invalid"]},"operation_id":"op"}`, http.StatusBadRequest, "POLICY_PAYLOAD_RETIRED"},
		{"revise missing operation id", "/policies/revise", fmt.Sprintf(`{"id":"pol_missing","payload":%s}`, server), http.StatusBadRequest, "POLICY_OPERATION_REQUIRED"},
		{"activate missing operation id", "/policies/activate", `{"id":"pol_missing","revision":1}`, http.StatusBadRequest, "POLICY_OPERATION_REQUIRED"},
		{"revoke missing operation id", "/policies/revoke", `{"id":"pol_missing","revision":1}`, http.StatusBadRequest, "POLICY_OPERATION_REQUIRED"},
		{"unknown policy", "/policies/revise", fmt.Sprintf(`{"id":"pol_missing","payload":%s,"operation_id":"op"}`, server), http.StatusNotFound, "POLICY_NOT_FOUND"},
		{"malformed json", "/policies", "{not json", http.StatusBadRequest, "POLICY_PAYLOAD_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyReceipt(t, postPolicy(t, b, tc.path, tc.body), tc.status); got.ErrorCode != tc.code {
				t.Fatalf("error_code = %q, want %q", got.ErrorCode, tc.code)
			}
		})
	}
}

func TestPoliciesPageActiveAndBrokenSnapshots(t *testing.T) {
	b := policyWriteApp(t)
	w := b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "默认预览") {
		t.Fatalf("default snapshot is not labelled: %.400s", w.Body.String())
	}
	create := func(layer, payload string) string {
		return policyReceipt(t, postPolicy(t, b, "/policies",
			fmt.Sprintf(`{"layer":%q,"name":"策略-%s","payload":%s,"operation_id":"op-create"}`, layer, layer, payload)), http.StatusCreated).ID
	}
	activate := func(id string) {
		policyReceipt(t, postPolicy(t, b, "/policies/activate",
			fmt.Sprintf(`{"id":%q,"revision":1,"operation_id":"op-activate"}`, id)), http.StatusOK)
	}
	client := `{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`
	server := `{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`
	clientID := seedLegacyClientPolicy(t, b, client)
	activate(create("server", server))

	w = b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"域名例外（news.example.invalid）", "域名例外（ai.example.invalid）", "当前生效的客户端策略通过"} {
		if !strings.Contains(body, want) {
			t.Fatalf("active snapshot missing %q: %.500s", want, body)
		}
	}
	if strings.Contains(body, "默认预览") || strings.Contains(body, "当前没有可用的真实策略数据") {
		t.Fatalf("active snapshot still showed a fallback: %.400s", body)
	}

	// A stored payload that no longer validates is never rendered as live.
	broken := `{"default":"proxy","rules":[{"priority":200,"match":{"domains":["news.example.invalid"]},"action":"direct"},{"priority":100,"match":{"domains":["other.example.invalid"]},"action":"direct"}]}`
	if _, err := b.app.Store.DB.Exec(`UPDATE route_policies SET payload=? WHERE id=? AND revision=1`, broken, clientID); err != nil {
		t.Fatal(err)
	}
	w = b.req("GET", "/policies", nil, nil)
	requireStatus(t, w, http.StatusOK)
	for _, want := range []string{"当前 active 策略未通过复核", "当前没有可用的真实策略数据"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("broken active snapshot missing %q: %.500s", want, w.Body.String())
		}
	}
}
