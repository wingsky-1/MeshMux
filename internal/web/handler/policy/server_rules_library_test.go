package policy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
)

func rulesLibraryApp(t *testing.T) *handlertest.Browser {
	t.Helper()
	app, _ := handlertest.TestApp(t)
	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)
	return b
}

// seedRuleSubscriber inserts the reference edge the used-by block and the
// delete guard share: a subscribers row plus a subscription_rules row. The
// table belongs to Task 4 and exists at schema 13; the columns are the Task-3
// contract (subscriber_id, rule_stable_key, rule_version, position) plus the
// Task-4 created_at.
func seedRuleSubscriber(t *testing.T, b *handlertest.Browser, subscriberID, subscriberName, stableKey string, version int) {
	t.Helper()
	db := b.App.Store.DB
	now := b.App.Now().Unix()
	if _, err := db.Exec(`INSERT INTO subscribers(id, display_name, state, revision, created_at, updated_at)
	  VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, subscriberID, subscriberName, "active", 1, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO subscription_rules(subscriber_id, rule_stable_key, rule_version, position, created_at)
	  VALUES(?,?,?,COALESCE((SELECT MAX(position)+1 FROM subscription_rules WHERE subscriber_id=?),0),?)`,
		subscriberID, stableKey, version, subscriberID, now); err != nil {
		t.Fatal(err)
	}
}

func createLibraryRule(t *testing.T, b *handlertest.Browser, key, name, action, kind, values string) *httptest.ResponseRecorder {
	t.Helper()
	return b.Post("/rules", url.Values{
		"stable_key": {key}, "name": {name}, "action": {action}, "matcher_kind": {kind}, "values": {values},
	})
}

func TestRulesLibraryPageShowsPresets(t *testing.T) {
	b := rulesLibraryApp(t)
	w := b.Req("GET", "/rules", nil, nil)
	handlertest.RequireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"规则库", "直连 · 中国大陆域名", "预置", "新建规则", "随版本迁移替换"} {
		if !strings.Contains(body, want) {
			t.Fatalf("library page missing %q: %.600s", want, body)
		}
	}
	// The page is admin-only like every other management surface.
	anon := &handlertest.Browser{App: b.App}
	handlertest.RequireStatus(t, anon.Req("GET", "/rules", nil, nil), http.StatusUnauthorized)
}

func TestRulesLibraryCreateAndReviseFlow(t *testing.T) {
	b := rulesLibraryApp(t)
	w := createLibraryRule(t, b, "proxy-ai", "AI 走代理", "proxy", "ruleset", "ai\n")
	handlertest.RequireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "已创建") {
		t.Fatalf("create notice missing: %.400s", w.Body.String())
	}
	w = b.Req("GET", "/rules", nil, nil)
	for _, want := range []string{"proxy-ai", "AI 走代理"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("created rule missing %q", want)
		}
	}
	// A match change is a new revision, never an edit.
	w = b.Post("/rules/revise", url.Values{
		"stable_key": {"proxy-ai"}, "name": {"AI 走代理 v2"}, "action": {"proxy"},
		"matcher_kind": {"ruleset"}, "values": {"ai\nai-video\n"},
	})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if body := w.Body.String(); !strings.Contains(body, "新版本 v2") || !strings.Contains(body, "旧版本订阅不受影响") {
		t.Fatalf("revise notice missing: %.400s", body)
	}
	w = b.Req("GET", "/rules", nil, nil)
	if body := w.Body.String(); !strings.Contains(body, "v2") || !strings.Contains(body, "AI 走代理 v2") {
		t.Fatalf("revised row not rendered: %.600s", body)
	}
}

func TestRulesLibraryRefusesBadWrites(t *testing.T) {
	b := rulesLibraryApp(t)
	for _, tc := range []struct {
		name, key, action, kind, values string
		status                          int
		code                            string
	}{
		{"preset namespace", "preset-evil", "direct", "geosite", "cn", http.StatusForbidden, "RULE_PRESET_IMMUTABLE"},
		{"preset revise", "preset-direct-cn", "proxy", "geosite", "cn", http.StatusForbidden, "RULE_PRESET_IMMUTABLE"},
		{"preset delete", "preset-direct-cn", "", "", "", http.StatusForbidden, "RULE_PRESET_IMMUTABLE"},
		{"preset delete step one", "preset-direct-cn", "", "", "", http.StatusForbidden, "RULE_PRESET_IMMUTABLE"},
		{"bad key", "Bad Key!", "direct", "geosite", "cn", http.StatusBadRequest, "RULE_INVALID"},
		{"bad action", "x-bad", "out", "geosite", "cn", http.StatusBadRequest, "RULE_INVALID"},
		{"bad kind", "x-bad", "direct", "ssid", "cn", http.StatusBadRequest, "RULE_INVALID"},
		{"bad value", "x-bad", "direct", "geosite", "CN", http.StatusBadRequest, "RULE_INVALID"},
		{"missing revision", "no-such-rule", "", "", "", http.StatusNotFound, "RULE_NOT_FOUND"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			switch {
			case strings.HasSuffix(tc.name, "revise"):
				rec = b.Post("/rules/revise", url.Values{
					"stable_key": {tc.key}, "name": {"改名"}, "action": {tc.action},
					"matcher_kind": {tc.kind}, "values": {tc.values},
				})
			case tc.name == "preset delete step one":
				// M1: the first step refuses a preset too — the page never
				// offers a delete confirm for a row that cannot be deleted.
				rec = b.Post("/rules/delete", url.Values{
					"stable_key": {tc.key}, "version": {"1"},
				})
			case strings.HasSuffix(tc.name, "delete"):
				rec = b.Post("/rules/delete", url.Values{
					"stable_key": {tc.key}, "version": {"1"}, "confirm": {"1"},
				})
			case strings.HasPrefix(tc.name, "missing"):
				rec = b.Post("/rules/delete", url.Values{
					"stable_key": {tc.key}, "version": {"1"}, "confirm": {"1"},
				})
			default:
				rec = createLibraryRule(t, b, tc.key, "坏输入", tc.action, tc.kind, tc.values)
			}
			handlertest.RequireStatus(t, rec, tc.status)
			if !strings.Contains(rec.Body.String(), tc.code) {
				t.Fatalf("body missing %q: %.300s", tc.code, rec.Body.String())
			}
		})
	}
}

func TestRulesLibraryDeleteProtectionListsSubscribers(t *testing.T) {
	b := rulesLibraryApp(t)
	handlertest.RequireStatus(t, createLibraryRule(t, b, "proxy-ai", "AI 走代理", "proxy", "ruleset", "ai\n"), http.StatusOK)
	seedRuleSubscriber(t, b, "sub-alice", "爱丽丝", "proxy-ai", 1)
	seedRuleSubscriber(t, b, "sub-bob", "鲍勃", "proxy-ai", 1)

	// Step one names the revision and re-renders the impacted subscriptions.
	w := b.Post("/rules/delete", url.Values{"stable_key": {"proxy-ai"}, "version": {"1"}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	for _, want := range []string{"爱丽丝", "鲍勃", "确认删除", "正被 2 个订阅引用"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("delete protection missing %q: %.600s", want, w.Body.String())
		}
	}
	// Step two with confirm is refused with the same names, and deletes nothing.
	w = b.Post("/rules/delete", url.Values{"stable_key": {"proxy-ai"}, "version": {"1"}, "confirm": {"1"}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	for _, want := range []string{"RULE_REFERENCED_BY_SUBSCRIPTIONS", "爱丽丝", "鲍勃"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("referenced refusal missing %q: %.300s", want, w.Body.String())
		}
	}
	w = b.Req("GET", "/rules", nil, nil)
	if !strings.Contains(w.Body.String(), "proxy-ai") {
		t.Fatal("referenced rule was deleted despite the refusal")
	}
	// An unreferenced revision deletes cleanly.
	w = b.Post("/rules/revise", url.Values{
		"stable_key": {"proxy-ai"}, "name": {"AI 走代理 v2"}, "action": {"proxy"},
		"matcher_kind": {"ruleset"}, "values": {"ai\n"},
	})
	handlertest.RequireStatus(t, w, http.StatusOK)
	w = b.Post("/rules/delete", url.Values{"stable_key": {"proxy-ai"}, "version": {"2"}, "confirm": {"1"}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "已删除") {
		t.Fatalf("delete notice missing: %.300s", w.Body.String())
	}
}
