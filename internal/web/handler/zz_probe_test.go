package handler

import (
	"net/url"
	"strings"
	"testing"
)

// Probe U: can the "可升级（不自动迁移）" hint EVER render? LatestRules()
// returns only the newest version per key, so latest[key] == rule.Version.
func TestProbeUpgradeHintIsDead(t *testing.T) {
	app, b, _ := wizardApp(t)
	// R1: the fixture Line is unused by this probe; keep creating it so the
	// scenario still has one Line, but discard the value so the package compiles
	// (the committed probe failed vet with "declared and not used").
	_ = wizardLine(t, app, "hk-01")
	require2xx(t, b.Post("/rules", url.Values{
		"stable_key": {"my-cn"}, "name": {"我的直连"},
		"action": {"direct"}, "matcher_kind": {"domain"}, "values": {"a.example.invalid"},
	}))
	require2xx(t, b.Post("/rules/revise", url.Values{
		"stable_key": {"my-cn"}, "name": {"我的直连 v2"},
		"action": {"direct"}, "matcher_kind": {"domain"}, "values": {"a.example.invalid"},
	}))
	w := b.Req("GET", "/subscribers/wizard", nil, nil)
	body := w.Body.String()
	t.Logf("wizard renders '可升级' hint? %v", strings.Contains(body, "可升级"))
	t.Logf("wizard offers my-cn@1 (the pinned old revision)? %v", strings.Contains(body, `name="rule_my-cn@1"`))
	t.Logf("wizard offers my-cn@2 (the new revision)? %v", strings.Contains(body, `name="rule_my-cn@2"`))
}
