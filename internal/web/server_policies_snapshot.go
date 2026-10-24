package web

// /policies snapshot for issue #10: rows rendered from each layer's active
// revision, falling back to the mesh-derived and built-in defaults. Nothing
// here stores or publishes a policy; writes are 10d-2a and publication 10d-2b.

import (
	"net/http"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// defaultServerAIRulesetTag is the canonical AI ruleset tag; its pin is 10d.
const defaultServerAIRulesetTag = "ai"

// policySnapshot builds the page from the active stored revisions; a layer
// without one falls back to the read-only mesh model (client) and
// DefaultServerPolicy (server). An active payload that no longer validates is
// never presented as live: the page shows the design draft and the conflict.
func (app *Server) policySnapshot(now time.Time) (policyPageView, compiler.ClientPolicy, bool) {
	out := app.policyOutState(now)
	_, clientIntent, clientErr := app.activePolicyIntent(PolicyLayerClient)
	_, serverIntent, serverErr := app.activePolicyIntent(PolicyLayerServer)
	for _, err := range []error{clientErr, serverErr} {
		if err != nil && !strings.HasPrefix(err.Error(), "POLICY_NOT_FOUND") {
			return policyBrokenView(err), compiler.ClientPolicy{}, false
		}
	}
	var policy compiler.ClientPolicy
	if clientErr == nil {
		policy = compiler.ClientPolicy{Default: clientIntent.Default, Rules: clientIntent.Rules}
		if err := policy.Validate(); err != nil {
			return policyBrokenView(err), compiler.ClientPolicy{}, false
		}
	} else {
		model, ok := app.policyMeshModel(now)
		if !ok {
			return policyFallbackView(), compiler.ClientPolicy{}, false
		}
		var err error
		if policy, err = compiler.DefaultClientPolicy(model, model.LineLabels[0], compiler.ClientDefaults{}); err != nil {
			return policyFallbackView(), compiler.ClientPolicy{}, false
		}
	}
	var server compiler.ServerPolicy
	if serverErr == nil {
		server = compiler.ServerPolicy{Default: serverIntent.Default, Rules: serverIntent.Rules}
		if err := server.Validate(); err != nil {
			return policyBrokenView(err), compiler.ClientPolicy{}, false
		}
	} else if server, serverErr = compiler.DefaultServerPolicy(defaultServerAIRulesetTag, nil, nil); serverErr != nil {
		return policyFallbackView(), compiler.ClientPolicy{}, false
	}
	return policyPageView{
		Out: out, Client: policyClientRows(policy), Server: policyServerRows(server, out),
		Conflicts: policyConflictRows(policy), ClientDefault: clientErr != nil, ServerDefault: serverErr != nil,
	}, policy, true
}

// activePolicyIntent reads one layer's active revision and decodes its payload.
func (app *Server) activePolicyIntent(layer PolicyLayer) (RoutePolicy, routePolicyPayload, error) {
	return app.store.activePolicyIntent(layer)
}

// activePolicyIntent reads one layer's active revision and decodes its payload.
// It is the single reader of the active intent, so the page, the publish
// pipeline and an implicit route derivation can never disagree about which
// revision is live.
func (s *store) activePolicyIntent(layer PolicyLayer) (RoutePolicy, routePolicyPayload, error) {
	record, err := s.activeRoutePolicy(layer)
	return activePolicyIntentOf(record, err)
}

// policyFallbackView is the draft fallback before any active revision or mesh
// data exists; it says so on the page.
func policyFallbackView() policyPageView {
	view := policiesDraftView()
	view.Draft, view.ClientDefault, view.ServerDefault = true, true, true
	return view
}

// policyBrokenView never renders an active payload that failed re-validation
// as live policy; it shows the draft plus the blocking conflict.
func policyBrokenView(err error) policyPageView {
	view := policiesDraftView()
	view.Draft = true
	view.Conflicts = []policyConflictView{{Detail: "当前 active 策略未通过复核：" + policyErrorDetail(err), Blocked: true}}
	return view
}

// policyMeshModel reuses the read-only mesh preflight; it mints no key.
func (app *Server) policyMeshModel(now time.Time) (subscription.MeshConfigModel, bool) {
	devices, err := app.store.listMeshDevices()
	if err != nil {
		return subscription.MeshConfigModel{}, false
	}
	for _, device := range devices {
		if device.Purpose != mesh.PurposeProxyMesh || device.SubscriberID == "" {
			continue
		}
		plan, err := app.meshConfigPreflight(device, now)
		if err == nil && len(plan.Model.LineLabels) > 0 {
			return plan.Model, true
		}
	}
	return subscription.MeshConfigModel{}, false
}

// policyOutState aggregates the read-only Out projection over all edge Lines:
// a configured-but-unavailable Out is degraded and outranks a healthy one.
func (app *Server) policyOutState(now time.Time) policyOutState {
	nodes, err := app.store.listNodesAt(now)
	if err != nil {
		return policyOutAbsent
	}
	state := policyOutAbsent
	for _, node := range nodes {
		if node.Role != "edge" {
			continue
		}
		facts, err := app.store.OutEgressFacts(node.ID, now)
		if err != nil || !facts.Configured {
			continue
		}
		if !facts.Available {
			return policyOutDegraded
		}
		state = policyOutActive
	}
	return state
}

func policyClientRows(policy compiler.ClientPolicy) []policyRuleView {
	rows := make([]policyRuleView, 0, len(policy.Rules)+1)
	for _, rule := range policy.Rules {
		rows = append(rows, policyRuleView{
			Match:  policyMatcherLabel(rule.Match),
			Action: policyActionLabel(rule.Action),
			Note:   policyRuleNote(rule),
			State:  "启用",
		})
	}
	return append(rows, policyRuleView{
		Match:  "兜底（未命中任何规则）",
		Action: policyActionLabel(policy.Default),
		Note:   "客户端层兜底固定为 Line，规则停用后流量回到兜底而不是断网。",
		State:  "启用",
	})
}

func policyMatcherLabel(match compiler.Match) string {
	switch {
	case len(match.SSIDs) > 0:
		return "家庭 Wi-Fi SSID（" + strings.Join(match.SSIDs, "、") + "）"
	case len(match.IPCIDRs) > 0:
		return "Tailnet / 指定网段（" + strings.Join(match.IPCIDRs, "、") + "）"
	case len(match.GeoSite) > 0:
		return "地区规则（" + strings.Join(match.GeoSite, "、") + "）"
	case len(match.GeoIP) > 0:
		return "地区 IP（" + strings.Join(match.GeoIP, "、") + "）"
	case len(match.RuleSets) > 0:
		return "规则集（" + strings.Join(match.RuleSets, "、") + "）"
	case len(match.DomainSuffixes) > 0:
		return "域名后缀（" + strings.Join(match.DomainSuffixes, "、") + "）"
	case len(match.Domains) > 0:
		return "域名例外（" + strings.Join(match.Domains, "、") + "）"
	default:
		return "未配置匹配条件"
	}
}

func policyActionLabel(action compiler.Action) string {
	switch action {
	case compiler.ActionDirect:
		return "直连"
	case compiler.ActionProxy:
		return "走 Line"
	case compiler.ActionTailscale:
		return "直连（Tailnet）"
	case compiler.ActionOut:
		return "Out 直出（可选）"
	default:
		return string(action)
	}
}

func policyRuleNote(rule compiler.Rule) string {
	switch rule.Action {
	case compiler.ActionTailscale:
		return "Mesh 内网目标始终直连，防止私有网络流量绕出。"
	case compiler.ActionDirect:
		if rule.Match.DNS == compiler.DNSDomestic {
			return "按地区或例外直连，并使用境内 DNS 解析。"
		}
		return "命中后整体直连，流量不进入代理。"
	default:
		return "境外目标经 Line 转发；DNS 使用加密解析，解析出口与访问出口一致。"
	}
}

// policyServerRows renders the default server intent; an absent Out never
// promises one.
func policyServerRows(policy compiler.ServerPolicy, out policyOutState) []policyRuleView {
	action, note := "Line 直出", "未配置 Out 不是错误：AI 与指定分流按 Line 直出，不生成指向 Out 的规则。"
	if out == policyOutActive {
		action, note = "Out 直出（可选）", "经 Out 直出；Out 不可用时按 fail-closed 处理，不会自动改走 Line。"
	}
	if out == policyOutDegraded {
		action, note = "Out 故障 · fail-closed", "Out 故障：指定到 Out 的分流进入 fail-closed，拒绝转发且不隐式回落 Line 直出。"
	}
	rows := make([]policyRuleView, 0, len(policy.Rules)+1)
	for _, rule := range policy.Rules {
		row := policyRuleView{Match: policyMatcherLabel(rule.Match), Action: "Line 直出", Note: note, State: "启用"}
		if rule.Action == compiler.ActionOut {
			row.Action = action
		}
		rows = append(rows, row)
	}
	return append(rows, policyRuleView{Match: "兜底（默认出口）", Action: "Line 直出", Note: "服务端层兜底固定为 Line；Out 故障只影响指定到 Out 的流量。", State: "启用"})
}

func policyConflictRows(policy compiler.ClientPolicy) []policyConflictView {
	if err := policy.Validate(); err != nil {
		return []policyConflictView{{Detail: policyErrorDetail(err), Blocked: true}}
	}
	return []policyConflictView{{Detail: "当前生效的客户端策略通过优先级重叠与 DNS 一致性校验。", Blocked: false}}
}

// policiesPage renders the read-only snapshot.
func (app *Server) policiesPage(w http.ResponseWriter, r *http.Request, sess session) {
	view, _, _ := app.policySnapshot(app.now())
	app.renderPolicies(w, r, sess, view)
}

func (app *Server) renderPolicies(w http.ResponseWriter, r *http.Request, sess session, view policyPageView) {
	app.render(w, r, http.StatusOK, PoliciesPage(pageData{Title: "路由策略", Path: "/policies", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP, DirectProxy: app.cfg.DirectProxy}, view))
}

func policyErrorDetail(err error) string {
	code, detail := policyFailure(err)
	return code + " · " + detail
}
