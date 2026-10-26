package handler

// /policies snapshot for issue #10: rows rendered from each layer's active
// revision, falling back to the mesh-derived and built-in defaults. Nothing
// here stores or publishes a policy; server-layer writes are the policy API and
// publication is 10d-2b. The client layer is read-only since Task 6, so its
// rows are always a preview of a legacy (or default) revision.

import (
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
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
func (app *Server) policySnapshot(now time.Time) (view.PolicyPageView, compiler.ClientPolicy, bool) {
	out := app.policyOutState(now)
	_, clientIntent, clientErr := app.ActivePolicyIntent(store.PolicyLayerClient)
	_, serverIntent, serverErr := app.ActivePolicyIntent(store.PolicyLayerServer)
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
	return view.PolicyPageView{
		Out: out, Client: policyClientRows(policy), Server: policyServerRows(server, out),
		Conflicts: policyConflictRows(policy), ClientDefault: clientErr != nil, ServerDefault: serverErr != nil,
	}, policy, true
}

func (app *Server) ActivePolicyIntent(layer store.PolicyLayer) (store.RoutePolicy, store.RoutePolicyPayload, error) {
	return app.store.ActivePolicyIntent(layer)
}

// policyFallbackView is the draft fallback before any active revision or mesh
// data exists; it says so on the page.
func policyFallbackView() view.PolicyPageView {
	page := view.PoliciesDraftView()
	page.Draft, page.ClientDefault, page.ServerDefault = true, true, true
	return page
}

// policyBrokenView never renders an active payload that failed re-validation
// as live policy; it shows the draft plus the blocking conflict.
func policyBrokenView(err error) view.PolicyPageView {
	page := view.PoliciesDraftView()
	page.Draft = true
	page.Conflicts = []view.PolicyConflictView{{Detail: "当前 active 策略未通过复核：" + policyErrorDetail(err), Blocked: true}}
	return page
}

// policyMeshModel reuses the read-only mesh preflight; it mints no key.
func (app *Server) policyMeshModel(now time.Time) (subscription.MeshConfigModel, bool) {
	devices, err := app.store.ListMeshDevices()
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
func (app *Server) policyOutState(now time.Time) view.PolicyOutState {
	nodes, err := app.store.ListNodesAt(now)
	if err != nil {
		return view.PolicyOutAbsent
	}
	state := view.PolicyOutAbsent
	for _, node := range nodes {
		if node.Role != "edge" {
			continue
		}
		facts, err := app.store.OutEgressFacts(node.ID, now)
		if err != nil || !facts.Configured {
			continue
		}
		if !facts.Available {
			return view.PolicyOutDegraded
		}
		state = view.PolicyOutActive
	}
	return state
}

func policyClientRows(policy compiler.ClientPolicy) []view.PolicyRuleView {
	rows := make([]view.PolicyRuleView, 0, len(policy.Rules)+1)
	for _, rule := range policy.Rules {
		rows = append(rows, view.PolicyRuleView{
			Match:  policyMatcherLabel(rule.Match),
			Action: policyActionLabel(rule.Action),
			Note:   policyRuleNote(rule),
			// The client layer has no consumer in this release, so its rows
			// read as preview instead of claiming they are in effect.
			State: "预览",
		})
	}
	return append(rows, view.PolicyRuleView{
		Match:  "兜底（未命中任何规则）",
		Action: policyActionLabel(policy.Default),
		Note:   "客户端层兜底固定为 Line，规则停用后流量回到兜底而不是断网。",
		State:  "预览",
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
func policyServerRows(policy compiler.ServerPolicy, out view.PolicyOutState) []view.PolicyRuleView {
	action, note := "Line 直出", "未配置 Out 不是错误：AI 与指定分流按 Line 直出，不生成指向 Out 的规则。"
	if out == view.PolicyOutActive {
		action, note = "Out 直出（可选）", "经 Out 直出；Out 不可用时按 fail-closed 处理，不会自动改走 Line。"
	}
	if out == view.PolicyOutDegraded {
		action, note = "Out 故障 · fail-closed", "Out 故障：指定到 Out 的分流进入 fail-closed，拒绝转发且不隐式回落 Line 直出。"
	}
	rows := make([]view.PolicyRuleView, 0, len(policy.Rules)+1)
	for _, rule := range policy.Rules {
		row := view.PolicyRuleView{Match: policyMatcherLabel(rule.Match), Action: "Line 直出", Note: note, State: "启用"}
		if rule.Action == compiler.ActionOut {
			row.Action = action
		}
		rows = append(rows, row)
	}
	return append(rows, view.PolicyRuleView{Match: "兜底（默认出口）", Action: "Line 直出", Note: "服务端层兜底固定为 Line；Out 故障只影响指定到 Out 的流量。", State: "启用"})
}

func policyConflictRows(policy compiler.ClientPolicy) []view.PolicyConflictView {
	if err := policy.Validate(); err != nil {
		return []view.PolicyConflictView{{Detail: policyErrorDetail(err), Blocked: true}}
	}
	return []view.PolicyConflictView{{Detail: "当前生效的客户端策略通过优先级重叠与 DNS 一致性校验。", Blocked: false}}
}

// policiesPage renders the read-only snapshot.
func (app *Server) policiesPage(w http.ResponseWriter, r *http.Request, sess session) {
	view, _, _ := app.policySnapshot(app.now())
	app.renderPolicies(w, r, sess, view)
}

func (app *Server) renderPolicies(w http.ResponseWriter, r *http.Request, sess session, model view.PolicyPageView) {
	app.render(w, r, http.StatusOK, view.PoliciesPage(view.PageData{Title: "路由策略", Path: "/policies", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP, DirectProxy: app.cfg.DirectProxy}, model))
}

func policyErrorDetail(err error) string {
	code, detail := policyFailure(err)
	return code + " · " + detail
}
