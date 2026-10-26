package view

import (
	"fmt"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/policy"
)

// views_policies.go holds the display-only view model for the /policies page.
// The server fills the snapshot from each layer's active revision, falling back
// to the mesh-derived and built-in defaults; PoliciesDraftView remains the
// no-data fallback. The page renders no publication control: publishing is
// 10d-2b (see docs/UX.zh-CN.md 交互安全性).

// PolicyOutState is the tri-state display of the optional Out egress.
type PolicyOutState string

const (
	// Out 未配置：可选节点缺失不是错误，不生成指向 Out 的规则。
	PolicyOutAbsent PolicyOutState = "absent"
	// Out 已接入且健康：指定分流优先经 Out 直出。
	PolicyOutActive PolicyOutState = "active"
	// Out 故障：fail-closed，不隐式回落 Line 直出。
	PolicyOutDegraded PolicyOutState = "degraded"
)

// PolicyRuleView is one display row of a policy layer.
type PolicyRuleView struct {
	Match  string // 匹配条件：SSID、Tailnet 网段、地区、域名、CIDR、规则集
	Action string // 动作：直连 / 走 Line / Out 直出（可选）/ 分流解析
	Note   string // 一句话命中说明
	State  string // 展示状态：启用 / 停用 / 例外
}

// PolicyConflictView is one priority-overlap display row.
type PolicyConflictView struct {
	Detail  string // 冲突说明
	Blocked bool   // true：保存时会被校验拦截；false：示例通过
}

// PolicyHitStep is one stage of the fixed hit explanation chain
// (规则 → 动作 → 实际出口 → DNS). The full simulator stays out of scope.
type PolicyHitStep struct {
	Stage string // 规则 / 动作 / 实际出口 / DNS
	Value string
}

// PolicyHitView is one hit-explanation result.
type PolicyHitView struct {
	Title string
	Note  string
	Steps []PolicyHitStep
}

// PolicyPageView is the whole /policies display snapshot.
type PolicyPageView struct {
	Out       PolicyOutState
	Client    []PolicyRuleView
	Server    []PolicyRuleView
	Conflicts []PolicyConflictView
	Hits      []PolicyHitView
	// Target is the explain query echoed back into the form.
	Target string
	// Draft marks the no-data fallback: the page then says so instead of
	// presenting design sample rows as live policy.
	Draft bool
	// ClientDefault and ServerDefault mark a layer rendered from the built-in
	// defaults because that layer has no active revision yet.
	ClientDefault bool
	ServerDefault bool
}

// Extension seams of the /policies page (reserved, nothing renders them yet):
//
//   - 影响面预览组件: PolicyConflictView already carries the two facts an
//     impact panel needs (the affected rows and whether saving is blocked),
//     and PolicyHitResult already renders the per-target hit chain. A future
//     impact panel adds a field here and renders it as one more independent
//     block; it never folds into Server/Client rows.
//   - 批量重批状态组件: the per-node batch status belongs on UpgradeSnapshot
//     (see upgrades.go StagedVerdict/ApprovalNotes), not here — this page has
//     no per-node rows.
//
// PolicyActionLabel renders one compiler action as the operator-facing word.
// The mapping is display-only: a new action renders as its stored spelling
// until this label learns it, never as an empty cell.
func PolicyActionLabel(action policy.CompilerAction) string {
	switch action {
	case policy.CompilerActionDirect:
		return "直连"
	case policy.CompilerActionProxy:
		return "走 Line"
	case policy.CompilerActionTailscale:
		return "直连（Tailnet）"
	case policy.CompilerActionOut:
		return "Out 直出（可选）"
	default:
		return string(action)
	}
}

// policyMatcherLabel renders one matcher as a single display row title.
func policyMatcherLabel(match policy.Match) string {
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

// policyRuleNote renders the one-line hit note of a rule.
func policyRuleNote(rule policy.CompilerRule) string {
	switch rule.Action {
	case policy.CompilerActionTailscale:
		return "Mesh 内网目标始终直连，防止私有网络流量绕出。"
	case policy.CompilerActionDirect:
		if rule.Match.DNS == policy.DNSDomestic {
			return "按地区或例外直连，并使用境内 DNS 解析。"
		}
		return "命中后整体直连，流量不进入代理。"
	default:
		return "境外目标经 Line 转发；DNS 使用加密解析，解析出口与访问出口一致。"
	}
}

// PolicyClientRows renders the client layer's read-only rows. The client layer
// has no consumer in this release, so every row reads as preview instead of
// claiming it is in effect.
func PolicyClientRows(clientPolicy policy.ClientPolicy) []PolicyRuleView {
	rows := make([]PolicyRuleView, 0, len(clientPolicy.Rules)+1)
	for _, rule := range clientPolicy.Rules {
		rows = append(rows, PolicyRuleView{
			Match:  policyMatcherLabel(rule.Match),
			Action: PolicyActionLabel(rule.Action),
			Note:   policyRuleNote(rule),
			State:  "预览",
		})
	}
	return append(rows, PolicyRuleView{
		Match:  "兜底（未命中任何规则）",
		Action: PolicyActionLabel(clientPolicy.Default),
		Note:   "客户端层兜底固定为 Line，规则停用后流量回到兜底而不是断网。",
		State:  "预览",
	})
}

// PolicyServerRows renders the server layer's rows under the Out tri-state.
// An absent Out never promises one: the rows say Line 直出 and say why.
func PolicyServerRows(serverIntent policy.ServerPolicy, out PolicyOutState) []PolicyRuleView {
	action, note := "Line 直出", "未配置 Out 不是错误：AI 与指定分流按 Line 直出，不生成指向 Out 的规则。"
	if out == PolicyOutActive {
		action, note = "Out 直出（可选）", "经 Out 直出；Out 不可用时按 fail-closed 处理，不会自动改走 Line。"
	}
	if out == PolicyOutDegraded {
		action, note = "Out 故障 · fail-closed", "Out 故障：指定到 Out 的分流进入 fail-closed，拒绝转发且不隐式回落 Line 直出。"
	}
	rows := make([]PolicyRuleView, 0, len(serverIntent.Rules)+1)
	for _, rule := range serverIntent.Rules {
		row := PolicyRuleView{Match: policyMatcherLabel(rule.Match), Action: "Line 直出", Note: note, State: "启用"}
		if rule.Action == policy.CompilerActionOut {
			row.Action = action
		}
		rows = append(rows, row)
	}
	return append(rows, PolicyRuleView{Match: "兜底（默认出口）", Action: "Line 直出", Note: "服务端层兜底固定为 Line；Out 故障只影响指定到 Out 的流量。", State: "启用"})
}

// PolicyConflictRows renders the client layer's conflict panel: one blocking
// row when the intent fails re-validation, one passing row otherwise.
func PolicyConflictRows(clientPolicy policy.ClientPolicy) []PolicyConflictView {
	if err := clientPolicy.Validate(); err != nil {
		return []PolicyConflictView{{Detail: PolicyErrorDetail(err), Blocked: true}}
	}
	return []PolicyConflictView{{Detail: "当前生效的客户端策略通过优先级重叠与 DNS 一致性校验。", Blocked: false}}
}

// PolicyErrorDetail splits a stable policy code from its detail and renders
// "code · detail" for the page. The policy domain refuses with "CODE: detail";
// an unrecognized shape is POLICY_INVALID with the whole message, never a code
// invented from text.
func PolicyErrorDetail(err error) string {
	message := err.Error()
	for _, code := range []string{
		policy.CodePolicyConflict, policy.CodePolicyInvalid, policy.CodePolicyNodeUnknown,
	} {
		if prefix := code + ": "; strings.HasPrefix(message, prefix) {
			return code + " · " + strings.TrimPrefix(message, prefix)
		}
	}
	return policy.CodePolicyInvalid + " · " + message
}

// PolicyCountLabel marks a layer without an active revision as default preview.
func PolicyCountLabel(count int, fallback bool) string {
	if fallback {
		return fmt.Sprintf("默认预览 · %d 条", count)
	}
	return fmt.Sprintf("%d 条", count)
}

// PolicyHitResult renders one hit-explanation chain in the operator's four-stage
// order (规则 → 动作 → 实际出口 → DNS). It is a pure display transform: the
// policy domain states the facts, this function states the words. A priority of
// zero is the fallback row, and the DNS phrasing follows the resolved resolver.
func PolicyHitResult(hit policy.HitExplanation, target string) PolicyHitView {
	rule := fmt.Sprintf("优先级 %d · %s", hit.Priority, hit.Matcher)
	title := "命中说明：" + target
	if hit.Priority == 0 {
		rule = "未命中任何显式规则，使用兜底"
		title = "兜底路径：" + target
	}
	dns := "境内 DNS，解析出口与访问出口一致"
	if hit.DNS == policy.DNSEncrypted {
		dns = "加密 DNS，解析出口与访问出口一致"
	}
	return PolicyHitView{
		Title: title,
		Note:  "仅对域名、域名后缀与 CIDR 规则求值；geo 与远端 ruleset 需要锁定数据，本结果不猜测其匹配。",
		Steps: []PolicyHitStep{
			{Stage: "规则", Value: rule},
			{Stage: "动作", Value: PolicyActionLabel(hit.Action)},
			{Stage: "实际出口", Value: hit.Egress},
			{Stage: "DNS", Value: dns},
		},
	}
}

// PolicyPreviewLabel marks the client layer as a rendered, gated preview. It
// keeps the rule count and the default-intent marker, but never implies that
// the layer is applied anywhere: no candidate and no subscription byte comes
// from it in this release.
func PolicyPreviewLabel(count int, fallback bool) string {
	if fallback {
		return fmt.Sprintf("默认预览 · 不改变订阅 · %d 条", count)
	}
	return fmt.Sprintf("预览 · 不改变订阅 · %d 条", count)
}

// PoliciesDraftView returns the static design sample the page renders until
// the backend supplies the real snapshot. Sample copy uses example.invalid
// and documentation ranges only.
func PoliciesDraftView() PolicyPageView {
	return PolicyPageView{
		Out: PolicyOutAbsent,
		Client: []PolicyRuleView{
			{Match: "家庭 Wi-Fi SSID（按名称列表）", Action: "直连", Note: "命中信任的 SSID 时整体直连，流量不进入代理。", State: "启用"},
			{Match: "Tailnet 网段（100.64.0.0/10 及通告子网）", Action: "直连", Note: "Mesh 内网目标始终直连，防止私有网络流量绕出。", State: "启用"},
			{Match: "中国大陆地区（域名与 IP 段）", Action: "直连", Note: "按地区数据直连境内目标。", State: "启用"},
			{Match: "国际目标", Action: "走 Line", Note: "未命中上述规则的境外目标经 Line 转发。", State: "启用"},
			{Match: "例外：镜像站 dl.example.invalid", Action: "直连", Note: "单独放行个别目标，即使命中「国际走 Line」。", State: "例外"},
			{Match: "DNS 解析", Action: "分流解析", Note: "境内域名使用境内 DNS，其余域名使用加密 DNS；解析出口与访问出口一致，避免解析和访问不同路。", State: "启用"},
			{Match: "兜底（未命中任何规则）", Action: "走 Line", Note: "客户端层兜底固定为 Line，规则停用后流量回到兜底而不是断网。", State: "启用"},
		},
		Server: []PolicyRuleView{
			{Match: "AI 域名与服务（按域名规则集）", Action: "Out 直出（可选）", Note: "命中后经 Out 直出；未配置 Out 时走 Line，Out 故障时 fail-closed，不隐式直出。", State: "启用"},
			{Match: "指定 CIDR 段", Action: "Out 直出（可选）", Note: "与 AI 分流同一三态：无 Out 走 Line，Out 故障 fail-closed。", State: "启用"},
			{Match: "指定规则集", Action: "Line 直出", Note: "固定经已纳管的 Line 转发，不依赖 Out。", State: "启用"},
			{Match: "兜底（默认出口）", Action: "Line 直出", Note: "服务端层兜底固定为 Line；Out 故障只影响指定到 Out 的流量，不改变兜底路径。", State: "启用"},
		},
		Conflicts: []PolicyConflictView{
			{Detail: "例外「镜像站 dl.example.invalid 直连」排在「国际走 Line」之前，例外先生效。", Blocked: false},
			{Detail: "示例：若例外排在「国际走 Line」之后，会被先命中的规则覆盖，保存时校验会拦截并列出重叠。", Blocked: true},
		},
		Hits: []PolicyHitView{
			{
				Title: "示例：访问一个 AI 服务域名",
				Steps: []PolicyHitStep{
					{Stage: "规则", Value: "服务端层 · AI 域名规则集，命中"},
					{Stage: "动作", Value: "Out 直出（可选）"},
					{Stage: "实际出口", Value: "Out（当前未配置 → 按 Line 直出展示）"},
					{Stage: "DNS", Value: "加密 DNS，解析出口与访问出口一致"},
				},
			},
			{
				Title: "示例：访问一个境外普通网站",
				Steps: []PolicyHitStep{
					{Stage: "规则", Value: "客户端层 · 国际目标，命中"},
					{Stage: "动作", Value: "走 Line"},
					{Stage: "实际出口", Value: "Line 01（已纳管 Line）"},
					{Stage: "DNS", Value: "加密 DNS，结果与 Line 出口一致"},
				},
			},
		},
	}
}
