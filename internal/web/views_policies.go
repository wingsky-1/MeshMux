package web

import "fmt"

// views_policies.go holds the display-only view model for the /policies page.
// The server fills the snapshot from each layer's active revision, falling back
// to the mesh-derived and built-in defaults; policiesDraftView remains the
// no-data fallback. The page renders no publication control: publishing is
// 10d-2b (see docs/UX.zh-CN.md 交互安全性).

// policyOutState is the tri-state display of the optional Out egress.
type policyOutState string

const (
	// Out 未配置：可选节点缺失不是错误，不生成指向 Out 的规则。
	policyOutAbsent policyOutState = "absent"
	// Out 已接入且健康：指定分流优先经 Out 直出。
	policyOutActive policyOutState = "active"
	// Out 故障：fail-closed，不隐式回落 Line 直出。
	policyOutDegraded policyOutState = "degraded"
)

// policyRuleView is one display row of a policy layer.
type policyRuleView struct {
	Match  string // 匹配条件：SSID、Tailnet 网段、地区、域名、CIDR、规则集
	Action string // 动作：直连 / 走 Line / Out 直出（可选）/ 分流解析
	Note   string // 一句话命中说明
	State  string // 展示状态：启用 / 停用 / 例外
}

// policyConflictView is one priority-overlap display row.
type policyConflictView struct {
	Detail  string // 冲突说明
	Blocked bool   // true：保存时会被校验拦截；false：示例通过
}

// policyHitStep is one stage of the fixed hit explanation chain
// (规则 → 动作 → 实际出口 → DNS). The full simulator stays out of scope.
type policyHitStep struct {
	Stage string // 规则 / 动作 / 实际出口 / DNS
	Value string
}

// policyHitView is one hit-explanation result.
type policyHitView struct {
	Title string
	Note  string
	Steps []policyHitStep
}

// policyPageView is the whole /policies display snapshot.
type policyPageView struct {
	Out       policyOutState
	Client    []policyRuleView
	Server    []policyRuleView
	Conflicts []policyConflictView
	Hits      []policyHitView
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

// policyCountLabel marks a layer without an active revision as default preview.
func policyCountLabel(count int, fallback bool) string {
	if fallback {
		return fmt.Sprintf("默认预览 · %d 条", count)
	}
	return fmt.Sprintf("%d 条", count)
}

// policiesDraftView returns the static design sample the page renders until
// the backend supplies the real snapshot. Sample copy uses example.invalid
// and documentation ranges only.
func policiesDraftView() policyPageView {
	return policyPageView{
		Out: policyOutAbsent,
		Client: []policyRuleView{
			{Match: "家庭 Wi-Fi SSID（按名称列表）", Action: "直连", Note: "命中信任的 SSID 时整体直连，流量不进入代理。", State: "启用"},
			{Match: "Tailnet 网段（100.64.0.0/10 及通告子网）", Action: "直连", Note: "Mesh 内网目标始终直连，防止私有网络流量绕出。", State: "启用"},
			{Match: "中国大陆地区（域名与 IP 段）", Action: "直连", Note: "按地区数据直连境内目标。", State: "启用"},
			{Match: "国际目标", Action: "走 Line", Note: "未命中上述规则的境外目标经 Line 转发。", State: "启用"},
			{Match: "例外：镜像站 dl.example.invalid", Action: "直连", Note: "单独放行个别目标，即使命中「国际走 Line」。", State: "例外"},
			{Match: "DNS 解析", Action: "分流解析", Note: "境内域名使用境内 DNS，其余域名使用加密 DNS；解析出口与访问出口一致，避免解析和访问不同路。", State: "启用"},
			{Match: "兜底（未命中任何规则）", Action: "走 Line", Note: "客户端层兜底固定为 Line，规则停用后流量回到兜底而不是断网。", State: "启用"},
		},
		Server: []policyRuleView{
			{Match: "AI 域名与服务（按域名规则集）", Action: "Out 直出（可选）", Note: "命中后经 Out 直出；未配置 Out 时走 Line，Out 故障时 fail-closed，不隐式直出。", State: "启用"},
			{Match: "指定 CIDR 段", Action: "Out 直出（可选）", Note: "与 AI 分流同一三态：无 Out 走 Line，Out 故障 fail-closed。", State: "启用"},
			{Match: "指定规则集", Action: "Line 直出", Note: "固定经已纳管的 Line 转发，不依赖 Out。", State: "启用"},
			{Match: "兜底（默认出口）", Action: "Line 直出", Note: "服务端层兜底固定为 Line；Out 故障只影响指定到 Out 的流量，不改变兜底路径。", State: "启用"},
		},
		Conflicts: []policyConflictView{
			{Detail: "例外「镜像站 dl.example.invalid 直连」排在「国际走 Line」之前，例外先生效。", Blocked: false},
			{Detail: "示例：若例外排在「国际走 Line」之后，会被先命中的规则覆盖，保存时校验会拦截并列出重叠。", Blocked: true},
		},
		Hits: []policyHitView{
			{
				Title: "示例：访问一个 AI 服务域名",
				Steps: []policyHitStep{
					{Stage: "规则", Value: "服务端层 · AI 域名规则集，命中"},
					{Stage: "动作", Value: "Out 直出（可选）"},
					{Stage: "实际出口", Value: "Out（当前未配置 → 按 Line 直出展示）"},
					{Stage: "DNS", Value: "加密 DNS，解析出口与访问出口一致"},
				},
			},
			{
				Title: "示例：访问一个境外普通网站",
				Steps: []policyHitStep{
					{Stage: "规则", Value: "客户端层 · 国际目标，命中"},
					{Stage: "动作", Value: "走 Line"},
					{Stage: "实际出口", Value: "Line 01（已纳管 Line）"},
					{Stage: "DNS", Value: "加密 DNS，结果与 Line 出口一致"},
				},
			},
		},
	}
}
