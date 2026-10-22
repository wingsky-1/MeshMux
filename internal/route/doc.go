// Package route holds the routing-decision domain: per-Line inbound selection,
// optional Out chaining, direct-only zero-Out Lines and the rules that decide
// which user may egress through which Out.
//
// Only one part of that scope is implemented (Issue #8): the AI egress decision
// and the AI ruleset version lock in out_ruleset.go. The decision states the
// three cases the server side must never conflate:
//
//   - no Out configured: the AI traffic uses the Line directly, which is the
//     configured egress of an Out-free deployment;
//   - Out configured and available: the traffic egresses through the Out and the
//     pinned ruleset bytes are verified against their SHA-256;
//   - Out configured but unavailable: the request is refused
//     (OUT_OFFLINE_FAIL_CLOSED) instead of silently using the Line, and only an
//     explicit administrator opt-in carrying the request operation id may fall
//     back.
//
// 状态：占位包已按 ADR-0007 的约定首次破壳，范围**仅限 Out 的 AI 出口与规则集
// 版本锁**；仍无通用规则引擎、规则市场、测速或多 Out 负载均衡。
//
// 职责：把"Line / Out / 规则集"的组合解析为一个可审计的出口决定，供发布链与
// 渲染层消费。
//
// 边界：与订阅分流不同——订阅分流负责把同一份用户集合渲染为不同客户端所需的
// sing-box 与 Mihomo 文档，属于渲染层的表达选择；route 只描述连通性与准入，
// 不渲染配置，不读写订阅 Token，也不定义 Out 的安装或升级流程。它同样不执行
// 任何主机动作：验证、下发与回读属于 internal/node 与 internal/web。
//
// See ADR-0007 for the original placeholder scope and the excluded cross-source
// ACL work.
package route
