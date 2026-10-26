// Package route holds the routing-decision domain: per-Line inbound selection,
// optional Out chaining, direct-only zero-Out Lines and the rules that decide
// which user may egress through which Out.
//
// Implemented scope after Task 6: the ruleset version lock and the retained
// AI-ruleset byte verification in out_ruleset.go. The former AI-egress decision
// layer (DecideAIEgress*, AIEgressRequest/Decision, resolveAIEgress) was
// removed because the rule library and the subscription composer now own that
// decision. What remains is the security half of the pin contract:
//
//   - a ruleset is usable only when it is pinned (exact HTTPS source, immutable
//     version, SHA-256) and its bytes match the digest; a mutable or malformed
//     pin is RULESET_PIN_INVALID and a download/digest/size failure is
//     RULESET_FETCH_FAILED;
//   - ResolveAIRuleset is kept although the current publication path does not
//     call it: pins are the future consumption path, and the byte check is the
//     contract that makes them safe (Task 6 Keep list).
//
// 状态：Out 的 AI 出口选择已由规则库/订阅组装器承担；route 不再提供第二套
// 决策 API。Line 入站选择、通用分流等其余 route 决策仍是 ADR-0007 下的占位，
// 未实现通用规则引擎、规则市场、测速或多 Out 负载均衡。
//
// 职责：维护规则集版本锁与字节校验，让引用 pins 的渲染层有唯一可信输入。
//
// 边界：与订阅分流不同——订阅分流负责把同一份用户集合渲染为不同客户端所需的
// sing-box 与 Mihomo 文档，属于渲染层的表达选择；route 只描述连通性与准入，
// 不渲染配置，不读写订阅 Token，也不定义 Out 的安装或升级流程。它同样不执行
// 任何主机动作：验证、下发与回读属于 internal/node 与 internal/web。
//
// See ADR-0007 for the original placeholder scope and the excluded cross-source
// ACL work.
package route
