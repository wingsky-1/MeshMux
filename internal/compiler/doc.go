// Package compiler turns Hub-side routing intent into deterministic documents.
//
// 10a implements the format-independent policy model (policy.go), the Geo and
// remote ruleset version lock (ruleset.go) and the sing-box 1.14.3 / Mihomo
// generators (render.go). Subscription owns subscriber documents and the
// existing client exports. This package only assembles, orders and hashes the
// intent that the rule library and the subscription composer have already
// admitted.
//
// The routing-decision domain lives here too (ruleset_pin.go), merged from the
// former internal/route package in the 2026-10-26 internal regroup: the ruleset
// version lock and the retained AI-ruleset byte verification. The former
// AI-egress decision layer (DecideAIEgress*, AIEgressRequest/Decision,
// resolveAIEgress) was removed because the rule library and the subscription
// composer now own that decision. What remains is the security half of the pin
// contract:
//
//   - a ruleset is usable only when it is pinned (exact HTTPS source, immutable
//     version, SHA-256) and its bytes match the digest; a mutable or malformed
//     pin is RULESET_PIN_INVALID and a download/digest/size failure is
//     RULESET_FETCH_FAILED;
//   - ResolveAIRuleset is kept although the current publication path does not
//     call it: pins are the future consumption path, and the byte check is the
//     contract that makes them safe (Task 6 Keep list).
//
// 状态：Out 的 AI 出口选择已由规则库/订阅组装器承担；compiler 不再提供第二套
// 决策 API。Line 入站选择、通用分流等其余路由决策仍是 ADR-0007 下的占位，
// 未实现通用规则引擎、规则市场、测速或多 Out 负载均衡。
//
// 边界：与候选渲染不同——node.CompileCandidate 已负责把 meshmux-node/v2 候选
// 规范化为节点本地配置，属于节点侧既有能力；compiler 面向 Hub 侧完整文档
// 组装，不复刻候选 schema，不承担传输、落盘或 apply，也不写 Mesh、订阅或
// 凭据数据。MeshConfigModel 只读消费，reconcile 不会猜测缺失的设备或节点。
// 与订阅分流也不同——订阅分流负责把同一份用户集合渲染为不同客户端所需的
// sing-box 与 Mihomo 文档，属于渲染层的表达选择；版本锁只描述制品的可验证性，
// 不渲染配置，不读写订阅 Token，也不定义 Out 的安装或升级流程。它同样不执行
// 任何主机动作：验证、下发与回读属于 internal/node 与 internal/web。
//
// See ADR-0007 for the original placeholder scope, the 10a revision and the
// excluded cross-source ACL work.
package compiler
