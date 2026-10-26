// Package policy is the Hub-side policy domain: the rule library and the
// routing intent that feeds the client and server document generators.
//
// Rule library (Task 3, ADR-0008 §5): the rule model with its six matcher
// kinds and three actions, the versioned preset seed bundle, and the
// immutable-row store (identity = stable_key + version) with the preset write
// guard and the subscription used-by lookup that the delete path shares.
//
// Routing intent and generators (merged from the former internal/compiler in
// the 2026-10-26 internal regroup): the format-independent client and server
// policy model (compiler_model.go), the Geo and remote ruleset version lock
// (ruleset.go) and the sing-box 1.14.3 / Mihomo generators (render.go,
// server_render.go). Subscription owns subscriber documents and the existing
// client exports; these generators only assemble, order and hash the intent
// that the rule library and the subscription composer have already admitted,
// and they embed no domain, CIDR or AI list.
//
// The vocabulary the two layers must agree on (actions, matcher kinds, pin and
// CIDR predicates, the mesh view) lives in the child package
// internal/subscription/ir. Policy imports it downward; the composer imports it
// as its own definition. Neither direction needs a second copy of a value or a
// predicate.
//
// The two layers keep distinct names for their own vocabularies: stored
// library rows use Action/Rule, while generator intent uses
// CompilerAction/CompilerRule, so neither name shadows the other now that both
// live in one package. The label functions stay where they were: the /rules
// library page maps Action in internal/web/view, the /policies snapshot maps
// CompilerAction in internal/web/handler, and the two are not merged.
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
// Dependency direction: policy imports internal/subscription/ir (the shared
// vocabulary and the read-only mesh view), internal/node/protocol (the kernel
// tags and wire grammars) and the standard library. It deliberately does NOT
// import the subscription package: the merged compiler must not call back into
// the composer. It never imports internal/web/*; the Hub SQLite migration in
// internal/control/store reuses SchemaDDL and SeedPresetsTx, and the handler calls
// the Store on the same *sql.DB the web store owns.
//
// Module boundary: a ClientPolicy's mesh view is a foreign value, so
// MeshClientPolicy validates its shape (ir.MeshView.Validate: identity, labels,
// canonical prefixes, bounded lists) before deriving a rule. Nothing else here
// accepts an external structure.
//
// Validation is per row (Rule.Validate) plus the store's identity guard. A
// cross-row shadow/overlap check used to live here as ValidateRuleSet; it was
// removed in Task 6 because the subscription composer owns the selected set and
// rejects duplicates/overlaps at composition time (COMPOSE_RULE_DUPLICATE /
// COMPOSE_RULE_CONFLICT), so there is exactly one set-level validator.
//
// 状态：Out 的 AI 出口选择已由规则库/订阅组装器承担；本包不再提供第二套
// 决策 API。Line 入站选择、通用分流等其余路由决策仍是 ADR-0007 下的占位，
// 未实现通用规则引擎、规则市场、测速或多 Out 负载均衡。
//
// 边界：与候选渲染不同——node.CompileCandidate 已负责把 meshmux-node/v2 候选
// 规范化为节点本地配置，属于节点侧既有能力；本包面向 Hub 侧完整文档组装，
// 不复刻候选 schema，不承担传输、落盘或 apply，也不写 Mesh、订阅或凭据数据。
// MeshConfigModel 只读消费，reconcile 不会猜测缺失的设备或节点。客户端策略消费的
// 组网视图是内部订阅 IR 的 MeshView（跨模块输入先做形状校验，不直接信任外部结构）。
// 与订阅分流也不同——订阅分流负责把同一份用户集合渲染为不同客户端所需的
// sing-box 与 Mihomo 文档，属于渲染层的表达选择；版本锁只描述制品的可验证性，
// 不渲染配置，不读写订阅 Token，也不定义 Out 的安装或升级流程。它同样不执行
// 任何主机动作：验证、下发与回读属于 internal/node 与 internal/web。
//
// See ADR-0007 for the original placeholder scope, the 10a revision and the
// excluded cross-source ACL work.
package policy
