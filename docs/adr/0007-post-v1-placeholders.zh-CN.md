# ADR-0007：post-v1.0.0 领域占位包（mesh / route / jobs / compiler）

状态：Accepted（原占位决策）；`internal/route` 已按 #8-D、`internal/mesh` 已按 PR-9a-1、`internal/compiler` 已按 PR-10a 首次破壳；`internal/jobs` 仍为占位。

## 修订记录

- 2026-10-22（PR-9a-1）：`internal/mesh` 不再是空包。MeshDevice 与一次性入网 Key 的纯领域模型在 `internal/mesh/device.go` / `enrollment.go` 实现：用途（`proxy_mesh` / `mesh_only` / `subnet_router`）与仅展示用平台（`ios` / `android` / `linux` / `nas` / `other`）分离、`proxy_mesh` 必须绑定 Subscriber 而 `mesh_only` 禁止绑定、同一 Headscale 用户内处于 `pending` / `registered` / `revoking` 的 NodeName 唯一、设备状态迁移表（`revoked` 终态）与固定 15 分钟、仅存 SHA-256、`consumed` 不可逆且每设备单活的入网 Key 状态机。该包**仍不**调用 Headscale API/CLI、不建表、不写 HTTP、不读写订阅 Token、不渲染配置、不执行主机动作，也不 import `internal/web` / `internal/install`；installer 与 Web 接线属后续 PR（9a-4 起）。下文“空包/无导出标识符”以及后果中“其余三包保持占位”的表述，从此只对 `jobs` / `compiler` 继续成立。
- 2026-10-22（Issue #8-D）：`internal/route` 不再是空包。`route.RulesetPin` / `route.ResolveAIRuleset` 与 AI 出口决定（无 Out = 直出、Out 故障 = `OUT_OFFLINE_FAIL_CLOSED`、显式 opt-in 回退需 `operation_id`）在 `internal/route/out_ruleset.go` 实现，由 `internal/web` 的 `planAIEgress` 消费。该包**仍不**渲染配置、不读写订阅 Token、不做通用规则引擎、规则市场、测速或多 Out 负载均衡，也不执行主机动作。下文“空包/无导出标识符”的表述只对其余三包继续成立。
- 2026-10-22（PR-10a）：`internal/compiler` 不再是空包。策略意图（客户端 `ClientPolicy` / 服务端 `ServerPolicy`）与 sing-box 1.14.3 JSON / Mihomo YAML 生成器分离；Geo/远端规则集复用 `route.RulesetPin` 的 HTTPS + 不可变版本 + SHA-256 版本锁，未 pin 的 geosite/geoip/remote 规则在生成前拒绝，下载/摘要/大小失败沿用 `RULESET_FETCH_FAILED`，Out 不可用沿用 `OUT_OFFLINE_FAIL_CLOSED`。`MeshConfigModel` 只读消费并复制切片，未知 Line 标签返回 `POLICY_NODE_UNKNOWN` 而非猜测节点。该包**仍不**写 `mesh_*` / `subscribers` / `proxy_credentials` / Token、不改冻结协议、不执行传输/落盘/apply，也不替 `node.CompileCandidate` 渲染候选；Web 接线与完整文档发布属 10b-10d。下文“空包/无导出标识符”以及后果中“其余三包保持占位”的表述，从此只对 `jobs` 继续成立。
- 2026-10-22（PR-10b-1）：`internal/compiler` 增加客户端策略后端 `client_policy.go`。`Match` 新增 `SSIDs` 与 `DNS` 注解（DNS 只标注解析器类别，不构成第二个 matcher kind）；`DefaultClientPolicy` 固定顺序为 Tailnet/远端家庭网段→Tailscale、CN→直连、例外域名→直连、其余→所选 Line 兜底。保存前 `Validate` 以 `POLICY_CONFLICT` 拒绝 SSID↔Tailnet、CN↔国际、例外顺序、尾网被前置规则遮蔽、重复 SSID 与 DNS 与出口矛盾，并列出重叠的优先级；`ExplainHit` 给出“规则→动作→实际出口→DNS”四段链。SSID 实测：sing-box 1.14.3 的 `wifi_ssid` 可用（`route/rule/rule_item_wifi_ssid.go`，`sing-box check` 通过）；Mihomo 1.19.32 无 SSID 规则类型，`RenderMihomo` 返回 `RENDER_UNSUPPORTED` 而不是编造字段。策略持久化与 Web 展示属 10b-2/10c，本包仍不建表、不写 DB。
- 2026-10-22（PR-10b-2）：`internal/web` 接线 `/policies`。页面从现有只读 mesh 预检（`MeshConfigModel`）与 `DefaultClientPolicy` 生成实快照，Out 三态复用 `OutEgressFacts`；新增 `POST /policies/validate` 冲突干跑（返回稳定 `POLICY_*` 与重叠优先级明细，不写库、不发布）与 `GET /policies/explain`（复用 `compiler.ExplainHit` 渲染四段链，geo/远端 ruleset 如实标注未求值）。本 PR **不新增数据库表、不落库、不发布**：`route_policies`/`config_revisions`/`publications` 的持久化、修订、发布门禁（Out fail-closed、回滚、审计）与 Agent apply 属 10d，先稳定只读视图与校验语义可避免在发布契约未定时固化 schema。`internal/compiler` 的数据模型未改。
- 2026-10-22（PR-10c-1）：`internal/compiler` 增加 `RenderServerRoute`，只组装 Line 侧 sing-box `route` 片段：rules 按策略优先级输出、rule_set 由 `RuleSetPins` 派生带 pin 版本标签的远端引用、final 取已 Resolve 的策略默认出口；仍有 Out 引用但 Out 未配置或不可用时在渲染前拒绝（`OUT_BINDING_INVALID` / `OUT_OFFLINE_FAIL_CLOSED`），不会静默直出。`node.CompileCandidateWithRoute` 把该片段嵌入既有 v1/v2 原生文档，并再次拒绝未配置 Out 的 `out` 引用；名为 `out` 的 outbound 本体归 Out 接入路径，compiler 与候选渲染都不创建它。无策略的 `CompileCandidate` 字节不变。Web 持久化与发布接线不在本修订。
- 2026-10-22（PR-10c-2）：`internal/compiler` 增加 `DefaultServerPolicy`，固定默认服务端意图：AI 规则集（tag 非空，优先级 100）→ Out、操作员域名（200）与 CIDR（300）→ Out、兜底 Line 直出；空输入即全直出默认，并复用既有 `Validate` 拒绝非法域名、CIDR 与 tag。`internal/web` 的 `/policies` 服务端区改为渲染该默认意图，按现有 `OutEgressFacts` 三态选注与动作：Out 未配置时 AI 行显示 `Line 直出` 而不是 `Out 直出（可选）`，Out 故障时显示 fail-closed。新增 `POST /policies/server/preview`（管理员会话 + CSRF + 4 KiB 体，JSON）做无状态干跑：`DefaultServerPolicy` → `ResolveServerPolicy` → `RuleSetPins.Validate` → `RenderServerRoute`，返回 `egress_state`、`egress_code`、前 40 行片段与稳定失败码（`OUT_OFFLINE_FAIL_CLOSED` / `OUT_FALLBACK_UNAUDITED` / `RULESET_UNPINNED` / `POLICY_*`）；无 Out 按已配置的 Line 直出解析，显式回退仍要求调用方 `operation_id`。预览不写库、不建修订、不发布；服务端策略持久化、发布门禁与 Agent apply 仍属 10d。

## 背景

当前 v1.0.0 的范围已由现有包覆盖：`internal/install` 负责特权安装，`internal/node` 固化主机布局与 sing-box 运行时契约，`internal/protocol` 冻结 Hub 与 Agent 的 v1 协议，`internal/subscription` 承载订阅者/凭据/Token 领域模型，`internal/web` 与 `internal/webcmd` 提供本地控制面。ADR 初版时，Issue #20 的后续能力（Mesh 设备生命周期、路由准入、跨节点任务、Hub 侧完整文档编译）尚未进入实现；后续破壳见修订记录。

若这些能力在实现前各自临时命名，边界会在 PR 之间漂移，出现重复实体或第二个 Node 模型。因此在 `internal/` 下先建立四个空包，只写包注释与边界，作为评审锚点。

## 决策

新增四个只有 `doc.go` 的空包，包名与目录名一致，**均无可导出标识符、无外部引用、不参与任何调用路径**：

- `internal/mesh`：MeshDevice 领域（用途/平台分离、一次性入网 Key、Headscale Node ID、路由批准与在线证据）。
- `internal/route`：路由意图与准入（逐 Line 入站、可选 Out 双跳、零 Out 直连、按用户 ACL）。
- `internal/jobs`：跨请求的长任务记录（修订、阶段、`operation_id`、partial/failed 与重试语义）。
- `internal/compiler`：Hub 侧完整配置文档的确定性组装与配置哈希。

## 边界

- **mesh vs node 运行时**：`node` 描述 Line 主机上的 sing-box 目录、配置与 Agent 数据契约；`mesh` 只描述 Headscale 侧设备身份与入网状态。二者不互相定义实体，`mesh` 不执行 Agent 动作。
- **route vs 订阅渲染 vs compiler**：`route` 只做连通性与准入决定（Line 直出、可选 Out、fail-closed），不渲染文档，也不接触订阅 Token；`subscription` 把同一用户集合渲染为客户端文档（现有 `ExportSingBox` / `ExportMihomo` / `ExportMeshDevice`），是渲染层的表达选择；`compiler` 在 Hub 侧把已确认的策略意图按优先级组装为确定性片段并计算哈希，生成器只消费策略与 `RulesetPin`，不复刻 `node.CompileCandidate`，不承担传输、落盘或 apply。
- **jobs vs 现有轮询**：当前 Web 仅登记任务、由 Agent 轮询拉取，Hub 侧没有执行器、队列或新进程。`jobs` 若被采纳，只是把既有阶段与稳定错误码固化为持久记录；不扩展 Agent allowlist，不支持任意 shell、路径或外部 URL。
- **compiler vs 候选渲染**：`node.CompileCandidate` 已负责把 `meshmux-node/v2` 候选规范化为节点本地配置。`compiler` 面向 Hub 侧完整文档组装，不复刻候选 schema，也不承担传输、落盘或 apply；10a 只交付意图模型、版本锁与格式生成器。

## 后果

- 占位包不得被 `cmd` 或其他 `internal` 包导入，避免以空壳提前固化 API；出现第一个真实调用方才提升为正式包并补充测试。`internal/route` 已因 #8-D、`internal/mesh` 已因 PR-9a-1、`internal/compiler` 已因 PR-10a 提升为正式包（见修订记录），只有 `internal/jobs` 保持占位。
- 空包对构建、链接、二进制体积无影响，`go build ./...` 与 `gofmt` 必须保持通过。
- 任一能力进入实现前，须先以新 ADR 或本 ADR 的修订确认职责与失败路径；本 ADR 初版不引入实现，后续破壳以修订记录为准，也不改变 v1.0.0 范围。

## 非目标

不包含跨源 ACL、精确计费、外部订阅导入、额外平台兼容性、通用任务引擎、`#8`/`#9`/`#11` 的具体实现，以及任何节点安装、重启或发布操作。
