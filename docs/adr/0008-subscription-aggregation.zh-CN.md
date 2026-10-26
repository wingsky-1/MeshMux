# ADR-0008：订阅聚合契约（实体独立、聚合只活在订阅里）

状态：Accepted（订阅聚合重构契约冻结，Task 1–8 引用；refs #113）。

日期：2026-10-26。

前置裁决：R1 全速开工（本分支即工作分支）；R2 存储 schema 11 归 11d，本重构从 schema 12 开始（`store_database_gate.go` 必须同步改）。

## 背景

v1.0.0 必须打通节点纳管、组网配置、规则管理、订阅生成（含 AI 双跳），但三类实体（节点 Line/Out、组网设备、规则）在实现中容易互相引用、提前耦合，导致删除保护、版本语义、授权派生在 PR 之间漂移。本 ADR 在 Task 0 先行冻结契约：实体互相独立，聚合只活在订阅里。订阅是纯函数 `f(lines, outs, rules, network) → 产物`，选择存快照，下载走现有收敛门禁。

上游输入：Council 结论、UX 稿 v2（首页空白/节点横条/订阅四分组弹窗/规则三动作/组网三步闭环）。本 ADR 是后续任务（Task 1–7）的唯一契约来源；与本 ADR 冲突的实现以本 ADR 为准，需修订先改 ADR。

既有约束继承：Out optional、Mesh-only 不需要代理订阅、Subscriber ≠ Mesh Device ≠ VLESS credential、Web-first 不可破坏；`policy_schema` 保持 8（路由策略契约，与存储 `user_version` 是两个版本，见 ADR-0007）。

## 决策

### 1. 聚合根：subscriber（一 Token 一配置）

- `subscriber` 是订阅聚合的唯一聚合根。一条 subscriber 行对应一个下载 Token、一份客户端配置产物集合（sing-box / mihomo / Mesh 设备配置按需表达）。
- Token 照发但标 `pending`，直到 Line 回读（readback）确认后才转为可用；下载门禁（版本/摘要/用户集精确匹配，见 ADR-0006）不变。
- Line、Out、Mesh 设备、规则均为被引用实体：它们不知道自己被哪些订阅选中；引用关系只记录在订阅侧边表（`subscription_lines` / `subscription_outs` / `subscription_rules` / `subscription_networks`，见 Task 4），附 `position` 排序（唯一约束）。
- 删除被 N 个订阅引用的节点/规则/组网设备时拒绝删除，并列出引用它的订阅名清单（used-by 完整图由 Task 4 交付，数据源由 Task 1/2/3 提供）。

### 2. 快照语义：最后一次选择 + 版本 + 排序（不存字节）

- 快照 = 订阅创建/修改时最后一次确认的选择集合：各边表行（实体 id）+ 被引用实体的不可变版本标识 + `position` 排序。
- 版本标识：规则用 `rule_revision_id = (stable_key, version)`（Task 3）；Line/Out 用候选 revision（Task 2/4）；组网用设备 id 集合（Task 1/4）。快照只存这些引用与排序，不存渲染后的配置字节。
- 快照只用于两件事：引用判断（实体变更/删除时判定哪些订阅受影响）与界面回显（向导重开时恢复上次选择）。下载字节永远由组装器按当前快照 + 当前实体版本实时组装，并过收敛门禁；快照本身不是下载来源。
- approved artifact（组装 + 门禁通过后的产物摘要）才是下载的唯一依据；快照与 artifact 不一致时以 artifact 为准并显式标注。

### 3. Out 约束：单订阅单 Out + 同一 Line 出一致性

- 1.0.0 只允许单订阅单 Out：`MAX_OUTS_PER_SUBSCRIPTION = 1` 常量，`subscription_outs` 表在 1.0 以唯一约束强制单条（Out 池本身不限个数，Task 2）。
- 同一 Line 的所有订阅必须选同一个 Out：创建/修改订阅时若与同一 Line 下已有订阅的 Out 选择不一致，拒绝后选（返回稳定错误码，UI 显式提示），绝不静默混用。这是 1.0 约束，1.1 按用户条件解除。
- 订阅选了 Out 但其 Line 内核 route 未生效时：预期拒绝创建（出冲突）或明确标注“待生效”，绝不静默生成缺 Out 路由的配置。
- 授权派生方向（Task 5，**Ruling R10 修订**）：服务端 Out 入站 ACL 与 Line→Out 双跳允许清单不再来自 `out_bindings`，也**不再**按订阅边推导，而是**节点成员制**——`outAllowedSources(outID)` = 所有持有当前配对身份的 Line 地址并集。Line 纳管成功即加入所有 Out 的 allowlist，Out 纳管成功即为全部现存 Line 生成 allowlist；Line/Out 删除或身份吊销即从相关 allowlist 移除；无成员即默认拒绝。订阅的创建/改选/状态变更**完全不碰 ACL**，也不再触发池级重算。切换与旧表删除在同一 PR 内原子完成，不留授权空窗。
- Out 删除语义（**Ruling R9**）：删除即彻底删除——先清空 ACL 并等待主机确认，再删除节点行、`out_settings`（出口地址与 link key）及候选/任务；被活跃订阅引用、Out 离线或仍有未完成链时拒绝（不删除任何内容）。
- 出口位扩展（**Ruling R11**）：节点类型为 Line / Out / HTTP 代理。HTTP 代理是**外部**端点：role=`http`、status 恒为 `external`，无 Agent、无配对、无安装、无候选、无回读，因此**排除在收敛门禁之外**（`outEgressFacts` / `LineOutEgressStatusTx` 不等待其 ACL 或回读）。订阅的 `MAX_OUTS_PER_SUBSCRIPTION = 1` 语义延续为“出口位二选一”：Out 或 HTTP 代理，同一 Line 的所有订阅仍须选择同一出口。服务端 route 的 `out` 出口按类型渲染：Out→Shadowsocks link key；HTTP 代理→sing-box `http` 出站 `{server, server_port, username?, password?}`。凭据与 Line 私钥同级存放（0600 数据库；URL 去 userinfo 后存 host:port，凭据分列），UI 只展示 host:port；无凭据时出站省略 username/password。HTTP 代理同样受 used-by 互锁与彻底删除约束（删除节点行与 `node_http_proxy`，被订阅选中时拒绝并列出订阅名）。

### 4. Out / Mesh 边界：1.0 记录不执行

- Out 与组网在 1.0 的订阅向导中保留选择步骤，但语义是“已记录，执行待 1.1”：Out 选择参与客户端配置组装与服务端 route 片段渲染（经现有 `sing-box check` 门禁），但多 Out 容错/负载、服务端 Out 路由的完整执行闭环不在 1.0；组网选择参与订阅分组与界面展示，子网路由执行以现有 Headscale 接线为准，不新增执行路径。
- UI 必须明示执行状态（“已记录，执行待 1.1”），无空控件；预览 `!` 只提醒，`✖`（保存/组装/门禁不过）才阻断。
- Mihomo 门禁仅在已安装固定版本（1.19.32）时执行；`sing-box check`（1.14.3）必需。mihomo 订阅含 sing-box 专属能力时 fail-fast 明示，不生成残缺配置。

### 5. 预置规则升级规则：不可写、随版本替换

- 预置规则不可写：任何创建/修改/删除预置规则（`stable_key` 命中预置种子）的写请求以 `RULE_PRESET_IMMUTABLE` 拒绝。规则库动作只有直连/代理/拒绝；匹配只有六种（域名/域名后缀/IP 段/GeoSite/GeoIP/规则集），无 SSID（`compiler.Match.SSIDs` 能力保留但规则库暂不上架，见计划 Task 6 Keep 项）。
- 预置随版本迁移替换：新版本预置以新 `version` 种子插入（`(stable_key, version)` 唯一），不原地改旧行。存量订阅停留在旧版本语义并标注“可升级”，不自动变、不静默变；运营者显式迁移才产生新 revision。
- 规则被引用后改 match/action：只能产生新 revision，旧订阅不受影响、下载字节不变，除非运营者显式迁移订阅到新 revision。
- `route_policies` 表保留，server 层语义 1.0 保留；client 层写入已在 Task 6 停写（`POLICY_LAYER_RETIRED`；表保留、可读，只作既有 revision 的预览），与本规则库不双写。`exceptions`/`ssids` 顶层字段显式拒绝（`POLICY_PAYLOAD_RETIRED`），schema 17 重写存量 payload 删除这两个从未被消费的键；`default`/`rules`/`note` 与 `policy_schema=8` 不变。

### 6. 版本与 schema 冻结

- `policy_schema` 保持 8；升级 manifest 校验规则（ADR-0007 PR-10d-1b 契约）不变。
- 存储 schema：11 归 11d，本重构从 12 开始（Task 3→12、Task 4→13、Task 5→14，按 progress.md Ruling R2 顺序编号；Task 7 不碰 schema；Task 8→16 重建 `nodes` 以容纳 role `http` 并新增 `node_http_proxy`）。每个迁移为纯增量 additive，并按 11d 门禁声明不可逆性；`store_database_gate.go` 必须同步改上限。Schema 16 的 `nodes` 重建必须在 `foreign_keys=OFF` 的独立事务中执行（SQLite 的 `DROP TABLE` 在 FK 开启时会级联删除子表），并重建候选不可变触发器。
- 规则表：`name` 不唯一，`UNIQUE(stable_key, version)`；预置种子版本号随迁移单调递增。

### 7. 组装与门禁（Task 4 必须遵守）

- 组装器是纯函数 `ComposeSubscription(lines, outs, rules, network) → (docs, diagnostics)`（`internal/subscription/compose.go`）：同输入同字节；geo/ruleset 双内核校验；mihomo 缺席时降级（不静默跳过必需门禁）。
- 预览 fail-fast 四层校验：输入提醒（`!`）/ 保存严格校验 / 组装冲突 / out 槽位非空与内核门禁（`✖` 阻断）。
- 服务端 Out 路由与 ACL 授权已由 Task 5 按 §3 落地为**节点成员制**（Ruling R10，见 §3 首条）；`out_bindings` 表与读写路径在同一变更内删除（schema 14），不留授权空窗。

## 后果

- Task 1（组网）、Task 2（节点 + Out 池 + Out 接入真实 SS 出站，2022-blake3-aes-128-gcm/16B link key，R7）、Task 3（规则库 + 预置 + 互锁）可并行：三轨只生产本 ADR 定义的数据源（设备 id/名称/在线/子网；Line 候选含真实 out 出站；`rule_revision_id`），不直接写订阅边表。
- Task 4 消费三轨接口，实现边表 + 快照 + 组装器 + 预览 fail-fast + used-by 图；Task 5 做授权原子切换（含 AI 双跳 E2E 证据）；Task 6 做死代码删除 + 文档同步；Task 7（web 包分层搬迁）为纯机械 PR，11d 合入后第一个做；Task 8（R11）在 Task 5 后加 HTTP 代理节点与出口位，不触碰 ACL 派生。
- 任一任务发现契约缺口，先修订本 ADR 再实现；不接受“实现先行、ADR 后补”。

## 非目标（1.1，不在本重构）

多 Out 执行与容错、订阅级 server 规则（按 user 条件）、多组网、流量统计与精确计费、规则版本用户自选 UI、横条/卡片视图切换、外部订阅导入、额外平台兼容性。

## 引用

- 本计划：`docs/superpowers/plans/2026-10-26-subscription-aggregation-blueprint.md`。
- ADR-0006（订阅身份/撤销证据/下载门禁）、ADR-0007（post-v1 占位包与升级 manifest / `policy_schema=8` 契约）。
- SDD 台账：`.superpowers/sdd/2026-10-26-subscription-aggregation-blueprint/progress.md`（Ruling R1–R4）。
