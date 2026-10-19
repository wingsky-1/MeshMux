# Issue #6 Phase 2B PR-A 交付评审

更新时间：2026-10-19。

## 状态

- Issue #5 已关闭。`c5be00c` 的树 `8e08dfe5327fdf3ec0ecc0cb4daad54e5b6cd5c0` 与 `main` `17baaa1` 相同；[Go/web run 39216454974](https://github.com/wingsky-1/MeshMux/actions/runs/39216454974)、[Debian 组件 run 39216454901](https://github.com/wingsky-1/MeshMux/actions/runs/39216454901) 和 [QEMU run 39216454882](https://github.com/wingsky-1/MeshMux/actions/runs/39216454882) 均成功，#6 可消费 #5 已合入的 Hub 接口。
- Issue #6 PR-A 已完成主控最终验收和本地评审/L1 验证，可进入主控授权的本地提交/ff merge 流程。当前没有新的远端 CI 结论，这不表示已发行、已现网部署或已获得 L2/L3 证据。
- #11 的 Web 全节点统一升级是 v1.0.0 P0，由 #11 独立实现和验收。
- PR-B 尚未实现；同一 Issue #6 任务接下来继续 B。Web 的 partial/failed 错误码查询展示、离线状态和 runtime 能力仍归 B。

## 原 P0 修复与本地验收

- **结果授权—已修复，本地验收通过**：`reportResult` 已绑定认证节点与任务节点，交叉节点提交被拒绝；终态结果幂等且不倒退，非终态允许重投，`rolled_back` 按失败终态处理。
- **配对原子性—已修复，本地验收通过**：`consumePairing` 的配对消费、身份/节点更新和提交处于同一事务；变异测试检出的“identity 错误提交仍使 consumed=1”不再成立。
- **任务幂等与状态机—已修复，本地验收通过**：`enqueueTask` 以完整信封执行单事务幂等/冲突控制和并发 revision 保护；`pendingTasks` 只重投 `pending/applying/verifying`，变异测试检出的“redelivery 只剩 1”不再成立。
- **严格解码—已修复，本地验收通过**：Agent strict JSON 拒绝 `null`、重复键、键名大小写变体，并校验正整数 `int64`、角色、状态与 `error_code`；pairing/result 使用 Agent 自定义严格解码，Web 端点统一拒绝 trailing JSON。heartbeat version body 仍是匿名 struct，因此不泛称 heartbeat 已拒绝重复键或未知键。
- **Web 状态披露—已修复，本地验收通过**：表单显示“期望 SSH”，SSH 探测/健康仍为待测；无心跳不显示 1970，已配对未健康不冒充健康，暂无可执行节点时不提供安装入口。

## 验证与边界

- 最终本地回归：`go test -race ./... -count=1` PASS，gofmt 与 diff check PASS。7 项有效语义 mutation 全部变红，下列“变异行为 / 基线预期”明确区分二者：expired `200/410`、replay `200/409`、wrong role `200/403`、forged Bearer `200/401`、identity 错误 Commit 使 `consumed=1`、redelivery 只剩 1、非法转换 `200/409`。前四项及最后一项斜杠左侧是变异后的错误返回，右侧是基线应返回的状态码；identity 与 redelivery 是测试检出的错误变异行为。
- 保留原有效 mutation 证据：protocol 10 项、migration 2 项、Web 5 项；rollback timeout 不计有效 mutation。SQLite/数据库 schema 1→2 迁移保留 admin/session，未来 schema 拒绝；`nodes.last_success` 仅由最近成功任务更新，不表示公网可达或代理握手成功；`agent_tasks.error_code` 已持久化。
- Browser Free 已真实执行原生表单初始化登录、Edge/Out 创建（HTTP 200）、配对码 GET 不再显示、期望 SSH 和未收到心跳的展示、1280/390 宽度无水平溢出，日志未发现 secrets；DB、service 与 session 已清理。浏览器复核完成，无待复核项。
- PR-A 没有 L2/L3 隔离 Debian 13 宿主机安装证据；不得用本地 L1 冒充系统验收。
- PR-A 当前无新的远端 CI 结论；ADR Accepted 仅指本地评审/L1 通过，不表示远端 CI、发行或现网验收通过。

## PR-B 最小拆分建议

以下只是后续实现拆分建议，不是交付承诺或验收结论；每个 PR 都应独立通过隔离 Debian 13 证据与人工验收。

1. **B1 · 安装与配对基座**：Edge/Out 预检、固定制品与校验、systemd 常驻 Agent、stdin 配对、心跳与状态任务。不实现 sing-box 配置、不开放 Out 入站；验收重点是首装、配对失败/重放、断线与重启恢复。
2. **B2 · 配置候选与 Line apply**：新增节点专属认证候选配置通道和不可变 revision 存储；任务仍只携带 `revision`，Agent 下载后做完整性校验、`sing-box check`、原子切换、受控重启与 readback。验收重点是非法/过期 revision、校验失败、启动失败、回退 last-known-good 和离线不停线。
3. **B3 · Out ACL**：在 B2 配置机制稳定后落地 Out nftables 默认拒绝、授权 Line 来源同步、撤销/同步失败 fail-closed。验收重点是真实入站阻断、授权 Line 可达、规则撤销和恢复，不与配置 apply 混在一个小 PR 里造成难以归因的失败。

**阻塞接口**：PR-B 配置任务必须复用 PR-A envelope，`config.*` params 只保留 `revision`；完整候选配置不能进入 task params、公开订阅 URL 或任意 Agent 指定 URL。建议的最小接口是管理员提交不可变候选 revision，Agent 用节点专属 Bearer 通过固定路径按 revision 拉取，响应包含 revision、内容哈希、大小、内容类型与候选内容；Agent 先校验哈希与单调节点约束，再执行 `config.check`。接口名称可在 PR-B 评审中定稿，但认证、角色绑定、不可变 revision 和哈希校验是硬边界。
