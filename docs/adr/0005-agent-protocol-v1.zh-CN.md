# ADR-0005：Agent 管理协议 v1 冻结（Issue #6 PR-A）

状态：Accepted（仅表示本地评审与 L1 验收通过；PR-B 实现 apply/ACL，#11 复用不改协议）。

## 背景

Issue #6 要求 Line/Out 安装后 Agent 主动出站配对，后续配置经 Hub 下发。
Issue #11 统一升级直接复用本阶段冻结的任务字段与身份模型。
PR-A 冻结协议与 Hub 配对面，不做宿主机 apply。当前已完成主控最终验收和本地评审/L1 验证，可进入主控授权的本地提交/ff merge 流程；Accepted 不表示远端 CI、发行或现网验收通过。

## 冻结内容

- 信封：`schema=meshmux-agent/v1`、`version=1.0`、`operation_id`（32 hex）、
  `revision`（单调递增）、`idempotency_key`（32 hex 或 43 字符 secret）、
  `node_id`、`kind`、`params`（对象，最大 4KiB）。
- 任务 allowlist（唯一合法远端行为）：
  `config.check`、`config.stage`、`config.apply`、`config.readback`、
  `health.status`、`node.status`。
- 预留但本阶段拒绝：`upgrade.*`、`rollback.*`（#11 实现）。
- 身份模型：Web 签发一次性 15 分钟配对码（JSON body，不进 argv/history/日志），
  Agent 出站 HTTPS 换节点专属可撤销身份；Hub 绑定 Node ID 与角色，错误角色拒绝；
  重放/过期/冒名明确拒绝；Bearer 身份后续心跳与任务拉取。
- 权限分离：Agent 只执行列举行为，无远端任意 Shell/URL/路径；未知参数键拒绝。
- 结果机：`pending/applying/verifying/healthy/partial/failed/rolled_back`，
  日志只记 `operation_id` 与稳定 `error_code`，不记配对码与身份凭据。
- 约束：Agent strict JSON 拒绝 `null`、重复键和键名大小写变体，并校验正整数
  `int64`、角色、状态与 `error_code`；pairing/result 使用自定义严格解码，Web
  端点统一拒绝 trailing JSON。heartbeat version body 仍为匿名 struct，本条不宣称
  heartbeat 已拒绝重复键或未知键。
- 持久化：`consumePairing` 全事务原子，`enqueueTask` 以完整信封执行单事务幂等/冲突
  与并发 revision 保护；`pendingTasks` 仅重投 `pending/applying/verifying`。SQLite/
  数据库 schema 1→2 迁移保留 admin/session，未来 schema 拒绝；`nodes.last_success`
  仅由最近成功任务更新，不表示公网可达或代理握手成功；`agent_tasks.error_code`
  已持久化。

## 非目标（PR-B/#11）

- Edge/Out 预检、`install edge/out`宿主机 apply、sing-box 1.14.3 check/切换/重启/回读。
- Out nftables 默认拒绝落地、断线维持 last-known-good 的 Agent 常驻实现。
- 升级任务持久化与 Hub 自升级（#11）。
- Web 的 partial/failed 错误码查询展示、离线状态与 runtime 能力仍属 PR-B。

## 验证

- 主控最终本地验收通过：`go test -race ./... -count=1` PASS，gofmt 与 diff check
  PASS；7 项有效语义 mutation 全部变红，状态码与错误行为的准确记录见
  [验收标准](../ACCEPTANCE.zh-CN.md)。
- 保留原有效 mutation：protocol 10 项、migration 2 项、Web 5 项；rollback timeout
  不计有效 mutation。Browser Free 复核已完成，详细证据见同一评审。
- 这只是 L1；PR-A 当前无新的远端 CI 结论，也没有 L2/L3 宿主机安装证据。
- PR-B 应以隔离 Debian 13 提供 Edge/Out 首装、真实 systemd、配置 apply/readback 与 Out ACL 证据；不得以本节本地 L1 结果冒充 L2/L3。
