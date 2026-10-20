# Issue #7 Phase 3A 会话交接（2026-10-20）

## 已合入的阶段

PR [#19](https://github.com/wingsky-1/MeshMux/pull/19) 已使用 merge commit 合入 `main`：`3f9ffb3020a0eb0f6f8b898a7f8a7f1c360e091a`，保留所有提交，未打 Tag。Issue #7 保持 OPEN。

PR-A 交付独立 Subscriber / per-Line Credential / Token 模型、显式 SQLite schema 4、288 bit Token 哈希存储、UUIDv4、严格 candidate v2 REALITY 与 v1 精确兼容、合法空用户、状态文件写入大小保护及私有文件/日志边界。Agent allowlist 和 readback 字段没有扩展。

最终 PR head `3789a3a7f7a0cb0c1388fa8dbdec291c04a2c478`，tree `0f13577f777c72b97e24a2dc1fba2c2f6782daac`：

- 主控独立检出：gofmt、vet、test（435）、race、build 全通过。
- [ci 39382159453](https://github.com/wingsky-1/MeshMux/actions/runs/39382159453) success。
- [hub-components 39382159461](https://github.com/wingsky-1/MeshMux/actions/runs/39382159461) amd64/arm64 success。
- [hub-vm 39382159464](https://github.com/wingsky-1/MeshMux/actions/runs/39382159464) Debian 13 amd64 Hub/Edge/Out 三 job success。主控已检查日志，Edge/Out 均实际执行 native check 与 REALITY 正确/错误/删除 UUID 握手 PASS。

## 当前工作区与 WIP

cwd `/home/tangyi/workspace/MeshMux`；分支 `verify/issue7-sub-lifecycle` 已 ff 到上述 main merge 后继续开发。不要复用 Issue #6 分支。交接时将后续变更分成 PR-B 与 PR-C 的 WIP 提交保存；它们尚未开新 PR、未验收、未合入 main。

PR-B 当前代码：

- `internal/subscription/export*.go`：标准 sing-box JSON / Mihomo YAML；按排序和 NodeID 稳定输出，客户端标签为显示名加完整 NodeID；强制一位 Subscriber 的逐 Line 凭据，禁止额外凭据/私钥输出，TCP Vision 能力明确。
- `internal/web/server_subscribers.go`、`views_subscribers*`、`assets/subscribers.css`：Web 线路参数、增停删、选线、Token 轮换/撤销、重试；增/状态/选线已调用 prepare。手工 `complete` 删除入口已移除。
- `store_line_snapshot.go`：所有活跃用户的完整期望集合，保留他人 UUID，空用户合法。
- `store_subscriber_sync.go` / `store_nodes.go`：从已持久化状态推导意图，无 schema 5；轮询/心跳/任务结果驱动同步，单 Line 单任务链，失败需显式重试，精确回读后自动完成删除。
- `server_subscriptions.go` / `store_subscription_download.go`：固定 `/subscription/{48char}/sing-box.json`、`mihomo.yaml`；独立 Host、GET/HEAD、拒绝编码/遍历/查询、统一 404、缓存/日志保护；快照事务检查 Token、状态、完整用户集、端口、REALITY、节点身份及回读。
- `internal/install/render.go` / `internal/webcmd`：Caddy 订阅 vhost 和内部 `--subscription-origin` 接线。
- `scripts/ci-subscription-clients.sh` / workflow：固定 sing-box 1.14.3、测试专用 Mihomo v1.19.32（GPL-3.0，不进入服务端包）；原生 amd64/arm64 容器验证导入与双 Line 数据面。

PR-C 当前代码：`internal/install/{apply.go,node_apply.go,node_render.go,local_line.go,local_line_test.go}`。共存 Line 使用独立 `/var/lib/meshmux-installer/local-line/state.json`，共享 Hub 程序只校验复用，复用 SSH jail。仍有下面的真实路径缺口。

## 本轮 WIP 验证（不能代替后续 PR CI）

- 阶段冻结后主控执行：`go test ./... -timeout=60s`、`go test -race ./... -timeout=60s`（各 538 tests）、`go vet ./...`、`go build ./...`、`git diff --check` 全通过；gofmt 已清理。
- 主控实际运行 `TestSubscriptionClientImport` 和 `TestSubscriptionExportHandshakeDataPath`：固定 sing-box / Mihomo 对生成的双 Line 配置均导入成功，并分别经两条 Line 请求本地目标成功。该 fixture 修改客户端监听端口以隔离运行，服务端及握手目标均 loopback。
- 浏览器：实际初始化/登录、创建待配对 Line、保存参数、选线创建 Subscriber；390px 无横向溢出；刷新后不再显示一次性 Token。截图仅保存在 `/tmp/opencode/meshmux-issue7-*-mobile.png`，未提交凭据截图。
- Debian 13 客户端脚本整体重跑受到 GitHub 下载 EOF/超时影响，未取得该完整脚本的最终 success；不能把本机已有二进制测试冒充新 CI。
- 隔离浏览器和开发 Web 进程已关闭；没有现网安装、清理或重启。

## 下会话优先修复与验收

1. **UI 误判风险（未修复）**：`subscriberViewModel` 仍用 `subscriberLineConfirmation(node)` / `NativeReady` 推断用户凭据确认。已有 `SyncStatus/SyncLabel/SyncClass/SyncCode` 字段未填充/渲染。使用 `subscriberSyncStatus` 和 `subscriberLineSyncViewTx` 的精确证据；不要在单连接事务内嵌套 store 调用。离线必须显式 partial。`linesSave` 保存后仍需对所有历史关联用户 fan-out prepare，先收集 ID 并关闭 rows。
2. **收敛审查（未修复）**：`readbackTaskHealthyTx` 只要求该 revision 的 readback healthy，没有约束同一任务链 check/stage/apply 全部成功。结合可信回读语义决定并落实完成规则，追加“前序失败、回读 healthy 仍不能假完成”测试。不要改写/取消已投递旧链。
3. **时间一致性（未修复）**：任务/结果路径仍有 `time.Now()`，与 handler 注入时钟不一致。发布同事务候选/任务时间和结果时钟需最小化统一，补固定时钟回归。
4. **Hub+Line repair 真路径缺陷（未修复）**：`node_plan.go` 的 `nodePortPreflight` 在 allowManaged 且 kernel hash 为空时仅 `ReadState("/")`；共存主机读到 Hub ledger，Node=nil，真实现存 listener 可能被误报 PORT_CONFLICT。改为有效 local-Line ledger，绑定 NodeID/Role/port，只采用记录的已验证 hash；补 fixture。
5. **PR-C 真实 VM 尚未实现**：`local_line_vm_test.go` 不存在。需在受控 Hub QEMU 中通过实际 Web 初始化/配对，安装本地 Line、repair、重启，验证 Hub 台账/程序/服务不受破坏，实际 Agent 下发 v2 与订阅握手。已有 synthetic native fixture不能替代实际安装 Line 的生命周期。
6. `local_line.go` 有“升级不在 v1.0.0”的过期注释：改成“不在 #7，由 #11 单独实现”；#11 仍是 v1.0.0 P0。继续独立审查共享程序及失败恢复边界。
7. 更新 README/FEATURES/ACCEPTANCE 的 #7 状态（当前仍主要写首 PR 进行中），补客户端能力及真实证据；不要提前关闭 Issue。
8. 按每 PR 一个验收单元提交：PR-B Web/订阅/收敛，PR-C Hub 共存。每个都全仓检查、浏览器和对应 CI/隔离 VM 通过后 merge，不 squash、不打 Tag。

不要按审查建议在“历史 Line 设置丢失”时直接跳过撤销：远端可能仍授权 UUID；保持 partial，直到有可证明的撤销/退役证据。

## 可复用验证资源

### 收尾后返回的共存代码审查（必须先处理）

- **HIGH：CLI repair 入口读取错误台账。** `cmd/meshmux/node.go` 的 `runner.ReadState("/")` 仍映射 `install.ReadState`，共存主机得到 Hub ledger（Node=nil），直接返回 `REPAIR_STATE_MISSING`，且 allowManaged 错误。`install.ReadNodeState` 已有但未接线。须同时修复 CLI gate 和上文 preflight 的有效台账读取；现有直接调用 InstallNode 的 fixture没有覆盖该入口。
- **MEDIUM：独立 Line 多 SSH listener 回归。** `node_apply.go` 独立分支调用 `verifyNodeSSHJail(..., installedCfg.SSHPort)` 只传一个端口，但 jail 渲染全部检测端口，精确集合回读会永久失败。应传完整 `sshPorts` 并补多 listener 用例。
- **MEDIUM：共存 plan 写集合不准确。** `BuildNodePlan` 仍无条件列共享 MeshMux 程序和独立 Node SSH jail 为写入目标，共存实际只复用它们；plan 应展示真实写入与复用边界。
- 低优先级：fresh Hub 回滚后的 SharedBinaries pin 可能指向已移除文件；partial rollback 后 Fail2ban 内存/磁盘可能未重载一致；默认 preflight 仍硬编码真实根和 ExecRunner；局部注释重复和 #11 版本措辞需清理。

这些是未修复的 WIP 审查发现，不影响已合入 PR-A 的结论。不要因为 L1 全绿而将 PR-C 标成可用。

已下载校验的临时二进制（可能被环境清理，使用前重新核对固定 manifest）：

- `/tmp/opencode/meshmux-issue7-mihomo/bin/sing-box-1.14.3-linux-amd64/sing-box`
- `/tmp/opencode/meshmux-issue7-mihomo/bin/mihomo-amd64-compatible`

测试环境变量：`MESHMUX_SINGBOX_TEST_BINARY`、`MESHMUX_MIHOMO_TEST_BINARY`；原生 fixture 使用 `MESHMUX_REALITY_CHECK_BINARY`、`MESHMUX_REALITY_INTEGRATION_BINARY`。

临时独立检出 `/tmp/opencode/meshmux-issue7-pra-verify` 用于已提交 PR-A 验证，不作为主工作目录。当前主目录未移动。

红线继续：只操作隔离 fixture/VM；不现网、不扩 Agent allowlist；upgrade/rollback 仅保留 schema/version/operation_id/revision/idempotency；不做 #8/#9/#11、Out 双跳/跨源 ACL。所有 commit 带 `(refs #7)`。用户已授权范围内 PR 和全绿后 merge，无需再次询问许可。
