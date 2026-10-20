# Issue #6 Phase 2B 实施评审

更新时间：2026-10-19。

## 状态

- Issue #5 已关闭。`c5be00c` 的树 `8e08dfe5327fdf3ec0ecc0cb4daad54e5b6cd5c0` 与 `main` `17baaa1` 相同；[Go/web run 39216454974](https://github.com/wingsky-1/MeshMux/actions/runs/39216454974)、[Debian 组件 run 39216454901](https://github.com/wingsky-1/MeshMux/actions/runs/39216454901) 和 [QEMU run 39216454882](https://github.com/wingsky-1/MeshMux/actions/runs/39216454882) 均成功，#6 可消费 #5 已合入的 Hub 接口。
- Issue #6 PR-A 已完成主控最终验收和本地评审/L1 验证，并已在本地 ff 合入 `adb7558`。远端 `main` 仍为 `17baaa1`；当前没有新的远端 CI 结论，这不表示已发行、已现网部署或已获得 L2/L3 证据。
- #11 的 Web 全节点统一升级是 v1.0.0 P0，由 #11 独立实现和验收。
- PR-B 的 Node CLI、安装事务、runtime、Web 固定操作和验证脚本已写入当前工作树，正在做全仓与隔离宿主机验收。没有 PR-B 远端 CI 链接，也不得把实现存在或定向测试通过当作 L2/L3 结论。

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

## PR-B 当前实现与验收边界

当前工作树已实现以下主路径，尚待主控按真实运行结果验收：

- **CLI**：用户入口仍为 `meshmux install hub|edge|out`；edge/out 接受 `--hub`、`--node`、`--vless-port`、`--ssh-port`、`--plan`、`--yes`、`--repair`。配对码没有 flag，只从同一个 buffered stdin reader 在确认之后读取 43 字符单行。私有 zero-arg `__internal-agent-version` 仅输出 `node.CurrentAgentVersion`，供 installer 验证暂存 Agent，不是用户管理命令。
- **Installer**：配置先于宿主探测；真实 preflight 覆盖 Debian 13、root、架构、磁盘、systemd、时钟、CA、Hub/GitHub HTTPS、端口、实际 SSH listener、包可用性与 nft ownership。plan 不消费配对码或写宿主；未确认不 apply。
- **Transaction**：sing-box 1.14.3 官方归档与解压后 binary 均校验固定 SHA-256；Agent 使用当前 CLI 的自复制 bytes/hash。state 仅按 Hub URL、Node ID、role、VLESS/SSH port 判断同一 Node，记录 owned paths、operation journal 和 stage/status/error/recovery。
- **Runtime**：固定六类任务；配置任务 params 只允许 `revision`。apply 在 runtime lock 内做 staged readback、sing-box check、受控重启与严格进程/监听/配置/二进制回读；有 LKG 时才尝试恢复，恢复后仍须完整 readback。
- **Web**：节点页面显示严格本机 readback 与最近任务；无 heartbeat、pending 或 heartbeat 超过 2 分钟显示离线，离线时不投递改动任务。固定 recheck 生成不可变 revision 和四任务链；“重签身份”撤销旧 token、替换 pairing code、终止旧未完成任务并回到 pending。
- **Agent boundary**：`meshmux __internal-agent` 是 systemd 固定入口；拒绝参数，不提供任意路径、命令或 URL 调度。CLI 没有新增 `upgrade`、`rollback`、`status` 管理命令。

## 待验与已知阻塞

- 全仓 `gofmt`、vet、test、race、build 和浏览器/CI 结果等待主控回填；当前不勾成功。
- L2 Debian 13 组件自检与 L3 edge/out QEMU 首装、repair、重启、失败恢复尚未取得证据。公网入站、真实协议握手和客户端可用也未测。
- 当前 VLESS 候选 `users` 为空，没有 TLS/REALITY、用户、凭据或订阅；#7 未实现。
- 当前 Out ACL 是 `policy accept` 加目标 VLESS TCP/UDP drop，与“空授权默认拒绝、仅目标端口可用”的要求不一致，是上线验收阻塞。#8、#9 与 #11 不在本轮实现范围；#11 仍是 v1.0.0 P0。
- 自定义 SSH/VLESS 端口必须不同；安装器从 ssh.socket、ss 和 sshd 读取实际 listener，Fail2ban jail/action 需覆盖全部 SSH listener 并排除 VLESS。真实封禁和 nft 行为只能由 L3 证明。
