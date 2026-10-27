# Issue #6 · Line / Out 安装、纳管与恢复

**状态（2026-10-19）：PR-A 已在本地 ff 合入 `adb7558`；远端 `main` 仍为 `17baaa1`。本页描述当前工作树中的 PR-B 实现路径，仍在进行全仓与隔离 Debian 13 宿主机验收。源码存在、定向测试通过或 plan 成功都不等于系统安装成功或 PR-B 已完成。**

本页只适用于隔离 Debian 13 测试机。未取得单独授权，不得在现网 VPS、NAS 或其他宿主机执行安装、repair、服务重启或 nftables 操作。

## 用户入口

用户侧仍只有 `meshmux install`。本轮新增的 Node 形式为：

```sh
meshmux install edge|out \
  --hub HTTPS_ORIGIN \
  --node 32_HEX \
  --vless-port PORT \
  --ssh-port PORT \
  [--plan|--yes] [--repair]
```

- `edge` 是 Line，`out` 是可选 Out。角色由 `node.ParseRole` 解析（hub 在 install 侧分派，不进入 node.Role），不会接受任意角色字符串。
- `--hub` 必须是一个直接可用的 HTTPS origin；用户信息、路径、查询串、片段、空白和换行均拒绝。
- `--node` 必须是 32 位小写十六进制 Node ID。
- VLESS 与 SSH 端口必须在 `1-65535` 范围内且不同。安装器还会把 VLESS 端口与当前实际 SSH listener 集合比较。
- 不提供 `--pairing-code`、`--token` 或同类 flag。未知参数和多余位置参数统一返回 `CONFIG_INVALID`，不会回显参数值。
- 不新增用户侧 `upgrade`、`rollback` 或 `status` 命令。`__internal-agent` 是固定 systemd 服务入口，零参数 `__internal-agent-version` 是安装器专用探针，都不是管理 CLI。

`--plan` 不能与 `--yes` 或 `--repair` 组合。它执行真实的只读 preflight，输出 plan JSON，但不读取配对码、不调用 `InstallNode`、不写宿主机。配置错误、任一 `fail` 检查或不可 apply 状态均返回非零。

## 安装流程

### 1. 本地配置校验

在读取安装器 state、访问宿主环境或开始 preflight 之前，CLI 先调用 `node.Config.Validate`。因此错误 origin、错误 Node ID、未知/多余参数、角色冲突、缺项和非法端口不会进入 preflight 或 apply。

### 2. 真实 preflight

即使指定 `--yes`，也先运行实际 preflight。当前检查包括：

- `/etc/os-release` 为 Debian 13。
- `dpkg --print-architecture` 与运行中的 MeshMux 架构一致，且只接受 amd64 或 arm64。
- 安装进程为 root；本机不是 Debian 13 或不是 root 时，即使指定 `--yes` 也拒绝。
- 根文件系统至少 1 GiB 可用。
- systemd 可用、NTP 已同步、CA bundle 可用。
- Hub origin 与官方 GitHub 下载源可通过 HTTPS 访问，且不跟随重定向。
- VLESS TCP/UDP 可绑定，或 repair 时确认为 MeshMux kernel unit 与固定二进制持有的 listener。
- 从 `ssh.socket`、`ss` 和传统模式下的 `sshd -T` 读取实际 SSH listener；配置的 `--ssh-port` 必须命中实际 listener，VLESS 不能与任一 SSH listener 冲突。
- 只查询 `ca-certificates`、`fail2ban`、`nftables`、`python3-systemd` 是否为 Debian 已安装包；缺失时，apply 只安装这些固定包，不升级其他包，也不添加第三方仓库。MeshMux 的 jail 全部使用 `backend = systemd`，而 Debian 只 Recommends `python3-systemd`，精简镜像（Debian 12/13 均可能）必须由安装器显式补齐。
- 执行 `fail2ban-client -t` 基线自检：已安装的 fail2ban 配置若不能通过自检，preflight 直接以 `FAIL2BAN_BASELINE_INVALID` 阻断，且发生在配对码被消费之前。交互模式只提供两种需明确确认的修复：安装 rsyslog 以生成 `/var/log/auth.log`，或新增 MeshMux 专属 `/etc/fail2ban/jail.d/meshmux-backend.local` 仅覆盖默认 sshd jail 的 `backend = systemd`（不改动其它 key，失败时回滚）；确认与结果写入本次 operation 的 `events.jsonl`。`--yes` 与非交互 handoff 不提示、不修改 jail，只返回稳定错误码和 next_action。fail2ban 尚未安装或只缺 `python3-systemd` 时，基线在固定包安装后、配对前再次自检。
- Out 的 `inet meshmux_out` 只能是首次不存在的表或已有 MeshMux ledger 明确拥有的表；不会接管、覆盖或删除其他 nftables 表。

公网入站、云安全组、真实协议握手和客户端可用是外部检查，保留 `pending`。本机 listener 或 plan 成功不能证明这些结果。

### 3. 展示 plan 与确认

CLI 把 plan JSON 写入 stdout，包含 operation ID、阶段、状态、检查、固定组件、端口、unit、受管路径和外部 pending 项。plan 中 `status=preflight_passed` 只表示本机检查没有 `fail`，不表示已安装。

交互模式要求精确输入：

```text
install edge
```

或：

```text
install out
```

输入其它内容即取消，退出非零且不调用 apply。`--yes` 只跳过这次交互确认，不跳过 preflight、配置校验或最终 result 处理。

### 4. stdin 配对码

首次安装确认通过后，CLI 在同一个 buffered stdin reader 上读取一行 43 字符 URL-safe 配对码。读取的是确认行之后的内容，避免 `bufio` 预读吞掉配对码。

- 配对码不进入 argv、安装 URL、Node config、安装 state、日志或结构化结果输出。
- 配对码只作为 Go 函数参数传给安装事务；未通过 43 字符格式检查时拒绝，不进入 `InstallNode`。
- 非交互 `--yes` 只省略确认短语，仍从 stdin 读取首次配对码。

### 5. 安装事务

安装器按以下顺序处理：

1. 读取并校验 `/var/lib/meshmux-installer/state.json`；已有 Node 配置必须与当前 Hub URL、Node ID、role、VLESS 端口和 SSH 端口相同。
2. 下载固定 sing-box 归档，校验归档 SHA-256，提取唯一 `sing-box` 文件，并校验解压后二进制 SHA-256。
3. 以当前运行中的 MeshMux CLI 自复制 Agent 二进制并校验 SHA-256；不采用外部 Agent 二进制。
4. 生成空 `users` 的 VLESS baseline 候选，使用暂存 sing-box 执行 `check`；Out 还执行 `nft -c -f` 配置语法检查。固定 Debian 包安装完成后、身份与配对之前，再次执行 `fail2ban-client -t`；基线仍不合格时以 `FAIL2BAN_BASELINE_INVALID` 停止，不消费配对码。
5. 完成配对并把节点身份以私有 `0600` 文件持久化。配对码本身不写入 identity、config 或 state。
6. 备份即将替换的 MeshMux 受管文件，原子写入 Agent、kernel、config、unit 和 Fail2ban jail；执行 `systemd-analyze verify`、`fail2ban-client -t` 和 `systemctl daemon-reload`。
7. Out 先应用并回读 ACL；然后启动/重启 sing-box，执行严格本机 readback，最后才启动或保持 Agent。

任何失败都以结构化 `InstallResult` 返回 `operation_id`、`stage`、`status`、稳定 `error_code` 和 recovery；`partial` 或 `failed` 返回非零。plan 成功不会被解释为安装成功。

## repair 与身份复用

`--repair` 只允许修复已记录的 Node 安装，且配置必须与 state 中记录的 Hub URL、Node ID、role、VLESS 端口和 SSH 端口完全一致。CLI 首次 repair 调用不读取配对码，传入空字符串，优先复用 `/var/lib/meshmux-agent/identity.json` 中的持久身份。

- 有可用持久 identity 时，repair 不要求旧配对码，也不会重复消费 code。
- repair 在成功复用 identity 后读取 Hub metadata 和既有 candidate，并重新执行本地检查、文件校验和数据平面恢复。
- **repair 不把节点拉齐到本次下载的候选。** 它保留已记录的 active candidate 与对应的已校验编译配置：候选的落地属于 Agent 的 `config.apply → config.readback` 链，并由 11c-3 的确认/回退记录锚定；安装器若在 repair 中悄悄换到另一个 revision，这些锚点就会指向宿主并未运行的发行。该决定是写死的，不是遗漏：当下载候选与记录候选不同时，结果以 `installed`、空 `error_code` 结束，并在 `next_action` 中以稳定码 `REPAIR_CANDIDATE_NOT_CONVERGED` 点名保留的 revision 与未应用的候选，`events.jsonl` 同时记 `stage/candidate_not_converged`。要真正换配置，请用 Web 的固定四任务链，而不是 repair。
- 只有安装器返回稳定 `PAIRING_CODE_REQUIRED` 或 `PAIRING_REQUIRED` 时，CLI 才提示管理员到 Hub Web 重签，并从 stdin 读取新 code；第二次调用继续使用同一个 operation ID。
- 缺少 identity 的 repair 返回 `IDENTITY_MISSING`，不会把已消费的旧 code 当成可重复凭据。
- 已有有效 LKG 的 repair 不为了“修布局”而覆盖 LKG；只有候选与已编译 active config 一致且文件权限正确时，LKG 才被视为有效。
- 记录的 identity 已被 Hub 撤销或替换时，repair 返回 `PAIRING_REQUIRED`（不是网络类的 `PAIRING_METADATA_FAILED`），CLI 提示重签；带新 code 的 repair 会重新配对、持久化新身份后继续。
- 已安装状态下非 repair 的再次安装直接拒绝（`REINSTALL_REJECTED`），不触碰宿主机与台账；v1.0.0 不支持重装，只支持同配置 `--repair`。
- Out 的 LKG 判定包含 ACL 文件：`out.nft` 必须存在、0600 且与候选编译结果逐字节一致，否则 repair 重写动态文件。active `config.json` 在生产 root 下还要求属主为 `root:meshmux-singbox`，否则同样视为非 LKG。

## 固定制品与版本边界

| 组件 | 版本 | 固定校验 |
| --- | --- | --- |
| sing-box amd64 归档 | 1.14.3 | `e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee` |
| sing-box amd64 binary | 1.14.3 | `768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93` |
| sing-box arm64 归档 | 1.14.3 | `29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e` |
| sing-box arm64 binary | 1.14.3 | `299f9f6080d9c43504714ddddae6aa9b853d430ccfc816c456a73613b5455689` |
| MeshMux Agent | `node.CurrentAgentVersion` | 从当前 CLI 自复制后校验 SHA-256 |

sing-box 不允许 `latest` 或调用者自定义下载 URL。Debian `fail2ban`、`nftables`、`python3-systemd` 和 `ca-certificates` 只通过当前发行仓库的包状态查询与安装路径处理，不在本页声称已完成 Debian snapshot 锁定。

CLI 已提供严格零参数的私有入口 `__internal-agent-version`，成功时只输出 `node.CurrentAgentVersion` 后换行，任何参数返回 2 且不回显参数。安装器侧已在 stage 接入该探针：对输出做 `TrimSpace` 后要求与 `node.CurrentAgentVersion` **完全相等**，禁用 `strings.Contains`；自复制哈希校验仍保留。探针的 L1 覆盖与全仓、隔离宿主机验收回填后方可记作完成。

## 受管路径与状态

| 路径 | 用途 |
| --- | --- |
| `/usr/local/libexec/meshmuxd` | 自复制并校验的 Agent binary |
| `/usr/local/libexec/meshmux-sing-box` | 固定 sing-box binary |
| `/etc/meshmux/agent.json` | 非 secret Agent 配置 |
| `/var/lib/meshmux-agent/identity.json` | 节点专属私有 identity |
| `/var/lib/meshmux-agent/state.json` | Agent runtime 状态与 LKG |
| `/var/lib/meshmux-agent/active-candidate.json` | 当前 active candidate 元数据 |
| `/var/lib/meshmux-agent/staged/` | runtime 暂存目录（按 revision 保留 candidate/config；健康 apply+readback 后只保留当前 revision、上一 revision 与最近窗口，失败/回退的暂存不回收） |
| `/var/lib/meshmux-singbox/config.json` | active sing-box 配置 |
| `/var/lib/meshmux-agent/out.nft` | Out ACL 脚本 |
| `/etc/systemd/system/meshmux-agent.service` | Agent 服务 |
| `/etc/systemd/system/meshmux-sing-box.service` | 独立 non-root kernel 服务 |
| `/etc/systemd/system/meshmux-out-acl.service` | Out ACL oneshot |
| `/etc/fail2ban/jail.d/meshmux-node-ssh.local` | MeshMux 专属 SSH jail |
| `/var/lib/meshmux-installer/state.json` | installer state 与 owned paths 台账 |
| `/var/lib/meshmux-installer/operations/<operation-id>/events.jsonl` | operation journal |
| `/var/cache/meshmux-installer/<operation-id>/` | 暂存与下载 cache |
| `/run/lock/meshmux-install.lock` | 安装/repair 串行锁 |
| `/var/lib/meshmux-agent/runtime.lock` | Agent 与 repair 的动态写事务锁 |

`InstallState.ManagedFiles` 记录的是本次 MeshMux 静态受管文件的 SHA-256；identity、active candidate、active config 和 runtime LKG 属于受保护的动态路径，不作为普通静态 ledger 项。已有第三方文件、symlink、未经 ledger 记录的非 MeshMux 路径、其他 nftables 表都不会被自动接管。

`runtime.lock` 只在动态写事务期间持有，不伴随 Agent 进程生命周期。Agent 离线不会自动停止独立运行的 `meshmux-sing-box.service`，也不会以“离线”为由删除 identity、candidate 或配置。Agent 启动对该锁的等待有 60s 上界：超过后以稳定码 `RUNTIME_LOCK_TIMEOUT` 退出，由 systemd 重启重试；首启 bootstrap readback 的瞬时重试同样有界且可取消，预算复用 `agentLockTimeout`。

Agent 启动发现未完成的 apply journal 时，恢复失败**不会**退出进程（否则 systemd 会把它拖进无限重启，且失败回执从未落盘）：可重试的宿主瞬态保留 journal，以 `recovery_required` 降级启动，`config.check`/`config.stage`/`config.apply` 以稳定码 `RECOVERY_REQUIRED` 拒绝动态写，轮询在 `runtime.lock` 内按上界重试；确定性失败（journal 损坏、缺少有效 LKG、LKG 候选缺失、ACL/readback 宿主漂移）以 `partial` + 稳定 `error_code` 落盘并上报后收敛、移除 journal，节点仍可被后续链修复。在这条恢复路径上，只有 state 无法持久化时才拒绝启动。

## partial、failed 与有限恢复

安装事务使用 `validate → stage → apply → readback`。失败语义如下：

- `partial`：已经发生一些宿主写入或数据平面状态，但尚未达到完整成功；退出非零并保留 operation journal。
- `failed`：当前阶段没有完成，且没有可声明的可用结果；退出非零。
- `rolled_back`：仅在已有受管文件和可恢复快照时，回滚成功；它也不是“安装成功”。
- rollback 本身失败、恢复不完整或 readback 不一致时仍是 `partial`，绝不提升为 success。
- repair 与回滚不自动恢复 nftables 表：快照只覆盖受管文件，`nft -f` 应用过的 Out 表失败时保持 fail closed（unit 停掉、文件保留），由管理员按恢复指引手动处理，不做自动 `nft delete/flush`。

Agent runtime 的 `config.check`、`config.stage`、`config.apply`、`config.readback` 使用固定任务类型，params 只允许 `revision`。apply 在 runtime lock 内校验暂存配置、执行 `sing-box check`、原子替换、受控重启并严格读回进程、listener、配置 hash 和 binary hash。只有存在有效 LKG 时才尝试恢复；恢复后仍要求完整 readback，失败则报告 `partial`。启动恢复失败同样以 `partial` 落盘并上报，而不是退出让 systemd 重启循环；未被 Hub 看到 `applying` 的 journal 用 `partial`（而非 `rolled_back`）作为回执，因为 Hub 的 pending 行只接受前者。plan 或 check 成功不代表 apply 成功。

## Web 固定操作与离线状态

Node 页面只暴露固定操作，管理员不能提交任意 task kind、命令、路径或 URL：

- “重新校验 / 应用”在一个事务中生成不可变 candidate revision，并排入固定的 `config.check → config.stage → config.apply → config.readback` 四任务链。
- 已有未完成 `pending/applying/verifying` 任务时拒绝重复排队，避免并发 apply。
- “重签身份”撤销旧节点身份、替换待用配对码、把未完成旧任务标记为 `IDENTITY_REPLACED`，节点回到 `pending`；不停止节点服务，也不删除 candidate/config 数据。
- “吊销身份”把未完成任务标记为 `IDENTITY_REVOKED`，并使待用配对码失效；不会代替管理员删除宿主机数据。
- 没有 heartbeat、节点仍为 `pending`，或最近 heartbeat 超过 2 分钟时，Web 视为离线，不向该节点投递会修改节点状态的任务。

Agent 的心跳与任务拉取共用同一个 1s ticker（`defaultAgentPollInterval`，`internal/core/node/command.go`）：每个周期先发心跳、再拉任务，所以排队的配置链最迟约 1s 后被取走。间隔可用 `RuntimeOptions.PollInterval` 覆盖（只接受不小于 1s 的值），没有对应的配置项或 CLI 参数。代价是每节点每秒一次小型已认证请求；当前机队规模下可接受，节点数量显著增长时需重新评估 Hub 的连接与写入压力。Hub 与 Agent 的日志默认级别都是 Warn（`internal/logging`），可用 `MESHMUX_LOG_LEVEL=info`（或 `debug`）恢复详细行；成功心跳本身在这条路径上只写 Debug，默认看不到，失败路径不变。详见 [OBSERVABILITY](OBSERVABILITY.zh-CN.md)。

`paired`、`check` 成功或页面显示“本机服务已确认”只表示最新 desired revision 与严格本机 readback 一致；它们仍不代表公网可达、真实协议握手或客户端可用。

## 当前 baseline 与非目标

当前 VLESS 候选明确生成空 `users`：

```json
{
  "type": "vless",
  "users": []
}
```

因此 v1 baseline **没有 TLS/REALITY、没有代理用户、没有客户端凭据、没有订阅**；#7 Phase 3A 已合入（PR #19/#21/#22），v2 REALITY 候选与订阅另行交付。不得从本地 listener、plan 或 readback 推导公网端口可达、真实 VLESS/REALITY 握手成功或客户端可连接。

Out 是可选组件。设计目标要求 Out 空授权默认全拒绝且仅目标端口可用；#8-B 已据此重写受管 ACL：`inet meshmux_out` 的 `input` chain 保留 `policy accept` 仅覆盖主机 SSH/回环/回程，VLESS 目标端口的 TCP/UDP drop 默认丢弃，只有 Hub 授权的 Line 源地址在 drop 之前 `accept`；`nft -j` 回读按已应用集合精确比对，任何差异为 `OUT_ACL_SOURCE_MISMATCH`。#8-D 的 `internal/route` 交付 AI 规则集版本锁与 Out 不可用 fail-closed，`DeleteOut` 单事务删路由并清 ACL。这些是源码与隔离测试证据；真实 nft readback 与 AI 双跳流量仍待隔离 Debian 13 VM 实测。`#9` 和 `#11` 不在本轮实现范围内；#11 仍是 v1.0.0 P0，需要独立实现和验收。

## 验收状态

以下矩阵必须由主控用真实运行结果回填。当前没有 PR-B CI 成功链接；不能把脚本存在、定向测试通过、源码实现或 plan 输出写成通过。

| 层级 | 待验范围 | 当前状态 |
| --- | --- | --- |
| L1 | CLI flag/stdin/确认/预检拒绝无副作用、repair 身份复用、structured partial/failed、内部版本探针 | 待验 |
| L1 | installer state/owned paths、check/stage/apply/readback、runtime LKG/journal、Web 离线与固定 recheck/reissue/revoke | 待验 |
| L2 | Debian 13 amd64 固定 sing-box 1.14.3、systemd unit、Fail2ban/nft 配置自检 | 未测 |
| L2 | Debian 13 arm64 固定制品与组件配置自检 | 未测 |
| L3 | 隔离 Debian 13 VM 的 edge/out 首装、repair、重启、故障恢复、实际 SSH/VLESS 端口与 Fail2ban/nft 行为 | 未测 |

Issue #5 的历史成功链接与 `c5be00c` / `17baaa1` 相同 tree 说明保留在 [验收标准](ACCEPTANCE.zh-CN.md)，不因本页变更历史结论。PR-B 的 `ci-node-vm.sh` 握手与 `TestNodeSystemVM` 已就位，待隔离 Debian 13 运行回填成功链接后方可把 Node L3 记为通过。

相关边界见 [验收标准](ACCEPTANCE.zh-CN.md)、[纳管流程](ENROLLMENT.zh-CN.md)、[安全设计](SECURITY.zh-CN.md) 和 [CI 验证规范](CI_HUB_VALIDATION.zh-CN.md)。
