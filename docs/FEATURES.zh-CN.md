# MeshMux 功能清单与版本边界

本表为**规划目标而非实现状态**。**P0 = 首个正式可发布版本 v1.0.0 必须验收**；**P1 = v1.0.0 之后**再由 Issue/PR 安排。功能实现和产品发行是两回事，单个 PR 不等于一个 Release。

## 当前实现与验收边界

- **Web 基座**：单管理员认证、安全会话、SQLite、基础控制台和节点工作区已提供隔离验收入口。
- **Hub 安装**：Issue #5 的 Hub `--plan`、确认后 apply、`--repair`、受管文件台账与有限恢复已合并，并有 L1/L2/L3 amd64 自动化证据；仍不是正式发行包。
- **Line / Out（Issue #6 已关闭）**：`meshmux install edge|out`、真实 preflight、固定制品、stdin 配对码、systemd Agent/sing-box、state/owned paths、structured partial/failed、有限 LKG 恢复与 Web 固定 recheck/reissue 已随 PR #18 合并进 `main`（merge `17c4e4c`）。证据：L2 [39372308917](https://github.com/wingsky-1/MeshMux/actions/runs/39372308917)、L3 [39367683751](https://github.com/wingsky-1/MeshMux/actions/runs/39367683751)（head `78e259b`、tree `e35fc88`）与 PR CI [39373760962](https://github.com/wingsky-1/MeshMux/actions/runs/39373760962)（head `0149581`）全 success。
- **Node baseline 与 Issue #7（已合入）**：PR-A 交付独立订阅域模型（SQLite schema 4、仅存哈希的 ≥288 bit Token、per-Line 安全 UUIDv4）、严格 v2 REALITY 编译器（legacy v1 逐字节不变）与合法空用户；PR-B 交付 Web 订阅用户增停删/选线/改名排序/Token 轮换撤销与精确同步证据、sing-box JSON 与 Mihomo YAML 双格式鉴权下载（双架构客户端真实导入全绿）、跨 Line 全链收敛与注入时钟；PR-C 交付 Hub 共存有效台账及修复/预检（隔离 VM 共存生命周期 PASS）。三者 CI（go/components/客户端导入/hub-vm）对应 head 全绿；尚无公网可达、真实公网握手或客户端可用证据。
- **Out**：安装产物可选。ACL 已由 #8-B 改为**空授权默认全拒绝**：`inet meshmux_out` 基线 `policy accept` 仅保留给主机 SSH/回环/回程，VLESS 目标端口在 `input` chain 内的两条 `tcp/udp dport drop` 默认丢弃，仅 Hub 授权的 Line 源地址（`/32`/`/128` 或已对齐 CIDR）在 drop 之前获得 `accept`；`nft -j` 回读逐条比对已应用集合，`OUT_ACL_SOURCE_MISMATCH` 不伪装健康。#8-C 完成 Hub↔Line↔Out 白名单协调与四事实双向 readback（白名单 / 入站 / REALITY / 最终出口），#8-D 完成 AI 规则集版本锁（`RulesetPin{Source,Version,SHA256}`，下载/摘要/大小失败 `RULESET_FETCH_FAILED` 拒绝发布）、Out 不可用默认 `OUT_OFFLINE_FAIL_CLOSED`（回退 Line 需显式 opt-in + `operation_id`）与 `DeleteOut` 删路由+清 ACL。**仿真证据**：隔离单元/竞态测试覆盖 ACL 有序 accept-before-drop、`nft -j` 精确集合、注入 accept 与 state 缺失断言、规则集 pin 与 fail-closed；**真实证据**：L2 privileged Debian 13 容器 `nft -f` apply + `nft -j list table inet meshmux_out` 至少 2 条 rule 断言与 `nft list` 日志（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)，head `9495730`、tree `5720b86`，amd64 实得 PASS 非 SKIP；无 `CAP_NET_ADMIN` 显式 SKIP，不计为通过）；L3 [hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)（同 head/tree）hub/edge/out 全 success，含真实 `nft list` 回读。**仍缺**：AI 双跳实际流量（已移交 #10）与客户端可用，不属本轮已有证据。
- **独立阶段**：#7 交付订阅模型、原生 REALITY 编译器、Web 订阅生命周期/下载与 Hub 共存，PR-A/PR-B/PR-C 均已合入（各 CI 全绿）。#8 的四项 PR 已交付源码与隔离自动化证据：仿真证据为 Go 单测/竞态，真实证据为 L2 privileged 容器 `nft -f` apply + `nft -j` readback 与 L3 VM readback（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)、[hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)，head `9495730`、tree `5720b86`），AI 双跳流量仍缺（双跳已移交 #10）；#9 不在其实现范围；#11 Web 全节点统一升级仍是 v1.0.0 P0，但不属于本轮实现或验收。

- **Hub 自升级（#11d）**：Web 统一升级的 Hub 段已交付 B 级实现：per-op 数据库备份（`keep=2`，confirmed-only GC）→ root 预置目标 manifest → 已校验 staged 包 → root dispatcher 协调换 Hub 二进制并重钉 co-located Line 的四处 pin → 重启 → 启动身份回读确认；任何失败都由旧包的 restore 在新 data-dir 上恢复。Web 没有特权、不构造 ExecStart、不下载 manifest；`operation_id` 与稳定码贯穿回执。**边界**：只支持 MeshMux 程序与发行包中明确兼容的固定组件；生产 Hub 自升级的目标 manifest 在 12e 建立发布通道前不存在，`MANIFEST_UNAVAILABLE` 是预期结果；11d 不新增表、不 bump schema（`user_version` 保持 10）；B 级 fixture 只证形状，C 级隔离 VM/真机验收归 #12。

### Hub 自升级的已知行为（#11d）

- **顺序与单飞**：Hub 必须先确认升级（`POST /tasks/hub-upgrade/backup` → `apply` → 启动身份回读）才允许为 Line/Out pin 更新的目标。单飞判据只看 journal 是否非终态（`HUB_UPGRADE_BUSY` / `HUB_HANDOFF_BUSY`）；`irreversible_approved` 是一次尝试门，Confirm 后清除，不参与 busy。
- **不可逆迁移**：manifest 的 `database_migration=irreversible` 必须先在 `/tasks` 的既有审批路由写入记录位（字面值 `irreversible_confirm=1`），否则 apply 以 `IRREVERSIBLE_CONFIRM_REQUIRED` 零变更拒绝；不存在 flag 或环境变量绕过。
- **恢复是有损的（LOSSY）**：restore 只按当前失败 op 的 per-op 副本恢复到 `<data-dir>/restore-<op>-<unix>`，不自动选择更早的 confirmed 代；`snapshot_at` 之后的写入丢失。11d **不做**额外的停机前 quiesce/`wal_checkpoint` 窗口，而是选择“如实标注”——`VACUUM INTO` 的事务一致快照与 `snapshot_at` 就是可承诺的边界，操作员必须在恢复后重做快照之后的变更。新 Web 的第一次对账（启动或 30s ticker）写 `hub-upgrade/restored.json`（schema 1、`operation_id`、`snapshot_at`、`lossy=true`）并把 journal 置 `reverted`。**LOSSY 只存在于 `restored.json` 与 `/tasks` 的 Hub 区块**：result schema 1 没有 `lossy`/`snapshot_at` 字段，不能声称 result 显示 LOSSY。恢复产生的数据目录里携带的旧记录（含扁平指针）只可作 `SCHEMA_TOO_NEW` 诊断，**不能作为下一次恢复源**；标记由**下一次对账 pass** 在见到新的已提交备份（journal `backed_up` 且 per-op 记录可读、`staged|confirmed`）时清除（`internal/hubupgrade/reconcile.go` 的 `clearSupersededMarker`），不是备份提交瞬间由 producer 清除。**活动数据目录是 `<原-data-dir>/restore-<op>-<unix>`**：确认恢复后若直接删除原 data-dir，会连同这个活动目录与正在使用的数据库一起删除；必须先确认新目录已被 Web 使用并保留，再另行处置原目录。
- **root 可控制台恢复（D2）**：旧包是唯一恢复执行体。root 可以不依赖 Web/请求目录直接运行冻结 argv（见 [验收](ACCEPTANCE.zh-CN.md) 的命令块），**但必须先按验收文档用 `sha256sum -c` 对旧包做执行前摘要核对**（记录里的 `from_agent_sha256`；RAUC/Mender 的 verify-then-exec 纪律——执行体自己的 `/proc/self/exe` 自检发生在 exec 之后，不能保护 exec 本身）。也可以由 root 向 `/run/meshmux-hub/requests` 投递一份归 `meshmux` 所有、0600 的恢复请求。两种方式都要求 journal 为 `failed`/`partial`/`verifying` 且没有待消费请求。
- **看门狗与启动守卫**：`meshmux-web.service` 有 `WatchdogSec=120`、`NotifyAccess=main`、`StartLimitIntervalSec=300`、`StartLimitBurst=3`；Web 只在 `SELECT 1` 可读时发 `WATCHDOG=1`。`/run/meshmux-hub/boot` 记录同一版本的健康前启动次数，三次未达健康后的下一次启动记 `HUB_UPGRADE_BOOT_CRASH_LOOP` 并退出，避免无限重启；成功监听即清除计数。**与 systemd 的交互**：快速崩溃循环时 systemd 的 `StartLimitBurst=3` 会先挡住第 4 次启动（二进制根本不运行），所以 `HUB_UPGRADE_BOOT_CRASH_LOOP` 通常只在**慢速/人工启动**（超出 300s 窗口或手动 `systemctl start`）时出现；这与 Kubernetes `CrashLoopBackOff` 的分工一致——快速循环由编排器/服务管理器的限流器观察并退避，进程内守卫只补充“同一版本连续不健康”的语义，不能替代 systemd。**确定性拒绝也会消耗启动预算**：`SCHEMA_TOO_NEW` 发生在 BootGuard 之后，会留下 `boot-attempts.json` 记录；错误 flag 在 `parseConfig` 阶段即退出、不会进入 BootGuard，但 systemd 的 `StartLimitBurst` 仍把它算作一次启动。两者都不会自行恢复，先修原因，不要重启循环。恢复：systemd 已限流时用 `systemctl reset-failed meshmux-web.service` 清启动限制；启动能进入二进制但被守卫拒绝（或人工修复后要做一次干净慢启动）时删除 `/run/meshmux-hub/boot/boot-attempts.json`；重启主机会清空 `/run`，也重置计数。按当前阻塞者选择，不要同时盲目执行。
- **恢复后 Web 起不来**：终态 + 人工指引，原 data-dir 保留，不自动重试；若二进制/pin 已改而恢复未完成，执行体落 `partial` 并保持 Web down。
- **Line 重启可观测性限制**：重钉后只有 Line 单元处于 active 才重启；跳过重启只在执行体日志可见，result schema 1 没有自由文本字段，回执不携带该提示。
- **写入前失败的可观测性**：restore/update 在 claim/result 之前的拒绝不写 result，只在 stderr/日志给出稳定码与 argv 中的 `operation_id`；`/tasks` 只能看到 journal 与旧 result，不会看到一条伪造的新失败。
- **交接暂存失败不落 failed（spec §5.5 偏差，记录在 T7 文档）**：`HUB_BACKUP_STAGE_FAILED` 时 journal 仍是 `backed_up`，per-op 备份仍有效、可重试同一 `operation_id`，且没有请求文件。spec §5.5 的“任意失败 → 终态 failed”在这里不适用：暂存目标包失败没有触碰主机，保留 `backed_up` 才能让操作员修好 manifest/包来源后用同一操作重试；该偏差只由本段记录，不回写 spec。
- **verifying 只由启动对账确认**：ticker 不会把 `verifying` 推进到 confirmed。若页面显示 `verifying` 而 running 已是 target，重启一次 Web 让启动对账执行确认。
- **`mixedVersionGate` 的运维后果**：Hub 运行版本前移前，任何为 Line/Out pin 更新目标的请求都会被旧 Hub 的目标门拒绝；co-located Line 滞后期间 v3 候选同样被拒。这比 Kubernetes 的 skew 更严（Hub 必须先升），发布 v3 路由前应先完成 Line 升级。
- **新增/收口的稳定码**（均在既有分组内）：`HUB_BACKUP_ORPHANED`、`HUB_BACKUP_POINTER_UNFLUSHED`、`HUB_UPDATE_VERSION_MISMATCH`、`HUB_UPDATE_PREFLIGHT_FAILED`、`HUB_SHARED_BINARY_REPIN_INCOMPLETE`、`HUB_UPGRADE_BOOT_CRASH_LOOP`、`HUB_UPGRADE_CLAIM_INVALID`/`_FAILED`、`HUB_RESTORE_PAYLOAD_MISMATCH`、`HUB_RESTORE_BINARY_MISSING`、`HUB_RESTORE_CARRIED_SOURCE`、`HUB_RESTORE_DROPIN_FAILED`、`HUB_RESTORE_HEALTH_FAILED`、`HUB_RESTORE_IDENTITY_MISMATCH`、`HUB_RESTORE_STOP_FAILED`、`HUB_RESTORE_START_FAILED`、`HUB_RESTORE_MARKER_INVALID`/`_FAILED`、`HUB_RESTORE_ARGV_INVALID`、`HUB_RESTORE_DIGEST_MISMATCH`、`HUB_RESTORE_EXEC_COPY_FAILED`、`HUB_RESTORE_EXEC_FAILED`。`CONFIG_CONFLICT` 仍是“副本 schema/版本与记录不符、停机前拒绝”的唯一码。

详见 [Web 开发说明](WEB_DEVELOPMENT.zh-CN.md)、[Hub 安装](INSTALL_HUB.zh-CN.md) 与 [Line / Out 安装](INSTALL_NODE.zh-CN.md)。下表仍是发行目标，不是任何单个 PR 的验收结论。

## P0：v1.0.0 最小可用闭环

| 领域 | 必须能力 | 可验收的用户结果 |
| --- | --- | --- |
| 安装 | Debian 13 amd64/arm64；Hub / Line / Out 宿主机 `install` | 干净 VM 能重复安装，错误有阶段与恢复方案 |
| 管理 | Hub 单管理员 Web、数据库、HTTPS；Out 可不部署 | 不依赖 Zero Trust；单机 Hub+Line、多 Line、可选 Out 都能工作 |
| 纳管 | Web 一次性配对，Line/Out 安装后 Agent 主动 HTTPS 连接；节点状态与展示名 | 目标机只需 install；身份可重签/撤销，非法任务拒绝 |
| 代理 | 固定 sing-box 1.14.3，VLESS/REALITY 入站，自定义监听端口，Line 生命周期 | PR-A 已交付模型与 v2 编译器，PR-B 已交付 Web 生命周期与订阅（双架构导入绿），PR-C 共存 VM 绿；真实公网握手与客户端可用仍缺证据 |
| 聚合 | 多 Line 线路选择、命名、标准订阅导出 sing-box / Mihomo | 客户端导入成功，新增 Line 按选择更新配置 |
| 订阅 | 用户创建、禁用、删除，Token 撤销与 per-Line VLESS UUID 删除分离，精确跨节点凭据撤销 | 旧 URL 不可下载；删除先门禁公开下载，远端部分失败不假完成 |
| Mesh | Headscale 注册/注销、Mesh-only、独立子网路由及路由批准（9a 设备生命周期、9b 子网路由声明/批准/撤销与观测归档均已随 PR #62/#63 交付：Web 页面 + `mesh_devices`/`mesh_enrollment_keys` + 本地 Headscale CLI 适配器） | 无代理订阅的 NAS 可以入网并实际路由（真实 NAS 跨网可达仍缺证据） |
| 单 VPN | 设备专属 sing-box 代理 + Mesh 配置（9c 已交付并仅覆盖待注册的 proxy_mesh 设备：一次性 Tailscale Endpoint + 代理 selector，无 TUN；标准订阅仍不含 Mesh）；该 Endpoint 固定 `accept_routes:false`——文档没有 TUN、唯一 Tailscale 规则只匹配 Tailnet CGNAT 前缀，接受对端子网路由没有出口，`mesh_only`/`subnet_router` 因此不渲染该文档而保留现成客户端（是否接受对端路由由该客户端的 `--accept-routes` 决定）；SSID 与远程家庭网段属 #10 | 经过 iOS/Android 真机、家庭 Wi-Fi 与外部网络验证 |
| 分流 | Web 配置客户端 CN/国际/Tailnet/DNS 与服务端域名/IP/规则集；AI Line→Out 或 Line 直出 | 不存在 Out 不生成无效配置；Out 出错默认不泄漏回退出口 |
| 基本诊断 | 节点/任务日志、固定错误码、必要的公网端口与协议健康检查 | 出错能辨别主机监听、云安全组、代理握手与 Mesh 问题 |
| 安全 | 单管理员认证/CSRF/限速；SSH + Web Fail2ban；端口与防火墙一致 | 匿名拒绝；暴力登录和异常来源安全处理 |
| 安全 | 节点独立身份、受限权限（实际边界待 Debian 13 VM 验证）、Out ACL、高熵 Token、日志脱敏 | 无任意 Shell；Out 空授权默认拒绝且仅目标端口可用；Token 可轮换/撤销 |
| 可靠性 | 版本固定与哈希验证；配置 check / stage / apply / readback / rollback | 错误配置不覆盖已验证版本，部分失败可重试 |
| 统一升级（#11） | Web 逐节点升级 MeshMux Hub/Line/Out 及发行包内经过兼容验证的固定组件，持久化任务、版本回读、失败回退 | 不需日常 SSH/CLI 完成已支持版本升级；部分失败明确报告，不声称跨节点原子事务 |

## P1：首版后独立规划

| 能力 | 原因 |
| --- | --- |
| 任意第三方组件或操作系统升级 | v1.0.0 只支持 #11 发行包内明确固定且完成兼容验收的版本；不提供任意 upstream latest、独立组件跨版本或系统发行版升级 |
| 精确用户流量配额、复杂统计/告警 | 先验证 sing-box 1.14.3 API 可用性与口径 |
| 多 Out 故障切换、第三方订阅导入 | 不影响单 Out/无 Out 的核心业务 |
| Telegram、额外 DERP、复杂 ACL 编辑、完善的路由策略模拟器 | 首版以正确配置和清晰回读优先 |
| Debian 11/12、Ubuntu、更多架构、纯 IP HTTPS | 需独立运行环境验收 |

## 不变量与质量底线

- **订阅聚合（Task 4，schema 13）**：订阅是纯函数产物——`ComposeSubscription(lines, outs, rules, network)` 对同一选择永远输出相同字节，并给出一个内容摘要；选择存 `subscription_lines`/`subscription_outs`/`subscription_rules`/`subscription_networks` 四张边表（`position` 组内唯一，1.0 单订阅最多 1 个 Out），`subscription_snapshots` 只存选择+版本+排序与已批准产物摘要，**不存字节**。`/subscribers/wizard` 四分组向导：预览只提醒（`!`）不写入，保存时组装冲突、Out 槽位与内核门禁不过即阻断（`✖`）且不写入任何选择；sing-box 门禁必需，Mihomo 仅在已安装固定版本时执行（缺席显示跳过提醒，不静默通过）。下载按快照重新组装并与已批准摘要比对，摘要不一致或从未批准即拒绝；未走过向导的存量订阅保持原导出路径。同一 Line 上的订阅必须选同一 Out，后选冲突返回 `SUBSCRIPTION_OUT_CONFLICT` 并列出既有订阅名；删除被订阅引用的 Out 被拒（`OUT_REFERENCED_BY_SUBSCRIPTIONS`），被引用规则删除由规则库拒绝并列出订阅名。
- **Subscriber ≠ Mesh Device ≠ VLESS Credential**，订阅用户和 Mesh 设备可分别创建/删除。
- **订阅聚合（Task 5，schema 14/15）**：Out 侧授权改为**节点成员制**（Ruling R10，覆盖早期的订阅驱动派生），`out_bindings` 表与其读写路径在同一变更内删除（不留授权空窗）。规则：① Line 纳管成功即把其出口 IP 加入所有 Out 的 allowlist，Out 纳管成功即生成含全部现存 Line 的 allowlist（同一节点行事件双向生效）；② Line/Out 删除或身份吊销即从所有相关 allowlist 移除；③ 订阅创建/改选/状态变更**完全不碰 ACL**，也不再触发任何池级重算。无成员即**显式空授权（默认拒绝）**，既不是省略键也不是错误。DNS 名 Line 不能成为源（`LINE_EGRESS_UNVERIFIED`，fail-closed 而不是猜地址）。服务端 Line 路由、发布门禁、双读回与 `OutEgressFacts` 仍读同一派生结果，因此投影与数据面不会各说一套。`/nodes/out/bind`、`/nodes/out/unbind` 已退役（`OUT_BINDING_API_RETIRED`，HTTP 410）并指向订阅向导。
- **HTTP 代理出口（Ruling R11，schema 16）**：节点类型扩展为 Line / Out / HTTP 代理；HTTP 代理是外部端点（role `http`、status 恒为 `external`，无 Agent/配对/安装/候选/回读，排除在收敛门禁外），`nodes` 表重建以容纳该 role，新增私有 `node_http_proxy`（node_id PK、URL、可空 username/password、时间戳）。订阅出口位仍是 1.0 单选（Out 或 HTTP 代理，`MAX_OUTS_PER_SUBSCRIPTION=1` 语义延续，同一 Line 的所有订阅必须选同一出口）；服务端 route 的 `out` 出口按类型渲染：Out→Shadowsocks link key，HTTP 代理→sing-box `http` 出站 `{server, server_port, username?, password?}`（无凭据时省略认证字段）。URL 仅接受 `http://host:port`（可带 userinfo），凭据拆分存储且与 Line 私钥同级（0600 数据库），UI/API 只展示 host:port；used-by 互锁与彻底删除复用 Out 语义。
- **收尾清理（Task 6，schema 17）**：删除零生产调用方的旧路径，不改变 1.0 能力面。`route_policies` 的 **client 层停写**（创建/改版/激活/撤销均以 `POLICY_LAYER_RETIRED` 拒绝；表与既有 revision 保留，发布时仍可只读渲染并过双内核门禁作预览）；`exceptions`/`ssids` 顶层字段**显式拒绝**（`POLICY_PAYLOAD_RETIRED`，空数组/null 也拒绝），schema 17 把存量 payload 的这两个键删除，`default`/`rules`/`note` 与 server 层语义不变。规则库是客户端分流的唯一写入面（六种匹配器，无 SSID；`compiler.Match.SSIDs` 能力保留但不进入库）。同时删除已被 Task 3/4/5 取代的 AI 出口决策层、`jobs` 阶段机与部分测试专用包装（Task 4/5 公开读投影、冻结契约校验器与测试缝保留，见验收记录）；`ResolveAIRuleset` 字节校验、`jsonAPI/jsonNamespace` 与 `compiler.Match.SSIDs` 按计划保留。证据：`TestClientLayerWritesAreRetired`、`TestRetiredPolicyFieldsAreRejected`、`TestSchema17StripsRetiredPolicyFields`、`TestPolicyWriteAPILifecycle`（客户端写 409）。
- **Out 删除（Ruling R9）**：删除即彻底删除——先把它自身的 ACL 重算为空并等待主机确认，再删除节点行、`out_settings`（出口地址 + link key）、候选与任务；引用过它的 Line 路由按 fail-closed 重算（不会静默改走直连）。被活跃订阅选中、或 Out 离线/仍有未完成链时**拒绝删除**并说明原因，本次不删除任何内容（HTTP 409，非 202）。证据：`TestOutAuthorization_MigratedACLMatchesBindingBytes`（ACL 字节一致）、`TestOutAuthorization_SubscriptionNeverTouchesTheACL`（订阅变更不重发 Out）、`TestOutAuthorization_EnrollmentAddsEveryLine`（纳管即互通）、`TestOutDelete*`（彻底删除与拒绝路径）、真实 sing-box 1.14.3 双跳 AI 域名请求经 Line→Out + 真实 nftables 安装 guard 到私有 netns（`TestOutAuthorization_AIDoubleHopEndToEnd`）；现网 VPS 与客户端 App 实测仍未含。
- Out 可选，且 AI 规则可明确选择 Line 直出；配置了 Out 时该 Out 故障默认 fail-closed（`OUT_OFFLINE_FAIL_CLOSED`），不会静默直出；回退 Line 必须是管理员显式 opt-in 并带 `operation_id` 审计。#8 已把 Out ACL 的 `policy accept` 边界修正为空授权默认拒绝 + 仅授权源可用（`internal/node/render.go`、`internal/node/runtime_readback.go`、`internal/install/node_acl_test.go` 等隔离测试）。仿真证据为隔离单测；真实证据为 L2 privileged 容器 `nft -f` apply 与 `nft -j` readback（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)，head `9495730`、tree `5720b86`，amd64 实得 PASS；无 `CAP_NET_ADMIN` 显式 SKIP）与 L3 VM readback（[hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)）。AI 双跳实际流量（已移交 #10）与客户端可用仍缺。
- 编辑路由或删除用户前生成可审阅配置，失败不能报告完成。
- “安全优先”意味着保留必要测试和失败回滚，不引入不必要的架构、审批链或不相关功能。
