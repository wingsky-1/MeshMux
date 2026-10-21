# 4A 架构（业务 / 应用 / 数据 / 技术）

## 1. Business Architecture — 业务

围绕五个稳定业务域展开：节点及线路、订阅发布、Mesh 设备、路由策略、任务与诊断。用户的核心旅程为「安装 Hub → Web 配对 Line → （可选）配对 Out → 创建订阅/独立 Mesh 设备 → 编辑规则 → 校验发布 → 观察与升级」。

## 2. Application Architecture — 应用

~~~mermaid
flowchart TB
    Browser["Browser / mobile"] --> Caddy["Caddy TLS"]
    Caddy --> Web["Hub Go Web / auth / API"]
    Web --> UseCases["Domain use cases"]
    UseCases --> Node["Node lifecycle"]
    UseCases --> Sub["Subscriber & subscriptions"]
    UseCases --> Mesh["Mesh devices & subnet routes"]
    UseCases --> Policy["Client/server routing policy"]
    UseCases --> Jobs["Persistent task runner"]
    Node --> AgentAPI["Authenticated Agent protocol"]
    Jobs --> AgentAPI
    Sub --> Compiler["Configuration compiler"]
    Policy --> Compiler
    Mesh --> Headscale["Headscale local adapter"]
    Compiler --> Singbox["sing-box config validator"]
    AgentAPI --> Agents["Outbound-connected node agents"]
~~~

Web 不直接操作 sing-box JSON 的任意字段；由业务模型生成版本化、可审阅的候选配置。候选文档当前为严格 `meshmux-node/v1`（非秘密、空 `users`）；#7 PR-A 已加入严格 `meshmux-node/v2` REALITY 文档（含用户与秘密字段），v1 行为逐字节不变，未知 schema 拒绝。Hub 可选兼任 Line。Agent 只执行固定能力协议，不接受命令字符串。Headscale 管理采用经版本验证的本地官方 API/CLI 适配器，不暴露公网管理端点。

当前 Node 安装路径把用户命令限制为 `meshmux install edge|out`，安装事务完成后由 systemd 启动固定服务：`meshmux-agent.service` 以受限 root 运行私有 `__internal-agent` 协议入口，独立 `meshmux-sing-box.service` 以非 root `meshmux-singbox` 运行 kernel。Agent 只接受固定任务类型、固定 binary/config 路径和固定 argv，不提供任意 shell、路径、URL 或管理命令；其动态写事务与 repair 通过 `/var/lib/meshmux-agent/runtime.lock` 串行化。Agent 离线不会自行停止 kernel。

## 3. Data Architecture — 数据

- Hub SQLite（WAL）保存：nodes、node_identities、subscribers、proxy_credentials、mesh_devices、mesh_routes、route_policies、config_revisions、publications、jobs、audit_events；版本化迁移和定期一致性备份。
- Headscale 自带数据库保存：Tailnet 用户、节点身份、PreAuthKey、路由等组网事实；MeshMux 只保存稳定引用（Headscale Node ID）及期望策略，不直接改其数据库。
- Agent 私有目录保存：独立身份凭据、最后已知好配置、候选配置、回退记录和版本信息。节点配置不从外部任意 URL 直接执行。当前 layout 使用 `/var/lib/meshmux-agent/identity.json`、`state.json`、`active-candidate.json`、`out.nft`，kernel 配置为 `/var/lib/meshmux-singbox/config.json`。
- Installer 的 `/var/lib/meshmux-installer/state.json` 记录 Node 的 immutable Hub URL、Node ID、role 和端口绑定，以及 MeshMux 静态受管文件 SHA-256 ledger；operation journal 位于 `/var/lib/meshmux-installer/operations/<operation_id>/events.jsonl`。
- 标准订阅 Token 和设备专属 Token 高熵、独立、可撤销；#7 PR-A 的 schema 4 只持久化 Token 哈希（原始值仅创建时展示一次），per-Line VLESS 凭据使用安全随机 UUIDv4。v2 候选携带的用户 UUID 与 REALITY 私钥属节点秘密，只经已认证的 Hub↔Agent 通道传输。公开制品仅在编译校验后原子切换。禁止普通日志记录完整订阅 URL、UUID 或密钥。
- 单操作 operation_id 贯穿 Web → job → agent → runtime → health probe，状态枚举 pending / applying / verifying / healthy / partial / failed / rolled_back。

## 4. Technology Architecture — 技术

Go 1.27.2、Debian 13、单一 Web/API Hub、Caddy HTTPS、SQLite、轻量后台任务、Headscale 0.29.5、sing-box 1.14.3、systemd、nftables、Fail2ban、结构化 slog。Web 层优先 chi + templ/HTMX，但仅在使用时引入依赖并固定其版本；初始脚手架只有 Go 标准库。Agent systemd unit 使用 root，并仅保留 `CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_CHOWN CAP_SYS_PTRACE` 的 capability bounding/ambient 集合；`CAP_SYS_PTRACE` 用于读取不同 UID sing-box 的 `/proc/PID/exe` 与 cmdline 实际 hash，`CAP_DAC_READ_SEARCH` 用于 `ss -p` 解析非 root sing-box 的 `/proc/PID/fd` 监听映射（无 `CAP_DAC_OVERRIDE`）。该权限边界仍需真实 Debian 13 VM 验证，当前不能宣称所有权限已经最小化验收。

~~~mermaid
flowchart LR
    Phone["Client sing-box"] -->|"VLESS/REALITY"| Line["Line sing-box"]
    Line -->|"ordinary egress"| Net["Internet"]
    Line -->|"optional AI / selected domains"| Out["Out sing-box"]
    Out --> Net
    Phone -.->|"Headscale coordination"| Hub["Hub + Headscale"]
    NAS["Mesh-only subnet router"] -.-> Hub
    Phone <-->|"Tailnet: direct first, DERP fallback"| NAS
    Agent["Line/Out Agent"] -->|"outbound HTTPS"| Hub
~~~

上图包含目标态的 VLESS/REALITY、用户、订阅和 Mesh 路径。`main` 上的 Node baseline 仍只生成空 `users` 的 v1 VLESS candidate，没有 TLS/REALITY、用户、凭据或订阅；本地 listener/readback 不代表公网可达、真实协议握手或客户端可用。Issue #7 PR-A 已合入独立订阅域模型与严格 v2 REALITY 编译器（v1 保持不变）；Web 生命周期、双格式下载、跨 Line 收敛与 Hub 共存已随 PR-B/PR-C 合入（含隔离 VM 证据），真实公网握手需后续证据。#8、#9 与 #11 不在本轮实现范围，#11 仍是 v1.0.0 P0。

## 5. 关键不变量

1. 任何部署类型都允许 **零 Out**；Out 不可用时被策略引用的请求默认阻断，只有用户显式允许才退回 Line。
2. 管理通道与代理数据通道解耦。Edge/Out 主动出站 HTTPS，不新增公网管理 TCP 端口。
3. 安装预检、校验、应用、回读分阶段运行；主机云安全组在本机无法修改，单独报告。`partial`/`failed` 必须显式返回，plan 或 check 成功不能当成 apply/安装成功。
4. 不承诺 sing-box 用户编辑零中断。优先配置验证、受控重启、回退，真正热更依赖验证后的官方能力。Out ACL 已由 #8-B 改为空授权默认全拒绝：`inet meshmux_out` 的 `input` chain 保留 `policy accept` 只为主机 SSH/回环/回程，VLESS 目标端口的 TCP/UDP drop 先于任何来源放行，只有 Hub 授权的 Line 源在 drop 之前 `accept`；`nft -j` 回读逐条比对已应用集合。真实 nft readback 与双跳流量仍待隔离 Debian 13 VM 实测。
5. Hub 的本地 Web / Agent 身份凭据与 Headscale 管理权限须隔离。Node 安装器只替换记录过的 MeshMux 自有文件和 `inet meshmux_out`，不接管第三方文件或 nftables 表。
