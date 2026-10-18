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

Web 不直接操作 sing-box JSON 的任意字段；由业务模型生成版本化、可审阅的候选配置。Hub 可选兼任 Line。Agent 只执行固定能力协议，不接受命令字符串。Headscale 管理采用经版本验证的本地官方 API/CLI 适配器，不暴露公网管理端点。

## 3. Data Architecture — 数据

- Hub SQLite（WAL）保存：nodes、node_identities、subscribers、proxy_credentials、mesh_devices、mesh_routes、route_policies、config_revisions、publications、jobs、audit_events；版本化迁移和定期一致性备份。
- Headscale 自带数据库保存：Tailnet 用户、节点身份、PreAuthKey、路由等组网事实；MeshMux 只保存稳定引用（Headscale Node ID）及期望策略，不直接改其数据库。
- Agent 私有目录保存：独立身份凭据、最后已知好配置、候选配置、回退记录和版本信息。节点配置不从外部任意 URL 直接执行。
- 标准订阅 Token 和设备专属 Token 高熵、独立、可撤销；公开制品仅在编译校验后原子切换。禁止普通日志记录完整订阅 URL、UUID 或密钥。
- 单操作 operation_id 贯穿 Web → job → agent → runtime → health probe，状态枚举 pending / applying / verifying / healthy / partial / failed / rolled_back。

## 4. Technology Architecture — 技术

Go 1.27.2、Debian 13、单一 Web/API Hub、Caddy HTTPS、SQLite、轻量后台任务、Headscale 0.29.5、sing-box 1.14.3、systemd、nftables、Fail2ban、结构化 slog。Web 层优先 chi + templ/HTMX，但仅在使用时引入依赖并固定其版本；初始脚手架只有 Go 标准库。

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

## 5. 关键不变量

1. 任何部署类型都允许 **零 Out**；Out 不可用时被策略引用的请求默认阻断，只有用户显式允许才退回 Line。
2. 管理通道与代理数据通道解耦。Edge/Out 主动出站 HTTPS，不新增公网管理 TCP 端口。
3. 安装预检、校验、应用、回读分阶段运行；主机云安全组在本机无法修改，单独报告。
4. 不承诺 sing-box 用户编辑零中断。优先配置验证、受控重启、回退，真正热更依赖验证后的官方能力。
5. Hub 的本地 Web / Agent 身份凭据与 Headscale 管理权限须隔离。
