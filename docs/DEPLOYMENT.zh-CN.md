# 部署视图

## 支持拓扑

| 模式 | 运行主机 | Out 是否必须 |
| --- | --- | --- |
| All-in-one | Hub 同时提供一个 Line 的 sing-box | 否 |
| Proxy aggregation | Hub + N 个 Line（N≥1） | 否 |
| AI egress | Hub + N 个 Line + 1 个 Out | 是，此模式选用才需要 |
| Mesh-only | Hub + 独立 Mesh 设备/子网路由 | 否 |

~~~mermaid
flowchart TB
  Browser["Admin browser"] -->|"HTTPS"| HubCaddy["Hub / Caddy"]
  HubCaddy --> HubWeb["Go Web, API, jobs, SQLite"]
  HubWeb --> HS["Headscale / DERP / STUN"]
  LineAgent["Line Go Agent"] -->|"HTTPS outbound management"| HubCaddy
  OutAgent["Optional Out Go Agent"] -->|"HTTPS outbound management"| HubCaddy
  Phone["Phone sing-box"] -->|"VLESS"| LineKernel["Line sing-box"]
  LineKernel -->|"direct"| Internet["Internet"]
  LineKernel -->|"selected AI destinations"| OutKernel["Optional Out sing-box"]
  OutKernel --> Internet
  Phone <-->|"Tailscale P2P or DERP"| NAS["NAS / subnet router"]
  Phone -.-> HS
  NAS -.-> HS
~~~

## 进程分工

- Hub: Go Web/API + Agent coordinator + task worker, SQLite, Headscale + DERP/STUN, Caddy, optionally local sing-box Line. 以 systemd 管理独立服务；不把 Go 应用作为 root HTTP 监听器。
- Line: Go Agent、sing-box、nftables、Fail2ban；SSH 为宿主机救援入口，正常运营不需再次使用 CLI。
- Out: 与 Line 相同的 Agent/内核基线，但 VLESS 入站只允许已授权 Line 的公开源地址；**默认拒绝**。
- Mesh-only devices: 使用标准 Tailscale 客户端注册 Headscale，无需 Agent、代理用户、VLESS、订阅下载；子网路由提供 advertise/approve/verify 流程。

## 端口原则

| 服务 | 默认建议 | 策略 |
| --- | --- | --- |
| Hub HTTPS 管理/控制与订阅 | TCP 443（Caddy 虚拟主机） | Web 仅 loopback；域名分离 |
| Hub HTTP challenge | TCP 80 | 视证书模式选择 |
| Hub STUN | UDP 3478 | 独立可配置，验证真实外网 |
| Hub 自带 Line | TCP 8443 | 防止与 Caddy 443 冲突 |
| Line / Out VLESS | TCP 443 | 安装前可自定义，检查云侧 ACL |
| SSH | 读取有效 SSH 配置 | 不默改端口；可按明确确认安全切换 |
| Agent 管理 | 无公网入站 | Agent 主动 HTTPS 连接 |

不得以服务监听成功推断云安全组已经开放或客户端握手成功。IPv4、IPv6 与 UDP 的诊断应分开。基线 Debian 13 amd64/arm64，其他操作系统须单独建立真实安装测试。
