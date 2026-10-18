# MeshMux

**Web-first management for proxy aggregation, private mesh networking, and policy-based egress.**

MeshMux 是面向自托管场景的轻量级 Go 控制台：通过一个 Web 管理原生 sing-box 代理线路、Headscale/Tailscale 异地组网，以及可选 AI Out 出口。手机可使用一份 sing-box 配置同时实现代理与 Mesh；也支持不需要代理订阅的纯 Mesh 设备和子网路由。

> **当前状态：可在隔离环境运行 Web 安全基座，尚不能安装或用于生产。** 本仓库的 `install` 命令仍是拒绝执行的占位程序。下方完整业务功能是 **v1.0.0 交付目标**，不是当前已实现功能。请勿用于生产环境。

## 体验当前 Web

已实现单管理员初始化、登录/退出/改密、服务端会话、SQLite、安全校验和手机/桌面基础管理台。代理、Mesh、订阅和安装仍未实现。

在普通用户的隔离 Linux 环境（Go 1.27.2）运行：

```sh
go build -o ./bin/meshmux-web ./cmd/meshmux-web
umask 077
./bin/meshmux-web --listen 127.0.0.1:9080 --origin http://127.0.0.1:9080 \
  --data-dir "$PWD/.local-state" --dev-http
```

打开 `http://127.0.0.1:9080`，在另一终端读取 `.local-state/bootstrap.token`，通过页面设置管理员密码并登录。**Web 拒绝 root；开发 HTTP 仅限本机，手机验收使用 Caddy HTTPS。**

[完整运行、安全行为和恢复说明](docs/WEB_DEVELOPMENT.zh-CN.md) · [界面截图与验收证据](docs/previews/README.md) · [依赖与许可证](docs/DEPENDENCIES.zh-CN.md)

## 核心设计

- **Web 优先**：Hub 安装后通过 Web 纳管 Line / 可选 Out、创建和删除订阅、管理 Mesh 设备和路由、配置分流。目标机器仅运行一次 `meshmux install`；CLI 不承担日常管理。
- **Out 可选**：既支持 Hub 一体机、多个 Line，也支持按策略 Line → Out 的 AI 双跳。没有 Out 不影响代理、订阅或 Mesh 的使用。
- **身份分离**：订阅用户、sing-box 代理凭据、Headscale 设备是独立对象；Mesh-only NAS 不依赖代理订阅。
- **成熟组件**：Go 实现 Web/编排，直接管理固定版本 sing-box，组网复用 Headscale/Tailscale，HTTPS 复用 Caddy；不重新实现这些底层协议。
- **默认安全**：单管理员认证、Fail2ban、节点独立凭据、最小权限 Agent、订阅高熵 Token、脱敏日志、配置应用失败回退。

## 首个正式版本：v1.0.0

**首个对外发布的 GitHub Release 和稳定 Tag 为 `v1.0.0`。** 开发中用 Issue / 小而可验收的 PR 记录里程碑；不要求提前发布 `v0.x` 或以每天一个版本代替验收。

| v1.0.0 必须可用 | 最低验收 |
| --- | --- |
| `install` | Debian 13 上 Hub / Line / Out 首次安装、一次性纳管及可诊断失败 |
| 原生代理纳管 | sing-box 1.14.3 的线路管理、自定义 VLESS 监听端口，Out 可选 |
| Mesh 节点与路由 | Headscale 设备入网/注销、Mesh-only 与子网路由批准、基本状态 |
| 订阅创建与删除 | sing-box/Mihomo 普通订阅、sing-box 单 VPN Mesh 配置、跨节点凭据精确撤销 |
| 分流规则 | Web 编辑/验证客户端与服务端规则、国内外与 AI Out/Line 直出、明确兜底 |
| 安全与恢复 | Web 认证、SSH/Web Fail2ban、自定义 SSH 端口、ACL、脱敏日志、配置校验与回退 |
| Web 统一升级 | Hub/Line/Out 的 MeshMux 程序和发行包内已验证兼容的固定组件版本；分节点验证、失败回退及任务追踪（#11） |

v1.0.0 以**能安装、能纳管、能联网、能安全创建/删除、能在 Web 统一升级并恢复故障**为完成标准。统一升级由 #11 独立验收，不在当前 Web 安全基座实现。任意第三方组件跨版本升级、操作系统大版本升级、精确用户流量配额、复杂通知及多 Out 故障切换不属于 v1.0.0。

完整清单见 [FEATURES](docs/FEATURES.zh-CN.md)，阶段拆分见 [ROADMAP](docs/ROADMAP.zh-CN.md)，发行条件见 [ACCEPTANCE](docs/ACCEPTANCE.zh-CN.md)。

## 架构与技术基线

| 项目 | 首版选择 |
| --- | --- |
| 操作系统 | Debian 13，Linux amd64 / arm64 |
| 控制面 | Go Web + SQLite；Hub 上 Caddy HTTPS |
| 代理 | 原生 sing-box **1.14.3** |
| 私有组网 | Headscale **0.29.5** + Tailscale |
| 主机安全 | systemd、nftables、Fail2ban |
| 节点通信 | Agent 主动 HTTPS 连接 Hub，仅执行有限操作 |

所有二进制在安装器实现前须锁定版本、来源和校验值。Go 构建工具链及具体依赖记录于 [VERSIONS](docs/VERSIONS.zh-CN.md)。

## 文档与开发

- [产品定位](docs/PRODUCT.zh-CN.md) · [功能清单](docs/FEATURES.zh-CN.md) · [用户体验](docs/UX.zh-CN.md)
- [4A 架构](docs/ARCHITECTURE.zh-CN.md) · [部署视图](docs/DEPLOYMENT.zh-CN.md) · [纳管时序](docs/ENROLLMENT.zh-CN.md)
- [安全设计](docs/SECURITY.zh-CN.md) · [日志与排障](docs/OBSERVABILITY.zh-CN.md) · [验收门槛](docs/ACCEPTANCE.zh-CN.md)
- [版本基线](docs/VERSIONS.zh-CN.md) · [开发路线](docs/ROADMAP.zh-CN.md) · [协作说明](docs/DEVELOPMENT.zh-CN.md) · [架构决策](docs/adr/)

本地脚手架验证：

~~~sh
go test ./...
go vet ./...
go build ./cmd/meshmux
~~~

后续每项开发按 **Issue → PR → CI / 独立验收 → 合并**推进，不直接在 `main` 实验。详见 [AGENTS.md](AGENTS.md)。

## 许可证

[Apache-2.0](LICENSE)。公开仓库不包含个人基础设施地址、私有订阅链接或凭据。
