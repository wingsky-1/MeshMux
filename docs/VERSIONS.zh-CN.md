# 版本策略与组件基线

## MeshMux 发布版本（SemVer 2.0.0）

- **\`v1.0.0\` 是首个公开稳定发行版本**；在此之前用 Issue/PR/CI 推进，不将 PR 阶段号作为发布版本，也不强制发布 \`0.x\`。
- 完整 P0 和隔离/真实网络验收通过后，创建唯一不可覆盖的 v1.0.0 Tag 与 GitHub Release。
- 发布后：向后兼容新功能升 MINOR（如 1.1.0）；向后兼容修复升 PATCH（如 1.0.1）；不兼容变更升 MAJOR（如 2.0.0）。
- API、Agent 协议、配置 schema、持久化数据迁移、订阅格式和运行节点兼容策略都在 SemVer 兼容范围内，不只关心 HTTP API。

## 目标运行时锁定候选

这份表是**待发行校验的设计基线**，不是已完成的制品锁。真正 install 前必须生成来源、SHA-256、架构、目标路径和签名（若发行方提供）的 manifest。

| 组件 | v1.0.0 候选基线 | 使用范围 |
| --- | --- | --- |
| 主机 OS | Debian 13 Trixie | Hub/Line/Out Linux amd64/arm64 |
| Go | 1.27.2 | 构建；目标机不安装 Go |
| sing-box | 1.14.3 | Line/Out 原生代理内核 |
| Headscale | 0.29.5 | Hub，Mesh 控制面 |
| Caddy | 2.11.7 | Hub TLS、订阅 |
| Fail2ban | Debian 13 官方维护包 | 宿主机 SSH/Web 登录 |
| nftables | Debian 13 官方维护包 | 主机与 Out ACL |
| SQLite | 受维护的 Go SQLite 驱动 | Hub 内部数据库 |
| Tailscale | 与固定 Headscale 兼容的客户端版本 | Mesh 客户端及 NAS，单独真机确认 |

- https://semver.org/spec/v2.0.0.html
- https://go.dev/doc/devel/release
- https://sing-box.sagernet.org/
- https://github.com/juanfont/headscale/releases/tag/v0.29.5
- https://github.com/caddyserver/caddy/releases

## 限制

不追 latest；未固定校验值或未证实能在 Debian 13 运行的制品不进入安装器。sing-box 的用户更新行为、流量统计和 API 能力必须以固定版本实测为准。Debian 11/12、Ubuntu、IPv6-only 等需要独立兼容性证据。
