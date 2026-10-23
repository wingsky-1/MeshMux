# 版本策略与组件基线

## MeshMux 发布版本（SemVer 2.0.0）

- **`v1.0.0` 是首个公开稳定发行版本**；在此之前用 Issue/PR/CI 推进，不将 PR 阶段号作为发布版本，也不强制发布 `0.x`。
- 完整 P0 和隔离/真实网络验收通过后，创建唯一不可覆盖的 v1.0.0 Tag 与 GitHub Release。
- 发布后：向后兼容新功能升 MINOR（如 1.1.0）；向后兼容修复升 PATCH（如 1.0.1）；不兼容变更升 MAJOR（如 2.0.0）。
- API、Agent 协议、配置 schema、持久化数据迁移、订阅格式和运行节点兼容策略都在 SemVer 兼容范围内，不只关心 HTTP API。

## 目标运行时锁定候选

这份表是**待发行校验的设计基线**，不是已完成的制品锁。Issue #5 PR A 已固定 **Caddy 2.11.7 / Headscale 0.29.5** 官方 GitHub 的 amd64/arm64 下载来源及 release asset SHA-256（见 `internal/install/artifacts.go`）；MeshMux 自有程序与 Debian apt 包的制品/版本锁尚待 PR B 交付，所以 **禁止真正 apply**。任何真实 install 前仍必须有完整的来源、SHA-256、架构、目标路径和可用签名策略。

**#11a 已交付只读发行 manifest**（`internal/upgrade/manifest.go`，`GET /tasks` 展示）：上表四个固定组件（Caddy / Headscale / sing-box / Mihomo）的版本、架构、官方 GitHub 来源与 SHA-256 由既有 pin 派生为统一结构，附带 `policy_schema=8` 与 `route_policy_revisions` 槽位，并在 `Validate` 中拒绝未知架构、未知 schema、`policy_schema≠8` 与任何被篡改的组件行。manifest 只描述发行，**不下载、不 apply、不回滚**；**#11c-1 起 Agent 通道改为双架构 set**（`meshmux-release-set/v1`，`GET /api/agent/manifest`），每架构条目仍是原单架构 `meshmux-release/v1` 文档，批准与校验按该架构投影的 SHA-256 pin。**#11b 已交付持久化升级任务记录**（复用 `agent_tasks` 的目标列，当批仅领域模型与只读接线）；**#11c-1 已交付受限执行器**（Hub 只记意图，Agent 本地以固定 argv 下载/校验/交棒/回读；`upgrade.*` 仍被拒绝）；自替换/重启恢复（11c-2）、备份指针/兼容回退（11c-3）、Hub 自升级（11d）与组件组合兼容闸门（11e）尚未实现，因此本条不构成“Web 统一升级已可用”。

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

## AI 规则集固定策略（#8-D）

AI 规则集是外部制品，但同样受“不追 latest”约束：`internal/route.RulesetPin{Source,Version,SHA256}` 要求 HTTPS 单一地址、不可变版本标签（`latest`/`main`/`master` 等可变通道与 URL 中的同名路径段一律 `RULESET_PIN_INVALID`）和 64 位小写十六进制摘要。下载体为空、超过 8 MiB 或摘要不匹配统一 `RULESET_FETCH_FAILED`，发布链必须拒绝而不是降级。规则集当前不入安装包、不提供在线市场、测速或多 Out 负载选择。

## 限制

不追 latest；未固定校验值或未证实能在 Debian 13 运行的制品不进入安装器。sing-box 的用户更新行为、流量统计和 API 能力必须以固定版本实测为准。Debian 11/12、Ubuntu、IPv6-only 等需要独立兼容性证据。
