# 版本与平台基线

本文件记录**初始设计候选基线**，不是已验收的运行制品锁文件。实现安装器之前必须生成带 Linux 架构、SHA-256、可信下载来源和目标路径的发行 manifest。

| 组件 | v0.1 目标基线 | 使用范围 |
| --- | --- | --- |
| 主机 OS | Debian 13 Trixie | Hub/Line/Out; Linux amd64/arm64 |
| Go | 1.27.2 | 构建；目标机不安装 Go 编译器 |
| sing-box | 1.14.3 | 所有服务端 Line/Out 原生内核 |
| Headscale | 0.29.5 | Hub，含已验证 DERP/STUN 能力 |
| Caddy | 2.11.7 | Hub HTTPS 与订阅 |
| Fail2ban | Debian 13 官方包 | 所有节点 |
| nftables | Debian 13 官方包 | 所有节点 |
| SQLite | 3.x 受维护 Go 驱动 | Hub 私有状态 |
| Tailscale 客户端 | 满足 Headscale 0.29.5 支持要求 | 设备/NAS，具体版本真实验收确认 |

官方参考：
- https://go.dev/doc/devel/release
- https://sing-box.sagernet.org/
- https://github.com/juanfont/headscale/releases/tag/v0.29.5
- https://github.com/caddyserver/caddy/releases

## 禁止默默追 latest

CI 与发行器记录 Go 和依赖版本；安装器仅接受经过固定 manifest 校验的目标版本。后续升级统一由 Web 发起，目标节点返回实际正在运行的版本和来源 SHA，不能把 staged 二进制当作 active。

## 兼容矩阵

Debian 13 = P0 唯一正式支持。Debian 11/12、Ubuntu、其他架构和 IPv6-only 主机均需要独立兼容测试、明确支持范围及异常恢复路径。sing-box 原生 API 的流量指标、用户管理更新行为需要在 1.14.3 固定版本上实测，不根据最新版文档推断所有能力。
