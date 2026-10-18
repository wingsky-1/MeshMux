# 分层验收和发行门禁

## 证据级别

A. 源码检查：架构、静态分析、安全审核；B. 本地/CI Mock：单元、接口、故障注入；C. 隔离 VPS/VM：真实 systemd/网络/端口/升级；D. 现网：管理员授权的真机场景。

任何 PR 至少通过 A+B。安装器/网络/双跳/升级的 P0 交付必须有 C；D 独立于 PR 合并，不得以 Mock 成功代替真实使用成功。

## PR0（仓库初始化）

- [ ] README 明确目前不可部署。
- [ ] 4A/部署/纳管/特性/安全/日志/验收/版本文档互相一致。
- [ ] 仅包含无外部依赖的 Go 骨架；未知 CLI 命令、未实现 install 必须拒绝且无副作用。
- [ ] gofmt / go vet / go test / go build / go test -race 在 GitHub CI 完成。
- [ ] 独立 PR 提交，评审通过前不合入 main。

## PR1（第一阶段：Web 安全基座）

- [ ] HTTP 仅绑定 127.0.0.1，服务绝不以 root 身份提供公网 HTTP。
- [ ] 管理员初始化、Argon2id 密码验证、登录/注销/改密、服务端会话。
- [ ] Secure/HttpOnly/SameSite cookie，Origin/CSRF，过期及撤销，登入限速。
- [ ] 所有 /api/ 和 Web 静态/private 路由具备明确的访问边界；匿名和错误来源一律失败封闭。
- [ ] SQLite schema 迁移及 WAL 备份设计；不把 Cookie/session secret/明文密码记入日志。
- [ ] Caddy/TLS 配置只有经过预检才能建议启用；无 Zero Trust 依赖。
- [ ] Fail2ban Web 认证日志格式和 SSH 实际监听端口的覆盖验收；橙云场景不因伪造 XFF 封禁代理出口。
- [ ] 真实部署前的 dry-run / fail-closed 测试齐备；本阶段不写 Headscale DB、不启动代理入口。
- [ ] Web 交互符合 docs/UX.zh-CN.md，并有响应式截图或可访问的测试预览。

## PR2/PR3/PR4 的关键端到端场景

- Hub+Line 单机、Hub+Line、Hub+Line+Out 三种模式都可安装。
- 新 Line 插入后自动扩展**符合条件**的订阅，但必须先验证 Out ACL。
- 标准 sing-box/Mihomo 订阅真实可导入；Mesh 客户端单 VPN 可访问代理与家庭路由。
- Mesh-only NAS 通过 Headscale 路由审批独立入网，无代理订阅依赖。
- 随机 Token 不可枚举；撤销/轮换后旧 URL 不可访问。
- 端口监听正常但云安全组阻断时显示 PUBLIC_PORT_UNREACHABLE 而非假成功。
- 配置 check 失败、远端断网、部分删除/更新失败、代理 handshake 错误都有具体错误码和恢复建议。
- 部署迁移时不自动清空 Headscale DB 或重建已存在 NAS 设备身份；如用户明确允许重注册，须另行设迁移验收。
