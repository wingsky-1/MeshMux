# MeshMux 功能清单与版本边界

本表为**规划目标而非实现状态**。**P0 = 首个正式可发布版本 v1.0.0 必须验收**；**P1 = v1.0.0 之后**再由 Issue/PR 安排。功能实现和产品发行是两回事，单个 PR 不等于一个 Release。

## 当前实现（Issue #2）

Web 单管理员认证、安全会话、SQLite 迁移、基础控制台已提供隔离验收入口；业务页面仅空状态。Caddy/systemd/Fail2ban 为候选配置，真实安装与封禁未验收。详见 [Web 开发说明](WEB_DEVELOPMENT.zh-CN.md)。下表仍是发行目标。

## P0：v1.0.0 最小可用闭环

| 领域 | 必须能力 | 可验收的用户结果 |
| --- | --- | --- |
| 安装 | Debian 13 amd64/arm64；Hub / Line / Out 宿主机 `install` | 干净 VM 能重复安装，错误有阶段与恢复方案 |
| 管理 | Hub 单管理员 Web、数据库、HTTPS；Out 可不部署 | 不依赖 Zero Trust；单机 Hub+Line、多 Line、可选 Out 都能工作 |
| 纳管 | Web 一次性配对，Line/Out 安装后 Agent 主动 HTTPS 连接；节点状态与展示名 | 目标机只需 install；权限可吊销，非法任务拒绝 |
| 代理 | 固定 sing-box 1.14.3，VLESS/REALITY 入站，自定义监听端口，Line 生命周期 | 客户端可真正连接；节点停用/删除配置可验证 |
| 聚合 | 多 Line 线路选择、命名、标准订阅导出 sing-box / Mihomo | 客户端导入成功，新增 Line 按选择更新配置 |
| 订阅 | 用户创建、禁用、删除，精确撤销跨节点 VLESS 凭据与下载 Token | 旧 URL 不可下载；删除时部分失败不假完成 |
| Mesh | Headscale 注册/注销、Mesh-only、独立子网路由及路由批准 | 无代理订阅的 NAS 可以入网并实际路由 |
| 单 VPN | 设备专属 sing-box 代理 + Mesh 配置，SSID 与远程家庭网段 | 经过 iOS/Android 真机以及两种网络验证 |
| 分流 | Web 配置客户端 CN/国际/Tailnet/DNS 与服务端域名/IP/规则集；AI Line→Out 或 Line 直出 | 不存在 Out 不生成无效配置；Out 出错默认不泄漏回退出口 |
| 基本诊断 | 节点/任务日志、固定错误码、必要的公网端口与协议健康检查 | 出错能辨别主机监听、云安全组、代理握手与 Mesh 问题 |
| 安全 | 单管理员认证/CSRF/限速；SSH + Web Fail2ban；端口与防火墙一致 | 匿名拒绝；暴力登录和异常来源安全处理 |
| 安全 | 节点独立身份、最小权限、Out ACL、高熵 Token、日志脱敏 | 无任意 Shell，Out 默认拒绝，Token 可轮换/撤销 |
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

- **Subscriber ≠ Mesh Device ≠ VLESS Credential**，订阅用户和 Mesh 设备可分别创建/删除。
- Out 可选，且 AI 规则可明确选择 Line 直出；配置了 Out 时该 Out 故障默认 fail-closed，不会静默直出。
- 编辑路由或删除用户前生成可审阅配置，失败不能报告完成。
- “安全优先”意味着保留必要测试和失败回滚，不引入不必要的架构、审批链或不相关功能。
