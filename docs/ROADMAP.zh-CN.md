# 可独立验收的 PR 路线图

严格按依赖推进；**不把日期估算当作能跳过真机验收的理由**。

| PR | 交付 | 验收重点 |
| --- | --- | --- |
| PR0 | 设计文档、ADR、Go 骨架、CI、贡献约束 | 无生产入口；文档 PR 可独立评审 |
| PR1 | Web 安全基座（单管理员、SQLite、Caddy 计划、Fail2ban） | 无 Zero Trust，匿名/CSRF/暴力破解失败封闭 |
| PR2 | Hub/Line/Out 安装与 outbound Agent 纳管 | Debian13 真正三角色安装、分阶段失败/回退 |
| PR3 | 原生 sing-box 用户、可选 Out 双跳、订阅发布 | 不安装 Out 也能订阅，AI 双跳与异常回退证据 |
| PR4 | Headscale、Mesh-only、子网路由、单 VPN 配置 | 平台中立设备、独立凭据、NAS 身份保留 |
| PR5 | 路由策略 Web 编辑、规则模拟与分层发布 | 客户端/服务端/Out 故障策略一致 |
| PR6 | Web 全节点升级、任务持久化、统一日志 | 版本收敛与 partial/rollback 真机证据 |
| PR7 | 隔离三节点全新安装、发行、文档与现网迁移 | 安全门禁，明确现网人工授权 |

## 当前第一阶段准备

1. 审核 PR0 文档及用户操作界面，确认 P0/非目标。
2. PR1 先固定 HTTP route/auth/session/error model，不做 root 操作；SQLite migrations 与 API contract 可先行。
3. 对 chi、templ、HTMX、SQLite driver 和 Argon2id 作最小选型试验，依赖锁定于第一处实际调用，不提前堆库。
4. 建立 Web UI 桌面及移动截图基线、API auth/security 测试、登录失败记录脱敏测试、Fail2ban 集成用例。
5. PR1 验收前不运行安装器，不改现有 Hub/Line/Out/家庭设备。

## 项目管理

一个总控 Issue 维护产品边界与依赖顺序；PR 各自有“具体变更、已知风险、测试证据、回退方案、影响文档”。大型变更先 ADR，再实现。旧 Python 项目不再作为代码兼容目标，仅用来提取真实环境需求与验收案例。
