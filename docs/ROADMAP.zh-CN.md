# v1.0.0 开发路线：Issue → 可验收 PR

**首个正式可发布版本为 v1.0.0**。PR0、PR1 等是交付阶段编号，不是语义化版本；不为中间开发阶段强制发布 `v0.x`。每个功能 Issue 都要规定范围、非目标和验收证据，合并 PR 由 CI 与明确验收支撑。

| 阶段 | 最小交付与范围 | 出口验收 |
| --- | --- | --- |
| PR0（已合并） | README、AGENTS、P0/P1、4A/部署/纳管设计、Go 最小骨架/CI | install 占位失败封闭，CI 成功，设计无矛盾 |
| PR1（Issue #2） | 单管理员 loopback Web、认证/会话、SQLite、Caddy 候选、登录防爆破、最小状态与日志 | 本地 Web 可登录、注销；匿名/CSRF/错误 Origin 被拒；不触碰生产服务 |
| PR2A（Issue #5 PR A） | Debian 13 Hub 只读预检、安装计划、组件固定 SHA-256、受管服务候选配置；无 host apply | 单元测试/CI、无副作用、失败有稳定诊断；**不关闭 #5** |
| PR2B（Issue #5 PR B） | Hub Web/Caddy/Headscale/Fail2ban 实际宿主机安装、回滚及隔离 VM 验收 | 独立干净 Debian 13 重复安装和失败恢复，HTTPS/DERP/STUN 非 Mock |
| PR2C（Issue #6） | Line/Out 安装、受限 Agent 主动配对；SSH/VLESS 端口安全 | Line/Out 隔离 VM 实测，配对凭据可撤销，幂等与异常回退 |
| PR3 | 原生 sing-box 线路纳管、用户创建/删除、标准订阅、可选 Out 与 AI 双跳 | 单 Line/多 Line/有 Out/无 Out 真正连接，撤销精确有效 |
| PR4 | Headscale Mesh 设备、Mesh-only、子网路由、sing-box 单 VPN | NAS 与手机分别入网；网段获批准可达；多设备互不影响 |
| PR5 | Web 路由/分流编辑、SSID、客户端/服务端配置生成、校验发布 | CN/国际/AI/Tailnet/DNS、无 Out 和 Out 故障策略验证 |
| Phase 6（Issue #11） | Web 全节点统一升级：发行清单、受限执行、任务持久化、Hub 自更新、逐节点验证与失败回退 | 两版测试制品 A→B、Hub/Line/Out 版本回读和异常恢复，不支持任意上游升级 |
| Phase 7（Issue #12） | 安全/诊断/备份回归，隔离三角色安装 E2E、安装与恢复文档 | P0 全面验收通过、满足 v1.0.0 发行门槛 |

后续阶段的详细范围与依赖以 [v1.0.0 总控 Issue #4](https://github.com/wingsky-1/MeshMux/issues/4) 和 #5～#12 为准，允许拆为更小且独立可测试的 PR。**#11 统一升级是 v1.0.0 P0；完整通用运维面板仍非首版目标。** 本阶段 #2 不提前实现升级器或通用任务引擎。

## 当前阶段：Issue #5 PR A / PR B

PR A 的只读安装计划与自带校验清单见 [INSTALL_HUB](INSTALL_HUB.zh-CN.md)；PR B 负责宿主机写操作和 Debian 13 实装。两者都归属 Issue #5，Issue #6 不提前依赖尚未合并的服务接口。

## 近期：PR1 的明确边界

PR1 只建立 **可信 Web 基座**：非 root loopback、单管理员、会话/CSRF、持久化基础数据、最小 UI、脱敏日志与测试；Caddy/Fail2ban 生成候选和集成验证。无需实现真实 Headscale、sing-box、远程 Agent、订阅发布、正式安装器或真实服务器变更。

优先 Go 标准库，外部成熟依赖在第一次实际需要时引入并锁定；仅保留格式、vet、测试、构建及现有必要 race CI。不要用过长 Mock 流程伪装端到端验收。

## 发行与版本

完成全部 P0 且隔离环境真实验收，复核组件来源/校验值和恢复流程，才发布 Git tag `v1.0.0`（不移动、不复用 Tag）。之后按 SemVer：兼容新增功能 `1.1.0`，向后兼容修复 `1.0.1`，破坏兼容 `2.0.0`。具体是否兼容须同时考虑 CLI 引导方式、Web API、Agent 协议、持久化数据、订阅格式与节点身份。

## 阶段一交付入口

Issue #2 的 Web 基座提供 [本机运行说明](WEB_DEVELOPMENT.zh-CN.md) 与 [界面/验证证据](previews/README.md)。验收和合并后再推进安装器及受限 Agent；统一升级在 #11 独立实现。
