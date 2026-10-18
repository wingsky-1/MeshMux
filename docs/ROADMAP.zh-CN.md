# v1.0.0 开发路线：Issue → 可验收 PR

**首个正式可发布版本为 v1.0.0**。PR0、PR1 等是交付阶段编号，不是语义化版本；不为中间开发阶段强制发布 `v0.x`。每个功能 Issue 都要规定范围、非目标和验收证据，合并 PR 由 CI 与明确验收支撑。

| 阶段 | 最小交付与范围 | 出口验收 |
| --- | --- | --- |
| PR0（当前） | README、AGENTS、P0/P1、4A/部署/纳管设计、Go 最小骨架/CI | install 占位失败封闭，CI 成功，设计无矛盾 |
| PR1（Issue #2） | 单管理员 loopback Web、认证/会话、SQLite、Caddy 候选、登录防爆破、最小状态与日志 | 本地 Web 可登录、注销；匿名/CSRF/错误 Origin 被拒；不触碰生产服务 |
| PR2 | Debian 13 Hub/Line/Out 的 install、受限 Agent 配对、SSH/VLESS 端口与 Fail2ban | 三角色隔离环境首次与重复安装、异常回退；目标机只执行 install |
| PR3 | 原生 sing-box 线路纳管、用户创建/删除、标准订阅、可选 Out 与 AI 双跳 | 单 Line/多 Line/有 Out/无 Out 真正连接，撤销精确有效 |
| PR4 | Headscale Mesh 设备、Mesh-only、子网路由、sing-box 单 VPN | NAS 与手机分别入网；网段获批准可达；多设备互不影响 |
| PR5 | Web 路由/分流编辑、SSID、客户端/服务端配置生成、校验发布 | CN/国际/AI/Tailnet/DNS、无 Out 和 Out 故障策略验证 |
| PR6 | 安全/诊断/备份回归，隔离三角色安装 E2E、安装与恢复文档 | P0 全面验收通过、满足 v1.0.0 发行门槛 |

PR2～PR6 可根据实际依赖拆成更小 PR，前提是每个 PR 仍独立可测试、可回退；不能把“更多 PR”当作工程产出目标。**全节点 Web 程序升级与完整运维面板移到 post-v1.0.0**，另开 Issue 再估算。

## 近期：PR1 的明确边界

PR1 只建立 **可信 Web 基座**：非 root loopback、单管理员、会话/CSRF、持久化基础数据、最小 UI、脱敏日志与测试；Caddy/Fail2ban 生成候选和集成验证。无需实现真实 Headscale、sing-box、远程 Agent、订阅发布、正式安装器或真实服务器变更。

优先 Go 标准库，外部成熟依赖在第一次实际需要时引入并锁定；仅保留格式、vet、测试、构建及现有必要 race CI。不要用过长 Mock 流程伪装端到端验收。

## 发行与版本

完成全部 P0 且隔离环境真实验收，复核组件来源/校验值和恢复流程，才发布 Git tag `v1.0.0`（不移动、不复用 Tag）。之后按 SemVer：兼容新增功能 `1.1.0`，向后兼容修复 `1.0.1`，破坏兼容 `2.0.0`。具体是否兼容须同时考虑 CLI 引导方式、Web API、Agent 协议、持久化数据、订阅格式与节点身份。
