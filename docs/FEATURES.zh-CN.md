# MeshMux 功能清单与版本边界

本表为**规划目标而非实现状态**。**P0 = 首个正式可发布版本 v1.0.0 必须验收**；**P1 = v1.0.0 之后**再由 Issue/PR 安排。功能实现和产品发行是两回事，单个 PR 不等于一个 Release。

## 当前实现与验收边界

- **Web 基座**：单管理员认证、安全会话、SQLite、基础控制台和节点工作区已提供隔离验收入口。
- **Hub 安装**：Issue #5 的 Hub `--plan`、确认后 apply、`--repair`、受管文件台账与有限恢复已合并，并有 L1/L2/L3 amd64 自动化证据；仍不是正式发行包。
- **Line / Out（Issue #6 已关闭）**：`meshmux install edge|out`、真实 preflight、固定制品、stdin 配对码、systemd Agent/sing-box、state/owned paths、structured partial/failed、有限 LKG 恢复与 Web 固定 recheck/reissue 已随 PR #18 合并进 `main`（merge `17c4e4c`）。证据：L2 [39372308917](https://github.com/wingsky-1/MeshMux/actions/runs/39372308917)、L3 [39367683751](https://github.com/wingsky-1/MeshMux/actions/runs/39367683751)（head `78e259b`、tree `e35fc88`）与 PR CI [39373760962](https://github.com/wingsky-1/MeshMux/actions/runs/39373760962)（head `0149581`）全 success。
- **Node baseline 与 Issue #7（已合入）**：PR-A 交付独立订阅域模型（SQLite schema 4、仅存哈希的 ≥288 bit Token、per-Line 安全 UUIDv4）、严格 v2 REALITY 编译器（legacy v1 逐字节不变）与合法空用户；PR-B 交付 Web 订阅用户增停删/选线/改名排序/Token 轮换撤销与精确同步证据、sing-box JSON 与 Mihomo YAML 双格式鉴权下载（双架构客户端真实导入全绿）、跨 Line 全链收敛与注入时钟；PR-C 交付 Hub 共存有效台账及修复/预检（隔离 VM 共存生命周期 PASS）。三者 CI（go/components/客户端导入/hub-vm）对应 head 全绿；尚无公网可达、真实公网握手或客户端可用证据。
- **Out**：安装产物可选。ACL 已由 #8-B 改为**空授权默认全拒绝**：`inet meshmux_out` 基线 `policy accept` 仅保留给主机 SSH/回环/回程，VLESS 目标端口在 `input` chain 内的两条 `tcp/udp dport drop` 默认丢弃，仅 Hub 授权的 Line 源地址（`/32`/`/128` 或已对齐 CIDR）在 drop 之前获得 `accept`；`nft -j` 回读逐条比对已应用集合，`OUT_ACL_SOURCE_MISMATCH` 不伪装健康。#8-C 完成 Hub↔Line↔Out 白名单协调与四事实双向 readback（白名单 / 入站 / REALITY / 最终出口），#8-D 完成 AI 规则集版本锁（`RulesetPin{Source,Version,SHA256}`，下载/摘要/大小失败 `RULESET_FETCH_FAILED` 拒绝发布）、Out 不可用默认 `OUT_OFFLINE_FAIL_CLOSED`（回退 Line 需显式 opt-in + `operation_id`）与 `DeleteOut` 删路由+清 ACL。**仿真证据**：隔离单元/竞态测试覆盖 ACL 有序 accept-before-drop、`nft -j` 精确集合、注入 accept 与 state 缺失断言、规则集 pin 与 fail-closed；**真实证据**：L2 privileged Debian 13 容器 `nft -f` apply + `nft -j list table inet meshmux_out` 至少 2 条 rule 断言与 `nft list` 日志（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)，head `9495730`、tree `5720b86`，amd64 实得 PASS 非 SKIP；无 `CAP_NET_ADMIN` 显式 SKIP，不计为通过）；L3 [hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)（同 head/tree）hub/edge/out 全 success，含真实 `nft list` 回读。**仍缺**：AI 双跳实际流量（已移交 #10）与客户端可用，不属本轮已有证据。
- **独立阶段**：#7 交付订阅模型、原生 REALITY 编译器、Web 订阅生命周期/下载与 Hub 共存，PR-A/PR-B/PR-C 均已合入（各 CI 全绿）。#8 的四项 PR 已交付源码与隔离自动化证据：仿真证据为 Go 单测/竞态，真实证据为 L2 privileged 容器 `nft -f` apply + `nft -j` readback 与 L3 VM readback（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)、[hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)，head `9495730`、tree `5720b86`），AI 双跳流量仍缺（双跳已移交 #10）；#9 不在其实现范围；#11 Web 全节点统一升级仍是 v1.0.0 P0，但不属于本轮实现或验收。

详见 [Web 开发说明](WEB_DEVELOPMENT.zh-CN.md)、[Hub 安装](INSTALL_HUB.zh-CN.md) 与 [Line / Out 安装](INSTALL_NODE.zh-CN.md)。下表仍是发行目标，不是任何单个 PR 的验收结论。

## P0：v1.0.0 最小可用闭环

| 领域 | 必须能力 | 可验收的用户结果 |
| --- | --- | --- |
| 安装 | Debian 13 amd64/arm64；Hub / Line / Out 宿主机 `install` | 干净 VM 能重复安装，错误有阶段与恢复方案 |
| 管理 | Hub 单管理员 Web、数据库、HTTPS；Out 可不部署 | 不依赖 Zero Trust；单机 Hub+Line、多 Line、可选 Out 都能工作 |
| 纳管 | Web 一次性配对，Line/Out 安装后 Agent 主动 HTTPS 连接；节点状态与展示名 | 目标机只需 install；身份可重签/撤销，非法任务拒绝 |
| 代理 | 固定 sing-box 1.14.3，VLESS/REALITY 入站，自定义监听端口，Line 生命周期 | PR-A 已交付模型与 v2 编译器，PR-B 已交付 Web 生命周期与订阅（双架构导入绿），PR-C 共存 VM 绿；真实公网握手与客户端可用仍缺证据 |
| 聚合 | 多 Line 线路选择、命名、标准订阅导出 sing-box / Mihomo | 客户端导入成功，新增 Line 按选择更新配置 |
| 订阅 | 用户创建、禁用、删除，Token 撤销与 per-Line VLESS UUID 删除分离，精确跨节点凭据撤销 | 旧 URL 不可下载；删除先门禁公开下载，远端部分失败不假完成 |
| Mesh | Headscale 注册/注销、Mesh-only、独立子网路由及路由批准（9a 设备生命周期、9b 子网路由声明/批准/撤销与观测归档均已随 PR #62/#63 交付：Web 页面 + `mesh_devices`/`mesh_enrollment_keys` + 本地 Headscale CLI 适配器） | 无代理订阅的 NAS 可以入网并实际路由（真实 NAS 跨网可达仍缺证据） |
| 单 VPN | 设备专属 sing-box 代理 + Mesh 配置（9c 已交付并仅覆盖待注册的 proxy_mesh 设备：一次性 Tailscale Endpoint + 代理 selector，无 TUN；标准订阅仍不含 Mesh）；该 Endpoint 固定 `accept_routes:false`——文档没有 TUN、唯一 Tailscale 规则只匹配 Tailnet CGNAT 前缀，接受对端子网路由没有出口，`mesh_only`/`subnet_router` 因此不渲染该文档而保留现成客户端（是否接受对端路由由该客户端的 `--accept-routes` 决定）；SSID 与远程家庭网段属 #10 | 经过 iOS/Android 真机、家庭 Wi-Fi 与外部网络验证 |
| 分流 | Web 配置客户端 CN/国际/Tailnet/DNS 与服务端域名/IP/规则集；AI Line→Out 或 Line 直出 | 不存在 Out 不生成无效配置；Out 出错默认不泄漏回退出口 |
| 基本诊断 | 节点/任务日志、固定错误码、必要的公网端口与协议健康检查 | 出错能辨别主机监听、云安全组、代理握手与 Mesh 问题 |
| 安全 | 单管理员认证/CSRF/限速；SSH + Web Fail2ban；端口与防火墙一致 | 匿名拒绝；暴力登录和异常来源安全处理 |
| 安全 | 节点独立身份、受限权限（实际边界待 Debian 13 VM 验证）、Out ACL、高熵 Token、日志脱敏 | 无任意 Shell；Out 空授权默认拒绝且仅目标端口可用；Token 可轮换/撤销 |
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
- Out 可选，且 AI 规则可明确选择 Line 直出；配置了 Out 时该 Out 故障默认 fail-closed（`OUT_OFFLINE_FAIL_CLOSED`），不会静默直出；回退 Line 必须是管理员显式 opt-in 并带 `operation_id` 审计。#8 已把 Out ACL 的 `policy accept` 边界修正为空授权默认拒绝 + 仅授权源可用（`internal/node/render.go`、`internal/node/runtime_readback.go`、`internal/install/node_acl_test.go` 等隔离测试）。仿真证据为隔离单测；真实证据为 L2 privileged 容器 `nft -f` apply 与 `nft -j` readback（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)，head `9495730`、tree `5720b86`，amd64 实得 PASS；无 `CAP_NET_ADMIN` 显式 SKIP）与 L3 VM readback（[hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)）。AI 双跳实际流量（已移交 #10）与客户端可用仍缺。
- 编辑路由或删除用户前生成可审阅配置，失败不能报告完成。
- “安全优先”意味着保留必要测试和失败回滚，不引入不必要的架构、审批链或不相关功能。
