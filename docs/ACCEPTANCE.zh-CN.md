# 验收与 v1.0.0 发行标准

## 分层证据

- A：源码评审、架构和安全边界。
- B：CI 自动化测试，关注行为正确、失败封闭和关键恢复路径。
- C：隔离 Debian 13 VM/VPS 真实安装与协议网络验证。
- D：明确授权的用户真实 Hub、Line、Out、手机/NAS 场景。

每个 PR 至少有适合范围的 A+B；安装、网络、组网、策略等 P0 上线结论必须取得 C。D 不能用 Mock 冒充，也不能成为自动化工具未经授权改现网的借口。CI 采用已有 gofmt / vet / test / race / build，不为每项操作增加重复门禁。

## PR0：初始设计和骨架

- [ ] README、AGENTS 及 PRODUCT/FEATURES/VERSIONS/ROADMAP 一致以 **v1.0.0** 为首发目标，当前不可安装。
- [ ] 4A、部署、纳管时序、安全、日志与验收文件清楚且不含真实个人配置。
- [ ] Go 骨架在未获确认时不修改宿主；未提供完整配置或预检未通过时，`install hub` 明确以非零结果退出且不留下宿主状态。
- [ ] CI 实测通过；独立 PR 合并前人工审查。

## PR1：Web 认证与本地基础

- [ ] 非 root loopback Web、管理员初始化与 Argon2id、登录/退出/改密与会话撤销。
- [ ] HTTP API、Cookie、CSRF、Origin、限速与默认拒绝；无 Zero Trust 依赖。
- [ ] SQLite 迁移、最低限度的备份恢复策略、脱敏结构化日志和有解释的失败响应。
- [ ] Caddy HTTPS/Fail2ban 的候选或隔离验证；本 PR 不操作真实系统服务、组网数据库或代理内核。
- [ ] 本地 Web 桌面/手机基础 UI 可交互，空状态诚实；CI 通过。

阶段一自动化、候选验证和浏览器证据记录在 [previews/README](previews/README.md)；这里保留人工出口验收勾选，CI 成功不代替用户验收或 Debian 13 部署。

## Issue #5 Hub 安装器拆分验收

- [ ] **PR A（只读，B 级）**：`install hub --plan` 严格域名验证、Debian 13/root/SSH socket/磁盘/时间/DNS/端口检查、官方 SHA-256 锁与未应用服务模板；现网无副作用，CI 通过。`public_https` / `public_stun` 保持 pending。
- [ ] **PR B 安装事务与回归（L1/B 级，已实现，仍受 L3 门禁约束）**：官方完整制品与 Go Web 锁、check/stage/apply/readback、幂等/恢复、受管文件台账回滚一致性、apt 查询优先、健康探针 303/禁止重定向语义、Web Fail2ban 默认禁用与 `--direct-caddy` 启用、RFC3339Nano 日期模式，均有 Go 测试覆盖；非 22 SSH Fail2ban 与 nftables 的真实系统行为仍需 L3 证明。
- [ ] **PR B 全系统验收（C 级，阻断 #5 关闭与 #6 接口消费）**：L3 尚未在本次修复后重跑；真实 systemd 安装、重启恢复、故障回滚、Caddy 真实 ACME/TLS、Headscale DERP/STUN 与 nftables 互不干扰尚无新的成功证据。`hub-vm` 已配置为安装器相关 PR 自动触发，但必须以成功运行链接为准，不能以 workflow 已存在或 L1/L2 绿灯代替。arm64 宿主机、公网 ACME/TLS、云防火墙和跨 NAT DERP/STUN 仍未测试，保持 pending。

阶段说明见 [Hub 安装](INSTALL_HUB.zh-CN.md)；单测与模板字符串校验不能代替服务实际健康或公网可达。

## v1.0.0 必须完成的真实用户闭环

- [ ] Debian 13 新环境可执行 install hub|edge|out，单机 Hub+Line、Hub+Line、Hub+Line+Out 三种拓扑正常，Out 可选。
- [ ] Line/Out 只执行首次 install 即完成 HTTPS Agent 纳管；配置推送与 readback 正常；SSH 及 VLESS 自定义端口与 Fail2ban/nftables 匹配。
- [ ] 原生 sing-box 1.14.3 VLESS/REALITY 真握手；新 Line 被纳入选定聚合订阅；有 Out 的 AI 双跳、无 Out 直出、Out 故障 fail-closed 均实际验证。
- [ ] 通过 Web 创建/禁用/删除订阅、独立 Token 轮换及准确跨节点撤销；旧 URL 无法下载，已有本地客户端缓存的局限明确说明。
- [ ] 普通 sing-box/Mihomo 格式真实导入；至少 iOS 与 Android 各一个 sing-box 单 VPN 代理+Mesh 配置通过。
- [ ] Mesh-only 节点/子网路由可在无 Subscriber 情况下注册、批准路由、注销；NAS 设备路由能被远程客户端访问。
- [ ] Web 可编辑发布国内外 / AI / 客户端 Tailnet/SSID/DNS 基础分流，规则/配置校验失败回退最后有效版本。
- [ ] Web 认证、SSH/Web 登录防爆破、Fail2ban 真正使用监听端口、Out 来源默认拒绝、密钥和订阅日志脱敏均通过测试。
- [ ] Web 统一升级 Hub/Line/Out：两版内部测试制品、固定 manifest/哈希/兼容范围、逐节点验证、Hub 自升级和断线/失败回退按 #11 通过隔离环境实测。
- [ ] 错误能定位 DNS、云安全组、监听、握手、授权、服务健康；配置应用半途失败可回退/重试，不报告虚假成功。
- [ ] 操作文档和受控恢复步骤完备，隔离三角色验证通过；才创建 v1.0.0 Release。

## 发行后

任意第三方运行时独立跨版本升级、系统发行版升级、实时用户配额和多 Out 智能容错不作为 v1.0.0 发版阻断项。**Web 全节点 MeshMux 程序及发行包中已验证兼容的组件升级属于 #11，必须在 v1.0.0 前验收。**
