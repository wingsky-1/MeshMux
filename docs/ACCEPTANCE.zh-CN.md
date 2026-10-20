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

- [x] **PR A（只读，B 级）**：`install hub --plan` 严格域名验证、Debian 13/root/SSH socket/磁盘/时间/DNS/端口检查、官方 SHA-256 锁与未应用服务模板；现网无副作用，CI 通过。`public_https` / `public_stun` 保持 pending。
- [x] **PR B 安装事务与回归（L1/B 级）**：官方完整制品与 Go Web 锁、check/stage/apply/readback、幂等/恢复、受管文件台账回滚一致性、apt 查询优先、健康探针 303/禁止重定向语义、Web Fail2ban 默认禁用与 `--direct-caddy` 启用、RFC3339Nano 日期模式，均有 Go 测试覆盖。[Go/web run 39216454974](https://github.com/wingsky-1/MeshMux/actions/runs/39216454974) 与 [Debian 13 组件 run 39216454901](https://github.com/wingsky-1/MeshMux/actions/runs/39216454901) 均为 head `c5be00c` PASS；该 head 的树 `8e08dfe5327fdf3ec0ecc0cb4daad54e5b6cd5c0` 与 `main` `17baaa1` 相同。
- [x] **PR B 全系统验收（C 级，amd64 自动化门禁）**：[L3 QEMU/systemd run 39216454882](https://github.com/wingsky-1/MeshMux/actions/runs/39216454882) 于 head `c5be00c` PASS，`internal/install/vm_test` 覆盖真实 systemd 服务与监听、本机内部证书 TLS 探针（非真实公网 ACME）、重启持久化、故障回滚以及 Fail2ban/nftables ban/unban；run head 的 Git 树 `8e08dfe5327fdf3ec0ecc0cb4daad54e5b6cd5c0` 与 `main` `17baaa1` 完全相同，Hub 接口可被 #6 消费。#5 已关闭。
- [ ] **PR B 外部环境边界**：arm64 宿主机 L3、真实公网 ACME/TLS、云防火墙入站以及真实 DERP/STUN 跨 NAT 握手仍未测试，保持 pending；不得扩展宣称全平台或生产环境验收完成。

阶段说明见 [Hub 安装](INSTALL_HUB.zh-CN.md)；单测与模板字符串校验不能代替服务实际健康或公网可达。

## Issue #6 PR-A 本地验收

- [x] **PR-A 本地验收（A/L1）**：Agent 严格协议、配对、任务状态与持久化边界，以及 Web 节点基础能力已由主控完成本地验收；完整 race、格式与 diff check 通过，浏览器复核完成，关键协议、迁移和 Web mutation 证据见 [PR-A 评审](PHASE2B_REVIEW.zh-CN.md)。
- [x] **#6 合入状态**：PR #18 已合入 `17c4e4c`，Issue #6 已关闭。最终 head `0149581` 的 [ci 39373760962](https://github.com/wingsky-1/MeshMux/actions/runs/39373760962) success；不得把这一历史证据用于 #7 的新实现验收。

## Issue #6 PR-B 实现与验收

PR-B 的 CLI、installer、runtime、Web 固定操作与 CI 脚本已由 PR #18 合入 `main`（`17c4e4c`）。以下为 #6 历史验收记录；源码存在、定向测试通过或 plan 成功不能替代全仓与隔离宿主机验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| L1 | `cmd/meshmux` 命令边界、stdin 配对码、确认/预检失败无副作用、repair 身份复用、structured partial/failed 与内部版本探针 | [x] 本地全绿（gofmt/vet/build/`go test` 分包/`-race`，见下） |
| L1 | installer state/owned paths、check/stage/apply/readback、runtime LKG/journal、Web 离线与固定 recheck/reissue | [x] 本地全绿（install 85 PASS/0 FAIL/4 门禁 SKIP；web/node/cmd 全过；install race 无 DATA RACE） |
| L2 | Debian 13 amd64 固定 sing-box 1.14.3、systemd unit、Fail2ban/nft 配置自检 | [x] [hub-components run 39372308917](https://github.com/wingsky-1/MeshMux/actions/runs/39372308917)（head `78e259b`，tree `e35fc88`）：releases.tsv pin、archive+binary SHA、unit verify、nft -c、fail2ban -t、candidate jq 全过；unit 语法用空可执行 stub 校验，binary 内容同 run 内 SHA 校验（含 DAC cap 与时钟 poll 后的 unit） |
| L2 | Debian 13 arm64 固定制品与组件配置自检 | [x] 同上 run（head `78e259b`），原生 arm64 runner，同矩阵同步骤全绿 |
| L3 | 隔离 Debian 13 VM 的 edge/out 首装、repair、重启、故障恢复、实际 SSH/VLESS 端口与 Fail2ban/nft 行为 | [x] [hub-vm run 39367683751](https://github.com/wingsky-1/MeshMux/actions/runs/39367683751)（head `78e259b`，tree `e35fc88`）：edge/out/hub 三 job 全 success；edge 含一次 TCG 时钟 `TIME_UNSYNCED` 抖动，重跑即过 |

- [x] **全仓自动化**：本地 `gofmt` 干净、`go vet ./...` 通过、`go build ./...` 通过；`go test` 分包全过（product/agent 52、node 46、install 85、web 56、cmd 三包 68），`go test -race` 全过（install/web/node/cmd 及 product/agent/webcmd 五包 120，无 DATA RACE）。
- [x] **PR-B CI**：L2 [hub-components run 39372308917](https://github.com/wingsky-1/MeshMux/actions/runs/39372308917)（head `78e259b`，tree `e35fc88`）amd64/arm64 全绿；L3 [hub-vm run 39367683751](https://github.com/wingsky-1/MeshMux/actions/runs/39367683751)（同 head/tree）edge/out/hub 全 success。后续链接必须指向对应 head，并说明该 head 的 Git tree。
- [ ] **#6 L3 外部边界**：真实公网入站、云安全组、真实协议握手和客户端可用未测；#6 baseline 无 TLS/REALITY、无用户、无订阅。#7 新实现及证据见下节。
- [ ] **Out ACL 语义**：当前源码为 `policy accept` 加目标 VLESS TCP/UDP drop，和“空授权默认拒绝、仅目标端口可用”的验收要求不一致；必须先修正并有真实 nft readback/流量证据。
- [x] **#6 自定义端口**：SSH 与 VLESS 端口不同；Fail2ban jail/action 与实际 SSH listener 匹配，nft 只替换 MeshMux 自有表。证据限于上述隔离 L2/L3 场景，不代表任意现网端口均已验证。

实施说明见 [Line / Out 安装](INSTALL_NODE.zh-CN.md)；#8、#9 与 #11 不在本轮验收范围，#11 仍是 v1.0.0 P0。

## Issue #7 Phase 3A 分 PR 验收（进行中）

#6 已由 PR #18 合入 `main`（`17c4e4c`，tree `40eed1f651cb19f47bbf69a96a6d3410e6e7d031`）并关闭。最终 head `0149581` 与该 merge tree 相同，PR [ci 39373760962](https://github.com/wingsky-1/MeshMux/actions/runs/39373760962) 与 [hub-vm 39373760970](https://github.com/wingsky-1/MeshMux/actions/runs/39373760970) 均 success；上文早期 PR-A/PR-B 的状态记录不代表当前待办。

- [x] PR-A（已合入）：独立模型、SQLite schema 4、哈希 Token、逐 Line UUID、严格 v2 REALITY 与 v1 编译兼容、合法空用户；主控独立检出 gofmt/vet/test（435）/race/build 全通过。合并 `3f9ffb3`，head `3789a3a`、tree `0f13577`。
- [x] PR-A：固定 sing-box 1.14.3 check、合法空用户、正确/错误/删除 UUID 的 REALITY 握手；[hub-vm 39382159464](https://github.com/wingsky-1/MeshMux/actions/runs/39382159464) 的 Edge/Out job 实际执行 native check 与三类 UUID 握手 PASS（主控已检查日志）。这是隔离 VM 自动化结果，不是公网或客户端可用证据。
- [x] PR-A：当前 head 对应 L2 amd64/arm64 与隔离 Debian 13 QEMU 全 success：[ci 39382159453](https://github.com/wingsky-1/MeshMux/actions/runs/39382159453)、[hub-components 39382159461](https://github.com/wingsky-1/MeshMux/actions/runs/39382159461)、[hub-vm 39382159464](https://github.com/wingsky-1/MeshMux/actions/runs/39382159464)；证据只覆盖上述 head/tree，不复用 #6。
- [x] PR-B（已合入）：Web 增停删、线路选择/改名/排序、两种标准订阅真实导入、Token 撤销/轮换、跨 Line partial 与幂等重试、精确 readback。合并 `c8033ab`（PR #21），head `452450e`。CI 全绿：[go 39425886188](https://github.com/wingsky-1/MeshMux/actions/runs/39425886188)、[components 39425886175](https://github.com/wingsky-1/MeshMux/actions/runs/39425886175)（amd64/arm64）、[subscription-clients 39425886213](https://github.com/wingsky-1/MeshMux/actions/runs/39425886213)（amd64/arm64 双架构真实导入+数据面）、[hub-vm 39425886103](https://github.com/wingsky-1/MeshMux/actions/runs/39425886103)（hub/edge/out 全 success）；证据只覆盖上述 head。独立评审 R1/R2/R4/R5/R6 通过。
- [x] PR-C（已合入）：Hub 兼任 Line、独立安装台账与恢复、零 Out 端到端隔离 VM 证据。合并 `983b1bc`（PR #22），head `1327b2b`。CI 全绿：[go 39434860540](https://github.com/wingsky-1/MeshMux/actions/runs/39434860540)、[components 39434860624](https://github.com/wingsky-1/MeshMux/actions/runs/39434860624)（amd64/arm64）、[hub-vm 39434860336](https://github.com/wingsky-1/MeshMux/actions/runs/39434860336)（hub/edge/out 全 success；hub job 内 `TestLocalLineSystemVM` install phase 真跑 110s PASS、reboot 后 post-reboot PASS，`Co-located Line full-system acceptance PASS`）。独立评审 R3/R7/R8 通过。

真实公网、云安全组与手机真机结果单独列出；没有实际执行则保持未验收。各 PR 证据只覆盖其 head。#8/#9/#11、Out 双跳与跨源 ACL 不在本轮。

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
