# 验收与 v1.0.0 发行标准

## 分层证据

- A：源码评审、架构和安全边界。
- B：CI 自动化测试，关注行为正确、失败封闭和关键恢复路径。
- C：隔离 Debian 13 VM/VPS 真实安装与协议网络验证。
- D：明确授权的用户真实 Hub、Line、Out、手机/NAS 场景。

每个 PR 至少有适合范围的 A+B；安装、网络、组网、策略等 P0 上线结论必须取得 C。D 不能用 Mock 冒充，也不能成为自动化工具未经授权改现网的借口。CI 采用已有 gofmt / vet / test / race / build，不为每项操作增加重复门禁。

## PR0：初始设计和骨架

- [ ] README、AGENTS 及 PRODUCT/FEATURES/VERSIONS/ROADMAP 一致以 **v1.0.0** 为首发目标；`install hub|edge|out` 已交付并具隔离 VM 证据，但尚未发行，不得宣称 v1.0.0 可用。
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

- [x] **PR-A 本地验收（A/L1）**：Agent 严格协议、配对、任务状态与持久化边界，以及 Web 节点基础能力已由主控完成本地验收；完整 race、格式与 diff check 通过，浏览器复核完成，关键协议、迁移和 Web mutation 证据见下文 #6 历史验收记录。
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
- [x] **Out ACL 语义（#8 源码已修复）**：ACL 已由 #8-B 改为空授权默认全拒绝（`inet meshmux_out` 只保留一条 `input` chain，`policy accept` 仅覆盖主机 SSH/回环/回程；VLESS 端口两条 `tcp/udp dport drop` 默认丢弃，仅 Hub 授权的 Line 源在 drop 之前 `accept`）。**仿真证据（隔离单测）**：`internal/node/render_acl_test.go`、`internal/node/runtime_readback_acl_test.go`、`internal/install/node_acl_test.go`（含有序 accept-before-drop、未对齐 CIDR 拒绝、`nft -j` 精确集合比对、注入 accept 拒绝、state 缺失退化为形状断言、repair 保留已授权 ACL）；`go test -race ./...` 全绿。
- [x] **Out ACL 真实 L2+L3 证据（#8 收尾）**：`scripts/ci-node-components.sh` 在 `nft -c` 后执行真实 `nft -f` apply，并用 `nft -j list table inet meshmux_out` 断言至少 2 条 rule、归档 `nft list` 输出；容器无 `CAP_NET_ADMIN` 时显式 SKIP，不计为通过。L2 [hub-components run 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)（head `9495730`、tree `5720b86`）amd64/arm64 全绿，amd64 日志实得 `nft apply/readback PASS`（2 rules，非 SKIP）；L3 [hub-vm run 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)（同 head/tree）hub/edge/out 全 success，out 含 `TestNodeSystemVM` 真实 `nft list table inet meshmux_out` 回读断言。AI 双跳实际流量（已移交 #10）与客户端可用仍缺。
- [x] **Out 缺失/故障语义与清理（#8-D）**：`internal/route/out_ruleset.go` 提供 `RulesetPin{Source,Version,SHA256}` 与 `ResolveAIRuleset`（下载/大小/摘要失败统一 `RULESET_FETCH_FAILED`，可变通道 `RULESET_PIN_INVALID`，均拒绝发布）；`internal/web/store_out_ai_egress.go` 分离“无 Out = 直出配置态”与“Out 故障 = `OUT_OFFLINE_FAIL_CLOSED`”，回退 Line 需 `FallbackToLine` + `operation_id` 否则 `OUT_FALLBACK_UNAUDITED`；`DeleteOut` 单事务删路由→复用 T3 回收 drain 清 ACL→同事务 readback（缺键或非空则回滚），未下发时返回 `OUT_SYNC_PENDING`（HTTP 202）而非假成功。**仿真证据（隔离单测）**：`internal/route/out_ruleset_test.go`、`internal/web/store_out_ai_egress_test.go`、`internal/web/store_out_bindings_test.go`、`internal/web/server_out_bindings_test.go`。
- [x] **#6 自定义端口**：SSH 与 VLESS 端口不同；Fail2ban jail/action 与实际 SSH listener 匹配，nft 只替换 MeshMux 自有表。证据限于上述隔离 L2/L3 场景，不代表任意现网端口均已验证。

实施说明见 [Line / Out 安装](INSTALL_NODE.zh-CN.md)；#9 与 #11 不在本轮验收范围。#8 本轮收尾已取 L2 真实 `nft -f` apply/readback（[hub-components 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)）与 L3 VM readback（[hub-vm 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)，head `9495730`、tree `5720b86`）；AI 双跳实际流量（已移交 #10）与客户端可用仍缺，#11 仍是 v1.0.0 P0。

## Issue #7 Phase 3A 分 PR 验收（#7 已 CLOSED）

#6 已由 PR #18 合入 `main`（`17c4e4c`，tree `40eed1f651cb19f47bbf69a96a6d3410e6e7d031`）并关闭。最终 head `0149581` 与该 merge tree 相同，PR [ci 39373760962](https://github.com/wingsky-1/MeshMux/actions/runs/39373760962) 与 [hub-vm 39373760970](https://github.com/wingsky-1/MeshMux/actions/runs/39373760970) 均 success；上文早期 PR-A/PR-B 的状态记录不代表当前待办。

- [x] PR-A（已合入）：独立模型、SQLite schema 4、哈希 Token、逐 Line UUID、严格 v2 REALITY 与 v1 编译兼容、合法空用户；主控独立检出 gofmt/vet/test（435）/race/build 全通过。合并 `3f9ffb3`，head `3789a3a`、tree `0f13577`。
- [x] PR-A：固定 sing-box 1.14.3 check、合法空用户、正确/错误/删除 UUID 的 REALITY 握手；[hub-vm 39382159464](https://github.com/wingsky-1/MeshMux/actions/runs/39382159464) 的 Edge/Out job 实际执行 native check 与三类 UUID 握手 PASS（主控已检查日志）。这是隔离 VM 自动化结果，不是公网或客户端可用证据。
- [x] PR-A：当前 head 对应 L2 amd64/arm64 与隔离 Debian 13 QEMU 全 success：[ci 39382159453](https://github.com/wingsky-1/MeshMux/actions/runs/39382159453)、[hub-components 39382159461](https://github.com/wingsky-1/MeshMux/actions/runs/39382159461)、[hub-vm 39382159464](https://github.com/wingsky-1/MeshMux/actions/runs/39382159464)；证据只覆盖上述 head/tree，不复用 #6。
- [x] PR-B（已合入）：Web 增停删、线路选择/改名/排序、两种标准订阅真实导入、Token 撤销/轮换、跨 Line partial 与幂等重试、精确 readback。合并 `c8033ab`（PR #21），head `452450e`。CI 全绿：[go 39425886188](https://github.com/wingsky-1/MeshMux/actions/runs/39425886188)、[components 39425886175](https://github.com/wingsky-1/MeshMux/actions/runs/39425886175)（amd64/arm64）、[subscription-clients 39425886213](https://github.com/wingsky-1/MeshMux/actions/runs/39425886213)（amd64/arm64 双架构真实导入+数据面）、[hub-vm 39425886103](https://github.com/wingsky-1/MeshMux/actions/runs/39425886103)（hub/edge/out 全 success）；证据只覆盖上述 head。独立评审 R1/R2/R4/R5/R6 通过。
- [x] PR-C（已合入）：Hub 兼任 Line、独立安装台账与恢复、零 Out 端到端隔离 VM 证据。合并 `983b1bc`（PR #22），head `1327b2b`。CI 全绿：[go 39434860540](https://github.com/wingsky-1/MeshMux/actions/runs/39434860540)、[components 39434860624](https://github.com/wingsky-1/MeshMux/actions/runs/39434860624)（amd64/arm64）、[hub-vm 39434860336](https://github.com/wingsky-1/MeshMux/actions/runs/39434860336)（hub/edge/out 全 success；hub job 内 `TestLocalLineSystemVM` install phase 真跑 110s PASS、reboot 后 post-reboot PASS，`Co-located Line full-system acceptance PASS`）。独立评审 R3/R7/R8 通过。

真实公网、云安全组与手机真机结果单独列出；没有实际执行则保持未验收。各 PR 证据只覆盖其 head。#8/#9/#11、Out 双跳与跨源 ACL 不在本轮。

## Issue #9 PR-9a Mesh 设备生命周期验收（#9 已 CLOSED；9b/9c/9d 已随 PR #63 合入）

PR-9a 分四个切片交付：9a-1 `internal/mesh` 纯领域模型、9a-2 `internal/headscale` 固定 argv 本地 CLI 适配器、9a-3 Web `/mesh` 页面与 schema 6 持久化（`store_mesh.go`），9a-4 Hub 的 Web↔Headscale socket 组边界与隔离 fixture。本行**只登记源码与自动化证据**，不构成发行验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| A | 领域与适配器边界：`internal/mesh` 无 I/O 且不 import `internal/web`/`internal/install`；`internal/headscale` 只经固定 binary/config 与固定 argv 表调用，无 shell、无 `preauthkeys list`、`nodes delete` 带 `--force`；Web 只经该接口读写 Headscale | [x] 源码评审 + 隔离单测 |
| B | 设备与 Key 生命周期：用途/绑定规则、NodeName 同用户占用唯一、`pending`/`registered` 只由观测到的 Node ID 推进、Key 15 分钟仅存 SHA-256 且单活/`consumed` 不可逆、注销先写意图再远端删除且幂等重试、撤销一台设备不影响订阅用户/凭据/Token | [x] `go test ./internal/web/ -run Mesh` 全绿（`store_mesh_test.go`、`server_mesh_test.go`、`mesh_fixture_test.go`）；`TestMeshHubFixture` 默认 SKIP |
| B | Web 路由边界：`/mesh` 需认证；四个 mutation 需 CSRF；页面渲染只发 `users list`/`nodes list` 两次只读调用；Headscale 不可用时返回稳定 `HEADSCALE_*` 且不写入任何设备/Key | [x] `TestMeshRoutesRequireAuthentication`、`TestMeshPageRequiresCSRFOnMutations`、`TestMeshPageRenderOnlyReadsControlPlane`、`TestMeshWithoutHeadscaleRefusesBeforeWrites` |
| B | 安装侧 socket 边界（9a-4）：`meshmux-web.service` 仅以 `SupplementaryGroups=meshmux-headscale` 穿过 0770 socket，数据目录仍 0700 且无 `Group=`/`ReadWritePaths` | [x] 模板断言 `internal/install/render_test.go`；**真实组权限链未验证** |
| C | 隔离 Debian 13 Hub VM：真实 Headscale 0.29.5 下 Web 账户经 socket 完成 `version`/`users list`/`nodes list`，页面创建设备并核对、注销，事件日志无 Key 明文 | [ ] 待执行：`MESHMUX_MESH_HUB_FIXTURE_DIR=... /tmp/web.test -test.run '^TestMeshHubFixture$'`，需在干净 VM 内以 `meshmux` 账户运行；head/tree 与 run 链接待回填 |

- [ ] **未含真机与真实注册**：本 PR 没有真实 tailnet 客户端入网，因此 `registered`、在线状态、Tailnet IP、真实 `nodes delete` 与 Key 消费均未被证明；`confirmMeshEnrollment` 目前只有 store 级单测，尚无 HTTP 消费端点。
- [ ] **未含 C 级结论**：子网路由发布/批准/readback、路由策略与单 VPN 客户端配置分别属 9b/9c；Mesh 的 v1.0.0 闭环（`v1.0.0 必须完成的真实用户闭环` 中的 Mesh-only 与 NAS 网段项）仍需真机与 #12 阶段验收。

## Issue #9 PR-9b 子网路由批准流与证据归档（B 级）

PR-9b 只交付按前缀的子网路由声明、批准、撤销批准与观测归档；Headscale 的 `nodes approve-routes` / `nodes clear-routes` 由固定本地 CLI 适配器调用，Web 不执行任意命令。本行只登记源码与隔离自动化证据，不构成发行或 C 级验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | 创建：`subnet_router` 表单强制至少一个规范 CIDR 前缀，前缀以 `advertised` 声明写入，批准前不产生 approved 意图；非子网路由用途不能声明前缀 | [x] `TestMeshCreateSubnetRouterRequiresPrefix`、`internal/web/store_mesh_routes_test.go` |
| B | 批准：发送 Headscale 观测到的 approved 集合 ∪ 新前缀；可发送的未跟踪已批准前缀保留并记录 `MESH_ROUTE_UNTRACKED` 审计事件；Headscale 适配器会拒绝的条目（`0.0.0.0/0`、`::/0`、带主机位的 CIDR 等）不再原样回传——`approve-routes` 是整表替换，一条不可发送的条目会让每次合法前缀批准都被整体拒绝——而是移出集合、逐条记录 `MESH_ROUTE_UNTRACKED_DROPPED` 事件并在页面披露，合法前缀照常批准；命令失败或 readback 未确认时行保持 `advertised` 且返回稳定码 `MESH_ROUTE_APPROVAL_UNCONFIRMED` | [x] `TestMeshRouteApproveSendsFullSetAndPreservesUntracked`、`TestMeshRouteApproveDropsUnsendableApprovedPrefix`、`TestMeshRouteApprovalSetDropsUnsendableEntries`、`TestMeshRouteApproveReadbackMismatchLeavesAdvertised` |
| B | 撤销批准：发送差集，差集为空时调用 `ClearApprovedRoutes`；不可发送的已批准条目同样移出差集并记录 `MESH_ROUTE_UNTRACKED_DROPPED`，只剩不可发送项时改走清空（同时撤销这些条目）；readback 仍含该前缀时不写回 `advertised` | [x] `TestMeshRouteRevokeSendsDifference`、`TestMeshRouteRevokeClearsWhenNothingRemains`、`TestMeshRouteWithdrawDropsUnsendableApprovedPrefix`、`TestMeshRouteWithdrawClearsWhenOnlyUnsendableRemains` |
| B | 核对：同一 `nodes list` 循环按设备记录 `available`/`approved`/`served` 证据；未声明前缀只记事件，任何通过都不会自动批准；单设备失败报 partial，不隐藏其余设备 | [x] `TestMeshReconcileRecordsRouteEvidence`、`TestReconcileMeshRoutesNeverApprovesUntracked` |
| B | 设备注销：先 `ClearApprovedRoutes` 再 expire/delete 节点；失败保持 `revoking` 可重试 | [x] `TestMeshRevokeClearsApprovedRoutesBeforeDelete` |
| B | 页面：设备卡直接渲染 approved/available/served 三列、意图徽标、批准/撤销批准、`operation_id` 与最后观测；页面渲染仍只有 `users list` + `nodes list` 两次只读调用 | [x] `TestMeshPageRenderOnlyReadsControlPlane` 口径不变、`TestMeshRouteApproveSendsFullSetAndPreservesUntracked` |
| C | 隔离 Debian 13 VM + 真实 NAS/远程客户端：真实 advertise/approve/readback、`served` 与跨网访问 | [ ] 未含：本切片没有真实 tailnet 客户端、NAS 或远程客户端流量；跨网可达必须由后续真机验收证明 |

- [ ] **未含 C 级跨网可达**：三列只证明 Hub 与 Headscale 对路由集合的记录/readback，不证明 ACL、客户端实际接受路由、NAS 网段可达或公网链路；不得据此声称子网路由已端到端可用。
- [ ] **客户端配置边界**：9c 已实现待注册 proxy_mesh 设备的一次性 sing-box 单 VPN 配置（Tailscale Endpoint + 代理 selector，无 TUN）；标准订阅仍不含 Mesh，SSID、远程家庭网段与真机导入属 #10/后续 C 级验收。本切片（9b）未做 exit-node 批准或批量批准。

NAS 既有 Tailnet 身份迁移到 MeshMux 纳管及 subnet_router 重装/换机的授权、旧身份处置、路由接管与回退设计见 [Mesh 身份迁移](MESH_MIGRATION.zh-CN.md)；9a/9b 的验收结论不变。

## Issue #10 Web 路由与分流（B 级）

#10 按 10a（策略模型 + 生成器 + 版本锁）→ 10b（客户端策略 + `/policies` 读/校验/写）→ 10c（服务端渲染 + 预览）→ 10d（持久化 + 发布管线）交付，PR #66–#79（10a-1/10a-2、10b-1、10b-2a/2b/2c、10c-1a/1b、10c-2、10d-1a/1b、10d-2a、10d-2b-1/2b-2），每支均过 `gofmt -s` / `go vet` / staticcheck / `go test` / `go generate` 无 drift / `go build` 与 PR CI（含 #73 触发的 QEMU hub/edge/out 整机全绿，[run 39777409228](https://github.com/wingsky-1/MeshMux/actions/runs/39777409228)）。本节只登记源码与隔离自动化证据，不构成发行或 C 级验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | 策略模型：客户端/服务端意图与 sing-box 1.14.3 JSON / Mihomo YAML 生成器分离；Geo/远端规则集复用 `RulesetPin`（HTTPS + 不可变版本 + SHA-256 + 8 MiB），未 pin 拒绝；确定性字节 + 哈希 | [x] `internal/compiler/*_test.go`（`TestGeneratorsFollowPolicyDataNotHardcodedLists`、`TestRulesetVersionLockAndChecksum`） |
| B | 客户端策略：SSID（sing-box `wifi_ssid` 实测可用，Mihomo 无表达走 `RENDER_UNSUPPORTED`）、Tailnet/远端 LAN、CN 直连/国际走 Line、DNS 与出口一致；SSID 首条 direct 豁免、跨动作遮蔽 `POLICY_CONFLICT`；`ExplainHit` 四段链 | [x] `internal/compiler/client_policy_test.go`（正/反例 + 兜底 + 命中链） |
| B | 服务端渲染：`RenderServerRoute`（AI 100/域名 200/CIDR 300 → `out`）+ `CompileCandidateWithRoute` + `meshmux-node/v3`（v1/v2 字节不变，route 白名单 `rules/rule_set/final`）；`final: out` 与无 Out 引 `out` 拒绝；候选按 route 声明 `direct`/`out`/`block` 出站，`out` 在 Out 接入路径落地前为 block stub（不静默直出），未知 egress 为 `CANDIDATE_ROUTE_INVALID` | [x] `internal/node/config_v3_test.go`、`render_route_test.go`（真实 `sing-box check -c` 覆盖有 Out/无 Out/block 三种路由）、`internal/web/publish_gate_kernel_test.go`（真实门禁跑存储的 Out 候选） |
| B | 发布管线：active 装配 → fail-closed（无 opt-in 即 `OUT_OFFLINE_FAIL_CLOSED`，匿名回退 `OUT_FALLBACK_UNAUDITED`）→ 双内核门禁（缺件/版本错为显式拒绝）→ 同一事务写候选 + 四任务链（revision/快照/在途三守卫，整笔回滚）→ 回执 `queued` 永不谎报已应用 | [x] `store_policy_publish_test.go`（三态/门禁/v3/manifest）、`server_policies_publish_test.go`、`publish_check_test.go`（固定 argv/版本锁） |
| B | Web：`/policies` 读 active 快照（失效回草案 + 冲突行）、validate 干跑、explain 查询、create/revise/activate/revoke（`operation_id` 强制）、publish（`policy_schema=8` + `route_policy_revisions` 供 #11 manifest 衔接）；schema 8 修订链 + append-only 审计 | [x] `server_policies_*_test.go`、`store_policies*_test.go`（状态机/触发器/迁移重放） |
| B | 客户端层边界（#113 1-2）：发布真相仅服务端 route；客户端层只渲染 + 双内核门禁，回执 `status=gated` 明示“不写候选、不改变订阅下载内容”，`/policies` 标为“预览 · 不改变订阅”，混合发布回执同时说明客户端不写候选 | [x] `store_policy_publish_client_preview_test.go`（客户端发布/第二个客户端版本/混合发布后 sing-box 与 mihomo 下载字节不变；页面预览标注）、`server_policies_publish_test.go` |
| C | 真实双出口 AI 双跳 / 无 Out 直出 / Out 故障 fail-closed 实际流量 | [ ] 未含：只有 fail-closed 语义与门禁单测；归 #12（`必须完成的真实用户闭环`第 3 项） |
| C | 真机 sing-box / Mihomo 导入、iOS/Android 单 VPN、SSID 现场行为、客户端实际可用 | [ ] 未含：只有渲染与 `check -c`/`-t` 门禁；归 #12（同第 5 项） |
| C | 真实 Line 上的路由发布/readback/回退（含 Web 发布真实策略） | [ ] 未含：只有候选事务与 Agent recover/LKG 复用；归 #12（同第 2/7 项） |

- [ ] **未含 C 级结论**：本节不证明任何真实流量、真机导入或现网发布成功；`queued` 回执不是已应用。#10 的 v1.0.0 闭环（`v1.0.0 必须完成的真实用户闭环` 第 3/5/7 项）由 #12 采集。

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
