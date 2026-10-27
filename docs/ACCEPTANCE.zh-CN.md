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
- [x] **PR B 全系统验收（C 级，amd64 自动化门禁）**：[L3 QEMU/systemd run 39216454882](https://github.com/wingsky-1/MeshMux/actions/runs/39216454882) 于 head `c5be00c` PASS，`internal/cli/install/vm_test` 覆盖真实 systemd 服务与监听、本机内部证书 TLS 探针（非真实公网 ACME）、重启持久化、故障回滚以及 Fail2ban/nftables ban/unban；run head 的 Git 树 `8e08dfe5327fdf3ec0ecc0cb4daad54e5b6cd5c0` 与 `main` `17baaa1` 完全相同，Hub 接口可被 #6 消费。#5 已关闭。
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
| L1 | 配对端点的预算与不可枚举（#113 3-4）：`/api/agent/pair` 自带**进程内** 20 次/分钟预算（窗口从首次尝试起算、失败不延长、配对成功即清零），第 21 次 429 `PAIRING_RATE_LIMITED` + `Retry-After`；判定路径零数据库访问，持有 `SetMaxOpenConns(1)` 的唯一连接时仍立即返回 429，且不共用登录预算；格式错误请求在触库前被拒、不计费；未知/过期/已消费的码合并为同一个 `401 PAIRING_INVALID`（同 body，不成为码历史 oracle），精确原因只进 `web_event`（`PAIRING_EXPIRED`/`PAIRING_CONSUMED`）；`403 ROLE_MISMATCH` 保留，数据库不可用为 `503`、身份签发失败为 `500` 而不伪装成码被拒绝 | [x] `TestPairingBudgetRefusesAFloodAndStatesTheWait`、`TestPairingFloodNeverContendsForTheSingleConnection`、`TestPairingSuccessClearsTheBudget`、`TestPairingRefusalIsNotACodeOracle`、`TestPairingRefusesAnUnavailableDatabaseAsItself`、`TestPairingSingleUseExpiryAndRole`；`go test ./internal/web/ -race` 全绿 |
| L1 | 同源 CLI 下载不整块缓冲（#113 3-5）：`/api/nodes/cli` 以 32 KiB 分块 `io.CopyBuffer(io.MultiWriter(响应, sha256))` 边发边算，不再 `io.ReadAll` 128 MiB；`Stat` 的大小同时约束两遍读取，128 MiB 上限不变；摘要不符仍在响应开始前返回 `503 INSTALL_ARTIFACT_CHANGED`；第二遍（两遍之间被改写）以 `http.ErrAbortHandler` 结束该响应并记同一稳定码，真正拒绝该文件的是安装器固定的 `sha256sum -c`；`Stat` 后追加的字节不进入响应或摘要 | [x] `TestInstallArtifactDownloadStreamsInsteadOfBuffering`（16 MiB 下载分配约 48 KiB）、`TestConcurrentInstallArtifactDownloadsDoNotScaleWithFileSize`（4×8 MiB 并发共约 184 KiB）、`TestInstallArtifactDownloadRefusesAChangedArtifactBeforeTheBody`、`TestInstallArtifactDownloadRefusesAnOversizedArtifactWithoutReadingIt`、`TestCopyArtifactVerifiedReportsWhatWentWrong`、`TestBoundaryLetsAnAbortReachNetHTTP`；`go test ./internal/web/ -race` 全绿 |
| L1 | 密码 KDF 槽只覆盖密码路由（#113 3-2）：进程内 `kdfSlot`（容量 1）只由 `POST /login`、`POST /setup`、`POST /password` 持有，仍保证同一时刻只有一个 Argon2id（64 MiB）运算；`POST /policies/publish` 等长任务不再占用它，因此发布在门禁里等待内核时创建节点、绑定 Out、订阅写入等管理 POST 都不再被拒；槽在会话/表单/CSRF 校验之后才获取，未认证或伪造请求不占槽。占用期间的密码请求返回 `429 AUTH_KDF_BUSY` + `Retry-After`（原 `AUTH_BUSY` 拆码，语义收窄为“另一个密码运算正在进行”），非密码 POST 完全不受影响 | [x] `TestPublishDoesNotHoldThePasswordSlot`（发布阻塞在门禁时建节点仍 200）、`TestPasswordSlotOnlyRefusesPasswordRoutes`（占槽时登录 429、建节点 200，释放后登录 303）、`TestBootstrapExpiryAndConcurrentInitialization`；`go test ./internal/web/ -race` 全绿 |
| L1 | 登录页不再被匿名会话锁死（#113 3-3）：`GET /login`、`GET /setup` 只签发 15 分钟的 `__Host-meshmux-form` 双提交令牌（Secure/HttpOnly/Strict/host-only，值为进程内 HMAC 签名的过期时间+nonce），不写入 `sessions`；`sessions` 只保存已认证会话，登录时整表替换；匿名 cookie-less 请求因此不消耗有界持久资源，256 次之后登录页仍 200 且表单可用；令牌缺失/伪造/重复 cookie/过期仍 `401 SESSION_INVALID`，cookie 与表单值不匹配仍 `403 CSRF_REJECTED`，成功登录/初始化/改密/退出清除该 cookie；旧版本遗留的 256 条匿名行不再影响渲染，并在下一次登录时清除 | [x] `TestAnonymousFloodCannotLockTheLoginPage`（256 次匿名 GET 后登录页 200、`sessions` 0 行、随后登录 303）、`TestLoginPageRendersWithLegacyAnonymousRowsFull`、`TestLoginFormTokenIsStillEnforced`、`TestSetupFormUsesTheSameStatelessToken`、`TestFormCookieIsHostOnlyAndHttpOnly`；`go test ./internal/web/ -race` 全绿 |
| L1 | repair 的候选语义（#113 4-4）：repair 明确**不**把节点拉齐到本次从 Hub 下载的候选，而是保留已记录的 active candidate 与已校验的编译配置；该决定写死并有声明——`InstallResult.next_action` 以稳定码 `REPAIR_CANDIDATE_NOT_CONVERGED` 开头说明保留的是哪个 revision、未应用哪个候选，`events.jsonl` 记 `stage/candidate_not_converged`；repair 仍以 `installed` + 空 `error_code` 结束（声明不是失败码，也不写 `state.Recovery`），因此 recorded-state 交接与 11c-3 confirm/revert 锚点不受影响；下载候选与记录候选逐字节相同时不产生声明，全新安装也没有声明 | [x] `TestNodeRepairDeclaresThatItKeepsTheRecordedCandidate`（Hub 给 revision 2、宿主记录 revision 1：结果 `installed`、`error_code` 空、`next_action` 前缀为稳定码且点名两个 revision、active candidate 仍为 1、journal 有 `candidate_not_converged` 且无 `error_code`）、`TestNodeFreshInstallDoesNotDeclareACandidateDecision`；`go test ./internal/install ./internal/node` 全绿 |
| L1 | staged 暂存不随 revision 线性增长（#113 4-3）：`/var/lib/meshmux-agent/staged/<rev>-candidate.json` 与 `<rev>-config.json` 原先每个已应用 revision 写一对且永不回收；现在只在 apply+readback 判定 healthy 之后回收，保留当前 revision（`loadLKGCandidate` 与所有 readback 的读取锚）、上一 revision（revert 要回到的发行）以及最近 `stagedKeepRevisions=2` 窗口，与 11c-3 rollback store 的 N-1 语义一致；回收不触碰 active candidate/config、`state.json` LKG、`upgrade-source` 快照或任何回退所需文件，失败/回退的 apply 与仅有 stage 的 pending revision 一律不回收，非本目录命名的文件、目录与符号链接不跟随不删除；回收为 best effort，失败只记 `STAGED_GC_FAILED` 日志、不改写 readback 已证明的 healthy 结果 | [x] `TestStagedGCKeepsTheCurrentAndPreviousRevision`（两次 healthy apply 后旧 revision 被回收，当前与上一 revision 仍在且 readback 仍可读）、`TestStagedGCKeepsThePreviousRevisionAcrossARevisionJump`（10→12 跳版仍保留 revert 锚点 10）、`TestStagedGCLeavesAFailedApplyAlone`（rolled_back 后 7/9/12 全在）、`TestStagedGCCollectsOnlyItsOwnRegularFiles`（外来名/伪装目录/符号链接与目标均不动）、`TestStagedGCRetentionMatchesTheRollbackStore`；`go test ./internal/node`、`go test -race ./internal/node` 全绿 |
| L1 | 启动锁有上界（#113 4-1）：`NewRuntime` 过去以 `context.Background()` 无限等待 `/var/lib/meshmux-agent/runtime.lock`，而首启 bootstrap readback 又在持锁状态下固定睡眠 29×2s（≈58s）且不可取消。现在启动等待以 `runtimeStartupLockTimeout=60s` 为界（与安装器无人值守的 `installLockWait` 同一窗口），窗口耗尽返回稳定码 `RUNTIME_LOCK_TIMEOUT` 而不是永远挂起、也不是会被下一轮误重投的 `RUNTIME_BUSY`；bootstrap 的瞬时 readback 重试改为可取消，预算复用 `agentLockTimeout`（5s，与一次轮询等待锁的上限一致，可用 `BootstrapReadbackTimeout`/`StartupLockTimeout` 缩短），只有启动瞬时信号（`SINGBOX_NOT_RUNNING`/`SINGBOX_SUPERVISOR_STARTING`/`SINGBOX_PID_CHANGED`/`LISTENER_*`）才重试，确定性失败仍在首次尝试即返回；进程 ctx 结束时启动等待与 readback 都立即以 `REQUEST_CANCELLED` 结束。update/revert/confirm、upgrade/manifest、protocol 与安装器回退语义不变 | [x] `TestStartupLockBound`（60s 常量 + 50ms 短窗口返回 `RUNTIME_LOCK_TIMEOUT`，且是可被退出行识别的稳定码）、`TestStartupLockWaitsForAnOrdinaryInstall`（窗口内释放仍正常启动）、`TestBootstrapReadbackRetriesInsideTheLockBudget`（永不就绪的内核在 700ms 预算内失败并释放锁，重试次数>1）、`TestBootstrapReadbackRecoversWhenKernelStarts`（预算内就绪仍成功）、`TestBootstrapReadbackStopsOnCancellation`（ctx 结束立即 `REQUEST_CANCELLED`）、`TestBootstrapReadbackFailsFastOnDeterministicErrors`（二进制不符只读回一次）、`TestBootstrapReadbackBudgetDefaultsToAgentLockTimeout`；`go test ./internal/node` 全绿 |
| L1 | journal 恢复失败不再崩溃循环（#113 4-2）：`NewRuntime` 过去在 `recoverJournal` 失败时直接返回错误，`Restart=on-failure` 会让 systemd 无限重启，且失败尝试记录的 partial 从未落盘或上报。现在恢复失败不再拒绝启动：失败尝试把 `partial` + 稳定 `error_code` 写入 `state.json` 的 idempotency，Hub 已看到 `applying` 时同时放入 outbox 由下一轮上报；journal 只在宿主瞬态（`LKG_RESTART_FAILED`、`LKG_PID_NOT_REPLACED`、内核未就绪的 `LKG_READBACK_FAILED`）时保留，此时 `config.check`/`config.stage`/`config.apply` 继续以 `RECOVERY_REQUIRED` 拒绝动态写，轮询在 `runtime.lock` 内按 20s 预算重试（同一进程最多 3 次）后收敛；确定性失败（`JOURNAL_INVALID`、`JOURNAL_WITHOUT_LKG`、LKG 候选缺失、ACL/readback 宿主漂移）立即以 `partial` 收敛并移除 journal，后续链可修复节点；`state.json` 无法持久化仍是唯一的启动拒绝。恢复成功的 `rolled_back` 仅在 Hub 已收到 `applying` 时使用，未上报的 journal 改报 `partial`（Hub 的 pending 行拒绝 `rolled_back`），避免无法投递的无限重试 | [x] `TestJournalRecoveryFailureStartsDegradedConvergesAndReportsPartial`（LKG 候选缺失：启动成功、journal 移除、partial 落盘并上报、随后 check 可用）、`TestJournalRecoveryKeepsTheJournalForAStartingKernel`（LISTENER 瞬态：降级启动、`RECOVERY_REQUIRED`、下一轮恢复并报 rolled_back）、`TestJournalRecoveryRetryIsBounded`（宿主始终不收敛：3 次后收敛且 check 可用）、`TestJournalRecoveryWithoutAReportedApplyUsesThePendingSafeReceipt`（未上报：重投返回 partial 而非 rolled_back）、`TestJournalInvalidRestoresBestEffortAndConverges`（损坏 journal：尽力恢复 LKG、partial/JOURNAL_INVALID 收敛）；`go test ./internal/node ./internal/update ./internal/install` 全绿 |
| L2 | Debian 13 amd64 固定 sing-box 1.14.3、systemd unit、Fail2ban/nft 配置自检 | [x] [hub-components run 39372308917](https://github.com/wingsky-1/MeshMux/actions/runs/39372308917)（head `78e259b`，tree `e35fc88`）：releases.tsv pin、archive+binary SHA、unit verify、nft -c、fail2ban -t、candidate jq 全过；unit 语法用空可执行 stub 校验，binary 内容同 run 内 SHA 校验（含 DAC cap 与时钟 poll 后的 unit） |
| L2 | Debian 13 arm64 固定制品与组件配置自检 | [x] 同上 run（head `78e259b`），原生 arm64 runner，同矩阵同步骤全绿 |
| L3 | 隔离 Debian 13 VM 的 edge/out 首装、repair、重启、故障恢复、实际 SSH/VLESS 端口与 Fail2ban/nft 行为 | [x] [hub-vm run 39367683751](https://github.com/wingsky-1/MeshMux/actions/runs/39367683751)（head `78e259b`，tree `e35fc88`）：edge/out/hub 三 job 全 success；edge 含一次 TCG 时钟 `TIME_UNSYNCED` 抖动，重跑即过 |

- [x] **全仓自动化**：本地 `gofmt` 干净、`go vet ./...` 通过、`go build ./...` 通过；`go test` 分包全过（product/agent 52、node 46、install 85、web 56、cmd 三包 68），`go test -race` 全过（install/web/node/cmd 及 product/agent/webcmd 五包 120，无 DATA RACE）。
- [x] **PR-B CI**：L2 [hub-components run 39372308917](https://github.com/wingsky-1/MeshMux/actions/runs/39372308917)（head `78e259b`，tree `e35fc88`）amd64/arm64 全绿；L3 [hub-vm run 39367683751](https://github.com/wingsky-1/MeshMux/actions/runs/39367683751)（同 head/tree）edge/out/hub 全 success。后续链接必须指向对应 head，并说明该 head 的 Git tree。
- [ ] **#6 L3 外部边界**：真实公网入站、云安全组、真实协议握手和客户端可用未测；#6 baseline 无 TLS/REALITY、无用户、无订阅。#7 新实现及证据见下节。
- [x] **Out ACL 语义（#8 源码已修复）**：ACL 已由 #8-B 改为空授权默认全拒绝（`inet meshmux_out` 只保留一条 `input` chain，`policy accept` 仅覆盖主机 SSH/回环/回程；VLESS 端口两条 `tcp/udp dport drop` 默认丢弃，仅 Hub 授权的 Line 源在 drop 之前 `accept`）。**仿真证据（隔离单测）**：`internal/core/node/render_acl_test.go`、`internal/core/node/runtime_readback_acl_test.go`、`internal/cli/install/node_acl_test.go`（含有序 accept-before-drop、未对齐 CIDR 拒绝、`nft -j` 精确集合比对、注入 accept 拒绝、state 缺失退化为形状断言、repair 保留已授权 ACL）；`go test -race ./...` 全绿。
- [x] **Out ACL 真实 L2+L3 证据（#8 收尾）**：`scripts/ci-node-components.sh` 在 `nft -c` 后执行真实 `nft -f` apply，并用 `nft -j list table inet meshmux_out` 断言至少 2 条 rule、归档 `nft list` 输出；容器无 `CAP_NET_ADMIN` 时显式 SKIP，不计为通过。L2 [hub-components run 39717249475](https://github.com/wingsky-1/MeshMux/actions/runs/39717249475)（head `9495730`、tree `5720b86`）amd64/arm64 全绿，amd64 日志实得 `nft apply/readback PASS`（2 rules，非 SKIP）；L3 [hub-vm run 39717249274](https://github.com/wingsky-1/MeshMux/actions/runs/39717249274)（同 head/tree）hub/edge/out 全 success，out 含 `TestNodeSystemVM` 真实 `nft list table inet meshmux_out` 回读断言。AI 双跳实际流量（已移交 #10）与客户端可用仍缺。
- [x] **Out 缺失/故障语义与清理（#8-D，Task 6 后现状）**：`internal/route/out_ruleset.go` 提供 `RulesetPin{Source,Version,SHA256}` 与 `ResolveAIRuleset`（下载/大小/摘要失败统一 `RULESET_FETCH_FAILED`，可变通道 `RULESET_PIN_INVALID`）；AI 出口决策层已由 Task 6 删除并移交规则库/订阅组装器。`OutEgressFacts` 仍分离“无 Out = 直出配置态”与“Out 故障 = 不可用”，无 Opt-in 回退即 fail-closed；删除语义已被 Task 5 的 Ruling R9 取代（先清空 ACL 并读回，再彻底删除；失败 409 且不删任何内容）。**仿真证据（隔离单测）**：`internal/route/out_ruleset_test.go`、`internal/web/handler/store_out_ai_egress_test.go`（facts）、`internal/web/handler/store_out_sync_test.go` 与 Task 5 的 `TestOutDelete*`。
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

PR-9a 分四个切片交付：9a-1 `internal/core/mesh` 纯领域模型、9a-2 `internal/headscale` 固定 argv 本地 CLI 适配器、9a-3 Web `/mesh` 页面与 schema 6 持久化（`store_mesh.go`），9a-4 Hub 的 Web↔Headscale socket 组边界与隔离 fixture。本行**只登记源码与自动化证据**，不构成发行验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| A | 领域与适配器边界：`internal/core/mesh` 无 I/O 且不 import `internal/web`/`internal/cli/install`；`internal/headscale` 只经固定 binary/config 与固定 argv 表调用，无 shell、无 `preauthkeys list`、`nodes delete` 带 `--force`；Web 只经该接口读写 Headscale | [x] 源码评审 + 隔离单测 |
| B | 设备与 Key 生命周期：用途/绑定规则、NodeName 同用户占用唯一、`pending`/`registered` 只由观测到的 Node ID 推进、Key 15 分钟仅存 SHA-256 且单活/`consumed` 不可逆、注销先写意图再远端删除且幂等重试、撤销一台设备不影响订阅用户/凭据/Token | [x] `go test ./internal/web/ -run Mesh` 全绿（`store_mesh_test.go`、`server_mesh_test.go`、`mesh_fixture_test.go`）；`TestMeshHubFixture` 默认 SKIP |
| B | Web 路由边界：`/mesh` 需认证；四个 mutation 需 CSRF；页面渲染只发 `users list`/`nodes list` 两次只读调用；Headscale 不可用时返回稳定 `HEADSCALE_*` 且不写入任何设备/Key | [x] `TestMeshRoutesRequireAuthentication`、`TestMeshPageRequiresCSRFOnMutations`、`TestMeshPageRenderOnlyReadsControlPlane`、`TestMeshWithoutHeadscaleRefusesBeforeWrites` |
| B | 安装侧 socket 边界（9a-4）：`meshmux-web.service` 仅以 `SupplementaryGroups=meshmux-headscale` 穿过 0770 socket，数据目录仍 0700 且无 `Group=`/`ReadWritePaths` | [x] 模板断言 `internal/cli/install/render_test.go`；**真实组权限链未验证** |
| B | 一次性 Key 的消费语义（#113 2-4）：不存在接收 secret 的消费端点，`reconcile`/`claim` 证明注册（观测到 Headscale Node ID）时在同一事务消费该设备 live Key（`consumed`、摘要清空）；窗口已过的 Key 记为 `expired`，停留 `issued` 之外的记录不被改写 | [x] `TestMeshRegistrationConsumesKey`、`TestMeshEnrollmentKeySingleActive`、`TestMeshClaimBindsUnclaimedSameNameNodeExplicitly`、`TestMeshRekeyWithdrawsOldKey` |
| B | 重签顺序（#113 2-3）：`/mesh/rekey` 按 validate → stage → apply → readback 执行——先解析 Headscale 用户并在内存中备好新 Key（proxy+mesh 另含 pre-auth key 与渲染文档），再用一次事务安装新 Key、作废旧 live Key；`expired → pending` 与安装 Key 同一事务。中途失败（Headscale 不可用、渲染失败、事务失败）不启用新 Key、不作废旧 Key，旧 Key 仍可用于入网；已过窗口的旧 Key 由该事务记为 `expired`，页面不称其为“已作废”；成功响应仍只出现一次新 Key | [x] `TestMeshRekeyHeadscaleFailureKeepsOldKey`、`TestMeshRekeySwapFailureKeepsOldKey`、`TestMeshRekeyExpiredDeviceGetsKeyWithItsStatus`、`TestMeshRekeyExpiredDeviceKeepsItsLapsedKeyOnNameConflict`、`TestMeshRekeyRenderFailureKeepsOldKeyUsable`、`TestMeshRekeyLapsesOldKeyWithoutClaimingAWithdrawal`、`TestMeshRekeyNeverLeavesTwoLiveKeys` |
| C | 隔离 Debian 13 Hub VM：真实 Headscale 0.29.5 下 Web 账户经 socket 完成 `version`/`users list`/`nodes list`，页面创建设备并核对、注销，事件日志无 Key 明文 | [ ] 待执行：`MESHMUX_MESH_HUB_FIXTURE_DIR=... /tmp/web-handler.test -test.run '^TestMeshHubFixture$'`，需在干净 VM 内以 `meshmux` 账户运行；head/tree 与 run 链接待回填 |

- [ ] **未含真机与真实注册**：本 PR 没有真实 tailnet 客户端入网，因此 `registered`、在线状态、Tailnet IP、真实 `nodes delete` 与真实 Headscale Key 消费均未被证明；自动化只证明观测到 Node ID 时 Hub 侧一次性 Key 转为 `consumed`、摘要清空。
- [ ] **未含 C 级结论**：子网路由发布/批准/readback、路由策略与单 VPN 客户端配置分别属 9b/9c；Mesh 的 v1.0.0 闭环（`v1.0.0 必须完成的真实用户闭环` 中的 Mesh-only 与 NAS 网段项）仍需真机与 #12 阶段验收。

## Issue #9 PR-9b 子网路由批准流与证据归档（B 级）

PR-9b 只交付按前缀的子网路由声明、批准、撤销批准与观测归档；Headscale 的 `nodes approve-routes` / `nodes clear-routes` 由固定本地 CLI 适配器调用，Web 不执行任意命令。本行只登记源码与隔离自动化证据，不构成发行或 C 级验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | 创建：`subnet_router` 表单强制至少一个规范 CIDR 前缀，前缀以 `advertised` 声明写入，批准前不产生 approved 意图；非子网路由用途不能声明前缀 | [x] `TestMeshCreateSubnetRouterRequiresPrefix`、`internal/web/handler/store_mesh_routes_test.go` |
| B | 批准：发送 Headscale 观测到的 approved 集合 ∪ 新前缀；可发送的未跟踪已批准前缀保留并记录 `MESH_ROUTE_UNTRACKED` 审计事件；Headscale 适配器会拒绝的条目（`0.0.0.0/0`、`::/0`、带主机位的 CIDR 等）不再原样回传——`approve-routes` 是整表替换，一条不可发送的条目会让每次合法前缀批准都被整体拒绝——而是移出集合、逐条记录 `MESH_ROUTE_UNTRACKED_DROPPED` 事件并在页面披露，合法前缀照常批准；命令失败或 readback 未确认时行保持 `advertised` 且返回稳定码 `MESH_ROUTE_APPROVAL_UNCONFIRMED` | [x] `TestMeshRouteApproveSendsFullSetAndPreservesUntracked`、`TestMeshRouteApproveDropsUnsendableApprovedPrefix`、`TestMeshRouteApprovalSetDropsUnsendableEntries`、`TestMeshRouteApproveReadbackMismatchLeavesAdvertised` |
| B | 撤销批准：发送差集，差集为空时调用 `ClearApprovedRoutes`；不可发送的已批准条目同样移出差集并记录 `MESH_ROUTE_UNTRACKED_DROPPED`，只剩不可发送项时改走清空（同时撤销这些条目）；readback 仍含该前缀时不写回 `advertised` | [x] `TestMeshRouteRevokeSendsDifference`、`TestMeshRouteRevokeClearsWhenNothingRemains`、`TestMeshRouteWithdrawDropsUnsendableApprovedPrefix`、`TestMeshRouteWithdrawClearsWhenOnlyUnsendableRemains` |
| B | 核对：同一 `nodes list` 循环按设备记录 `available`/`approved`/`served` 证据；未声明前缀只记事件，任何通过都不会自动批准；单设备失败报 partial，不隐藏其余设备 | [x] `TestMeshReconcileRecordsRouteEvidence`、`TestReconcileMeshRoutesNeverApprovesUntracked` |
| B | 批准/撤销的“远端已成功、本地写入失败”（#113 2-2）：先 readback 意图列——已带目标状态的写入视为已提交，不回退（否则制造不一致）；仍为旧意图时按操作前的可发送批准集合补偿（空集走 `ClearApprovedRoutes`），并回读回退结果。回退被确认记 `MESH_ROUTE_COMPENSATED`，页面报普通失败并说明本次变更未生效；回退被拒或未确认才报 `MESH_ROUTE_APPROVAL_PARTIAL`/`MESH_ROUTE_WITHDRAW_PARTIAL`（HTTP 500，附回退失败的稳定码与“重新核对”动作）。观测证据写入失败不回退：意图已与 Headscale 一致，只报证据待刷新 | [x] `TestMeshRouteApproveLocalFailureRevertsHeadscale`、`TestMeshRouteApprovePartialWhenRevertFails`、`TestMeshRouteRevokeLocalFailureRestoresApproval`、`TestMeshRouteRevokePartialWhenClearRevertFails`、`TestMeshRouteLocalFailureDoesNotRevertACommittedWrite` |
| B | 设备注销：先 `ClearApprovedRoutes` 再 expire/delete 节点；失败保持 `revoking` 可重试 | [x] `TestMeshRevokeClearsApprovedRoutesBeforeDelete` |
| B | 页面：设备卡直接渲染 approved/available/served 三列、意图徽标、批准/撤销批准、`operation_id` 与最后观测；页面渲染仍只有 `users list` + `nodes list` 两次只读调用 | [x] `TestMeshPageRenderOnlyReadsControlPlane` 口径不变、`TestMeshRouteApproveSendsFullSetAndPreservesUntracked` |
| B | 客户端配置的用途边界（#113 2-5）：`accept_routes` 不再是与用途无关的字面量——导出器按 `Purpose` 查表并只渲染 `proxy_mesh`，`accept_routes` 在该用途下有意固定 `false` 并在 `FEATURES`/`CLIENT_CAPABILITIES` 声明原因（无 TUN、唯一条 Tailscale 规则只匹配 Tailnet 前缀）；`mesh_only`/`subnet_router`/缺省用途一律以 `EXPORT_MESH_PURPOSE_UNSUPPORTED` 拒绝，继续使用现成 Tailscale 客户端，子网路由设备保留带 `--advertise-routes` 的入网命令 | [x] `TestExportMeshDeviceAcceptRoutesFollowsPurpose`、`TestMeshPurposeProfilesAreClosed`、`TestMeshConfigPurposeReachesTheExporter`、`TestMeshSubnetRouterKeepsTheStockClient`；真实 `sing-box check` 接受该文档 |
| C | 隔离 Debian 13 VM + 真实 NAS/远程客户端：真实 advertise/approve/readback、`served` 与跨网访问 | [ ] 未含：本切片没有真实 tailnet 客户端、NAS 或远程客户端流量；跨网可达必须由后续真机验收证明 |

- [ ] **未含 C 级跨网可达**：三列只证明 Hub 与 Headscale 对路由集合的记录/readback，不证明 ACL、客户端实际接受路由、NAS 网段可达或公网链路；不得据此声称子网路由已端到端可用。
- [ ] **客户端配置边界**：9c 已实现待注册 proxy_mesh 设备的一次性 sing-box 单 VPN 配置（Tailscale Endpoint + 代理 selector，无 TUN）；标准订阅仍不含 Mesh，SSID、远程家庭网段与真机导入属 #10/后续 C 级验收。本切片（9b）未做 exit-node 批准或批量批准。该文档的 `accept_routes` 按用途固定 `false` 并已声明不支持对端子网路由（见上表 #113 2-5 行）：代理+Mesh 客户端不声称能到达远端 LAN。

NAS 既有 Tailnet 身份迁移到 MeshMux 纳管及 subnet_router 重装/换机的授权、旧身份处置、路由接管与回退设计见 [Mesh 身份迁移](MESH_MIGRATION.zh-CN.md)；9a/9b 的验收结论不变。

## Issue #10 Web 路由与分流（B 级）

#10 按 10a（策略模型 + 生成器 + 版本锁）→ 10b（客户端策略 + `/policies` 读/校验/写）→ 10c（服务端渲染 + 预览）→ 10d（持久化 + 发布管线）交付，PR #66–#79（10a-1/10a-2、10b-1、10b-2a/2b/2c、10c-1a/1b、10c-2、10d-1a/1b、10d-2a、10d-2b-1/2b-2），每支均过 `gofmt -s` / `go vet` / staticcheck / `go test` / `go generate` 无 drift / `go build` 与 PR CI（含 #73 触发的 QEMU hub/edge/out 整机全绿，[run 39777409228](https://github.com/wingsky-1/MeshMux/actions/runs/39777409228)）。本节只登记源码与隔离自动化证据，不构成发行或 C 级验收。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | 策略模型：客户端/服务端意图与 sing-box 1.14.3 JSON / Mihomo YAML 生成器分离；Geo/远端规则集复用 `RulesetPin`（HTTPS + 不可变版本 + SHA-256 + 8 MiB），未 pin 拒绝；确定性字节 + 哈希 | [x] `internal/compiler/*_test.go`（`TestGeneratorsFollowPolicyDataNotHardcodedLists`、`TestRulesetVersionLockAndChecksum`） |
| B | 客户端策略：SSID（sing-box `wifi_ssid` 实测可用，Mihomo 无表达走 `RENDER_UNSUPPORTED`）、Tailnet/远端 LAN、CN 直连/国际走 Line、DNS 与出口一致；SSID 首条 direct 豁免、跨动作遮蔽 `POLICY_CONFLICT`；`ExplainHit` 四段链 | [x] `internal/compiler/client_policy_test.go`（正/反例 + 兜底 + 命中链） |
| B | 服务端渲染：`RenderServerRoute`（AI 100/域名 200/CIDR 300 → `out`）+ `CompileCandidateWithRoute` + `meshmux-node/v3`（v1/v2 字节不变，route 白名单 `rules/rule_set/final`）；`final: out` 与无 Out 引 `out` 拒绝；候选按 route 声明 `direct`/`out`/`block` 出站，`out` 在 Out 接入路径落地前为 block stub（不静默直出），未知 egress 为 `CANDIDATE_ROUTE_INVALID` | [x] `internal/core/node/config_v3_test.go`、`render_route_test.go`（真实 `sing-box check -c` 覆盖有 Out/无 Out/block 三种路由）、`internal/web/handler/publish_gate_kernel_test.go`（真实门禁跑存储的 Out 候选） |
| B | 发布管线：active 装配 → fail-closed（无 opt-in 即 `OUT_OFFLINE_FAIL_CLOSED`，匿名回退 `OUT_FALLBACK_UNAUDITED`）→ 双内核门禁（缺件/版本错为显式拒绝）→ 同一事务写候选 + 四任务链（revision/快照/在途三守卫，整笔回滚）→ 回执 `queued` 永不谎报已应用 | [x] `store_policy_publish_test.go`（三态/门禁/v3/manifest）、`server_policies_publish_test.go`、`publish_check_test.go`（固定 argv/版本锁） |
| B | Web：`/policies` 读 active 快照（失效回草案 + 冲突行）、validate 干跑、explain 查询、create/revise/activate/revoke（`operation_id` 强制）、publish（`policy_schema=8` + `route_policy_revisions` 供 #11 manifest 衔接）；schema 8 修订链 + append-only 审计 | [x] `server_policies_*_test.go`、`store_policies*_test.go`（状态机/触发器/迁移重放） |
| B | 客户端层边界（#113 1-2）：发布真相仅服务端 route；客户端层只渲染 + 双内核门禁，回执 `status=gated` 明示“不写候选、不改变订阅下载内容”，`/policies` 标为“预览 · 不改变订阅”，混合发布回执同时说明客户端不写候选；Task 6 起客户端层**停写**（`POLICY_LAYER_RETIRED`），既有 revision 只读预览 | [x] `store_policy_publish_client_preview_test.go`（客户端发布/第二个客户端版本/混合发布后 sing-box 与 mihomo 下载字节不变；页面预览标注）、`server_policies_publish_test.go` |
| C | 真实双出口 AI 双跳 / 无 Out 直出 / Out 故障 fail-closed 实际流量 | [ ] 未含：只有 fail-closed 语义与门禁单测；归 #12（`必须完成的真实用户闭环`第 3 项） |
| C | 真机 sing-box / Mihomo 导入、iOS/Android 单 VPN、SSID 现场行为、客户端实际可用 | [ ] 未含：只有渲染与 `check -c`/`-t` 门禁；归 #12（同第 5 项） |
| C | 真实 Line 上的路由发布/readback/回退（含 Web 发布真实策略） | [ ] 未含：只有候选事务与 Agent recover/LKG 复用；归 #12（同第 2/7 项） |

## 订阅聚合重构（Task 4：组装 + 预览 + 快照 + 互锁）

本节只登记源码与隔离自动化证据；不证明现网安装、真实双跳流量或客户端可用。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | 纯函数组装：`subscription.ComposeSubscription(lines, outs, rules, network)` 同输入同字节；返回内容摘要；两份客户端文档（sing-box JSON / Mihomo YAML）与每 Line 服务端 route 片段 | [x] `internal/core/subscription/compose_test.go`（`TestComposeSubscriptionIsByteDeterministic` 等） |
| B | 规则双内核：同一规则选择在 sing-box route 与 Mihomo rules 都出现；geo/ruleset 未 pin 为 `COMPOSE_RULESET_UNPINNED`；重复/重叠规则分别 `COMPOSE_RULE_DUPLICATE`/`COMPOSE_RULE_CONFLICT` | [x] `TestComposeSubscriptionRulesReachBothDocuments`（真实 `sing-box check` 通过）、`TestComposeSubscriptionRefusesUnpinnedRuleSet`、`TestComposeSubscriptionDuplicateRuleIsBlocking`、`TestComposeSubscriptionRejectsOverlappingRules` |
| B | Out 约束：1.0 单订阅最多 1 个 Out（`COMPOSE_OUT_LIMIT`）；选 Out 后无代理规则即 `COMPOSE_OUT_WITHOUT_PROXY_RULE`；同一 Line 上既有订阅的 Out 选择不一致即 `SUBSCRIPTION_OUT_CONFLICT` 并列出订阅名 | [x] `TestComposeSubscriptionRefusesSecondOut`、`TestWizardSaveRefusesBlockingPreviewWithoutWriting`、`TestWizardSaveRefusesOutConflictWithExistingSubscription`、`TestSaveSubscriptionSelectionRefusesSecondOutAndOutConflict` |
| B | 边表 + 快照：schema 13 的 `subscription_lines/outs/rules/networks`（`position` 组内唯一）与 `subscription_snapshots`（选择+版本+排序+已批准摘要，不存字节）；`proxy_credentials` 仍为凭据具现；保留 Line 沿用 UUID | [x] `TestSchema13CreatesSelectionTables`、`TestSaveSubscriptionSelectionWritesEdgesAndSnapshot`、`TestSaveSubscriptionSelectionKeepsCredentialPerLine`、`TestWizardSaveKeepsExistingCredentialOnReSave` |
| B | 预览 fail-fast 四层：输入 `!` 不阻断、保存严格校验、组装冲突、Out 槽位与内核门禁 `✖` 阻断且**不写入**；Mihomo 缺席为跳过提醒，Mihomo 拒绝为阻断 | [x] `TestWizardPreviewWritesNothingAndRemindsOnRecordedGroups`、`TestWizardSaveRefusesGateFailure`、`TestMihomoAbsentDegradesWithoutBlocking`、`TestWizardSaveRefusesMihomoRejectionButAcceptsAbsentBinary` |
| B | 下载门禁：按快照重新组装并与已批准摘要比对，漂移 `SUBSCRIPTION_ARTIFACT_DRIFT`、未批准 `SUBSCRIPTION_ARTIFACT_NOT_APPROVED`；未走过向导的存量订阅保持原导出路径 | [x] `TestApproveSubscriptionSelectionRecordsArtifactAndRefusesDrift`、`TestApproveSubscriptionSelectionRefusesUnapprovedAndFailedGate`、`TestDownloadRefusesDriftedOrUnapprovedArtifact` |
| B | used-by 互锁：被订阅引用的规则删除由规则库拒绝并列出订阅名；被订阅选择的 Out 删除被拒；组网设备引用可查 | [x] `TestRuleDeleteRefusedWithSubscriptionName`、`TestSelectionUsedByNames`、`TestWizardMeshGroupRefusesRevokedDevice` |
| C | 真实 `sing-box check` 组合产物、真实双跳流量、Mihomo 固定版本门禁 | [x] 单测内真实 `sing-box 1.14.3` 通过（`TestWizardGateUsesRealSingBox`、`TestComposeSubscriptionRulesReachBothDocuments`，需 `MESHMUX_SINGBOX_TEST_BINARY`）；[ ] 真实双跳流量与 Mihomo 固定版本实测未含 |

## 订阅聚合重构（Task 5：授权迁移 —— 删除 `out_bindings`，Out ACL 改节点成员制）

本节登记“删除 `out_bindings` + 授权改节点成员制（Ruling R10）”的同 PR 原子切换证据。**C 级真机（现网 VPS、公网入口、客户端 App）仍未含**，只到 C-（真实内核 + loopback 拓扑）。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | 单一授权源（**Ruling R10：节点成员制**）：`DeriveOutAllowlist(out)` = 所有持有当前配对身份的 Line 地址并集；Line/Out 纳管即互通，身份吊销或删除即移除；无成员 = 显式空集（默认拒绝），不是省略键、不是错误 | [x] `TestOutAuthorization_DerivationIsNodeMembership`、`TestOutAuthorization_EnrollmentAddsEveryLine`、`TestOutAuthorization_EmptyMembershipIsDefaultDeny` |
| B | 订阅与 ACL 解耦：订阅创建/改选/暂停/恢复**不改变**派生集合、**不重发** Out 链、链参数逐字节不变 | [x] `TestOutAuthorization_SubscriptionNeverTouchesTheACL`（5 种变更逐项比对派生 + 修订数 + 链参数） |
| B | 迁移前后 ACL 字节一致：对“成员/吊销/传输移除/订阅选中/取消选中/暂停/删除”七种状态，派生 allowlist 与渲染 nft 字节与旧绑定派生的等价集合逐字节相同 | [x] `TestOutAuthorization_MigratedACLMatchesBindingBytes`（7 个子用例，含 `node.SameACLSourceSet` + `node.CompileACL` 字节比对） |
| B | 空成员拒绝：没有可授权 Line 时 Out 链携带 `[]`，渲染出的 nft 只有两条 drop 规则、无 accept；Line 自身仍是直连（`direct`）且不被 Out 门禁阻塞 | [x] `TestOutAuthorization_EmptyMembershipIsDefaultDeny` |
| B | **Out 彻底删除（Ruling R9）**：先清空 ACL 并读回，再删节点行 + `out_settings`（地址/link key）+ 候选/任务；被订阅引用时拒绝并列出订阅名；离线或链条在途时拒绝（409，本次不删任何内容）；删除后引用过它的 Line 按 fail-closed 重算 | [x] `TestOutDeleteManagementAPICleansTheRoute`、`TestOutDeleteRefusesALiveSubscriptionReference`、`TestOutDeleteRefusesWhenTheHostCannotDropItsGuard`、`TestOutAuthorization_BindingTableIsGone` |
| B | 表与读写路径删除：schema 14 删除 `out_bindings` 与索引；`/nodes/out/bind`、`/nodes/out/unbind` 返回 `OUT_BINDING_API_RETIRED`（410）并指向上位替代动作；`out_settings`/订阅边表保留 | [x] `TestOutAuthorization_BindingTableIsGone`、`TestOutBindingEndpointsAreRetired`、`TestOutPoolListsTransportAndSelection` |
| B | 服务端 Line 路由读派生结果：发布门禁、双读回、`OutEgressFacts`、AI 决策、节点页投影全部一致；选择 Out 只改客户端路由（不触发 Out 重发），被订阅引用的 Out 删除被拒（`OUT_REFERENCED_BY_SUBSCRIPTIONS` 并列出订阅名） | [x] `TestOutAuthorization_SelectingTheOutAuthorizesAndPublishes`、`TestOutAuthorization_DroppingTheSelectionKeepsTheACL`、`TestOutPreviewDerivesFromTheSubscription`、`TestSubscriberSyncFailsClosedWhenTheOutIsDeleted` |
| B | 无法验证的源 fail-closed：DNS 名 Line 不能进 allowlist（`LINE_EGRESS_UNVERIFIED`），派生报错而不是猜地址；派生顺序与选择顺序无关（链参数可比对） | [x] `TestOutAuthorization_UnverifiableLineFailsClosed`、`TestOutAuthorization_SourceOrderIsByteStable` |
| C- | 真实 sing-box 1.14.3 双跳：Out（SS 入站 `2022-blake3-aes-128-gcm`）+ Line（VLESS/REALITY 入站 + SS 出站 + AI 域名 route）+ 客户端 SOCKS，AI 域名请求真实走 Line→Out 到目标；两侧日志分别归属 `inbound/vless`→`outbound/shadowsocks[out]` 与 `inbound/shadowsocks`→`outbound/direct[direct]`；派生 guard 由真实 nftables 解析并安装到私有 netns | [x] `TestOutAuthorization_AIDoubleHopEndToEnd`（需 `MESHMUX_SINGBOX_TEST_BINARY`，loopback-only）；nft 在无 `CAP_NET_ADMIN`/netns 时显式 skip |
| C | 现网 VPS 双跳、公网入口、客户端 App 实际可用、Out 故障时的真实流量 drop | [ ] 未含；归 #12（`必须完成的真实用户闭环` 第 3/5 项） |

- [ ] **未含 C 级结论**：本节不证明任何真实流量、真机导入或现网发布成功；`queued` 回执不是已应用。#10 的 v1.0.0 闭环（`v1.0.0 必须完成的真实用户闭环` 第 3/5/7 项）由 #12 采集。

## 订阅聚合重构（Task 6：清理 —— 死代码删除 + 文档同步）

本节登记“删除零生产调用死代码 + `route_policies` client 层停写 + `exceptions`/`ssids` 显式拒绝（schema 17）”的证据。**不改变 Task 0-5/8 已合入的运行语义**；C 级真机仍归 #12。

| 层级 | 待验范围 | 状态 |
| --- | --- | --- |
| B | client 层停写：创建/改版/激活/撤销 client revision 均以 `POLICY_LAYER_RETIRED` 拒绝（store 与 HTTP 两个入口一致，HTTP 409 + next_action）；既有 client 行仍可读、可作发布预览，server 层读写不变 | [x] `TestClientLayerWritesAreRetired`、`TestPolicyWriteAPILifecycle`（4 个 client 写入口 409）、`TestPolicyWriteAPIRejectsBadRequests` |
| B | `exceptions`/`ssids` 显式拒绝：payload 含任一键（含空数组/null）即 `POLICY_PAYLOAD_RETIRED`，不再“写入成功但被忽略”；active 读取为严格解码，绕过迁移的旧键为 `POLICY_CORRUPT` | [x] `TestRetiredPolicyFieldsAreRejected`、`TestSchema17StripsRetiredPolicyFields` |
| B | schema 17 存量重写：只改含退役键的 payload，`default`/`rules`/`note` 保留，revision/status/时间戳与审计事件不变；已干净 payload 逐字节不变；重放幂等；不可逆时回退到升级前数据库备份 | [x] `TestSchema17StripsRetiredPolicyFields`（含 16→17、strict read、replay） |
| B | 死代码删除：只删已验证零生产调用且不在 Keep 清单的函数，连同其专属测试；`ResolveAIRuleset` 字节校验、`jsonAPI/jsonNamespace`、`compiler.Match.SSIDs` 保留；`render_v2`/Task 4/5/8 行为测试全部保留 | [x] 删除清单与复现命令见本 PR 描述（deadcode 前后 66→27 + 逐项 grep）；`make verify`（gofmt/vet/staticcheck/test/race/build）与 `go test ./...` 全绿 |
| B | 文档与契约同步：ARCHITECTURE 表清单/schema 17、FEATURES/UX 客户端层只读、ADR-0007 修订记录、受影响包 `doc.go` | [x] 本 PR 文档 diff |
| C | 现网旧库升级、真机客户端、发布后下载字节 | [ ] 未含：只有 schema fixture 与 loopback 单测；归 #12 |

## Issue #11 11d Hub 自升级验收（B 级；C 级归 #12）

本段只记录 **B 级 fixture** 证据：不触碰宿主 systemd、不装包、不下载真实发行资产、不覆盖真实公网或客户端握手。`v1.0.0` 的 Hub 自升级在 C 级隔离 VM/真机（#12）通过前不得宣称端到端可用。

| 能力（spec） | B 级证据 | 边界 |
| --- | --- | --- |
| per-op 备份、`keep=2`、指针与单飞（§5.2/§5.2.1） | `TestBackupPublishesPerOpThenPointer`、`TestBackupSingleFlight`、`TestLatestIsJournalBacked`、`TestGCKeepTwoConfirmed`、`TestGCNeverCollectsNewestOrStaged`、`TestConfirmCollectsConfirmedBeyondTwo`、`TestConfirmPointerFailureStillCollects`、`TestHubCleanupRejectsKeepBelowTwo` | 记录/载荷为临时目录 fixture；VACUUM 在测试 SQLite 上执行，非生产负载。指针刷新失败只记 `HUB_BACKUP_POINTER_STALE`；已发布但未 fsync 记 `HUB_BACKUP_POINTER_UNFLUSHED`，两者都不回滚确认/GC |
| 交接、对账、确认（§5.5） | `TestHandoffOrder`、`TestReconcileRestoredMarker`、`TestReconcileClaimSwappingNewBinary`、`TestReconcileClaimOldBinaryInert`、`TestApplyReceipt`、`TestNoSchema11`、`TestReadbackComparesVerifyingOpTarget` | `user_version` 固定 10；无 `hub_upgrade_operations` 表 |
| 版本绑定、pre-flight、Line 四 pin、claim（§5.6） | `TestUpdateVersionMismatchZeroWrite`、`TestUpdatePreflightTrial`、`TestApplyPrecheckNeedsFourPins`、`TestLineRepinAllOrNothing`、`TestClaimWrittenBeforeSwap`、`TestApplyResultBeforeRestart` | 通过 fixture ledger/agent.json 证明写集；未执行真实 `systemctl restart` |
| restore（§5.7） | `TestRestoreHappyPath`、`TestRestoreAcceptsStagedSource`、`TestRestoreRefusesPayloadDigestMismatch`、`TestRestoreRefusesForeignSchemaCopy`、`TestRestoreMissingOldPackage`、`TestRestoreRefusesCarriedRecordAsSource`、`TestRestoreUnitShapeInvalid`、`TestRestoreSecondRequestBusy`、`TestRestoreSpaceCheck`、`TestRestoreConsoleInvocation` | 副本为 fixture SQLite；`/healthz` 由注入 Probe 代表；chown 在测试 uid 下为同主 no-op |
| 不可逆 UX 与悬空文案（§5.11） | `TestHubUpgradePage`、`TestHubUpgradePageOffersHandoffForBackedUp`、`TestApproveHintPointsToHubUpgrade`、`TestRestoreReceipt`、`TestRestoreSecondRequestBusy`、`TestRestoreRejectsCarriedRecord` | 页面只渲染；不可逆确认位形状与拒绝路径有测试，真实迁移执行仍属目标版本 |
| D2 单元、watchdog、启动守卫、回滚禁 `.path` | `TestWebUnitWatchdogAndStartLimit`、`TestWatchdogHeartbeat`、`TestBootGuardStopsCrashLoop`、`TestRollbackDisablesHubDispatchPath`、`TestHubRuntimeDirsDeclaredWritable` | `systemd-analyze verify` 与真实 `WatchdogSec` kill 在 CI/VM 覆盖；本机跳过时如实记 skip |

### T7 文档收口（stable codes 与 spec 偏差）

- **LOSSY 位置**：`lossy=true` 与 `snapshot_at` 只存在于 `hub-upgrade/restored.json`（schema 1）和 `/tasks` 的 Hub 区块。**result schema 1 没有 `lossy` 字段**，不得声称 result 显示 LOSSY。
- **标记清除时机**：由**下一次对账 pass**（`internal/cli/hubupgrade/reconcile.go` 的 `clearSupersededMarker`，约 609-640 行）在见到新的已提交备份（journal `backed_up` 且 per-op 记录 `staged|confirmed` 可读）时清除；不是 backup producer 在提交瞬间清除。Web 停机期间标记会保留，这是有意的。
- **§5.5 偏差（记录在 T7 文档，不回写 spec）**：`HUB_BACKUP_STAGE_FAILED` 时 journal 保持 `backed_up`，不是 `failed`；只有 per-op 记录与载荷可复用、同一 `operation_id` 可重试。spec §5.5 的“任意失败 → 终态”不覆盖“尚未触碰主机、可安全重试”的暂存失败。
- **指针稳定码**：`HUB_BACKUP_POINTER_STALE`（未发布新指针）与 `HUB_BACKUP_POINTER_UNFLUSHED`（已发布但未 fsync）都只记录、不回滚确认与 GC。
- **活动数据目录**：恢复后的 `--data-dir` 是 `<原-data-dir>/restore-<op>-<unix>`；删除原目录会删除活动数据库（详见下方恢复警告）。

### 记录字节冻结的“替换等价”措辞（T1r carry）

T1r 删除 layout 后，`TestRecordByteCompatNodeAndHub` 不再比较同一目录下两种布局产生的两份文件；它用同一 `Spec`、`Now` 和 operation id，在两个 root 分别以 `PayloadTree` / `PayloadSingleDB` 写入，再比较两份 `record.json` 的字节。这是**替换等价**：唯一编码器 + 相同输入 ⇒ 相同字节。旧稿“同一路径出现两份逐字节相同的记录”的措辞与 per-op 布局不再成立，后续文档不得把它当作证据。

### root 控制台恢复：执行前摘要（强制）

在执行旧包前，root **必须先**从该操作的 per-op 记录读取 `from_agent_sha256`，并用 `sha256sum -c` 核对旧包字节。安装器只显式安装 `ca-certificates`/`fail2ban`/`nftables`/`python3-systemd`（见 `internal/cli/install/apply_shared.go`）；`grep`/`sha256sum`/`printf` 属于 Debian essential/coreutils，不能假设 `jq` 或 `python3` 一定存在。下列是固定形式（无新工具依赖）：

```sh
RECORD="<data-dir>/database-backup/<op32hex>/record.json"
FROM_SHA="$(grep -o '"from_agent_sha256":[[:space:]]*"[0-9a-f]\{64\}"' "$RECORD" | grep -o '[0-9a-f]\{64\}')"
[ "${#FROM_SHA}" -eq 64 ] || { echo "record has no from_agent_sha256" >&2; exit 1; }
printf '%s  %s\n' "$FROM_SHA" "<data-dir>/upgrade/meshmuxd-<from_version>-<arch>" | sha256sum -c -
```

摘要不符时**不要执行 restore**：执行体自己的 `/proc/self/exe` 自检发生在 exec 之后，无法保护 exec 本身；这与 RAUC/Mender 的 verify-then-exec 纪律、以及 dispatcher “边复制边哈希到 root-only `exec-<op>`” 的纪律一致——执行前摘要才是信任锚。若跳过此步，执行体仍会以 `HUB_RESTORE_DIGEST_MISMATCH`/`HUB_RESTORE_BINARY_MISSING` 拒绝，但坏字节已经获得一次 exec。

### root 控制台恢复 argv（逐字节）

下列 argv 由 root 直接执行，**不经 Web、不经请求目录**；`<...>` 由 journal/记录取值，执行体自身再校验 `/proc/self/exe` 摘要与旧包摘要。`--restore-dir` 必须是 `<data-dir>/restore-<op32hex>-<unix>`（执行体拒绝其它形状）。执行前提：journal 为 `failed`/`partial`/`verifying`，无待消费请求，`restored.json` 不存在，**且上面的执行前摘要已通过**。

<!-- hub-restore-console:start -->
```sh
/var/lib/meshmux/upgrade/meshmuxd-<from_version>-<arch> __internal-hub-restore --expected-sha256 <from_agent_sha256> --operation-id <op32hex> --data-dir <data-dir> --restore-dir <data-dir>/restore-<op32hex>-<unix>
```
<!-- hub-restore-console:end -->

从记录取值的对应关系：`from_version` = `record.from_version`，`from_agent_sha256` = `record.from_agent_sha256`（旧包摘要），`op32hex` = `journal.operation_id`，`data-dir` = 当前 Web 单元的 `--data-dir`，`unix` = 当前时间。**root 可直接运行，但 argv 中的摘要与路径必须与记录一致**；不一致会在停机前以 `HUB_RESTORE_BINARY_MISSING`/`HUB_RESTORE_DIGEST_MISMATCH`/`CONFIG_CONFLICT` 拒绝。

**恢复后的活动目录警告**：成功恢复后 Web 的 `--data-dir` 是 `<原-data-dir>/restore-<op32hex>-<unix>`，它仍在原 data-dir 内部。确认前不要删除原目录；确认后若直接删除原目录，会连同活动目录与正在使用的数据库一起删除。先把新目录移出并更新 drop-in（或确认不再需要旧目录后再整体清理），不要把“旧的失败目录”当成可随手删除的垃圾。

### root 投递恢复请求（无 Web 的替代路径）

若 root 希望由已启用的 path unit 执行旧包，可投递一份与 Web 相同形状的请求；文件必须是 `meshmux` 属主、0600，先落在未监视的 staging 目录再 rename：

```sh
umask 077
printf '%s\n' '{"schema":1,"kind":"restore","operation_id":"<op32hex>","data_dir":"<data-dir>"}' \
  > /run/meshmux-hub/staging/<op32hex>.json
chown meshmux:meshmux /run/meshmux-hub/staging/<op32hex>.json
mv /run/meshmux-hub/staging/<op32hex>.json /run/meshmux-hub/requests/<op32hex>.json
```

请求只表达“恢复这个冻结操作”；它不提供路径、目标、摘要或 argv。dispatcher 仍会重新校验 Web 单元的 `--data-dir`、journal 状态、记录、旧包摘要并生成冻结 argv。

### claim 与启动守卫行为

- claim 在换二进制**之前**写 `swapping`，四处 pin 全成后才置 `repinned` 并删除；`swapping` + running==target 的启动对账立即给 `HUB_SHARED_BINARY_REPIN_INCOMPLETE`，`swapping` + running==from 保持普通超时/`NOT_APPLIED`，`repinned` 惰性。restore 在 pin 还原后删除 claim；删除失败只留惰性残骸，不改变恢复事实。
- `BootGuard` 在 `/run/meshmux-hub/boot/boot-attempts.json` 记录同一版本 10 分钟内未达健康的启动；已有三次时下一次启动以 `HUB_UPGRADE_BOOT_CRASH_LOOP` 退出，`Listen` 成功后 `ClearBootAttempts` 清空。`StartLimitIntervalSec=300`/`StartLimitBurst=3` 是 systemd 侧的第二道闸。文件损坏按“无记录”重置，守卫不可用不阻止 Web 启动（可用性硬化，不是授权）。
- **systemd 会先于 BootGuard 挡住快速循环**：快速 crash loop 在 300s 内触发 `StartLimitBurst=3` 后，第 4 次启动会被 systemd 直接拒绝，二进制根本不运行，所以 `HUB_UPGRADE_BOOT_CRASH_LOOP` 通常只在**慢速/人工启动**（超出窗口或手动 `systemctl start`）时出现。这与 Kubernetes `CrashLoopBackOff` 的行业分工一致：快速循环由编排器/服务管理器的限流器观察并退避，进程内守卫补充“同一版本连续不健康”的语义，不能替代 systemd。**确定性拒绝也会消耗启动预算**：`SCHEMA_TOO_NEW` 在 BootGuard 之后发生并写入 `boot-attempts.json`；坏 flag 在 `parseConfig` 阶段即退出、不进入 BootGuard，但 systemd 的 `StartLimitBurst` 仍计一次启动。两者都不会自行恢复；不要重启循环，先修原因。恢复步骤按阻塞者选择：systemd 已限流 → `systemctl reset-failed meshmux-web.service`（必要时再 `systemctl start meshmux-web.service`）；启动能进入二进制但被 BootGuard 拒绝 → 删除 `/run/meshmux-hub/boot/boot-attempts.json`（一次干净的慢启动/人工修复后使用）；重启主机会清空 `/run` 并重置计数。

### 安装回滚与请求/result 目录

失败安装的 `rollbackManaged` 先 `systemctl disable --now meshmux-hub-dispatch.path`，再按快照恢复/删除两个 Hub dispatch 单元，避免半失败安装留下 root 武装面；repair 回滚在服务恢复后重新 `enable --now` 该 path。**请求/result 目录不参与受管文件回滚**：`/run/meshmux-hub/{requests,staging,boot}` 是 tmpfiles 拥有的 tmpfs 运行时树，`/var/lib/meshmux-installer/hub-upgrade/results/` 是 root 写、Web 只读的证据目录；回滚既不清空请求（可能仍属于上一次已安装的运行面），也不删除 result（它是执行事实，不是安装器文件）。需要人工清理时只删除本操作自己的请求文件或由 root 按操作编号处理 result。

### 明确未完成（C 级归 #12）

- 真实 Debian 13 amd64/arm64 上的 path unit/oneshot、`ReadWritePaths` EROFS/226、`chown -R root→meshmux`、真实 `/healthz` 轮询与 systemd 重启/watchdog kill。
- 真实 `VACUUM INTO` 并发负载、磁盘耗尽、断电/重启后的 claim 对账与恢复后 Caddy/Headscale 联通。
- 12e 的发布资产与 root manifest 预置/签名通道；在此之前生产 Hub 自升级只会得到 `MANIFEST_UNAVAILABLE`。
- 还原后的节点/订阅/客户端真实可用性，以及 `mixedVersionGate` 在真实混版本舰队上的行为。

## v1.0.0 必须完成的真实用户闭环

- [ ] Debian 13 新环境可执行 install hub|edge|out，单机 Hub+Line、Hub+Line、Hub+Line+Out 三种拓扑正常，Out 可选。
- [ ] Line/Out 只执行首次 install 即完成 HTTPS Agent 纳管；配置推送与 readback 正常；SSH 及 VLESS 自定义端口与 Fail2ban/nftables 匹配。
- [ ] 原生 sing-box 1.14.3 VLESS/REALITY 真握手；新 Line 被纳入选定聚合订阅；有 Out 的 AI 双跳、无 Out 直出、Out 故障 fail-closed 均实际验证。
- [ ] 通过 Web 创建/禁用/删除订阅、独立 Token 轮换及准确跨节点撤销；旧 URL 无法下载，已有本地客户端缓存的局限明确说明。
- [ ] 普通 sing-box/Mihomo 格式真实导入；至少 iOS 与 Android 各一个 sing-box 单 VPN 代理+Mesh 配置通过。
- [ ] Mesh-only 节点/子网路由可在无 Subscriber 情况下注册、批准路由、注销；NAS 设备路由能被远程客户端访问。
- [ ] Web 可编辑发布国内外 / AI / 服务端分流；客户端分流经规则库（六种匹配器，无 SSID），客户端层既有 revision 仅只读预览；规则/配置校验失败回退最后有效版本。
- [ ] Web 认证、SSH/Web 登录防爆破、Fail2ban 真正使用监听端口、Out 来源默认拒绝、密钥和订阅日志脱敏均通过测试。
- [ ] Web 统一升级 Hub/Line/Out：两版内部测试制品、固定 manifest/哈希/兼容范围、逐节点验证、Hub 自升级和断线/失败回退按 #11 通过隔离环境实测。
- [ ] 错误能定位 DNS、云安全组、监听、握手、授权、服务健康；配置应用半途失败可回退/重试，不报告虚假成功。
- [ ] 操作文档和受控恢复步骤完备，隔离三角色验证通过；才创建 v1.0.0 Release。

## 发行后

任意第三方运行时独立跨版本升级、系统发行版升级、实时用户配额和多 Out 智能容错不作为 v1.0.0 发版阻断项。**Web 全节点 MeshMux 程序及发行包中已验证兼容的组件升级属于 #11，必须在 v1.0.0 前验收。**
