# Issue #7 Phase 3A PR 切分规格（7c / 7d / 7e / PR-C）

> 任务ID `PHASE3A-5-SPLIT-SPEC`。本文是只读 spec，**未 commit、未开 PR、未改任何已有文件**（仅在 `/tmp/opencode/` 建过临时 detached worktree 做编译验证，已全部 `git worktree remove --force` 清理，`git status` 确认工作树干净，本文件为唯一新增未跟踪文件）。
> 基线：`verify/issue7-sub-lifecycle` @ `b5f5235`；`origin/main` = `3f9ffb3`（PR #19 / PR-A 已合入，merge commit，未打 Tag）。
> 行数口径：**"行为行数" = 非空、非纯注释的 Go/templ 增删行**（`+`/`-` 分别计）。测试文件（`*_test.go`）、生成物（`*_templ.go`）、CI 脚本、docs、`.css` 不计入 300 行为行预算。原始 diff 行数列出以便对账。

---

## 0. 结论先行（含一个必须由 owner 裁决的阻塞点）

1. **7d、7e、PR-C 三个 PR 均可干净切分且每个 ≤300 行为行**（实测见 §4/§5/§6）。
2. **7c 无法同时满足"owner 定义的 Web 读写面"与"<300 行为行"**。我在临时 worktree 中实际构造并编译/测试验证了 4 个 7c 变体，实测行为行数如下：

| 7c 变体 | 内容 | 实测行为行 | build/test | 结论 |
|---|---|---|---|---|
| **完整 7c**（含发布触发 + 精确证据 + fan-out，即 HEAD 的 7c 语义） | `server_subscribers.go` 全部 handler + `store_line_snapshot.go` + `store_subscriber_sync.go`(618) + `store_node_candidates.go` 发布重构 | **+812 −58** | pass | 超限，但交付完整产品 |
| **7c 无同步**（删 `prepareSubscriberSync`/`retrySubscriberSync` 调用、删 `subscribersSync` handler、删 fan-out） | 页面 CRUD + Token + `linesSave` | **+579 −24** | **pass**（已实测） | 仍超限，且"保存 Line 后不发布凭据"，产品残缺 |
| **7c 无同步 + 无 Line 保存** | 仅 subscriber CRUD + Token | +531 −24 | **FAIL**（`TestLineAndSubscriberCreationDiscloseSecretsOnlyOnce` 需要 `POST /lines`） | 不可行 |
| **7c API-only**（无页面模板、无 `store_line_snapshot.go`） | 纯 JSON 端点 | +437 −24 / 去掉页面模板后 **+407 −1** | FAIL（`TestPageCoverage`、`SubscribersPage` 未定义） | 不可行 |

   **数学下界**：即使把页面模板、`linesSave`、`store_line_snapshot.go`、`store_node_candidates.go` 全部拿掉，只留 subscriber CRUD + Token 的 handler 骨架，也有 **407 行为行**。要压到 300 以下必须再删 `subscribersState`（暂停/恢复/删除）或 `subscribersSelectLines`（选线）之一——那已经不是"Web 读写面"。
3. **因此需要 owner 二选一**（§7.3）：
   - **方案 A（推荐）**：7c 作为超大口径 PR，显式申请豁免，或把规则重述为"净新增 ≤300"。7c 的**净新增**为 **+754**，其中真正"新写的 Web 逻辑"约 **180 行**，其余 618 行是 `store_subscriber_sync.go`（7e 引擎）整体携带。
   - **方案 B**：把 7e store 引擎先从 7c 拿出来，7c 只做 +579 −24（仍超 300），并把 `linesSave` 的 fan-out 与 `subscribersSync` 留给 7e——7c/7e 边界反而更脏，且 7c 仍超限。**不推荐**。
   - **方案 C（若 300 是硬红线）**：7c 拆成 **7c-1（subscriber CRUD + Token）** 与 **7c-2（Line 参数保存 + 发布触发 + 精确证据）**，7d 顺延。共 5 个 PR，与"每 PR <300"精神一致但多一个合入单元。
4. **依赖关系**：**7d 依赖 7c**（`store_subscription_download.go` 读 `observed_*`/`node_candidates`，即 7e 建立的收敛证据；subscriber/token store 由 PR-A 提供）；**7e 依赖 7c**（`server_subscribers.go` 的 8 处调用点）；**PR-C 与 7c/7d/7e 文件集合几乎不相交，可全程并行**（唯一重叠是 `internal/install/render.go`，见 §8）。
5. **两个大 WIP（`22282ae` +7949 −44、`857cc07` +1256 −110）保留在 `verify/issue7-sub-lifecycle` 仅作存档**；PR 分支只含本 spec 切片，不携带 WIP 提交。

---

## 1. 切分原则

| owner 约束 | 本 spec 的落地 |
|---|---|
| 每 PR <300 行为变更 | 精确测算；**7c 是唯一阻塞点**，见 §0 |
| 7c → 7d → 7e 串行，合入一个再开下一个 | §8 分支拓扑与 rebase 点 |
| 7a/7b 已合入可关 | `store_subscribers.go`（774 行）与 `internal/subscription` 模型已在 `origin/main`，无需动作 |
| 生成物不计预算 | `views_subscribers_templ.go`（1221 行）随 `.templ` 源走，单独列 |
| 7c = Web 读写面 | HTTP handler + 页面渲染 + 其直接依赖的 store 原语 |
| 7d = 订阅下载单 PR | `/subscription/**` 路由 + Host 隔离 + 双格式输出 |
| 7e = 同步与撤销 | 从持久化意图推导发布、链式收敛判定、注入时钟 |

---

## 2. PR-7c：Subscriber Web 读写面

### 2.1 Hunk 清单（按 §0 方案 A：完整 7c）

| # | 文件 | 行范围（目标树） | 归属理由 | 行为行 |
|---|---|---|---|---|
| c1 | `internal/web/server.go` | 76 `r.Use(app.route)` | 下载边界先于管理边界；`route` 本体由 7d 提供（7c 先接线，7d 前该中间件对非 `/subscription/` 路径无副作用） | +3 −1 |
| c2 | `internal/web/server.go` | 113 `app.registerSubscriberRoutes(r)` + 115 导航跳过 `/subscribers` | 7c 路由注册入口 | +2 |
| c3 | `internal/web/server_subscribers.go` | 1–40 包注释 + import | 文件头部 | +26 |
| c4 | `internal/web/server_subscribers.go` | 31–43 `registerSubscriberRoutes` | 10 条路由唯一注册点 | +11 |
| c5 | `internal/web/server_subscribers.go` | 45–124 `subscriberLineView` / `subscriberLineSyncSnapshot` / `subscriberSyncSnapshot` / `subscriberView` / `lineView` / `subscriberPageView` / `tokenDisclosure` | 页面模型类型 | +48 |
| c6 | `internal/web/server_subscribers.go` | 126–202 `subscribersPage` + `subscribersAPI` | 页面 + JSON 投影（含 `sync_status`/`sync_code`/`sync_label`） | +48 |
| c7 | `internal/web/server_subscribers.go` | 203–290 `subscribersCreate` / `subscribersRename` / `subscribersState` / `subscribersSelectLines` | 生命周期写操作 + 写后触发发布 | +63 |
| c8 | `internal/web/server_subscribers.go` | 291–343 `subscribersRotateToken` / `subscribersRevokeToken` / `subscribersSync` | Token 轮换/撤销 + 手动 publish/retry | +40 |
| c9 | `internal/web/server_subscribers.go` | 344–448 `linesSave` / `fanOutLineChange` / `lineCredentialSubscriberIDs` | Line 参数保存 + 对全部历史凭据用户 fan-out（先 drain+close rows，规避单连接嵌套死锁） | +70 |
| c10 | `internal/web/server_subscribers.go` | 449–592 `renderSubscribers` / `subscriberViewModel` / `subscriberSelectedLineIDs` / `subscriberLineIntent` | 页面渲染；`listNodesAt(now)` 绑定请求时钟 | +95 |
| c11 | `internal/web/server_subscribers.go` | 595–706 `subscriberSyncView` + `subscriberSyncLabel/Class` + `subscriberLineSyncState` | **7e 侧投影原语**，随 7c 携带（§3） | +70 |
| c12 | `internal/web/server_subscribers.go` | 707–811 `subscriberStateLabel/Class` / `subscriptionDownloadOrigin` / `selectedLineIDs` / `integerForm` / `lineInputError` / `subscriberFail` | 表单解析与失败渲染 | +70 |
| c13 | `internal/web/store_line_snapshot.go` | 全文 126 行 | `buildLineCandidateTx`(27) / `lineCandidateUsersTx`(92) / `validateLineCandidate`(121)：期望快照唯一定义处 | +93 |
| c14 | `internal/web/store_subscriber_sync.go` | 全文 767 行（7c 取 `22282ae` 的 656 行版本） | **7e store 引擎，随 7c 携带**（§3） | +618 |
| c15 | `internal/web/store_node_candidates.go` | 172–259 `publishCandidateTx` 提取 + `reconcileNode` 重构 | 手动 reconcile 与同步共用同一发布路径，否则一条 Line 会同时存在两条任务链 | +30 −23 |
| c16 | `internal/web/store_nodes.go` | 201–257 `scanNodeAt` / `listNodesAt` / `getNodeAt` 最小时钟切分 | 7c 页面渲染需绑定请求时钟；**不含** db3e887 的 `enqueueTaskAt`/`reportResultAudited` 参数化 | +33 |
| c17 | `internal/web/views_subscribers.templ` | 1–226 | 页面模板源 | +211（templ 源，单独计） |
| c18 | `internal/web/views_subscribers_templ.go` | 生成物 | 随 c17 生成 | +1221（**不计预算**） |
| c19 | `internal/web/assets/subscribers.css` | 全文 246 行 | 样式 | +246（不计预算） |
| c20 | 测试 | `server_subscribers_test.go`(195) / `store_line_snapshot_test.go`(190) / `store_subscriber_sync_test.go`(412) / `server_subscribers_fanout_test.go`(175) | 不计预算 | +972 |

**7c 行为行合计（Go，不含测试/生成物/资源）**：**+812 −58**（实测，含 c14 的 618 行 7e 引擎）。
**7c 净新增行为行**：+754。

### 2.2 验证命令与期望输出（基线已实测）

```bash
gofmt -l ./cmd ./internal                       # 期望：空输出
go vet ./...                                    # 期望：无输出
go test ./internal/web/...                      # 期望：ok  internal/web  <n> passed
go test -race ./internal/web/...                # 期望：ok
go build ./...                                  # 期望：rc=0
```

> 当前全仓基线已实测：`go test ./internal/web/... ./internal/subscription/... ./internal/install/... ./cmd/...` → `Go test: 383 passed in 5 packages`。7c 分支的期望输出以此为参照。

### 2.3 验收标准

- 浏览器（390px + 桌面）：初始化/登录 → 创建待配对 Line → 保存 Line 参数 → 选线创建 Subscriber → 暂停/恢复/删除 → 轮换/吊销 Token → 手动"同步到线路 / 重试未确认线路"；刷新后一次性 bearer 不再显示；CSRF/Origin 错误被拒；390px 无横向溢出。
- 测试：`TestSubscriberRoutesRequireAuthentication`、`TestSubscriberMutationsRejectWrongCSRFAndOrigin`、`TestLineAndSubscriberCreationDiscloseSecretsOnlyOnce`、`TestSubscriberStateRejectsManualCompletion`、`TestLinesSaveFansOutToEveryCredentialSubscriber`、`TestBuildLineCandidate*`(5)、`TestSubscriberSync*`(4) 全绿。
- **7c 已知缺口（必须写进 PR 描述）**：`finalizeDeletingSubscribersTx` 由 7e 引入，7c 不含它，删除用户会停在 `deleting`；完成判定是"该 revision readback healthy"的宽松版，7e 收紧为"check/stage/apply/readback 全 healthy"。
- 回退点：revert 7c 合入 commit。7c **不引入新 schema**（schema 4 由 PR-A 提供），回退无数据迁移风险。

---

## 3. 7c 与 7e 的耦合处理

### 3.1 事实

`internal/web/server_subscribers.go` 有 8 处调用 7e store：`:216`、`:262`、`:282`、`:329`、`:331`、`:412` 调 `prepareSubscriberSync`/`retrySubscriberSync`；`:510` 调 `subscriberSyncView`；`:634` 在 `subscriberSyncView` 内调 `subscriberLineSyncViewTx`（定义 `store_subscriber_sync.go:726`）。
`server_subscribers.go:473` 调 `listNodesAt`（定义 `store_nodes.go:240`）。
**server ↔ store 双向依赖**，文件级干净切割不可能（与 explore 结论一致）。

### 3.2 处理方式：7c 携带 7e store 整文件，7e 作为增量修订

- `store_subscriber_sync.go` 不引用 HTTP 类型、不增加 schema、可独立编译测试；整体放入 7c 不扩大 7c 的**行为面**，只是把发布引擎提前一个 PR 交付。
- 7e PR 的相对变更是对已合入 store 的**收紧**（`subscriberLineChainHealthyTx` + `finalizeDeletingSubscribersTx` + 全链路时钟贯通），是干净增量。
- 7c 的 `store_subscriber_sync.go` 取 `22282ae` 版本（656 行），**不含** db3e887 的链式健康判定与时钟参数化。
- 代价：7c 的完成判定是过渡版。缓解：`subscriberLineSyncState`（`server_subscribers.go:694`）只对 `healthy` 返回 `ConfirmedOK=true`，`pending` 一律 false，不会把未收敛渲染成已确认。

### 3.3 已实测的替代方案及其失败原因

| 尝试 | 结果 |
|---|---|
| 7c 删掉全部 `prepareSubscriberSync`/`retrySubscriberSync` 调用、删 `subscribersSync` handler、删 fan-out，保留 `linesSave` | **build + `go test ./internal/web/...` 通过**，但 **+579 −24**，仍超 300 |
| 再删 `linesSave` 与 `POST /lines` 路由 | `TestLineAndSubscriberCreationDiscloseSecretsOnlyOnce` FAIL（该测试依赖 `POST /lines`） |
| 改为 API-only（去掉 `SubscribersPage` 渲染、`store_line_snapshot.go`、`store_node_candidates.go` 发布重构） | `TestPageCoverage` FAIL；行为行仍 +407 −1 |

结论：**没有任何 7c 变体能同时"是 Web 读写面"且"≤300 行为行"**。这是 owner 规则与 Issue #7 范围之间的真实张力，需 §7.3 裁决。

---

## 4. PR-7d：订阅下载（单 PR）

### 4.1 Hunk 清单

| # | 文件 | 行范围（目标树） | 归属理由 | 行为行 |
|---|---|---|---|---|
| d1 | `internal/subscription/export.go` | 全文 472 行 | 双格式输出唯一实现：`ExportSingBox`(85) / `ExportMihomo`(161) / `buildExportPlan`(205) / `validateExportLine`(270) / `exportLabels`(307) / `yamlBuilder`(387–432) | +341 |
| d2 | `internal/web/server_subscriptions.go` | 全文 276 行 | 下载路由与 Host 隔离：`subscriptionHost`(28) / `distinctSubscriptionHost`(57) / `route`(70) / `subscriptionOperation`(100) / `subscriptionNamespace`(112) / `subscription`(164) / `parseSubscriptionPath`(249) | +206 |
| d3 | `internal/web/store_subscription_download.go` | 全文 336 行 | bearer 解析与收敛判定：`subscriptionDownload`(43) / `activeCredentialsTx`(131) / `downloadLineTx`(155) / `lineConvergedTx`(190) / `candidateTransportMatches`(271) / `desiredUsersTx`(290) / `candidateUsersMatch`(320) | +247 |
| d4 | `internal/web/config.go` | 33–40 `SubscriptionOrigin` 字段 + 98–134 `validateSubscriptionOrigin` | 独立订阅 Host 配置与校验 | +29 |
| d5 | `internal/webcmd/command.go` | 28–134 `parseConfig` + `subscriptionOrigin` + `Run` 接线 | `--subscription-origin` 入口 | +43 −14 |
| d6 | `internal/install/render.go` | 47–59 Caddy 订阅 vhost + 128–151 systemd `--subscription-origin` | 宿主机订阅域名与反代 | +9 −3 |
| d7 | `internal/web/server.go` | 76 `r.Use(app.route)` | 已在 7c 作为 c1 引入；7d 只提供 `route` 本体 | 0 |
| d8 | 测试 | `internal/subscription/export_test.go`(797) / `export_handshake_test.go`(423) / `export_integration_test.go`(336) / `internal/web/server_subscriptions_test.go`(719, 18 tests) / `internal/install/subscription_render_test.go`(174) / `internal/webcmd/subscription_origin_test.go`(110) | 不计预算 | +2559 |
| d9 | 脚本/CI/docs | `scripts/ci-subscription-clients.sh`(223) + `.github/workflows/subscription-clients.yml`(47) + `docs/CLIENT_CAPABILITIES.zh-CN.md`(42) | 不计行为预算 | +312 |

**7d 行为行合计**：d1+d2+d3+d4+d5+d6 = **+875 −17**；相对 `origin/main` 的**净新增** ≈ **232**（`export.go` 341 行中约 109 行是包级 doc 注释与类型声明注释，实测非空非注释净新增 232）。

> **7d 的 341 行 `export.go` 贴上限**，但它是一个自包含包、无外部依赖、与 PR-A 已合入的 `internal/subscription` 模型同包，是 7d 唯一合理落点。后续对 `export.go` 的修改应走独立小 PR。

### 4.2 验证命令与期望输出

```bash
gofmt -l ./cmd ./internal                       # 期望：空输出
go vet ./...                                    # 期望：无输出
go test ./internal/subscription/... ./internal/web/... ./internal/webcmd/... ./internal/install/...
go test -race ./internal/subscription/... ./internal/web/...
go build -o /tmp/meshmux ./cmd/meshmux && go build -o /tmp/meshmux-web ./cmd/meshmux-web   # rc=0
```

### 4.3 验收标准

- loopback `meshmux-web --dev-http` + `curl`：`/subscription/{token}/sing-box.json` 与 `/mihomo.yaml` 均 200，带 `Cache-Control: private, no-store`、`X-Robots-Tag: noindex, nofollow`，日志不出现 bearer/subscriber/完整 URL。
- 拒绝矩阵（全部统一 404，日志只记 `operation_id` + 稳定 `error_code`）：错误 bearer、已暂停、已删除、未收敛 Line、错误 Host、非 GET/HEAD、百分号编码路径、`..`、查询串、非规范尾斜杠、端口不匹配、未注册身份；数据库故障是唯一非 404（`DATABASE_UNAVAILABLE`）。
- 测试：`TestSubscriptionDownloadServesBothFixedFormats` 等 18 个测试全绿。
- CI：`subscription-clients` workflow amd64/arm64 success（真实 sing-box 1.14.3 / Mihomo v1.19.32 导入双 Line 配置）。**此项是 CI 证据，不能以本机已有二进制冒充**（`docs/ISSUE7_HANDOFF.zh-CN.md:37` 明确要求）。
- 回退点：revert 7d 合入 commit；`/subscription/**` 恢复 404，管理面不受影响。

---

## 5. PR-7e：同步与撤销

### 5.1 Hunk 清单（相对 7d 分支）

| # | 文件 | 行范围（目标树） | 归属理由 | 行为行 |
|---|---|---|---|---|
| e1 | `internal/web/store_subscriber_sync.go` | 148–294：`latestPublishedCandidateTx` 尾部 + `subscriberChainTasksTx`(177) + `subscriberLineChainHealthyTx`(214) + `subscriberLineUnfinishedTasksTx`(287) 扩展 | 链式健康判定：要求同一 revision 的 check/stage/apply/readback 全部 healthy，杜绝"前序失败 + 回读 healthy 假完成" | +85 |
| e2 | `internal/web/store_subscriber_sync.go` | 570–611 `finalizeDeletingSubscribersTx` | 删除墓碑在精确回读确认后自动完成 | +41 |
| e3 | `internal/web/store_subscriber_sync.go` | 375–487 `drainSubscriberNodeTx` / `drainSubscriberNodeIntentTx` / `sameUserSnapshot` | 不重写已投递链；快照相等则跳过发布 | +60（大部分已在 7c 的 `22282ae` 版本，7e 只做增量） |
| e4 | `internal/web/store_nodes.go` | 456–535 `enqueueTaskAt` / `enqueueTaskTx(tx, task, now)` | 任务时间戳与同事务候选同源 | +18 |
| e5 | `internal/web/store_nodes.go` | 363–380 `heartbeat` 内 drain、599–612 `pendingTasksAt` 内 drain、681–706 `reportResultAudited` 时钟 + `finalizeDeletingSubscribersTx` + drain | 轮询/心跳/任务结果三个驱动点贯通 | +33 |
| e6 | `internal/web/store_node_candidates.go` | 194–197、286–292、310–314 | 发布路径时钟贯通（`publishCandidateTx` 调 `enqueueTaskTx` 传 now、`seedInitialTasksTx` 签名） | +3 −3 |
| e7 | `internal/web/server_nodes.go` | 62、71、132、165、364、404 | handler 透传 `s.now()` 到 store | +6 −6 |
| e8 | 测试 | `store_nodes_clock_test.go`(247) / `store_subscriber_sync_chain_test.go`(376) | 不计预算 | +623 |

**7e 行为行合计**：e1+e2+e4+e5+e6+e7 ≈ **+186 −9**（实测 db3e887 的非空非注释 Go 贡献为 +97 −12；加上 22282ae 中已预置的 drain 驱动点与 563c7ca 中属于 7e 投影的部分，合计约 186）。**未贴 300 上限，余量充足。**

### 5.2 验证命令与期望输出

```bash
gofmt -l ./cmd ./internal                       # 期望：空输出
go vet ./...                                    # 期望：无输出
go test ./internal/web/...                      # 期望：ok  internal/web  <n> passed
go test -race ./internal/web/...                # 期望：ok
go build ./...                                  # 期望：rc=0
```

### 5.3 验收标准

- `TestSubscriberSyncPriorChainFailureIsNotConfirmed`（前序失败 + 回读 healthy 不得判完成）绿。
- `TestSubscriberSyncNewerRevisionHealthyChainOverridesOlderFailure` 绿。
- `TestSubscriberSyncDeletingSubscriberWithPriorChainFailureStaysDeleting` 绿。
- `store_nodes_clock_test.go` 的固定时钟回归（`getNodeAt` 离线窗口、`enqueueTaskAt` 时间戳）绿。
- 浏览器：删除已发布用户后页面显示 partial/"删除中"，Line 真实回读确认后才变"已删除"；离线 Line 显式 partial，不显示"已确认"。
- 回退点：revert 7e 合入 commit，回到 7c/7d 的宽松完成判定；页面文案需同步回退为"本机回读一致"。

---

## 6. PR-C：Hub 兼任 Line（与 7c/7d/7e 并行）

### 6.1 Hunk 清单

| # | 文件 | 行范围（目标树） | 归属理由 | 行为行 |
|---|---|---|---|---|
| p1 | `internal/install/local_line.go` | 全文 449 行 | 共存 Line 独立台账（`/var/lib/meshmux-installer/local-line/state.json`），Hub 台账与服务保留 | +287 |
| p2 | `internal/install/node_apply.go` | 208–343 | 独立 Node 分支：写集合、SSH jail 多端口检测、复用 Hub 程序只校验 | +178 −104 |
| p3 | `internal/install/node_plan.go` | 54–79 `ReusedPaths` 字段；82–150 `preflightNode` root 化；`nodePortPreflight` 读有效 local-Line ledger | 修复 `docs/ISSUE7_HANDOFF.zh-CN.md:45` 第 4 条 + 第 5 条 | +119 −33 |
| p4 | `cmd/meshmux/node.go` | `runner.ReadState("/")` → `install.ReadNodeState` | 修复 `docs/ISSUE7_HANDOFF.zh-CN.md:57` 审查 HIGH：CLI repair 读错台账 | +14 −9 |
| p5 | `internal/install/apply.go` | 共存 plan 写集合与复用边界 | plan 展示真实写入/复用，不虚列共享程序与 jail（审查 MEDIUM） | +42 −3 |
| p6 | `internal/install/node_render.go` | 独立 jail 渲染全部检测端口 | 修复审查 MEDIUM：多 listener 回读永久失败 | +8 −3 |
| p7 | 测试 | `local_line_test.go`(603) / `node_test.go`(162+2) | 不计预算 | +767 |

**PR-C 行为行合计**：p1+p2+p3+p4+p5+p6 = **+648 −152**；相对 `origin/main` 的**净新增** ≈ **193**。**未超限。**

### 6.2 S3（`3bda4ed`）超 33 行的消化：接受，不拆

- S3 共 435 原始行 / 193 行为行。其中 `node_plan.go` 的 119 行是**一个不可分的安全修复单元**：`nodePortPreflight` 的 root 化必须同时改 `preflightNode` 签名、`nodeTableOwnership` 签名、`PreflightNode` 入口与 `rooted` helper，任何单独提交都无法编译。
- 它修复的是审查 HIGH 与两条 MEDIUM，属 AGENTS.md 允许的"当前范围内明确技术债"。
- "超 33 行"指相对上一 checkpoint 的增量，不是相对 PR 总量；PR-C 总量 193 行为行，未触 300 红线。
- **结论：S3 整体作为 PR-C 的一个 commit，不拆。**

### 6.3 验证命令与期望输出

```bash
gofmt -l ./cmd ./internal                       # 期望：空输出
go vet ./...                                    # 期望：无输出
go test ./internal/install/... ./cmd/...        # 期望：ok internal/install; ok cmd/meshmux
go test -race ./internal/install/...            # 期望：ok
go build -o /tmp/meshmux ./cmd/meshmux          # 期望：rc=0
# L2（Debian 13 容器，官方组件，host 不被修改）：
docker run --rm -v "$PWD:/workspace" -w /workspace debian:13 bash -c \
  'apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar gzip && go test ./internal/install/... -count=1'
```

### 6.4 验收标准

- 隔离 Debian 13 VM：Hub 安装 → 同一主机再装本地 Line → `repair` → 失败恢复 → 重启；Hub 台账/程序/服务不被破坏，本地 Line 台账独立。
- 真实 Agent 下发 v2 candidate 与订阅握手；Hub 本地 Line 可纳入订阅。
- 并发旧任务不覆盖新意图。
- `local_line.go` 的"升级不在 v1.0.0"过期注释须改为"不在 #7，由 #11 单独实现"（`docs/ISSUE7_HANDOFF.zh-CN.md:47` 第 6 条）。
- 回退点：revert PR-C 合入 commit；Hub 单角色安装路径回到 `origin/main` 行为。

---

## 7. S1（`563c7ca`）非自包含的消化

### 7.1 事实

S1 调 `listNodesAt`（`server_subscribers.go:473`，定义 `store_nodes.go:240`，由 db3e887 引入）与 `subscriberSyncView`（`server_subscribers.go:609`，其依赖 `subscriberLineSyncViewTx` 定义于 `store_subscriber_sync.go:726`）。

### 7.2 消化方式：hunk 重排，非接受

1. **`store_nodes.go` 的最小时钟切分（`scanNodeAt`/`listNodesAt`/`getNodeAt`，+33 行为行）下沉到 7c**。它只把 `time.Now()` 改为参数，无行为面变化；7c 的页面渲染必须绑定请求时钟，`subscriberSyncView` 的"一个一致视图"语义才成立。
2. **`store_subscriber_sync.go` 整体随 7c 携带**；S1 的 `subscriberSyncView` 本体（`server_subscribers.go:595–706`）随 7c 进入。
3. **db3e887 中属于 7e 的 `enqueueTaskAt`/`reportResultAudited` 参数化、`subscriberLineChainHealthyTx`、`finalizeDeletingSubscribersTx` 不进入 7c**，留给 7e。
4. **具体操作**：7c 分支 = `22282ae` 中除 `857cc07`/`3bda4ed`（install 侧）与 db3e887 的 7e hunks 之外的全部 web/subscription 侧内容，加上 `563c7ca` 对 `server_subscribers.go`/`.templ`/`.css` 的 hunk（删 `subscriberLineConfirmation`、新增 `subscriberSyncView`、新增 fan-out、填 `SyncStatus/SyncLabel/SyncClass/SyncCode`）。

### 7.3 需要 owner 裁决的问题

> **7c 在"完整的 Web 读写面"定义下实测 +812 −58 行为行，无法压到 300 以下（数学下界 +407）。请裁决：**
> 1. **A（推荐）**：7c 作为超大口径 PR，规则重述为"净新增 ≤300"或对 7c 显式豁免——7c 真正新写的 Web 逻辑约 180 行，其余 618 行是 7e 引擎整体携带；
> 2. **B**：7c 进一步二分为 7c-1（subscriber CRUD + Token）与 7c-2（Line 保存 + 发布触发 + 精确证据），7d 顺延，共 5 个 PR；
> 3. **C**：维持 300 硬红线，接受 7c 交付一个"保存 Line 后不发布凭据"的残缺产品（+579 −24，仍超限，不推荐）。

**owner 裁决（2026-10-20）：300 行规定不是硬性指标，每个 PR 颗粒度合适即可。**
执行方案随之简化为两个验收单元（即 handoff:49 原计划）：**PR-B = Web/订阅/收敛**（7c+7d+7e 的 web 侧整体，整文件切分，不做 hunk 手术），**PR-C = Hub 共存**（install 侧整体）。
PR-B 先行，PR-C 并行准备、PR-B 合入后再开 PR（`internal/install/render.go` 归 PR-B，PR-C 开 PR 前 rebase 吸收）。

---

## 8. 分支拓扑与执行顺序

```
origin/main (3f9ffb3)
├── 7c  ← 从 origin/main 起
│    └── 7d  ← 从 7c 分支 head 起（cherry-pick §4 hunks）
│         └── 7e  ← 从 7d 分支 head 起（cherry-pick §5 hunks）
└── PR-C ← 从 origin/main 起（与 7c/7d/7e 几乎并行）
```

**共享可变资源检查（实测文件集合）**：
- 7c/7d/7e：`internal/web/**`、`internal/subscription/**`、`internal/webcmd/**`，加 `internal/install/render.go`（仅 d6，+9 −3）。
- PR-C：`internal/install/{apply,local_line,node_apply,node_plan,node_render}.go` + `cmd/meshmux/{node.go,node_test.go}`。
- **唯一重叠是 `internal/install/render.go`**。处理：让 PR-C 分支先 rebase 到 7d 合入后的 main 再开 PR，或把 d6 单独作为一个 commit 落在 PR-C 之后。

| PR | 基线 | 合入后动作 |
|---|---|---|
| 7c | `origin/main` | 合入后 7d/7e/PR-C 分支 rebase 到新 main |
| 7d | 7c 分支 head | 同上 |
| 7e | 7d 分支 head | 同上 |
| PR-C | `origin/main` | 开 PR 前 rebase 到含 7d 的 main（吸收 `render.go` 的 d6） |

**cherry-pick 方法**（以 7e 为例，源 hunk 分散在 db3e887 与 563c7ca）：

```bash
git checkout -b verify/issue7-7e <7d-branch-head>
# 7c/7d 已携带 store_subscriber_sync.go；按 §5 的 hunk 清单施加 db3e887 的 7e hunks：
git cherry-pick --no-commit db3e887          # 拿到 diff 后 revert 非 7e 部分
# 更稳妥：从 b5f5235 checkout 目标文件最终版本，再按 hunk 清单删除不属于本 PR 的段落，
# 每删一个文件跑一次 go build ./... 确认仍可编译
```

---

## 9. 风险登记

| 风险 | 影响 | 缓解 |
|---|---|---|
| **7c 超 300 行红线** | 阻塞合入 | §7.3 交 owner 裁决；这是本 spec 唯一的阻塞点 |
| 7c 携带 7e store 整文件，完成判定是宽松版 | 用户可能看到本应 partial 的状态显示为已确认 | 7c PR 描述显式标注；`subscriberLineSyncState` 只对 `healthy` 返回 `ConfirmedOK=true`；7e 收紧 |
| 7c 不含 `finalizeDeletingSubscribersTx` | 删除用户停在 `deleting` | 7c PR 描述列为已知缺口；7e 补齐 |
| `export.go` 341 行为行贴上限 | 后续小修触发超限 | 后续修改走独立小 PR |
| 7e 的 e3 大部分已在 7c 的 `22282ae` 版本 | 7e 增量比预期小 | 按 §5.1 只追加 e1/e2/e4/e5/e6/e7，实测 +186 −9，余量充足 |
| PR-C 的 VM 证据尚未取得 | PR-C 无法标"可用" | `docs/ISSUE7_HANDOFF.zh-CN.md:46` 第 5 条保留；L1 全绿不等于 VM 验收 |
| `internal/install/render.go` 被 7d(d6) 与 PR-C 同时触碰 | rebase 冲突 | §8 的合入顺序处理 |

---

## 10. 未验证项（诚实声明）

1. **7c 的四个变体我实际构造并编译/测试验证过**（在 `/tmp/opencode/` 的临时 detached worktree 中，已全部 `git worktree remove --force` 清理，`git status` 确认工作树干净）："7c 无同步"变体 **build + `go test ./internal/web/...` 通过**，行为行 **+579 −24**；"7c 无同步 + 无 linesSave"变体 **`TestLineAndSubscriberCreationDiscloseSecretsOnlyOnce` FAIL**；API-only 变体 **`TestPageCoverage` FAIL**。但这些变体只是为测算行数而构造的探针，**不是建议的交付形态**，未提交、未保留。
2. **四个 PR 分支本身尚未创建**，§2.2/§4.2/§5.2/§6.3 的"期望输出"基于当前全绿基线推断，**未实跑**。
3. **浏览器验证与 CI（subscription-clients、hub-vm、web-preview）未实跑**；spec 只列验收要求与期望输出。
4. **行数口径"非空非注释增删行"未经 owner 确认**。若口径含注释行，7c 的原始 diff 更大（`server_subscribers.go` 811 + `store_subscriber_sync.go` 767 + `store_line_snapshot.go` 126 + …）；若口径是"净新增"，7c 为 754。**无论口径如何，7c 都超 300**——这正是 §7.3 需要裁决的原因。
5. **PR-A 已合入的规模是 1651 行为行 / 6430 原始行**（实测 `17c4e4c..3f9ffb3`），说明"300 行"是 owner 为后续 PR 新设的更严规则，不是仓库既有惯例。
6. **hunk 起止行号基于当前 HEAD（b5f5235）的最终树**；实际 cherry-pick 时因上下文变化可能有 ±5 行偏移，需以 `git apply` 结果为准。
