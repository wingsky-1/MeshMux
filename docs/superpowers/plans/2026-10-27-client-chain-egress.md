# 客户端链式双跳设计（替代服务端双跳）

> 状态：已定方向。Out 不再黑暗；订阅自带出口凭据，客户端自己链两跳。
> 两条铁律：① 所有分流策略只在客户端生效，服务端 sing-box 不下发任何路由规则，只发布代理端口+校验凭据；
> ② UI 面向小白/非技术人员，只展示“纳管了什么、能做什么”，运维概念（revision/回读/门禁/allowlist/候选）一律不暴露。

## 1. 新模型一句话

订阅文档里直接带 Out 出口（SS 地址+link key / HTTP URL+凭据），客户端按规则把代理流量发给 Out、其余发给 Line。服务端只管发配置：Line 不再转发，不再有“同 Line 同 Out”约束，Out 不再限制来源 IP。

## 2. 各模块改动

### 订阅组装（core/subscription）
- `ComposeSubscription` 把选中 Out 的材料渲染进两份客户端文档：SS 出站（`tag=out`，server/port=Out 拨号地址，password=link key）/ HTTP 出站（现有逻辑保留）；proxy 动作映射到 `out` tag（确定性，不经 selector）。
- 删除 `renderLineRoute` 与 `LineRoutes` 产物（服务端不再需要；字段保留但不再填充，v1 后续版本删除）。
- 删除 same-Line-Out 校验调用；`COMPOSE_OUT_WITHOUT_PROXY_RULE` 保留（选了 Out 必须有 proxy 规则才有意义）。
- HTTP 代理路径不动（本来就是客户端链式）。

### 控制编排（control/store）
- 服务端职责冻结为两件事：发布代理端口（Line VLESS / Out SS），校验凭据（UUID / link key）。Line 候选只含 listener+用户集，不再含任何路由/出口/策略；`makeLineRouteFragment`/`buildLineRoutePlan`及服务端路由产物整个删除（字段保留置空，标注退役），不再下发到 Agent。
- 删除 `enforceSameLineOutTx` 调用及 `SUBSCRIPTION_OUT_CONFLICT` 产生路径（函数可删；impact 预览同步去掉该项）。
- **Out ACL 整个拿掉**：不再维护 `allowed_sources`/nft allowlist，Out 入站只认 SS link key（凭据即准入）。相关读回/门禁里引用 allowlist 的分支删除或恒 pass；nft `meshmux_out` 表不再写入（保留 table 定义注释说明已退役，避免C刀阔斧删表引发存量迁移问题——由实现 lane 决定删表还是留空表，二选一写进 PR）。
- Line 发布门禁不再看 Out；`OutEgressExternalDeclared` 保留（HTTP 本来就无控制器）。
- `DrainOutsForLine/RepublishOutAuthorizations` 与 Out 相关的联动保留（Out 自身变更仍重发），Line 侧不再订阅 Out 状态。

### Web（handler/view）——小白可用是验收线，分两步走
- 第一步（现在，只做 PC 简化）：删掉所有“同一 Line 必须选同一出口”文案与阻断提示；向导 Out 选择恢复为纯独立选项。
- 表达方式：用操作和按钮本身表达状态和信息，尽量减少常驻文本。实在需要的说明文字收进感叹号+悬浮（tooltip）里，不占版面。页面第一眼只有：是什么、在哪、通不通、能点什么。
- 运维信息独立成单独页面（如诊断/运维）：revision/回读/门禁/allowlist/候选/任务链只在该页展示，不耦合进节点/订阅/向导等业务页面。业务页保持小白可用，排障时再进运维页。
- Out 卡片保留“出口公开给订阅者、凭 key 接入”说明；删除确认页写清影响（所有引用它的订阅下次下载会变）。
- 第二步（后，PC 验收通过后再做）：响应式/移动端适配，小屏布局单列一轮，本轮不做。

## 3. 契约与安全边界

- Out link key 随订阅下发（bearer URL 保护，与 VLESS UUID 同级）。后果：Out 对全网可达，凭据泄露面从 Hub/Line 扩展到所有订阅者。
- 已知缺口（v1 接受，文档写明）：Out 凭据是单 key 多人共用；吊销单个订阅者不能立即断其 Out 访问（UUID 在 Line 侧已停，但 key 还在他手里），要断必须轮换 Out key（影响该 Out 全部订阅者）。per-user Out 凭据列为 post-v1.0。
- 字节必然变化：所有含 Out 的订阅 golden 重生成（预期变更，PR 里逐项列出）。

## 4. 验证

- `go test ./...` 全绿；golden diff 只含 Out 出站新增段。
- 真机：重建含 Out 订阅 → 下载 → 客户端走代理域名，出口 IP == Out 公网 IP；直连域名出口 IP == Line IP。
