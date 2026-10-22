# NAS Tailnet 身份迁移与 subnet_router 重装/换机（Issue #9 PR-9d 设计）

**状态（2026-10-22）：设计稿，不是实现或验收声明。** 本文只定义 NAS 既有 Tailnet 身份迁移到 MeshMux 纳管的授权、旧身份处置、路由接管与失败回退，以及 `subnet_router` 重装/换机流程。当前代码没有迁移授权、迁移存储、迁移 Web 入口或外部控制面操作；本文不改变 9a/9b/9c 与 v1.0.0 的任何验收结论。真实 NAS、真实 tailnet 与跨网流量仍属 C 级证据，未执行。

## 1. 结论与范围

- **身份不能被“转移”。** Tailscale/Headscale 的节点身份由控制面签发并绑定该节点自己的 NodeKey；MeshMux 不读取、不导出、不复制 NAS 的 `tailscaled` 状态、NodeKey、旧 pre-auth key 或旧登录凭据。迁移的目标态始终是新的 MeshMux `MeshDevice` 与新的 Headscale Node ID。
- **同一时间只加入一个控制面。** 受支持的 NAS 形态是一台 `tailscaled` 加入一个控制面。本文的“保留旧身份”只表示旧控制面的节点记录/账号暂时不删除，不表示 NAS 同时双活，也不表示新旧 tailnet 可以互通。
- **迁移、重装、换机都是显式操作。** 创建 `subnet_router` 设备、签发一次性 Key、批准路由或页面上的普通“重新核对”都不构成迁移授权。
- **路由接管是逐节点批准集合的转移，不是 tailnet 合并。** 旧 tailnet 的用户、ACL、DNS、标签、路由批准和节点身份不会进入 MeshMux 的 Headscale；新节点必须重新声明并批准前缀。
- **不把既有节点直接 adoption。** 即使旧节点就在同一个 Headscale 中，9d 也不把 `nodes list` 里的节点直接绑定成 MeshMux `registered` 设备；它只作为待处置的旧身份。MeshMux 的 `registered` 仍必须来自 MeshMux 发起的入网并经观测到的 Node ID 确认。当前设备模型没有“停止纳管但保留节点”的非破坏性回退：adoption 的回退只能删除节点或留下无记录节点，都会破坏审计；若未来需要原地 adoption，必须另立设计并补该边界，不在本文隐式引入。
- **失败必须显式。** 沿用现有 `pending / applying / verifying / healthy / partial / failed / rolled_back` 语义与 `operation_id + stage + error_code + recovery` 返回；任何“已迁移”结论都必须有路由 readback 和旧身份处置证据。

### 1.1 术语

| 术语 | 含义 |
| --- | --- |
| 旧身份 | NAS 在旧控制面的节点记录与登录态，可能是同一 Headscale 的未纳管节点、另一个 Headscale，或官方 Tailscale。 |
| 目标设备 | 本次迁移新建的 MeshMux `MeshDevice`，用途必须为 `subnet_router`，拥有自己的 NodeName 与 Headscale Node ID。 |
| 迁移授权 | 一次性、显式、可审计的操作员决定，绑定旧身份、目标设备、路由集合和旧身份处置；不是长期开关，也不是设备属性。 |
| 路由接管 | 把旧节点上与目标集合相交的 approved 前缀撤销，再在目标节点上批准目标集合；不是复制旧 tailnet 的路由表。 |
| 保留 | 旧控制面中的节点/账号记录暂时不删除，作为有限窗口内的回退锚点；NAS 已退出该控制面。 |
| 注销 | 先清空旧节点批准，再 `expire`，确认后再 `delete`；删除不可逆。 |
| 外部控制面 | 官方 Tailscale 或其他不由本 Hub 管理的 Headscale；MeshMux 不集成其管理 API/凭据，只能记录操作员提供的人工证据。 |
| 原地纳管（adoption） | 把同一 Headscale 已有节点直接登记为 MeshMux 设备而不重新入网；9d 明确不做，见第 1、10 节。 |

## 2. 现有恢复语义（不重复定义）

本文不重新实现或改写以下已覆盖的恢复语义，只在其上增加身份迁移特有的授权与顺序。实现迁移时应复用这些边界。

| 主题 | 已覆盖的恢复语义 | 本文的关系 |
| --- | --- | --- |
| Hub 安装事务 | [INSTALL_HUB](INSTALL_HUB.zh-CN.md)：`--plan`、`validate → stage → apply → readback`、受管文件 `ManagedFiles` 台账、operation journal、`rolled_back` 与 `partial`；管理/订阅/Headscale 域名迁移不属于自动 repair。 | 迁移不重新定义安装回滚；沿用它的事务与证据格式。 |
| 状态与台账位置 | [ARCHITECTURE](ARCHITECTURE.zh-CN.md)：Hub SQLite 与 Headscale DB 的归属；installer `state.json` 与 `operations/<operation-id>/events.jsonl`；Agent identity/LKG 属动态路径，不作为普通静态 ledger 项。 | 迁移只新增授权/迁移证据，不改变这些路径的归属；不接管未记录文件。 |
| Node 安装与 repair | [INSTALL_NODE](INSTALL_NODE.zh-CN.md)：repair 优先复用持久 identity，失败返回 `PAIRING_REQUIRED`/`IDENTITY_MISSING`；不自动接管第三方文件或 nftables 表；`partial`/`failed` 非零退出。 | NAS 不是 Line/Out 安装路径；但“先验证、后应用、失败不假成功”的原则沿用。 |
| 运行时配置回退 | [INSTALL_NODE](INSTALL_NODE.zh-CN.md) 与 [ADR-0006](adr/0006-subscription-lifecycle.zh-CN.md)：只有有效 LKG 才尝试恢复，恢复后仍须严格 readback，失败保持 `partial`。 | 迁移不把“服务重启成功”当作身份或路由迁移成功。 |
| Hub SQLite 恢复 | [WEB_DEVELOPMENT](WEB_DEVELOPMENT.zh-CN.md)：只从可信备份恢复到新的私有目录，禁止把旧 WAL/SHM 混入或直接覆盖运行中的主库。 | 这是 Hub 数据灾难恢复，不是撤销一次 Headscale 节点删除的手段。 |
| Headscale/tailnet 事实 | [ARCHITECTURE](ARCHITECTURE.zh-CN.md) 与 [ENROLLMENT](ENROLLMENT.zh-CN.md)：Headscale 自有数据库保存 tailnet 事实；不得自动重置 Headscale 数据库、Docker/NAS Tailscale 身份；MeshMux 只保存 Node ID 引用和期望策略。 | 迁移只经固定本地 CLI 适配器操作同一 Headscale，不直接改其数据库。 |
| Mesh 设备生命周期 | [ADR-0004](adr/0004-mesh-device-model.zh-CN.md)：`pending/registered/revoking` 占用 NodeName，`expired/failed/revoked` 释放；`revoked` 终态；一次性 Key 15 分钟、仅存 SHA-256、每设备单活。 | 重装/换机直接复用该状态机，不新增第二套身份表。 |
| 路由批准与注销 | [ACCEPTANCE](ACCEPTANCE.zh-CN.md) 9b：批准按前缀显式执行；`SetApprovedRoutes`/`ClearApprovedRoutes` 后必须 readback；注销先清批准再 expire/delete，失败保持 `revoking`。 | 迁移的路由接管按同一顺序执行，不自动批准。 |

因此，下文只回答现有文档没有回答的问题：**谁授权迁移、旧身份何时保留或注销、旧/新节点的路由按什么顺序交接、在哪一步之后不能再回退。**

## 3. 迁移来源与能力边界

| 来源 | MeshMux 能观测 | 可执行的旧身份动作 | 迁移方式 |
| --- | --- | --- | --- |
| 同一 Headscale，未纳管节点 | `nodes list` 可见 Node ID、NodeName、用户、地址、available/approved/subnet 路由与在线状态。 | 经固定本地 CLI 适配器清空批准、`expire`、`delete`。 | 新建 MeshMux 设备（不直接绑定旧 Node ID）；NAS 退出旧节点后重新入网。旧节点可在验证窗口内保留。 |
| 外部 Headscale | 不能经本 Hub 适配器读取；只能使用操作员提供的人工证据。 | MeshMux 不能执行；由操作员在旧控制台处理。 | 新建设备并重新入网；旧控制面的移除只能人工完成并记录证据。 |
| 官方 Tailscale | 不能读取；MeshMux 不集成其管理 API/凭据。 | MeshMux 不能执行；由操作员在官方管理界面移除/登出。 | 同上；旧 NodeKey 与登录态不得导入。 |
| 已由 MeshMux 纳管 | 有 `MeshDevice`、Node ID 和路由记录。 | 走设备注销/重签流程。 | 不是身份迁移；按第 8 节重装/换机处理。 |

同一 Headscale 的旧节点虽然可观测，也不自动成为 MeshMux 设备：避免把操作员历史上手工创建的节点误标为“已纳管”，也避免在没有独立授权的情况下改变其路由和注销语义。

## 4. 独立迁移授权

### 4.1 独立性的含义

迁移授权必须同时满足：

1. **独立步骤**：与创建 `subnet_router`、声明前缀、签发一次性 Key、批准路由分开。管理员可以预先创建目标设备，但在授权前不得对旧身份做任何远端动作。
2. **独立操作 ID 与审计**：一次迁移一个 `operation_id`，记录授权人、时间、旧/新身份、旧身份处置、路由集合、证据快照和每阶段结果。设备创建或 Key 签发的事件不能替代迁移授权事件。
3. **一次性且有时效**：授权绑定本次操作并在完成、失败、放弃或证据变化后失效；不提供长期“允许迁移”开关，不把授权放在 URL、查询串或日志中。
4. **显式确认**：确认内容至少包含旧身份名称/来源、目标设备、旧身份处置和路由集合；不能用通用“继续”按钮代替。

### 4.2 授权至少记录的内容

| 字段 | 说明 |
| --- | --- |
| `operation_id` | 贯穿预检、入网、路由接管、旧身份处置与回退。 |
| 来源类型 | 同一 Headscale / 外部 Headscale / 官方 Tailscale。 |
| 旧控制面标识 | 同一 Headscale 使用固定本地适配器；外部只记录操作员声明的控制面名称，不保存凭据。示例域名可用 `headscale.example.invalid`。 |
| 旧节点证据 | Node ID（仅同一 Headscale 可观测）、NodeName、用户、最后观测时间、地址与路由集合；不记录 NodeKey、登录 token、pre-auth key。 |
| 目标设备 | `MeshDevice` ID、用途 `subnet_router`、目标 NodeName、绑定订阅用户（可空）。 |
| 目标路由集合 | 规范化 CIDR 前缀的完整集合；不支持默认路由/exit node。 |
| 旧身份处置 | 保留、先 expire 后 delete（可分阶段）或外部人工移除；是否允许删除必须单独确认。 |
| 路由处置 | 清空旧批准后重建，或仅接管相交前缀；未声明/未跟踪前缀的处置必须列出。 |
| 时间与负责人 | 维护窗口、授权时间、保留截止时间和负责人（若保留）。 |
| 证据快照 | 旧/新节点的 `nodes list` 观测时间与结果摘要；外部来源为人工证据记录。 |

旧身份若在同一 Headscale，迁移的写操作只允许通过固定适配器执行 `ClearApprovedRoutes`、`SetApprovedRoutes`、`ExpireNode`、`DeleteNode`，不得直接改 Headscale SQLite，也不得调用任意 shell。

### 4.3 预检（只读）

预检失败不写入任何设备、Key、路由或旧身份状态：

- 管理员已认证，迁移 mutation 受 CSRF/Origin 保护；并发迁移或同一设备的活动任务必须拒绝。
- 旧身份在授权快照后未发生变化；Node ID、NodeName、用户或路由集合变化时授权失效，必须重新授权。
- 目标设备状态允许入网：`pending` 或 `expired`；`registered`/`revoking`/`revoked`/`failed` 不得直接当作可重装状态。
- 同一 Headscale 的旧 Node ID 未被任何 `MeshDevice` 绑定，避免一个节点被两套设备记录管理；目标 NodeName 未被其他 `pending/registered/revoking` 设备占用。同一 Headscale 下还要用 `nodes list` 检查旧节点或其他节点是否仍占用该名字，MeshMux 的唯一约束只覆盖自己的设备记录，不能替代 Headscale 侧检查。
- 目标前缀已规范化：无主机位、非 `/0`、非 exit route；与任何其他节点已批准/已宣告前缀的冲突必须显式列出。与旧节点相交的前缀属于本次接管；与其他节点相交的前缀默认拒绝，除非授权明确指定接管对象。
- 旧节点上未跟踪的 approved 前缀已列入授权；不得在“清空旧批准”时静默清除未跟踪路由。
- 旧身份处置在当前能力内可执行：同一 Headscale 可 expire/delete；外部控制面只能人工执行，页面必须明确显示“未确认”，不能显示为已删除。
- 路由只以 Headscale 的 readback 为准；`available`/`served` 只是观测，不等于批准或真实转发。

### 4.4 阶段状态

迁移沿用既有阶段语义，不引入通用任务引擎：

`requested → preflighted → authorized → applying → verifying → completed | failed | partial | rolled_back`

授权在 `completed` 或操作员放弃后失效；`failed`/`partial` 的同一操作可在证据未变化时沿用原授权继续重试，但来源、目标或路由集合发生变化时必须重新授权并生成新的操作记录。

## 5. 旧身份注销/保留决策

旧身份处置必须在授权中明确，不能由“迁移成功”自动推导。

| 处置 | 含义 | 适用 | 回退/限制 |
| --- | --- | --- | --- |
| 保留（retain） | 旧控制面保留节点/账号记录；清空与新路由相交的旧批准；NAS 已退出旧控制面。 | 需要验证窗口回退；旧控制面仍可登录。 | 不能与新节点同时服务同一前缀；必须有截止时间和负责人；到期后仍应注销。 |
| 过期（expire） | 旧节点标记过期/登出，记录保留；批准先清空。 | 同一 Headscale，验证已通过但暂不删除。 | 不是无感恢复；重新加入需要重新认证/新 Key。 |
| 删除（delete） | 从旧控制面删除节点。 | 安全事件（设备丢失/凭据泄露）或验证完成后的最终清理。 | **不可逆**；同一 Headscale 的 Node ID 不能恢复；不得用恢复 Headscale 数据库来撤销。 |
| 外部人工移除 | 在官方 Tailscale/外部 Headscale 管理界面登出或删除。 | 外部控制面。 | MeshMux 不能执行或确认；只记录操作员证据，不能声称已远程删除。 |

默认顺序是**先保留、后注销**：目标节点完成注册、路由批准与 readback，且（在具备条件时）完成真实跨网验证后，才 expire/delete 旧身份。以下情况例外：

- **安全事件**：设备丢失、旧节点凭据可能泄露时，先撤销旧节点及其路由，再处理新身份；可用性让位于撤销。
- **Name/路由冲突**：旧节点仍占用目标 NodeName，或与新前缀相交且无法在旧节点上保留不相交集合时，必须先清空旧批准；若仍冲突，先 expire/delete 旧节点，再迁移。此时回退只能依赖旧控制面的重新认证，不能承诺自动恢复。
- **外部控制面**：MeshMux 只能要求操作员在旧控制台完成移除；在收到人工证据前，旧身份状态保持“未确认”。

保留的约束：

- “保留”不等于双活。NAS 不同时加入两个 tailnet；旧节点保持离线且不得保留与新节点相交的 approved 前缀。
- 保留旧身份不等于 NAS 仍持有旧 NodeKey；切换控制面或重装可能已覆盖本地状态，回退可能需要在旧控制面重新认证或新建节点，不能承诺无感恢复。
- 保留必须有截止时间和负责人；到期未处置应在审计/页面显示为待清理，但不得自动删除。
- 旧节点若保留，仍占用 Headscale 侧 NodeName；目标设备必须使用不同 NodeName，或在旧节点确认消失后再创建同名设备。
- 旧身份被保留不改变订阅用户、代理凭据或订阅 Token；撤销一台 Mesh 设备不影响 Subscriber（ADR-0004）。

## 6. 路由接管顺序

### 6.1 不变量

- 只有目标设备已观测到 Headscale Node ID（`registered`）后，才允许对其批准路由；`pending` 或仅创建 Key 不得批准。
- 批准按前缀显式执行；不允许默认路由 `/0`、exit node、带主机位前缀或任意前缀批量批准。
- 同一前缀不能同时由旧、新两个节点批准并服务。相交集合必须先撤销旧批准，再批准新节点；非相交集合可以按“先新后旧”减少中断，但仍需显式授权。
- 旧节点上未跟踪的 approved 前缀必须保留或由授权显式列出后清除；不得因为迁移而静默丢失。无法规范化的未跟踪项必须先人工确认，不能靠适配器报错后静默丢弃。
- `approved` 只证明控制面批准；`served`、真实跨网访问和客户端接受路由是另一层证据，不能混写。

### 6.2 同一 Headscale（可观测、可回退）

设旧节点当前 approved 集合为 `O`，目标声明集合为 `N`，相交集合为 `O ∩ N`。推荐顺序：

1. **授权与快照**：确认旧节点、`O`（含未跟踪项）、旧 NodeName、目标设备与 `N`；记录观测时间。
2. **创建目标设备**：旧节点仍占用名字时使用新的目标 NodeName；签发一次性 Key。此时不改变任何 Headscale 路由。
3. **目标入网**：NAS 退出旧控制面并加入 MeshMux 的 Headscale；观测到目标 Node ID，确认在线、目标 approved 为空、advertised 与 `N` 一致。若目标未注册，停止，旧节点保持原状。
4. **撤销旧节点相交批准**：对旧节点发送 `O \ N`；若差集为空则 `ClearApprovedRoutes`，否则 `SetApprovedRoutes`。readback 必须确认 `O ∩ N` 已消失，`O \ N` 仍在。失败则停止，不批准目标；尝试恢复 `O` 并报告 `partial`/`failed`。
5. **批准目标集合**：对目标节点发送“当前目标 approved ∪ `N`”；readback 必须包含 `N`，目标上已有的未跟踪项保留并记录 `MESH_ROUTE_UNTRACKED`；若未跟踪项无法在授权中归类或与 `N` 冲突，停止并报告冲突，不能静默清除。失败则先清空目标已批准项，再恢复旧节点 `O`；若目标清空失败，保持 fail closed，报告 `partial`，不恢复相交旧批准以免双节点同时服务。
6. **验证 served 与跨网**：用同一次 `nodes list` 记录目标 `available/approved/served`；真实 NAS 到远程客户端的跨网访问属于 C 级证据，不能由 readback 代替。
7. **处置旧身份**：目标路由确认后，按授权清空旧节点剩余批准并 `expire`，确认后再 `delete`，或按第 5 节保留。旧节点确认消失后，NodeName 才在 Headscale 侧释放。
8. **完成与审计**：记录目标 Node ID、路由集合、readback、旧身份最终状态、保留截止时间（如有）和所有 `operation_id`。没有 C 级证据时只能声明“本机/控制面已确认”，不能声明“跨网可用”。

在单 `tailscaled` 形态下，数据面中断从第 3 步 NAS 退出旧控制面开始；第 4–5 步是控制面批准顺序，不应被描述成零中断切换。

回退规则：

- 第 3 步失败：目标设备停在 `failed`/`revoking`；撤销未消费的 Key；旧节点完全不动。
- 第 4 步失败：不批准目标；重新观测并尝试恢复旧 `O`。恢复不完整即 `partial`，不得继续。
- 第 5 步失败：清目标、恢复旧 `O`；若恢复失败或目标清空失败，保持 fail closed，报告 `partial`。
- 第 7 步之前旧节点仍存在，路由回退有锚点；第 7 步 `delete` 之后不可逆，不能再用恢复 Headscale 数据库的方式回滚。

### 6.3 外部 Headscale / 官方 Tailscale（不可观测、非原子）

MeshMux 不能读取或修改外部控制面，因此不存在原子路由接管：

1. 授权并记录人工证据：旧控制面、旧 NodeName、旧路由集合、旧账号状态；明确这是外部操作，MeshMux 不执行旧控制面的路由命令。
2. 创建目标设备并签发 Key；目标入网前不批准任何路由。
3. 在 NAS 上退出旧控制面（旧节点离线，旧 tailnet 失去该子网路由），保留旧账号作为回退窗口。
4. NAS 加入 MeshMux Headscale；观测到目标 Node ID 后才批准 `N` 并 readback。
5. 完成跨网验证后，操作员在旧控制台登出/删除旧节点，并回填人工证据；未回填前旧身份状态为“未确认”。
6. 需要回退时：目标侧清空批准并撤销目标设备；NAS 重新登录旧控制面（若旧节点仍有效），旧控制面路由由操作员恢复。旧节点一旦在外部控制面删除，回退只能重新认证/新建旧侧节点，MeshMux 不承诺自动恢复。

外部来源没有“旧路由 readback”，因此不得把“新节点已批准”写成“旧 tailnet 已切换”；只能写“旧控制面移除待人工确认”。

### 6.4 非相交前缀

若 `N` 与旧节点 `O` 完全不相交，且没有其他节点冲突，可以先批准目标 `N`、验证 served，再撤销旧节点上的旧前缀并处置旧身份。此路径中断更小，但仍要求：

- 授权中明确 `O ∩ N = ∅`；
- 不把 `/0` 或 exit route 当作普通前缀；
- 旧节点最终仍按第 5 节处置，不能长期与新节点并存而不记录。

## 7. 失败与回退

| 阶段 | 可能的失败 | 必须的记录/动作 | 可回退性 |
| --- | --- | --- | --- |
| 授权/预检 | 缺授权、证据过期、Name/路由冲突、旧身份不可处置 | 不写任何状态；返回稳定拒绝码与冲突项；要求重新授权。 | 完全回退（未发生变更）。 |
| 目标创建/Key | Key 签发失败、设备创建后 Key 失败 | 保留设备记录并显示可重签；不消费旧 Key；不触碰旧身份。 | 撤销 Key/目标设备即可。 |
| 目标入网 | NAS 未注册、观测不到 Node ID、Key 过期 | 目标保持 `pending`/`failed`/`revoking`；撤销未消费 Key；旧身份不动；不得批准路由。 | 旧节点仍可继续服务；清理目标后重试。 |
| 撤销旧批准 | 命令失败、readback 与 `O \ N` 不一致 | 停止，不批准目标；尝试恢复 `O`；记录旧节点实际批准集合。 | 旧节点仍在，可恢复批准；恢复失败为 `partial`。 |
| 批准目标 | 命令失败、readback 缺前缀、出现未授权前缀 | 先清目标已批准项，再恢复旧 `O`；未授权前缀保留并审计/拒绝；不得声称成功。 | 旧节点仍在时可回退；目标清空失败则 fail closed。 |
| served/跨网验证 | 目标不转发、客户端不可达 | 保留证据；按授权回退路由或标记 `failed`/`partial`；不把控制面批准当作流量成功。 | 旧节点未删除时可回退；外部控制面需人工。 |
| 旧身份 expire/delete | 删除失败、状态仍 `revoking`、外部控制台未确认 | 保持 `revoking`/“未确认”，可重试；不得创建第二个同身份设备。 | expire 后需重新认证；delete 后不可逆。 |
| 回退本身 | 旧批准恢复失败、目标清空失败、旧节点已删除 | 报告 `partial`，列出未恢复的批准/节点/证据；保持 fail closed；不得提升为 `healthy`。 | 可能需要人工或新的迁移。 |

强制规则：

- **`rolled_back` 只在目标身份已清理、旧批准集合已按 readback 恢复、旧节点仍可用时成立。** 任一条件不满足就是 `partial` 或 `failed`。
- **不自动恢复 Headscale 数据库。** 用数据库快照回退节点删除会丢失快照之后的 tailnet 状态，属于灾难恢复，不是迁移回退。
- **不把“旧节点已保留”当成回退成功。** 还必须确认 NAS 能重新登录、旧路由能恢复；外部控制面由操作员完成。
- **失败后不自动新建第二个目标设备或重复 Key。** 先清理 `pending`/`revoking`/`failed` 目标，再决定重试或新建设备。
- 任何失败都返回 `operation_id`、阶段、稳定 `error_code`、目标/旧节点标识、计划与实际路由集合和恢复建议；日志不记录 Key 明文、NodeKey、登录 token、完整订阅 URL。

## 8. subnet_router 重装/换机

### 8.1 状态与动作

重装/换机必须先观测 Headscale 与本地状态，不能只相信 NAS 磁盘上的旧文件。

| 设备状态 | Headscale 节点是否存在 | 是否占用 NodeName | 能否直接重签 | 推荐动作 |
| --- | --- | --- | --- | --- |
| `pending` | 无 | 是 | 是 | 撤销未消费 Key，签发新 Key；换机则先注销该设备再新建。 |
| `registered` | 是 | 是 | 否 | 先撤销/删除旧节点（清路由 → expire → delete）；或新建设备用新名字并行接管后再撤销旧设备。 |
| `expired` | 已确认不存在 | 否（已释放） | 是（`expired → pending`） | 重签并重新入网；旧 Node ID 只保留审计，不复用。 |
| `failed` | 无 | 否（已释放） | 否 | 只能走 `failed → revoking → revoked` 清理，再新建记录；不能直接 rekey。 |
| `revoking` | 可能仍存在 | 是 | 否 | 重试远端删除直到 `revoked`；期间不得复用名字或新建同名设备。 |
| `revoked` | 已确认不存在 | 否（终态释放） | 否 | 新建 `subnet_router` 设备并重新入网；旧记录不可复活。 |

`registered` 不能签发第二个一次性 Key；`failed`/`revoked` 不能通过 rekey 复活。状态迁移仍以 `internal/mesh` 的领域规则为准：`revoked` 是唯一终态，`revoking` 只能由确认删除收敛。

### 8.2 同一台 NAS 重装

- **本地 Tailscale 身份仍有效且 Headscale 节点仍是同一个**：不要创建新设备或新 Key；先“重新核对”确认 Node ID、在线状态和路由观测，再按现有设备继续。重装不应制造重复身份。
- **本地身份丢失，但旧节点仍在 Headscale**：不要直接签第二把 Key。先执行旧设备注销（清空批准 → expire → delete，直到 `revoked`），或按授权用新名字新建设备、完成路由接管后再注销旧设备。旧节点删除前，NodeName 仍被占用。
- **旧节点已被 Headscale 确认消失**：重新核对把 `registered` 收敛为 `expired`；对 `expired` 执行 rekey（`expired → pending`），签发新 Key，重新入网，再显式批准路由。旧 Node ID 不复用。
- **旧设备是 `failed`**：没有可用的 Headscale 节点，不能 rekey；先注销收敛到 `revoked`，再新建设备。`failed` 已释放 NodeName，但重试入网是新的设备记录。
- **旧设备是 `revoking`**：先重试注销；不要把 `revoking` 当成已删除，也不要在旧节点可能仍存在时复用其名字。

### 8.3 换机

1. **授权换机**：明确旧设备、旧 NodeName、目标是否沿用旧名、旧身份处置（保留/注销）和目标路由集合。换机是身份变更，不是普通编辑。
2. **处置旧设备**：优先 `registered/revoking` 的显式注销，顺序固定为清空批准 → `expire` → `delete` → 确认 `revoked`。安全事件（丢失/被盗）必须先撤销，不等待新设备。
3. **释放名字**：只有旧设备进入 `expired`/`revoked`，且 Headscale `nodes list` 确认旧节点不存在后，旧 NodeName 才可用于新设备。`failed` 也释放名字，但它从未有节点；`revoking` 不释放。
4. **创建新设备**：用途 `subnet_router`，声明完整目标前缀；签发一次性 Key。若无法沿用旧名，记录实际分配名与旧名映射，不把自动后缀/换名写成“同名迁移成功”。
5. **入网并观测**：新设备 `pending → registered` 必须由观测到的 Headscale Node ID 确认；未确认前不批准路由。
6. **重新批准路由**：旧路由批准不随设备记录或 NodeName 自动转移；对新 Node ID 逐前缀批准、readback，并记录 served 证据。
7. **完成审计**：旧设备记录保留为 `revoked` 历史；订阅用户/凭据/Token 不因换机被删除；旧身份如保留，记录截止时间与负责人。

### 8.4 NodeName 释放与“重签”

- **占用规则**：`pending`、`registered`、`revoking` 占用 NodeName；`expired`、`failed`、`revoked` 释放。`expired` 表示 Headscale 已确认节点消失；`failed` 表示从未有节点；`revoked` 表示删除已确认。`revoking` 只表示删除请求已记录，不能释放。注意 `failed` 的注销会先进入 `revoking` 并重新占用名字，因此要复用旧名应先收敛到 `revoked` 再创建同名设备；`expired` 重新入网会进入 `pending` 并重新占用名字，若名字已被其他设备占用则返回 `MESH_NODE_NAME_DUPLICATE`，不得静默换名。
- **本地与远端两层检查**：MeshMux 唯一索引只覆盖自己的设备记录；Headscale 可能仍有未纳管或外部旧节点。迁移/换机必须同时检查 `nodes list`，不能只凭本地状态复用名字。
- **“重签”**：只用于 `pending` 或 `expired` 设备。`pending` 撤销未消费 Key 后签发新 Key；`expired` 先 `expired → pending`（清除旧 Node ID 引用）再签发。每台设备同时只有一把 live Key，窗口 15 分钟，Key 只存 SHA-256；`consumed`/`expired`/`revoked` 均不可复用。
- **不是旧 tailnet 的 auth key**：MeshMux 的一次性入网 Key 与 Headscale pre-auth key 是不同层；9d 不复用 NAS 旧控制面的 auth key，也不把旧 NodeKey 写进任何配置或日志。真实 Headscale pre-auth key 由入网消费端点按固定适配器签发；该消费端点的实现仍属后续切片，本文不声称已存在。
- **路由不随名字转移**：即使新设备得到与旧设备相同的 NodeName，它仍是新的 Node ID，必须重新批准路由；旧批准只属于旧节点。

## 9. 证据与验收边界

| 层级 | 9d 需要证明 | 当前状态 |
| --- | --- | --- |
| A | 本文的授权、旧身份处置、路由顺序、失败回退和重装/换机矩阵经设计评审；与 9a/9b 领域规则一致。 | 设计稿；未评审为完成。 |
| B | 自动化覆盖：无授权拒绝、证据变化失效、Name/路由冲突、路由交接受阻时恢复旧集合、目标清理失败时 fail closed、`expired → pending` 与 `failed/revoked` 不可 rekey、日志无秘密。 | 未实现、未测试；不得写成已通过。 |
| C | 隔离 Debian 13 Hub + 真实 NAS（同一 Headscale 与外部/官方控制面各至少一例）+ 远程客户端：真实入网、advertise/approve/readback、跨网访问、重装/换机、失败注入与回退。 | 未执行；属后续真机验收。 |

迁移完成的证据至少包括：目标 Node ID 与在线观测、完整路由集合的 approved readback、`served` 观测、旧身份最终状态（保留截止/ revoked/外部人工确认）、所有 `operation_id` 与失败阶段。没有 C 级流量证据时只能声明控制面与本机已确认，不能声明“NAS 网段已可被远程客户端访问”。

## 10. 明确不做

- **不自动迁移**：不扫描 NAS、不自动发现旧 Tailscale/Headscale 登录态、不自动把 `nodes list` 中的节点变成 MeshDevice、不自动签发 Key、不自动登出旧控制面、不自动注销旧节点或自动批准路由。所有迁移和重装/换机都必须有独立授权。
- **不做跨 tailnet 合并**：不合并用户、ACL、DNS、标签、节点身份、路由批准或订阅；不把一个 tailnet 的路由“导入”另一个；不支持一台 NAS 同时归属两个 tailnet 或双活服务同一前缀。旧 tailnet 保留时仍是独立网络，不属于 MeshMux。
- **不导入身份材料**：不读取、导出、复制或持久化旧 NodeKey、`tailscaled` state、旧 pre-auth key、登录 token 或控制面凭据；不接受“沿用旧 Node ID”的迁移。
- **不自动处置旧身份**：不自动 expire/delete，不在外部控制面代替操作员操作，不把未确认的外部移除显示为已删除。
- **不自动批准/迁移任意前缀**：不批准 `/0`、exit node、带主机位前缀或未在授权中列出的前缀；不静默清除旧节点未跟踪的 approved 前缀。
- **不承诺零中断或自动回退**：不实现双归属、HA 路由切换或无损身份转移；旧节点删除、外部控制面移除和 Headscale 数据库恢复都不在自动回退范围。
- **不迁移订阅/客户端配置**：本文只处理 Mesh 身份与子网路由；订阅 Token、代理凭据、客户端 sing-box 配置（9c）不在迁移范围。
- **不新增通用能力**：不引入通用任务引擎、任意 shell/URL、用户侧迁移 CLI 或任意 Headscale 命令；仍只经固定 Web 操作与固定本地适配器。
- **不改变设备模型**：`nas` 仍只是展示平台，不是身份或状态机输入；不因 NAS 场景复制平台类型或新增第二套设备表。

## 11. 关联文档

- [纳管、安装与状态收敛时序](ENROLLMENT.zh-CN.md)
- [架构与数据边界](ARCHITECTURE.zh-CN.md)
- [Hub 安装器](INSTALL_HUB.zh-CN.md)
- [Line/Out 安装、纳管与恢复](INSTALL_NODE.zh-CN.md)
- [安全设计](SECURITY.zh-CN.md)
- [Web 安全基座、SQLite 备份与离线恢复](WEB_DEVELOPMENT.zh-CN.md)
- [ADR-0004：设备用途与平台分离](adr/0004-mesh-device-model.zh-CN.md)
- [ADR-0006：订阅生命周期与 LKG](adr/0006-subscription-lifecycle.zh-CN.md)
- [验收标准](ACCEPTANCE.zh-CN.md)
