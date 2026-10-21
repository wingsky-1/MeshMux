# ADR-0007：post-v1.0.0 领域占位包（mesh / route / jobs / compiler）

状态：Proposed（仅为占位，未引入任何实现；随 Issue #20 后续 PR 逐项评审）。

## 背景

当前 v1.0.0 的范围已由现有包覆盖：`internal/install` 负责特权安装，`internal/node` 固化主机布局与 sing-box 运行时契约，`internal/protocol` 冻结 Hub 与 Agent 的 v1 协议，`internal/subscription` 承载订阅者/凭据/Token 领域模型，`internal/web` 与 `internal/webcmd` 提供本地控制面。Issue #20 的后续能力（Mesh 设备生命周期、路由准入、跨节点任务、Hub 侧完整文档编译）尚未进入实现。

若这些能力在实现前各自临时命名，边界会在 PR 之间漂移，出现重复实体或第二个 Node 模型。因此在 `internal/` 下先建立四个空包，只写包注释与边界，作为评审锚点。

## 决策

新增四个只有 `doc.go` 的空包，包名与目录名一致，**均无可导出标识符、无外部引用、不参与任何调用路径**：

- `internal/mesh`：MeshDevice 领域（用途/平台分离、一次性入网 Key、Headscale Node ID、路由批准与在线证据）。
- `internal/route`：路由意图与准入（逐 Line 入站、可选 Out 双跳、零 Out 直连、按用户 ACL）。
- `internal/jobs`：跨请求的长任务记录（修订、阶段、`operation_id`、partial/failed 与重试语义）。
- `internal/compiler`：Hub 侧完整配置文档的确定性组装与配置哈希。

## 边界

- **mesh vs node 运行时**：`node` 描述 Line 主机上的 sing-box 目录、配置与 Agent 数据契约；`mesh` 只描述 Headscale 侧设备身份与入网状态。二者不互相定义实体，`mesh` 不执行 Agent 动作。
- **route vs 订阅分流**：订阅分流是把同一用户集合渲染成不同客户端所需文档的渲染选择；`route` 只表达连通性与准入，不渲染配置，不接触订阅 Token，也不定义 Out 安装/升级。
- **jobs vs 现有轮询**：当前 Web 在请求内直接调用节点并短轮询状态，没有执行器、队列或新进程。`jobs` 若被采纳，只是把既有阶段与稳定错误码固化为持久记录；不扩展 Agent allowlist，不支持任意 shell、路径或外部 URL。
- **compiler vs 候选渲染**：`node.CompileCandidate` 已负责把 `meshmux-node/v2` 候选规范化为节点本地配置。`compiler` 面向 Hub 侧完整文档组装，不复刻候选 schema，也不承担传输、落盘或 apply。

## 后果

- 占位包不得被 `cmd` 或其他 `internal` 包导入，避免以空壳提前固化 API；出现第一个真实调用方才提升为正式包并补充测试。
- 空包对构建、链接、二进制体积无影响，`go build ./...` 与 `gofmt` 必须保持通过。
- 任一能力进入实现前，须先以新 ADR 或本 ADR 的修订确认职责与失败路径；本 ADR 本身**不引入任何实现**，也不改变 v1.0.0 范围。

## 非目标

不包含跨源 ACL、精确计费、外部订阅导入、额外平台兼容性、通用任务引擎、`#8`/`#9`/`#11` 的具体实现，以及任何节点安装、重启或发布操作。
