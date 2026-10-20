# ADR-0006：订阅身份、原生配置与撤销证据

状态：Proposed（Issue #7 实现中，未发布；验收证据待补齐）。

Subscriber、每个 Line 的 VLESS Credential、Node、Subscription Token 是独立身份。改展示名与排序不得改变 Node ID 或 UUID；下载 Token 使用至少 36 字节安全随机数，仅存哈希。Token 撤销立即阻止后续下载，但不会使已下载配置中的 UUID 失效。

暂停或删除先持久化用户状态并撤销公开下载权限，再向所有可能持有该用户凭据的 Line 同步完整期望用户集合。集合包含其他用户，不能以单用户操作覆盖整条 Line。离线、失败、回退或未完成 readback 均不能报告凭据撤销成功；保留 partial 与可重试状态。已下载配置在远端 UUID 撤销确认前可能仍可连接。

候选通过严格的 `meshmux-node/v2` 表达 REALITY 和逐线路用户；已有 v1 文档及编译结果保持不变，未知 schema 拒绝。v2 是秘密材料，仅通过节点认证候选通道传输，存入私有目录，不放入公开订阅、任务参数、诊断或日志。公开订阅只含相应客户端必需的 UUID、端点及公钥。

继续使用既有 `config.check → config.stage → config.apply → config.readback`，不扩展 Agent allowlist。每次发布不可变修订，配置错误保留 last-known-good；回退到旧凭据集合仍是撤销未完成，不能因服务恢复活跃而标记 healthy。完成证据绑定节点、修订、配置哈希和凭据集合。

首个 PR 交付模型、存储与编译器；后续 PR 交付 Web 生命周期、固定订阅下载路由、多 Line 收敛及 Hub 兼任 Line。零 Out 合法，只编译直接出口。不包含 AI Out 双跳/跨源 ACL、Mesh、精确计费、外部订阅导入或 #11 升级。

验收分别记录 L1、固定组件 check、隔离 Debian 13 VM 和真实客户端协议结果，不用 Mock 或服务监听替代握手。证据入口见 [验收标准](../ACCEPTANCE.zh-CN.md) 与 [Phase 3A 计划](../PHASE3A_PLAN.zh-CN.md)。
