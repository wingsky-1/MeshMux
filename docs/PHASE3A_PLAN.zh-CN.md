# Issue #7 Phase 3A 实施与验收计划

基线：`origin/main` `17c4e4c`（PR #18 已合入、#6 已关闭）。分支：`verify/issue7-sub-lifecycle`。以 Issue #7 本体为范围，逐 PR 验收；使用 merge commit 保留提交，不创建 Tag/Release。

## PR-A：独立模型、持久化与原生配置编译

- `internal/subscription` 定义 Subscriber、逐 Line Credential、Subscription Token 和既有 Node 的线路传输设置引用。展示名不参与稳定身份；UUID 为规范 UUIDv4，Token 为 36 字节安全随机数。
- 显式 SQLite schema 4：`subscribers`、`proxy_credentials`、`subscription_tokens`、`line_settings`；Token 仅存 SHA-256。UUID、REALITY 私钥需要用于重编译，保存在既有私有数据目录及数据库权限边界内，不承诺额外静态加密。
- 严格 `meshmux-node/v2` 承载 REALITY 与全量用户集；空用户合法。v1 的精确文档及编译结果保持兼容，baseline 仍可生成 v1。
- 固定 sing-box 1.14.3 编译直出配置。继续现有 check → stage → apply → readback，不改变 Agent allowlist、任务参数或 readback 字段。
- 既有配置 SHA-256 回读绑定完整用户集合，无需增加冗余用户摘要字段。v2 候选是秘密材料，仅走节点认证候选通道。

验收：主控 gofmt/vet/test/build/race；严格解码、迁移原子性、改名/Token 操作保持 UUID、精确移除及合法空用户；固定组件真实 check 与隔离 REALITY 正反握手；对应 head 的 L2/L3 结果。PR-A 不交付 Web 用户操作、公开下载或跨节点生命周期。

## PR-B：Web 生命周期、订阅输出与多 Line 收敛

- Web 配置线路端点、显示名及排序，创建用户并选择 Line，支持暂停、恢复、删除、独立 Token 轮换/撤销与重试。
- 生命周期意图先持久化；暂停/删除先使公开下载失效，再同步所有可能持有该用户 UUID 的 Line。保留删除墓碑与历史关联，直到 readback 确认精确撤销。
- 每条 Line 由所有活跃用户的选定凭据构建完整快照，避免误删他人。同步意图直接来自已持久化的用户状态与选线关系，在轮询、心跳和任务结束时重新比较完整配置；复用既有任务，不增加重复的进度模型或通用引擎。
- 离线、任务失败、回退及未匹配 readback 显式 pending/partial；重试使用新的任务操作 ID 和递增修订，传输重投保留原幂等标识。完成由精确候选哈希及凭据集合判定。
- 固定路由 `/subscription/{token}/sing-box.json` 和 `/subscription/{token}/mihomo.yaml`；独立订阅 Host 只开放 GET/HEAD 下载。无登录/IP/验证码限制，统一不存在响应；禁止路径穿越、查询和规范化重定向。
- 每次下载检查当前 Token、用户状态及线路收敛；两种输出来自同一受验证快照，保持确定排序与零 Out 直出。返回 private/no-store、noindex、no-referrer，日志只记录允许的操作编号与错误码。
- sing-box 1.14.3 与测试专用 Mihomo v1.19.32 真实导入生成配置，验证至少两条线路。Mihomo 固定官方来源和 SHA-256，amd64 使用兼容制品，不加入服务端发行包。

验收：两用户/两 Line 增停删、旧 URL 失效、缓存 UUID 撤销、删除最后一人、离线/半途失败与重试、并发旧任务不覆盖新意图、不泄漏他人凭据。浏览器验证手机布局及 Origin/CSRF。服务端配置错误保留 LKG，撤销回退不能标为完成。

## PR-C：Hub 兼任 Line

- 沿用已有 install edge 入口，固定共存配置，不增加用户管理 CLI。
- 独立本地 Line 安装台账，保留 Hub 台账与服务；共享 MeshMux 程序由 Hub 拥有，Line 校验并复用相同内容，拒绝不兼容覆盖。
- 保留全局安装锁；共存安装/repair/回退只能恢复所属受管状态，不破坏另一个角色。升级协调仍由 #11 单独实现。

验收：隔离 Debian 13 VM 的 Hub→Line 安装、repair、失败恢复及真实零 Out 代理生命周期；远程多 Line 与 Hub 本地 Line 均可纳入订阅。

## 证据与恢复边界

每个 PR 分别报告完成、未完成、测试结果、风险/回退和下一步。L1、Debian 13 容器组件验证、QEMU 全系统验证和真实客户端数据面证据分别记录，引用对应 head/tree，不互相替代。

迁移失败整体回滚；旧程序拒绝打开未来 schema，程序回退需配套数据库备份。配置回退保留服务可用性，但旧 UUID 可能仍获授权，撤销保持 partial。Token 轮换只阻止下载，不能使已缓存 UUID 失效。

不包含 Out 双跳/跨源 ACL、#8/#9/#11、Mesh Endpoint、精确计费/配额、外部订阅导入或通用适配器。真实公网、云安全组、ACME 和 iOS/Android 真机仅在实际执行后记证据；本轮协议握手仍须在隔离环境真实验证。不现网安装、清理、重启，不推版本 Tag。
