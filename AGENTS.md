# MeshMux — AI coding / contributor instructions

本文件是当前仓库开发约定。开始任务前按需阅读：`README.md`、`docs/PRODUCT.zh-CN.md`、`docs/FEATURES.zh-CN.md`、`docs/ARCHITECTURE.zh-CN.md`、`docs/SECURITY.zh-CN.md`、`docs/ACCEPTANCE.zh-CN.md`。仅阅读与本任务直接相关的 ADR；避免把整套文档作为每次微小改动的阻碍。

## 1. 产品边界与版本

- **首个公开稳定发行版是 `v1.0.0`，使用 SemVer 2.0.0。** 此前允许连续合并小范围 Issue/PR，但不默认发布 `0.x`；不得将 PR 编号/开发阶段误称为发行版。
- `v1.0.0` 必须闭环：Debian 13 宿主机 `install`、Hub / Line / 可选 Out 原生 sing-box 纳管、Headscale Mesh 设备/子网路由、订阅创建/删除、客户端/服务端分流配置，及这些能力必需的安全、日志与配置回退。
- **Out optional、Mesh-only 不需要代理订阅、Subscriber ≠ Mesh Device ≠ VLESS credential、Web-first** 均不可破坏。客户端 iOS/Android 只是平台模板差异；不要在模型中复制设备类型。
- CLI 面向用户仅有 `meshmux install`（可有受限选项）；后续管理通过 Hub Web。内部服务及救援机制不等同于用户管理 CLI。
- 自助全节点升级、第三方组件更新、严格实时用户配额、多 Out 容错、额外平台兼容性属于 **post-v1.0.0**，不要偷偷扩大当前 PR 范围。

## 2. Issue → PR → 合并：最小闭环

- **先确认目标 Issue**：列清功能范围、明确非目标、预期用户操作、验收标准、已知风险及关联文档。范围不清先更新 Issue；不要扩大到无关重构。
- **一个可验收的 PR 交付一个清晰能力**。PR 引用 Issue，描述行为变化、失败/恢复路径、影响文件、运行过的测试和真实联调证据；让用户能在手机端有效审阅。
- 为需求选择最小可维护实现。优先标准库及有维护的成熟库，先核查兼容性、许可证与安全维护状态；不要因为流行而引入框架、Redis、队列、插件机制、复杂接口层或新进程。
- 尽量保留小规模清晰模块、单一数据来源和简单错误路径。不做无关抽象、兼容尚不存在的历史数据、纯形式上的层层审批；遇到明确技术债要么在当前范围修复，要么记录新的 Issue。
- **必要工程基线**：gofmt、go vet、go test、go build；现有 CI 的 race 检测保留。只对高风险边界追加针对性安全/失败测试，避免冗余 Mock、重复覆盖、脆弱快照或过多 CI 门禁。
- PR 必须通过 CI 并获得明确验收后合并；别因单测通过声称 VPS/客户端端到端已完成。及时更新有关 README/FEATURES/ACCEPTANCE/ADR，移除过期分支和无用样例。
- 只在明确版本符合发行范围、自动化+隔离环境验收通过后创建 `v1.0.0` Tag/Release。后续向后兼容功能用 `1.x.0`，修复用 `1.x.y`，破坏兼容用 `2.0.0`；不覆盖发行 Tag。

## 3. 安全与运行边界

- 公开仓库使用 `example.invalid` / 文档 IP / 伪造凭据。不得提交或打印个人公网 IP、域名、Tailnet 拓扑、数据库、真实 Token、私钥、VLESS UUID、密钥或完整订阅 URL。
- Web 默认拒绝未认证访问，仅非 root loopback 监听，必须具备单管理员安全会话、CSRF/Origin 防护、登录限速、Fail2ban。SSH jail 使用真实监听端口；Cloudflare 代理场景禁止无依据封禁共享代理出口 IP。
- 订阅 Token 保持密码学随机、不可枚举和可撤销；不要对下载强加登录、固定 IP、验证码或复杂限速；日志不记录完整 URL。
- Agent 只执行明确列举的行为；不能支持任意 shell、路径、系统命令、外部 URL 或绕过配置校验。Out 入站默认拒绝非授权 Line。
- 每项可能影响运行状态的操作先 validate → stage → apply → readback；失败显式 partial/failed，并提供有限回退。配对凭据/任务修订和服务权限必须受到约束。
- **未经用户单独授权，不执行现网安装、清理、重启、迁移、Headscale 注销或发布有效订阅。** 开发和自动测试默认只操作隔离 fixture/VM。
- 当前 `cmd/meshmux` 安装占位程序故意返回非零、无副作用；实现可验收安装器前不得移除这种保护。

## 4. 日志与交付

- 错误返回明确 `operation_id`、阶段、稳定 `error_code`、建议动作；日志默认脱敏。区分“已安装/服务活跃/公网可达/真实协议握手/用户端可用”的证据级别。
- 涉及版本或外部二进制时固定来源、版本、校验和，禁用不受控的 `latest`；先验证 Debian 13 与目标架构。
- 回复和 PR 总结需要明确 **完成内容、未完成内容、测试结果、风险/回退、下一步**；不虚构测试或升级成功，不承诺后台工作。
