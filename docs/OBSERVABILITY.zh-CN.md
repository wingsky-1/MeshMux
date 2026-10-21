# 统一日志与可诊断性

目标：管理员在 Web 中能看到“哪里失败、为什么、应该检查哪一层”，不需要凭猜测多次重装 VPS。

## 事件合同

每个安装、配对、发布、删除、升级任务都有全局唯一 operation_id。Hub、Agent、systemd 适配、外部探测都记录时间（UTC）、severity、stage、node_id、operation_id、config_revision、release_sha、error_code、message（脱敏），以及受限的 next_action。不得记录完整命令行中的配对凭据。

| 稳定错误码 | 归因层 | 首选排查 |
| --- | --- | --- |
| PREFLIGHT_OS_UNSUPPORTED | 环境 | Debian / arch 基线 |
| PREFLIGHT_PORT_IN_USE | 环境 | 实际监听/端口冲突 |
| SSH_LISTENER_MISMATCH | 系统 | sshd -T、systemd socket、Fail2ban 端口 |
| DNS_RESOLUTION_FAILED | 网络 | DNS 与 A/AAAA |
| ARTIFACT_CHECKSUM_MISMATCH | 供应链 | manifest/来源验证 |
| AGENT_PAIRING_REJECTED | 鉴权 | code 失效、Hub 身份/TLS |
| CONFIG_VALIDATION_FAILED | 代理配置 | sing-box check 日志 |
| PUBLIC_PORT_UNREACHABLE | 公网入口 | 本机监听 vs 云侧安全组 |
| OUT_ACL_UNATTESTED | Out 授权 | 来源集合/远端 ACL 状态 |
| PROXY_HANDSHAKE_FAILED | 协议 | REALITY 参数、网络路径 |
| HEADSCALE_REGISTRATION_FAILED | Mesh | Key/控制 URL/Headscale 服务 |
| SUBNET_ROUTE_NOT_APPROVED | Mesh | 子网路由审批/通告 |
| RELEASE_PARTIAL | 分布式任务 | 失败节点列表 + 重试入口 |
| ROLLBACK_FAILED | 恢复 | 人工恢复说明和备份位置 |

### Issue #8 Out 授权 / 同步 / AI 出口（新增，上表行不变）

| 稳定错误码 | 归因层 | 首选排查 |
| --- | --- | --- |
| OUT_ACL_SOURCE_MISMATCH | Out 授权 | Out 已应用集合与 Hub 授权集合不一致（退役→重验的预期过渡，需显式重试） |
| OUT_ALLOWLIST_INVALID | Out 授权 | 授权源不是单个 IP/已对齐 CIDR，或超出上限 |
| OUT_NOT_AUTHORIZED | Out 授权 | 绑定两端未配对/身份已撤销，或 Line 的 Out 出口尚未确认（发布门） |
| OUT_BINDING_INVALID | Out 绑定 | out_id / line_id 不是 32 位小写 hex |
| OUT_BINDING_NOT_FOUND | Out 绑定 | 该 Out 尚无绑定记录（与“从未配置”区分） |
| OUT_NOT_FOUND | Out 绑定 | Hub 内不存在该 Out 节点 |
| OUT_ROLE_INVALID | Out 绑定 | 所选节点不是 Out 角色 |
| OUT_BINDING_FAILED | Out 绑定 | 绑定操作未分类失败（需凭 operation_id 查日志） |
| OUT_DELETED | Out 绑定 | 删除路由并清 ACL 已完成（成功审计事件） |
| LINE_ID_INVALID | Out 授权 | Line id 不是 32 位小写 hex |
| LINE_NOT_FOUND | Out 授权 | Hub 内不存在该 Line 节点 |
| LINE_ROLE_INVALID | Out 授权 | 所选节点不是 Line（edge）角色 |
| LINE_NOT_CONFIGURED | Out 授权 | Line 尚无存储的传输参数，不能作为出口锚点 |
| LINE_EGRESS_UNVERIFIED | Out 授权 | Line 传输地址是 DNS 名，Hub 无法证明 Out 将看到的源地址 |
| LINE_NOT_AUTHORIZED | Out 授权 | 绑定 Line 没有当前未撤销的配对身份 |
| LINE_NOT_RETIRED | Out 授权 | 试图回收仍可验证的 Line；须先撤销身份 |
| OUT_SYNC_IN_PROGRESS | Out 同步 | 存在在途链，等待其结算 |
| OUT_SYNC_PENDING | Out 同步 | 授权变更尚未发布（Offline/在途/删除清理未下发） |
| OUT_SYNC_FAILED | Out 同步 | 双 readback 未收敛且无更具体子码 |
| OUT_OFFLINE | Out 同步 | Out 超过心跳窗口未上报，不下发状态变更任务 |
| OUT_EGRESS_REALITY_UNVERIFIED | Out 同步 | 白名单与入站均健康，但已确认候选缺 REALITY 块 |
| OUT_CANDIDATE_INVALID | Out 同步 | Out 候选不是无凭据基线（含用户或 REALITY） |
| RULESET_FETCH_FAILED | AI 规则集 | 固定规则集下载/大小/摘要校验失败，拒绝发布 |
| RULESET_PIN_INVALID | AI 规则集 | 规则集固定项可变或畸形（非 HTTPS、可变通道、摘要格式） |
| OUT_OFFLINE_FAIL_CLOSED | AI 出口 | 已配置 Out 不可用且未显式允许回退 Line |
| OUT_FALLBACK_UNAUDITED | AI 出口 | 请求显式回退 Line 但缺 operation_id，无法审计 |

说明：`BOOTSTRAP_ACL_UNAVAILABLE` / `BOOTSTRAP_ACL_INVALID` 只在 #8-B 的中间提交存在过，同一 PR 内随「bootstrap 只做形状断言、不以受管文件自证」修正被删除，从未进入 `main`；排查时应使用 `OUT_ACL_READBACK_FAILED` 与 `ACL_*` 系列。`OUT_ACL_UNATTESTED` 仍保留，用于「远端 ACL 无法 attest」这一独立事实。

## UI 交互

任务详情页含步骤时间线、节点级日志与诊断建议；概览展示当前版本、最近运行健康状态、待重试任务。日志检索按 node_id / operation_id / level / error_code，不支持对公共 Web 直接下载未脱敏原始运行文件。

## 实际健康证据

至少区分 Host 运行、监听端口、云侧可达、代理握手、Out 双跳、Headscale 在线、Tailnet 子网可达、P2P 直连或 DERP 回退。任何一项未真实测试都用 unknown 或 pending-verification 标注，不能显示绿色成功。

建议将 stdout/stderr 写入 journald，Go slog 按 JSON 输出；持久化任务阶段进 SQLite。单节点离线不应影响其他节点查询和发布，必须显示数据最后采集时间。
