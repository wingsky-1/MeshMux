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

## UI 交互

任务详情页含步骤时间线、节点级日志与诊断建议；概览展示当前版本、最近运行健康状态、待重试任务。日志检索按 node_id / operation_id / level / error_code，不支持对公共 Web 直接下载未脱敏原始运行文件。

## 实际健康证据

至少区分 Host 运行、监听端口、云侧可达、代理握手、Out 双跳、Headscale 在线、Tailnet 子网可达、P2P 直连或 DERP 回退。任何一项未真实测试都用 unknown 或 pending-verification 标注，不能显示绿色成功。

建议将 stdout/stderr 写入 journald，Go slog 按 JSON 输出；持久化任务阶段进 SQLite。单节点离线不应影响其他节点查询和发布，必须显示数据最后采集时间。
