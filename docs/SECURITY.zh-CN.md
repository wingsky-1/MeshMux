# 安全设计基线

## 安全边界

- 外网：Caddy HTTPS 是唯一 Hub Web 入口；Web Go HTTP 服务必须以非 root 身份监听 loopback。
- Web：单管理员（无自助注册），强密码哈希（Argon2id），服务端会话、Secure/HttpOnly/SameSite cookie，精确 Origin + CSRF 验证，身份失败限速及注销/失效。
- Privilege boundary：Web API 不直接执行 root 命令；通过固定 schema/allowlist 的特权执行器或 Agent 权限边界访问 systemd、Headscale 与 sing-box；不得提供任意 Shell、下载 URL、进程参数或文件路径。Node Agent 实际为受限 root，只允许固定任务/路径/argv；独立 `meshmux-sing-box.service` 以非 root `meshmux-singbox` 运行。不能把该 Agent 描述为 unprivileged。Agent 的 systemd capability 集合为 `CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_CHOWN CAP_SYS_PTRACE`；其中 `CAP_SYS_PTRACE` 用于读取不同 UID sing-box 的 `/proc/PID/exe` 与 cmdline 实际 hash，`CAP_DAC_READ_SEARCH` 用于 `ss -p` 解析非 root 进程的监听映射（无 `CAP_DAC_OVERRIDE`）。权限边界和该 capability 的真实必要性仍需 Debian 13 VM 验证，当前不宣称已证明全部权限最小。
- Node pairing：短期一次性注册码仅首次使用，可信 TLS 验证，配对后升级为节点专属可轮换和可吊销身份，所有任务携带单调修订/超时/审计 ID。用户 CLI 的 `edge|out` 不接受 pairing-code/token flag；43 字符 code 只在 plan 与确认后从 stdin 单行读取，并只传给安装调用，不写入 argv、URL、Node config、InstallState、日志或结果输出。
- Auth secrets、数据库、Headscale 身份及 REALITY 私钥保持本地 0600 root/服务账户边界，备份加密、可恢复，不在公开 Git、诊断包或通用日志中。

## Fail2ban 与端口

首版 Fail2ban 必须安装、启用并验证 SSH + Web 登录保护；SSH jail 的 action/port 与 sshd 实际生效监听匹配（非 22 端口、IPv4/IPv6 也必须测试），不要只检查 jail 存在。Web 身份失败事件使用不含账户密码的结构化日志。

Cloudflare 代理开启时不可把未经验证的转发头当作真实客户端地址，也不得封禁共享的 Cloudflare 出口 IP；不能建立可信 IP 源链时优先应用层登录限速。Web 下游 Caddy 仅信任明确配置的代理来源；同样不能直接信任用户伪造的 X-Forwarded-For。

nftables 新建本项目专属 table/chain，不覆盖已有规则；Out 私有入站仅放行已认证纳管 Line 的真实公网来源，且在规则撤销/同步失败时默认拒绝。当前 Out 渲染实际为 `policy accept` 并 drop 目标 VLESS TCP/UDP 端口，尚未满足该安全目标，是上线前阻塞；安装器只接受不存在或已由 MeshMux ledger 拥有的 `inet meshmux_out`，不接管其他表。云安全组不是本机防火墙，必须做外部探测。

SSH 保护必须绑定实际 listener：安装器从 `ssh.socket`、`ss` 和传统模式下的 `sshd -T` 读取端口集合，要求配置的 SSH 端口命中实际 listener，VLESS 不与任一 SSH listener 冲突，并回读 Fail2ban jail/action 端口集合与全部实际 SSH listener 完全一致。Fail2ban 使用 MeshMux 专属 `meshmux-node-sshd` jail 和 nftables action，不重配 sshd，不 flush 主机 ruleset。该行为需要 L2/L3 实测。

## 订阅 Token 与凭据生命周期（#7）

随机独立 Token 至少维持现有 ~288 bit 熵基线，禁止顺序 ID、用户名拼 URL、目录索引或自动暴露路径。标准与 Mesh 设备 Token 独立。**#7 首个 PR 的 schema 4 只持久化 Token 哈希，原始值仅在创建时展示一次**；泄漏后通过撤销/轮换失效，旧 URL 验证不再通过。只公布固定 JSON/YAML 下载路由，保持 Cache-Control: private, no-store、noindex、no-referrer；Caddy/程序访问日志不写完整 URL 或 bearer Token。

Token 撤销与 VLESS UUID 删除是**独立操作**：撤销/轮换 Token 不触碰任何 UUID；删除凭据按精确 UUID 匹配目标 Line，绝不误删其他订阅者的 UUID。删除/暂停先完成公开侧门禁（先停止/撤销公开下载），再同步并回读远端凭据移除；远端同步部分失败必须显式 `partial`，不得标记 healthy。已下载到客户端的配置无法远程撤回，需明示该边界。

v2 候选携带的用户 UUID 与 REALITY 私钥属节点秘密：只经已认证的 Hub↔Agent 通道传输，节点侧私有 0600 边界保存，不进入公开响应、订阅产物或通用日志；固定 `config.check → stage → apply → readback` 流水线与 Agent allowlist 不变，不新增任意 shell/路径/URL。

订阅下载**不增加**用户名密码、Cloudflare Access、验证码、固定客户端 IP 或默认下载 Fail2ban/复杂风控。有效 URL 在轮换前被他人获取仍可用，这是 bearer 凭据的固有边界；不能夸大随机性防泄漏作用。

## 升级与安装制品

发行制品版本固定并有 manifest 与 SHA-256；可信发布源、制品检验和 Host/Agent 升级操作必须绑定目标版本。下载失败、签名/哈希异常或运行状态与期望不符，禁止继续启动新配置；保留可回退版本。GitHub Actions 仅在受限工作流里发行，不在通用 PR 作业执行安装到生产主机。

## Node 安装与 runtime 边界

Node 安装先执行配置校验和真实 preflight，再展示 plan；未通过精确确认或 `--yes`，不进入 apply。即使 `--yes` 也不能绕过 Debian 13、root 和失败检查。`--plan` 不消费 code、不调用安装事务、不写宿主。`--repair` 优先复用私有 identity，只有安装器明确要求 pairing 时才提示重新签发 code。

Agent 动态写事务与 repair 共用 `/var/lib/meshmux-agent/runtime.lock`，锁只在事务期间持有，不是常驻服务锁。Agent 离线或控制平面失联不会自动停止独立 kernel；恢复只尝试已有有效 LKG，恢复后必须严格 readback，失败保持 `partial` 而不是成功。

## 阶段一已实现边界

Argon2id 固定成本、服务端哈希会话、初始化令牌、精确 Host/Origin/CSRF、持久化全局认证限速、私有 SQLite 目录与事务迁移已实现。默认不信任转发 IP，Fail2ban 候选默认禁用；真实封禁仍需安装阶段隔离验收。参数、失败行为、可信本机边界和备份恢复要求见 [Web 安全基座](WEB_DEVELOPMENT.zh-CN.md)。

Issue #6 已关闭，Node/Agent 边界以上文固定通道为准。Issue #7 首个 PR 只引入订阅域模型（schema 4、仅哈希 Token、per-Line 安全 UUIDv4）与严格 v2 REALITY 编译器；Web 用户操作、公开下载、远端凭据同步与跨节点生命周期尚未实现，也不得据此宣称真实握手或客户端可用。
