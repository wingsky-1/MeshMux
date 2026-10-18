# 安全设计基线

## 安全边界

- 外网：Caddy HTTPS 是唯一 Hub Web 入口；Web Go HTTP 服务必须以非 root 身份监听 loopback。
- Web：单管理员（无自助注册），强密码哈希（Argon2id），服务端会话、Secure/HttpOnly/SameSite cookie，精确 Origin + CSRF 验证，身份失败限速及注销/失效。
- Privilege boundary：Web API 不直接执行 root 命令；通过固定 schema/allowlist 的特权执行器或 Agent 权限边界访问 systemd、Headscale 与 sing-box；不得提供任意 Shell、下载 URL、进程参数或文件路径。
- Node pairing：短期一次性注册码仅首次使用，可信 TLS 验证，配对后升级为节点专属可轮换和可吊销身份，所有任务携带单调修订/超时/审计 ID。
- Auth secrets、数据库、Headscale 身份及 REALITY 私钥保持本地 0600 root/服务账户边界，备份加密、可恢复，不在公开 Git、诊断包或通用日志中。

## Fail2ban 与端口

首版 Fail2ban 必须安装、启用并验证 SSH + Web 登录保护；SSH jail 的 action/port 与 sshd 实际生效监听匹配（非 22 端口、IPv4/IPv6 也必须测试），不要只检查 jail 存在。Web 身份失败事件使用不含账户密码的结构化日志。

Cloudflare 代理开启时不可把未经验证的转发头当作真实客户端地址，也不得封禁共享的 Cloudflare 出口 IP；不能建立可信 IP 源链时优先应用层登录限速。Web 下游 Caddy 仅信任明确配置的代理来源；同样不能直接信任用户伪造的 X-Forwarded-For。

nftables 新建本项目专属 table/chain，不覆盖已有规则；Out 私有入站仅放行已认证纳管 Line 的真实公网来源，且在规则撤销/同步失败时默认拒绝。云安全组不是本机防火墙，必须做外部探测。

## 订阅 URL 不可枚举

随机独立 Token 至少维持现有 ~288 bit 熵基线，禁止顺序 ID、用户名拼 URL、目录索引或自动暴露路径。标准与 Mesh 设备 Token 独立。只公布固定 JSON/YAML 下载路由，保持 Cache-Control: private, no-store、noindex、no-referrer；Caddy/程序访问日志不写完整 URL 或 bearer Token。泄漏后通过 Web 轮换/撤销，旧 URL 验证失效。

订阅下载**不增加**用户名密码、Cloudflare Access、验证码、固定客户端 IP 或默认下载 Fail2ban/复杂风控。有效 URL 在轮换前被他人获取仍可用，这是 bearer 凭据的固有边界；不能夸大随机性防泄漏作用。

## 升级与安装制品

发行制品版本固定并有 manifest 与 SHA-256；可信发布源、制品检验和 Host/Agent 升级操作必须绑定目标版本。下载失败、签名/哈希异常或运行状态与期望不符，禁止继续启动新配置；保留可回退版本。GitHub Actions 仅在受限工作流里发行，不在通用 PR 作业执行安装到生产主机。

## 阶段一已实现边界

Argon2id 固定成本、服务端哈希会话、初始化令牌、精确 Host/Origin/CSRF、持久化全局认证限速、私有 SQLite 目录与事务迁移已实现。默认不信任转发 IP，Fail2ban 候选默认禁用；真实封禁仍需安装阶段隔离验收。参数、失败行为、可信本机边界和备份恢复要求见 [Web 安全基座](WEB_DEVELOPMENT.zh-CN.md)。
