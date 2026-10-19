# Issue #5 · Hub 安装器：PR A 只读预检与制品基线

**状态：PR A 可审核，未实施主机安装。** 当前 `meshmux install hub` 仍会以非零退出，绝不会触碰宿主机配置或启停服务。首次真正安装、重复安装、修复与回滚属于 PR B。不要在生产 VPS 上验证本阶段。

## 运行方式

从本仓库当前源码使用 Go 1.27.2 构建：

```sh
go build -o ./bin/meshmux ./cmd/meshmux
./bin/meshmux install hub --plan \
  --management-domain console.example.org \
  --subscription-domain sub.example.org \
  --headscale-domain mesh.example.org
```

`example.org` 仅展示语法。实际预检时须使用本人控制、已解析 A/AAAA 的测试域名；不得把个人地址或私钥提交到仓库。计划以 JSON 写入终端错误输出，含一次性 operation_id、逐项状态/错误码/补救建议、组件和端口。这里**不读取、收集或输出管理员密码**。默认 install 不接受确认开关，执行写操作仍关闭。

预检读取 `/etc/os-release`，校验 Debian 13、amd64/arm64、root、至少 1 GiB 可用空间、systemd、NTP、三域名 DNS、GitHub 出站 HTTPS、TCP 80/443 与 Web/Headscale loopback 监听冲突、UDP 3478，以及 SSH 实际监听端口。SSH 包含 ssh.socket systemd socket activation 与 ss 的实际监听；传统 sshd 进一步与 `sshd -T` 对比。不调用 `iptables -F`、`nft flush ruleset`，不重配 SSH，也不写 Fail2ban jail。

`checks[].status`：`pass`、`fail`、`pending`；失败返回非零。公网 443/IPv6/UDP 3478/cloud security group 的验证明确标记 `pending`，不能通过本机 DNS 或成功绑定端口推断公网可达。即使主机检查全绿，`apply_available=false` 且 **没有安装成功状态**。TCP/UDP bind 是短暂探针而非持续保留端口，PR B 在 apply 前仍须重新检查所有权。

## 官方制品与版本锁

`internal/install/artifacts.go` 锁定：
- Caddy v2.11.7：GitHub 官方 release 的 linux amd64/arm64 tar.gz，以及官方 release asset SHA-256。
- Headscale v0.29.5：GitHub 官方 release 的 linux amd64/arm64 ELF，以及官方 release asset SHA-256。
- `VerifyFile` 精确比对 SHA-256；`DownloadVerified` 只接受源码内已锁的制品清单，限制 128 MiB，采用 0700 私有目录/临时文件及校验后原子硬链接；校验失败拒绝返回文件路径。
- Debian 13 官方仓库提供 Fail2ban/nftables，实际 apt pin 和安装留待 PR B 记录锁定的 Debian snapshot 或发行包版本。
- sing-box 1.14.3 是 v1.0.0 基线，但 Hub 安装阶段**不启动代理核心**。本项目 MeshMux Web 自有发布制品目前缺少已发布 SHA-256 manifest；PR B 必须补齐并与构建来源关联，否则 **禁止 apply**。

固定校验和来源可通过 GitHub 上游 API release assets digest 重复核查。不能用临时抓取的 `latest` 替代。本阶段 `DownloadVerified` 是可供后续 staging 调用的独立库函数，`--plan` **不会下载制品**。

## 候选配置（未激活）

`CandidateFiles` 以严格验证的域名和有效 SSH 端口生成专属配置内容，不在 `--plan` 时写入系统：

| 未来受管文件 | 职责 |
| --- | --- |
| `/etc/meshmux/Caddyfile` | 3 个可配置域名；Web loopback；隐藏健康探针；阻断 Headscale 管理路由 |
| `/etc/meshmux/headscale.yaml` | 0.29.5、SQLite、内置 DERP 999、自建 STUN UDP/3478、`derp.urls=[]`、禁用 DERP map 自动拉取 |
| `/etc/systemd/system/meshmux-{web,headscale,caddy}.service` | 隔离非 root 服务身份；Caddy 唯一持有 80/443 绑定能力 |
| `/etc/fail2ban/jail.d/meshmux-ssh.local` | 使用当前真实 SSH 端口；默认 nftables action，未经验证不得激活 |

Headscale 模板按官方 v0.29.5 标签的 `config-example.yaml` 字段构建，非从 my-sub 复制。Hub Web 使用 Issue #2 已实现的 Argon2id/SQLite/CSRF/限速、`/healthz` 和本机初始化令牌。Web 的公网证书由 Caddy 默认 HTTP-01/TLS-ALPN-01 管理，不需要 Cloudflare DNS 插件或 Zero Trust。使用 CDN/Cloudflare 时**不能**启用依赖真实客户端 IP 的 Web Fail2ban jail；应用限速始终启用。

**已知边界：** 只有一个自建 DERP 时具备单点故障；公网不可达另须检查云安全组。模板语法和 Headscale 0.29.5 运行时验证、Fail2ban action、systemd 实际账户权限及 Caddy ACME 证书签发均属于 PR B 的隔离 Debian 13 验收，不能以字符串测试替代。

## PR B 阻断清单与回退约束

1. MeshMux Web 及 CLI 可验证的自身制品 manifest/来源与 SHA-256；下载和安装前完整校验，禁止不可信二进制以 root 执行。
2. 真实 `check → stage → apply → readback`，记录每次 operation_id/阶段/持久状态；配置原子写入、所有权/现有服务检查、锁、防中断、重试幂等和 rollback；不得覆盖其他 Caddy/Headscale，也不得删除 MeshMux/Headscale SQLite。
3. Debian 官方 Fail2ban/nftables 包安装与真实 SSH 非 22 jail action 验证；若已有 host 规则，使用 MesMux 专属对象，不修改既有默认策略。
4. 通过 `headscale configtest`（先核实实际 0.29.5 CLI 支持方式）、`caddy validate`、`systemd-analyze verify`、服务健康与 HTTPS 外部真实访问、UDP STUN/DERP 验证；外部未验收保持 pending。
5. 采用分层 CI：L1 每次 Go 回归；L2 Debian 13 容器验证固定版本真实 Caddy/Headscale/systemd/Fail2ban 配置；L3 PR B 退出时通过至少一套自动化 Debian 13 完整 systemd VM 验证真实安装、重复执行、重启及故障恢复。arm64 若无完整宿主机验证须明确限制。参见 [CI 验证规范](CI_HUB_VALIDATION.zh-CN.md)。
6. 所有修复先停受影响服务、备份 SQLite 一致性快照，再仅更换该项目受管文件。不能依赖删除数据库来恢复成功安装。

## 与后续 Issue 的接口

PR B 输出稳定 Hub 配置路径、systemd 单元、MeshMux Web loopback、Headscale 0.29.5 本地服务/API、可追踪 operation_id 与锁定制品 manifest。Issue #6 只消费这些已确认接口，实现 Line/Out Agent 主动纳管，不重新建立 Web/Headscale 身份或修改 SSH。

**验收标记：** PR A 只证明源码单测/CI 等 B 级证据；尚无 C 级 Debian 13 VM 安装证据。Issue #5 不因 PR A 合并而关闭，更不能由此启动 #6 的依赖实施。

## 分层 CI 验证

已确立 [L1/L2/L3 CI 验证规范](CI_HUB_VALIDATION.zh-CN.md)。PR A 的 L2 配置集成不能冒充真实 Hub 安装；完整 VM 测试将在 PR B 完成 apply 后加入。
