# Issue #5 · Hub 安装器（PR A 预检 + PR B 安装执行）

**阶段状态：PR #14 已通过 L1/L2；PR #15 的 install/apply 已实现初稿并处于 L3 QEMU 隔离验收。两 PR 均未合并，禁止在任何现网 VPS/NAS 上执行 Draft 安装器。**

## PR B 安装、重试和恢复（仅隔离 Debian 13 测试 VM）

用于手动复核 CI 步骤的命令示例，不是当前公开生产安装指令：

```sh
go build -o ./bin/meshmux ./cmd/meshmux
./bin/meshmux install hub --plan \
  --management-domain console.example.org \
  --subscription-domain sub.example.org \
  --headscale-domain mesh.example.org

# 仅在全新可销毁 VM 上，且域名由操作者控制时执行
sudo ./bin/meshmux install hub \
  --management-domain console.example.org \
  --subscription-domain sub.example.org \
  --headscale-domain mesh.example.org

# 重复执行：仅做已安装健康读回，不修改数据和制品
sudo ./bin/meshmux install hub --yes \
  --management-domain console.example.org \
  --subscription-domain sub.example.org \
  --headscale-domain mesh.example.org

# 发生部分安装/需主动修复时，显式使用 --repair
sudo ./bin/meshmux install hub --repair --yes \
  --management-domain console.example.org \
  --subscription-domain sub.example.org \
  --headscale-domain mesh.example.org
```

交互模式需输入准确短语 `install hub`，非交互自动化需 `--yes` 与全部三个域名。Web 不从命令行接收管理员密码，而是在 `/var/lib/meshmux/bootstrap.token` 生成一次性初始化令牌（敏感权限 0600）。带 `--direct-caddy` 时才启用 Web IP 封禁；经过 CDN/多层代理一律不要开启。

- 原生安装器 `/usr/local/libexec/meshmuxd` 是与操作 CLI 相同的经 SHA-256 比对的可执行文件。CI 发布对应源码提交的构建制品和 `SHA256SUMS`；**这不等于已存在公开 Release 或长期有效的签名 manifest**。
- 使用官方 Caddy 2.11.7 / Headscale 0.29.5 发行制品的固定校验值。真实 Caddy ACME/TLS 不允许将测试证书禁用校验；`tls internal` 仅由不可从用户 CLI 访问的 CI VM 测试钩子生成。
- 只修改 MeshMux 专属 Caddy/Headscale 文件、专属 systemd 服务和 Fail2ban jail/filter。不会 `nft flush ruleset`、不会重写 SSH、不会清空数据库或 Headscale 私钥。
- 每次操作的 root 私有状态在 `/var/lib/meshmux-installer/state.json`，日志在 `/var/lib/meshmux-installer/operations/<operation_id>/events.jsonl`；冲突、非受管文件、外部编辑漂移均拒绝覆盖。
- 安装完成判定采用“传输层就绪”语义：探针以管理域名作为 SNI 访问本机 Caddy，要求 TLS 握手成功（TLS 1.2 及以上）且 origin 返回 2xx/3xx；探针显式禁止跟随重定向。首次安装尚未创建管理员时，`/login` 返回 303 跳转 `/setup` 属于正常业务状态，不是服务不可用。
- 失败回滚是“恢复到操作前状态”，而不是清空记录：受管文件台账 `ManagedFiles` 会按成功回滚后的磁盘实况重新核对哈希，保留已恢复文件的归属、移除本次新建后又被删除的文件，因此回滚后仍可继续执行 `--repair`。运行 `--repair` 前仍应排查 journal 和 systemd unit；管理域名、订阅域名或 Headscale 域名迁移不属于自动 repair 范围。
- Debian 官方包采用查询优先的幂等安装：安装或修复前逐项执行 `dpkg-query -W -f=${Status}`，仅对未处于 `install ok installed` 的缺失包执行 `apt-get update` 和 `apt-get install`；全部包已安装时不调用 apt。
- 真实外网证书签发、云安全组和跨 NAT STUN/DERP 检查必须另列 `pending`，本机 TLS/端口健康无法证明公网可达。

## 原 PR A 基线及设计说明

## 运行方式

从本仓库当前源码使用 Go 1.27.2 构建：

```sh
go build -o ./bin/meshmux ./cmd/meshmux
./bin/meshmux install hub --plan \
  --management-domain console.example.org \
  --subscription-domain sub.example.org \
  --headscale-domain mesh.example.org
```

`example.org` 仅展示语法。实际预检时须使用本人控制、已解析 A/AAAA 的测试域名；不得把个人地址或私钥提交到仓库。计划以 JSON 写入标准输出，含一次性 operation_id、逐项状态/错误码/补救建议、组件和端口。这里**不读取、收集或输出管理员密码**。交互执行必须在展示计划后键入准确短语 `install hub`；非交互执行仅在显式使用 `--yes` 且预检全部通过后才进入 apply，未获确认不修改宿主。

预检读取 `/etc/os-release`，校验 Debian 13、amd64/arm64、root、至少 1 GiB 可用空间、systemd、NTP、三域名 DNS、GitHub 出站 HTTPS、TCP 80/443 与 Web/Headscale loopback 监听冲突、UDP 3478，以及 SSH 实际监听端口。SSH 包含 ssh.socket systemd socket activation 与 ss 的实际监听；传统 sshd 进一步与 `sshd -T` 对比。不调用 `iptables -F`、`nft flush ruleset`，不重配 SSH，也不写 Fail2ban jail。

`checks[].status`：`pass`、`fail`、`pending`；失败返回非零。公网 443/IPv6/UDP 3478/cloud security group 的验证明确标记 `pending`，不能通过本机 DNS 或成功绑定端口推断公网可达。即使主机检查全绿，`apply_available=false` 且 **没有安装成功状态**。TCP/UDP bind 是短暂探针而非持续保留端口，PR B 在 apply 前仍须重新检查所有权。

## 官方制品与版本锁

`internal/cli/install/artifacts.go` 锁定：
- Caddy v2.11.7：GitHub 官方 release 的 linux amd64/arm64 tar.gz，以及官方 release asset SHA-256。
- Headscale v0.29.5：GitHub 官方 release 的 linux amd64/arm64 ELF，以及官方 release asset SHA-256。
- `VerifyFile` 精确比对 SHA-256；`DownloadVerified` 只接受源码内已锁的制品清单，限制 128 MiB，采用 0700 私有目录/临时文件及校验后原子硬链接；校验失败拒绝返回文件路径。
- Debian 13 官方仓库提供 Fail2ban/nftables，实际 apt pin 和安装留待 PR B 记录锁定的 Debian snapshot 或发行包版本。
- sing-box 1.14.3 是 v1.0.0 基线，但 Hub 安装阶段**不启动代理核心**。本项目 MeshMux Web 自有发布制品目前缺少已发布 SHA-256 manifest；PR B 必须补齐并与构建来源关联，否则 **禁止 apply**。

固定校验和来源可通过 GitHub 上游 API release assets digest 重复核查。不能用临时抓取的 `latest` 替代。本阶段 `DownloadVerified` 是可供后续 staging 调用的独立库函数，`--plan` **不会下载制品**。

## 候选配置（未激活）

候选文件渲染以严格验证的域名和有效 SSH 端口生成专属配置内容，不在 `--plan` 时写入系统：

| 未来受管文件 | 职责 |
| --- | --- |
| `/etc/meshmux/Caddyfile` | 3 个可配置域名；Web loopback；隐藏健康探针；阻断 Headscale 管理路由 |
| `/etc/meshmux/headscale.yaml` | 0.29.5、SQLite、内置 DERP 999、自建 STUN UDP/3478、`derp.urls=[]`、禁用 DERP map 自动拉取 |
| `/etc/systemd/system/meshmux-{web,headscale,caddy}.service` | 隔离非 root 服务身份；Caddy 唯一持有 80/443 绑定能力 |
| `/etc/fail2ban/jail.d/meshmux-ssh.local` | 使用当前真实 SSH 端口；默认 nftables action，未经验证不得激活 |
| `/etc/fail2ban/jail.d/meshmux-web.local`、`/etc/fail2ban/filter.d/meshmux-web.conf` | Web jail 默认禁用，仅在 `--direct-caddy` 时启用；filter 的 `datepattern` 支持 RFC3339Nano 的 1-9 位小数 |
| `/etc/systemd/journald.conf.d/99-meshmux.conf` | 唯一一条宿主级 journald 配额（`SystemMaxUse=1G`、`RuntimeMaxUse=512M`、`MaxFileSec=30day`）；只含配额项，不改主 `journald.conf`，下一次 `systemd-journald` 启动生效 |

Headscale 模板按官方 v0.29.5 标签的 `config-example.yaml` 字段构建，非从 my-sub 复制。Hub Web 使用 Issue #2 已实现的 Argon2id/SQLite/CSRF/限速、`/healthz` 和本机初始化令牌。Web 的公网证书由 Caddy 默认 HTTP-01/TLS-ALPN-01 管理，不需要 Cloudflare DNS 插件或 Zero Trust。Web Fail2ban jail 默认禁用，仅在 Caddy 直接面向客户端且显式传入 `--direct-caddy` 时启用；使用 CDN/Cloudflare 或多层代理时**不能**启用依赖真实客户端 IP 的 Web Fail2ban jail，应用限速始终启用。

**Web 与 Headscale 的 socket 边界（PR-9a-4）：** `meshmux-web.service` 增加 `SupplementaryGroups=meshmux-headscale`，只用于穿过 0770 的 `/run/meshmux-headscale/headscale.sock`（`unix_socket_permission: "0770"`）。该组成员身份**不**给予 `/var/lib/meshmux-headscale` 的任何访问：数据目录仍是 `meshmux-headscale:meshmux-headscale` 0700，Web 单元也没有 `Group=meshmux-headscale` 或对应的 `ReadWritePaths`。Headscale 自己的 CLI 是唯一写数据库的进程，Web 只经固定 CLI 适配器调用本机 socket；这条组权限链需要在隔离 Debian 13 上由 `systemd-analyze verify` 与真实 `nodes list` 一起验证，不能以模板字符串断言替代。

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

**验收标记：** PR A 只证明源码单测/CI 等 B 级证据；PR B 的 Go 事务测试、健康探针语义、回滚台账一致性、apt 幂等和 Fail2ban 模板已有 L1 证据，但 L3 尚未重跑，尚无可引用的 Debian 13 VM 成功运行证据。Issue #5 不因 PR A 合并而关闭，更不能由此启动 #6 的依赖实施。

## 分层 CI 验证

已确立 [L1/L2/L3 CI 验证规范](CI_HUB_VALIDATION.zh-CN.md)。PR A 的 L2 配置集成不能冒充真实 Hub 安装；`hub-vm` 会在触及安装器路径的 PR 上自动运行 L3，但只有取得明确成功运行链接后才能把真实 systemd 安装、重启恢复和故障回滚记为通过。
