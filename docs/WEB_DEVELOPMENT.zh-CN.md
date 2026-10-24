# Web 安全基座：隔离运行与验收

对应 Issue #2，后续 #5～#10 已在此基座上合入：Web 现已覆盖 Hub/Line/Out 安装、订阅用户与双格式订阅下载、Mesh 设备与子网路由、分流策略校验/发布，`meshmux install hub|edge|out` 正常可用（不再是占位或非零退出）。**仍非正式安装发行包**：v1.0.0 发布前不创建 Tag/Release；#11 统一升级尚未实现。本文其余部分仍描述本地隔离运行 Web 的方式。

## 本机启动（Linux，普通用户）

使用 Go 1.27.2。在普通用户的隔离目录中执行，**不要 sudo 启动 Web**：

```sh
go build -o ./bin/meshmux-web ./cmd/meshmux-web
umask 077
./bin/meshmux-web --listen 127.0.0.1:9080 \
  --origin http://127.0.0.1:9080 --data-dir "$PWD/.local-state" --dev-http
```

浏览器打开 `http://127.0.0.1:9080`。必须精确使用这个地址，不能替换为 localhost。程序只接受字面量 loopback IP，不接受 `0.0.0.0`、通配地址或可解析为公网的主机名。数据目录的父目录需已存在，路径不能包含符号链接。`--dev-http` 是明确的本机 HTTP 例外，仅此模式的 Cookie 不带 Secure；不允许在此模式开启代理 IP 信任。不要把开发 HTTP 暴露到公网或转发到手机。

首次访问进入初始化页面。在**另一个本机终端**读取一次性凭据（不放入 URL、参数或日志）：

```sh
cat .local-state/bootstrap.token
```

在页面输入该凭据和管理员密码（至少 12 个字符、最多 256 UTF-8 字节）。账号固定为 `admin`。凭据有效期 30 分钟；未初始化时重启会轮换凭据，限速计数不会重置。初始化成功会删除引导文件、关闭初始化入口并清空匿名会话，然后使用密码登录。没有公开注册、密码找回、默认密码或认证绕过开关。

登录后可以浏览八个导航页面、刷新本机 Web 状态，在设置中修改密码并退出。修改密码会撤销所有会话；再次登录也替换上一次登录会话。代理、订阅、Mesh 与路由页面只有明确空状态；任务/日志页显示带“模拟”标记的 SSH 预检失败示例，未读取真实 SSH 配置。

使用 Ctrl+C / SIGTERM 优雅退出。服务重启保留尚未过期的会话，不会复活已经注销或因改密撤销的会话。浏览器打开开发者工具可检查 Cookie 与错误响应。

## HTTPS 与手机验收

正式 Cookie 使用 `__Host-meshmux`，始终带 Secure、HttpOnly、SameSite=Strict、Path=/，无 Domain。默认要求精确 HTTPS Origin。仅在隔离 VM 手动准备专用账户、二进制、域名/TLS 和候选配置；本 PR 不提供或执行安装器。

```sh
./bin/meshmux-web --listen 127.0.0.1:9080 \
  --origin https://admin.example.invalid --data-dir "$PWD/.local-state"
```

`example.invalid` 是文档占位，必须替换为隔离环境的测试域名。Caddy 与 Web 在同一主机，通过 HTTPS 向手机/PC 提供入口；手机不得直接访问 9080。没有域名时可在隔离实验环境使用本机信任的测试证书，纯 IP 公网证书部署不在本阶段范围。

候选文件：

- `deploy/Caddyfile.example`：HTTPS 反代、精确 Host 透传、覆盖专用 IP 头、禁用公网 healthz。未启用请求访问日志，避免 URL/凭据进入访问日志。
- `deploy/meshmux-web.service`：专用非 root 用户，0700 StateDirectory、0077 umask、无能力集、只读系统、journald。**不会自动创建账户、安装二进制或启用单元。**
- `deploy/fail2ban/`：Web filter 和默认禁用的 jail 候选。

验证命令（只检查候选，不启动服务）：

```sh
caddy validate --config deploy/Caddyfile.example --adapter caddyfile
systemd-analyze verify deploy/meshmux-web.service
fail2ban-regex internal/web/testdata/fail2ban.log deploy/fail2ban/meshmux-web.conf
```

systemd 验证需要候选 `ExecStart` 路径存在；开发时可复制到临时文件，仅把该路径改成构建产物后验证。Caddy 语法通过不等于域名/TLS、公网可达或 Debian 13 主机部署已通过。

## 认证和 HTTP 边界

| 边界 | 行为 |
| --- | --- |
| 密码 | x/crypto Argon2id，64 MiB / 3 次 / 4 路，16 字节随机盐、32 字节结果；固定 PHC 格式，拒绝损坏/超大成本参数 |
| 初始化 | 256 bit 随机本地凭据，DB 只存 SHA-256，30 分钟过期，仅允许一名管理员 |
| 会话 | 256 bit 随机令牌，DB 只存 SHA-256；独立 CSRF 值；登录旋转令牌，最长 8 小时、空闲 30 分钟 |
| 并发登录 | 同时只保留一个管理员登录；新登录撤销旧会话。匿名会话最长 15 分钟、最多 256 条，到期时回收 |
| POST | 包括登录/初始化，必须精确 Origin、有效会话和 CSRF；拒绝跨站、重复 Origin/表单字段、URL 表单参数、非表单 Content-Type、大于 4 KiB 的请求体 |
| Cookie | 生产 `__Host-`、Secure、HttpOnly、Strict；重复同名 Cookie、未知/过期/已撤销令牌拒绝 |
| 未认证 | `/` 跳登录；受保护页面和 API 返回 401；静态资产、初始化/登录表单和本机 healthz 允许匿名 |
| 限速 | 初始化、登录、改密共用持久化全局预算，10 次/10 分钟；窗口从首次尝试起算，服务重启不清零；第 11 次返回 429 + 窗口剩余等待时间。初始化成功、登录成功、改密成功在同一事务内清零预算——只有已证明的凭据能清零，错误密码永不清零，因此 10 次成功登录不会锁住唯一管理员；一次只执行一个密码运算 |
| 配对限速 | `/api/agent/pair` 用**独立的进程内**预算（20 次/分钟，窗口从首次尝试起算、失败不延长、配对成功即清零），第 21 次返回 429 `PAIRING_RATE_LIMITED` + `Retry-After`。它不共用 `auth_limit`：匿名洪水不能花掉登录预算，也不占用 `SetMaxOpenConns(1)` 的唯一连接（预算判定本身零数据库访问）。格式错误的请求在触库前被拒，不计费。配对成功后已配发身份的心跳/任务/配置端点不受任何配对预算影响 |
| 配对拒绝 | 未知、过期、已消费的码一律 `401 PAIRING_INVALID`（相同 body），响应不是码历史的 oracle；`PAIRING_EXPIRED`/`PAIRING_CONSUMED` 只进 `web_event` 日志，凭 `operation_id` 可查。角色不匹配仍是 `403 ROLE_MISMATCH`；数据库不可用为 `503 DATABASE_UNAVAILABLE`，身份签发失败为 `500 IDENTITY_ISSUE_FAILED`，都不伪装成码被拒绝 |
| 失败封闭 | 数据库故障时不会跳过认证或限速，返回 503；退出失败不声称会话已经撤销 |
| 响应 | CSP 禁止外部资源/内联脚本/eval，no-store、same-origin Referrer（不向外站发送）、nosniff、frame-ancestors none；templ 转义文本 |
| 日志 | slog JSON 白名单字段；不记录 URL、请求体、Header、Cookie、密码、引导凭据或原始 HTTP 错误；服务日志 UTC |

全局限速适合单管理员，不依赖可能伪造或共享的 IP。代价是持续攻击者可以暂时耗尽登录预算；已经登录的只读访问和退出不受该预算影响。匿名表单会话数量受限，持续请求可能导致新表单短时返回 503，过期后回收；不是公网 DDoS 防护承诺。

**预算成功即清零是显式取舍（#113 3-1）。** 每天正常登录或改密的次数远低于 10 次，成功清零保证管理员不会被自己的正常操作锁在门外，也让 429 恢复路径可执行：成功一次就立即恢复，不必等满十分钟。反过来的代价必须说明：攻击者若确实知道密码，第一次成功就会拿到新预算；但这等同于已经取得管理员凭据，此时限速已不是防线。对**不知道密码**的攻击者，清零不改变任何成本——只有错误尝试消耗配额、永不重置，故暴力破解仍被 10 次/10 分钟、从首次尝试起算的窗口限制。清零与凭据验证的写入在同一事务提交，失败不会留下“半重置”状态，也不会把会话失败误报成成功。429 页面给出剩余等待时间与“已登录会话/只读页面/退出不受影响”，不提示密码是否正确。这套机制是应用层 KDF 成本边界，不是抗 DDoS 承诺。

**配对预算单独成账是显式取舍（#113 3-4）。** `/api/agent/pair` 在任何会话存在前就消耗秘密，所以它既不能落在登录预算上，也不能落在 `SetMaxOpenConns(1)` 的那条连接上：前者让匿名洪水直接锁住管理员登录，后者让每次配对排进 Hub 唯一的数据库连接。实现因此是进程内 20 次/分钟（窗口从首次尝试起算、失败不延长、配对成功即清零），判定路径零数据库访问，`TestPairingFloodNeverContendsForTheSingleConnection` 在持有唯一连接时仍能拿到 429 来固定这一点。代价与登录预算同款：持续攻击者可以短暂拒绝真实配对；窗口只有一分钟且 429 给出剩余时间，服务重启会重置计数（远端请求无法触发重启）。代价是显式接受的可用性风险，不是缺陷。三个“这个码不能用”的答案合并为同一个 `401 PAIRING_INVALID`，因为分开返回会让端点变成码历史的 oracle（曾存在/何时过期/已被使用）；日志保留精确原因，凭 `operation_id` 可查。

应用的本机边界信任服务账户、root 和本机反代。不能以此抵御已控制主机或同一服务账户的攻击者。没有通用 Shell、任意文件操作或远程进程控制入口。

## Fail2ban：先验证来源链，再考虑封禁

默认不解析 X-Forwarded-For、Forwarded、CF-Connecting-IP，也不记录它们。默认每次认证失败的 `ban_candidate=false`、`client_ip=""`，Web jail 禁用。

只有 **浏览器直接连接本机 Caddy**、不存在其他反代/CDN 时，才可在隔离验证后为 Web 添加 `--direct-caddy`。Caddy 必须覆盖 `X-MeshMux-Client-IP` 为 TCP 连接来源。Web 只接受 loopback 同行传入的单个合法 IP，不接受列表/主机名；日志仅在此条件下标记可封禁候选。Caddy 改为位于 Cloudflare、CDN、其他负载均衡之后时，必须同时移除该参数并禁用 Web jail，不能封禁共享出口。

Filter 限定日志事件、字段和 IP 格式，fixture 六行仅两行应匹配（IPv4/IPv6）；未可信来源、普通事件和主机名都不匹配。**本阶段只验证匹配，不验证真实 nftables 封禁。** Debian 13、实际端口、IPv4/IPv6 action 和解封由下一安装阶段在隔离 VM 验收。

SSH 只读预检设计：先读取 sshd 生效配置和监听套接字（包括 socket activation），再对照 jail 的实际 action 端口；不一致返回 `SSH_LISTENER_MISMATCH`，不擅自改成 22、不自动修改防火墙。本阶段没有执行这些主机命令。

## SQLite 迁移、备份与恢复

只创建 admin、sessions、bootstrap、auth_limit 四张表及必要索引。WAL、foreign_keys、busy_timeout、synchronous=FULL；单连接；目录排他锁防止两个 Web 进程同时管理状态。启动检查服务账户所有权、文件类型、目录/DB/WAL/SHM/引导凭据权限与符号链接；不自动“修复”不安全的现有目录。

Schema 由 `PRAGMA user_version` 管理，迁移整体事务提交，可重复启动。更高版本 schema 明确拒绝，失败迁移回滚。**不要删除或只复制运行中的 DB 主文件，WAL 中可能仍有已提交数据。**

**存储 schema 与策略 schema 是两个版本号（#11c-3）。** `PRAGMA user_version` 是 SQLite 文件自身的存储 schema（本构建拥有 `10`），只能由 store 迁移升级；`policy_schema` 是升级 manifest 声明的路由策略契约（当前 `8`），由升级批准与兼容门禁校验。`SCHEMA_TOO_NEW` 只表示数据库比当前二进制新：必须换回匹配的二进制或恢复已验证备份，不能靠修改 `policy_schema`、删除表或降级迁移绕过；反过来，更高 `policy_schema` 的发行会被批准门禁以 `UPGRADE_SCHEMA_INCOMPATIBLE` 拒绝，但不会把数据库标成“太新”。两者都是编译常量，没有新增持久配置值。

`database_versions` 是单行 last-known-good 记录（`last_good_version`、`last_good_schema`、`confirmed_at`）。它只在 Web 打开数据库、迁移事务提交并回读 `user_version` 等于本构建 schema 之后写入；迁移事务本身不写确认行，失败迁移不会留下“上次很好”的假象。Hub 没有 Agent 的 `config.readback` 通道，这一启动时的 schema 回读就是 Hub 侧等价物；11d 的 Hub 健康回读消费该行。

**`SCHEMA_TOO_NEW` 指向数据库备份记录，不指向新表。** Hub 数据库备份独立于节点回滚存储，固定位于 `<data-dir>/database-backup/`：`record.json`（0600 元数据，与节点备份记录共用冻结的 `update.BackupRecord` schema）与 `payload/`（0700 目录，内放 0600 的 `meshmux.db` 一致性副本；留待 11d 用 `VACUUM INTO` 写入并在恢复后做 `PRAGMA integrity_check`）。旧二进制只 `lstat` 记录是否存在，不解析未来 schema；错误直接给出该记录路径，并说明记录中的 `from_version` / `db_schema` 才是上次良好状态。启动失败日志保留稳定码 `SCHEMA_TOO_NEW` 并把该路径写入 `detail`（不含凭据、DSN 或 SQL 文本）；其他启动错误只记录稳定码。不可逆迁移的 Web 确认位 `irreversible_approved` 只存放在这份记录上；`POST /tasks/db-migration/approve` 是唯一写入路径（管理员会话 + 精确 Origin + CSRF + `operation_id`，只接受 `irreversible_confirm=1`，无 flag 绕过），本段不新增确认表，也不执行迁移或备份；实际的备份、恢复与 Hub 自升级属 11d。

当前仅提供受控的离线恢复程序；Web 备份按钮与 Hub 自升级执行尚未实现。以下是隔离环境操作说明，本 PR 不自动执行：

1. 停止 Web，确认所有该目录的写入者已退出。不要复制运行中的 db/wal/shm 组合快照。
2. 以原服务用户、`umask 077`，用 SQLite 官方 CLI 的 `.backup` 生成一致性备份。该命令会读取源数据库及其 WAL。
3. 校验备份的 `PRAGMA integrity_check;` 返回 `ok`，加密并离线保管；备份含密码哈希和会话数据，不能上传公开 Issue/诊断包。
4. 恢复到**新的空 0700 私有目录**，以相同二进制/schema 打开。不要把旧 WAL/SHM 混进恢复目录，也不要在原目录直接覆盖一个主 DB 文件。
5. 恢复前用 SQLite CLI 事务清空 `sessions` 和 `bootstrap`，避免复活备份时存在、后来已经注销的会话；保留管理员与限速记录。备份中没有管理员时，启动后重新走本机引导。
6. 修改服务的 data-dir 指向恢复目录，启动、登录和检查 healthz；失败则停服，恢复原二进制和原完整目录。不要使用旧程序直接打开新 schema。

示例（停止 Web 后，在数据目录内执行，全部文件权限仅服务用户可读写）：

```sh
umask 077
sqlite3 meshmux.db ".backup '../meshmux-backup.db'"
sqlite3 ../meshmux-backup.db 'PRAGMA integrity_check;'
# 复制到新的恢复目录后，针对恢复副本执行：
sqlite3 /path/to/private-restored/meshmux.db \
  'BEGIN; DELETE FROM sessions; DELETE FROM bootstrap; COMMIT; PRAGMA integrity_check;'
```

忘记密码时没有 Web 后门：恢复可信备份；如果是无业务数据的阶段一测试环境，也可停服后保留旧目录、改用新的私有目录重新初始化。后者是测试重置，不是未来生产数据迁移策略。

## 日志和健康检查

`GET /healthz` 仅返回本机 Web/数据库探针 `{"status":"ok"}`；DB 不可用返回 503，不包含版本、凭据或主机信息，Caddy 候选拒绝公网访问。登录后 `GET /api/status` 返回真实 Web 状态，代理与 Mesh 等未实测业务状态按 OBSERVABILITY 标为 `unknown` / `pending-verification`。

响应带 `X-Operation-ID`。失败页面/JSON 包含 `operation_id`、`stage`、稳定 `error_code` 和下一步建议。常见错误包括 `AUTH_REQUIRED`、`SESSION_INVALID`、`CSRF_REJECTED`、`ORIGIN_REJECTED`、`HOST_REJECTED`、`FORM_INVALID`、`AUTH_FAILED`、`AUTH_RATE_LIMITED`、`DATABASE_UNAVAILABLE`。日志也记录初始化、登录、退出、改密完成事件；原始数据库/请求内容不会写入日志。启动期的本地配置/权限错误保留原因以便管理员定位，不包含凭据值。

## 订阅同步的 offline 码表

订阅凭据发布到 Line 时，Line 与 Node 在本域指同一条被纳管宿主：`nodes` 表的一行既是 Hub 可见的 Node，也是承载 VLESS 凭据的 Line。离线判定只有一处实现（`internal/web/store_subscriber_sync.go` 的 `subscriberLineNodeOfflineTx`），写路径与只读投影对同一时刻给出同一结论。

| 码 | 出现位置 | 触发 | 语义与影响 |
| --- | --- | --- | --- |
| `LINE_OFFLINE` | 写路径 `drainSubscriberNodeIntentTx` 返回 `errors.New("LINE_OFFLINE: line is offline; synchronization stays pending")`；`sanitizeSubscriberSyncCode` 截取冒号前的稳定码，作为 `web_event` 日志的 `error_code` | 显式发布/重试（`prepareSubscriberSync` / `retrySubscriberSync`）遇到离线 Line；自动 drain（Agent 轮询/心跳/结果触发的 `drainSubscriberNode`）遇到同一条件时静默丢弃该错误 | 本次不发布新候选、不入队 Agent 任务；订阅表中的意图保留，Line 恢复后由下一次轮询/心跳/结果 drain 补发。页面“同步”表单提交失败时 HTTP 响应码是 `SUBSCRIBER_SYNC_FAILED`（409），`LINE_OFFLINE` 只作为错误串和日志码出现 |
| `NODE_OFFLINE` | 只读投影 `subscriberLineSyncViewTx` 返回 `subscriberSyncPartial, "NODE_OFFLINE"`；订阅级聚合为 `sync_status=partial`，`sync_code` 取该订阅首个非空的 Line 码（多 Line 时可能是其他码，逐 Line 的 `sync_code` 始终保留） | 同一判定为离线 | 只报告未收敛，不写任何状态；页面显示“未收敛 · 需要处理”。恢复在线并完成回读后自然转为 `healthy` |

两码共用的判定（`subscriberLineNodeOfflineTx`）：

- `nodes.status = 'pending'`（从未配对）或 `last_heartbeat = 0`：离线。
- `now - last_heartbeat > offlineAfter`：离线。`offlineAfter = 2 * time.Minute`（`internal/web/store_nodes.go`）是唯一阈值。
- 恰好等于 2 分钟仍算在线（严格大于才离线）；`now` 由调用方注入、判定不直接读墙钟，Web 写路径与页面投影传入同一请求时钟。
- 行不存在时该判定返回离线标记并附带 `NODE_NOT_FOUND`，调用方优先按错误处理；数据库错误返回 `DATABASE_UNAVAILABLE`。两者都以对应稳定码进入 `sync_code`，不会变成 `LINE_OFFLINE` / `NODE_OFFLINE`。

**不改码声明**：双码是既有对外契约，不是待清理的重复。`internal/web/store_subscriber_sync_test.go` 分别钉住 `LINE_OFFLINE`（写路径错误串）与 `NODE_OFFLINE`（投影 code）；收窄为单码会改变已合入行为与测试，超出文档范围。本节只统一语义说明，不改变任何 Go 代码、判定阈值或 HTTP 行为。

## 依赖与前端再生成

依赖与许可证核查见 [DEPENDENCIES](DEPENDENCIES.zh-CN.md)。所有浏览器资源嵌入二进制，不从 CDN 加载；HTMX 仅用于只读状态刷新，关闭 eval、脚本执行和 history 缓存，网络/会话错误有文字反馈。登录、初始化、改密、退出使用原生表单，无 JavaScript 也可完成。

templ 生成文件提交到 Git，普通构建无需安装前端工具或生成器。修改模板后：

```sh
go generate ./internal/web
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/meshmux
go build ./cmd/meshmux-web
```

CI 保留原有格式、vet、test、race、build，扩展原 Build 步骤编译 Web；独立的 `web-preview` 作业仅负责本阶段必要的浏览器流程和截图，不引入应用构建工具链。`TestServiceProcess` 在普通用户下启动真实服务子进程，验证初始化、登录、SIGINT 优雅退出、重启保持会话及注销；root 环境验证启动失败且不写数据。页面截图、环境限制与本阶段证据见 [previews](previews/README.md)。
