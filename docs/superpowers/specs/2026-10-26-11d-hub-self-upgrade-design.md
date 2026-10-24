# 11d Hub 自升级执行设计（第 2 稿，送审）

所属：#11 v1.0.0 Web 统一升级，7 段串行之第 6 段（11c-3 已合入 main，基线 `f82f84c`）。
状态：设计送审。第 1 稿两份评审均为 NEEDS-REWORK；本稿重做执行基座（§5.1）、对账与确认（§5.4/§5.5）、属主与恢复（§5.7）、manifest 信任链（§5.8），并把 co-located Line 重钉纳入范围（§5.6）。11e（兼容矩阵内容）与 C 级 VM/真机验收（归 #12）不在本文范围；本文只消费 11c-3 已冻结的备份/确认/回退接口，不重定义其中任何语义。

## 1. 背景与意图

11c-2 让 Line/Out 自替换，11c-3 定了 Hub 数据库备份记录、健康门控确认、分级 revert、`database_versions` 与不可逆确认位，但没有执行者：

1. Hub 自己不能升级：今天只能手工停服、改 `--data-dir`、换二进制，Web 统一升级在 Hub 断链。
2. 有写者没消费者：`POST /tasks/db-migration/approve` 让操作员“从 Hub 自升级的备份记录复制 `operation_id`”，却没有代码写这份记录；`database_versions` 没有生产读消费者；`server_upgrade_check.go` 仍 pin 自己运行的版本。
3. 顺序无机制保证：新 Hub 才懂新记录/新 schema，先升 Line/Out 会让旧 Hub 读不懂回执。

还有一条第 1 稿漏掉的硬事实：**Hub 与 co-located Line 共用 `/usr/local/libexec/meshmuxd`**，Line 的 `/etc/meshmux/agent.json` 与 Hub ledger 的 `shared_binaries.meshmuxd` 都钉住这个二进制的摘要。换 Hub 二进制必然触碰 Line，`SHARED_BINARY_MISMATCH` preflight 会拒绝 Line 启动。11d 必须把“换 Hub”做成一次协调重钉，或显式 fail-closed。

## 2. 目标

1. Hub 自升级闭环：预升级备份 → root 预置目标 manifest → 已校验 staged 包 → 换二进制 + Line 重钉 → 重启 → 启动身份回读确认，失败可恢复。
2. **Hub 先升**：Hub 确认后才允许为 Line/Out pin 更新的目标（§5.8）。
3. 执行与浏览器/页面连接无关：交接后由 PID 1 托管，页面只读磁盘 op journal。
4. 重启后可查询：op journal 与 result 文件跨 schema、跨 data-dir 存活；DB 表是 schema 11 内的镜像（§5.5）。
5. 恢复可用：停机前校验 → 停 Web → 换回旧二进制 → 新 0700 目录 → 翻 data-dir → `/healthz` 200 → 只读身份核对。
6. 消费 11c-3 的备份记录、确认位、`database_versions`、`SCHEMA_TOO_NEW` 与空间规则；不新增公开 CLI、不新增 protocol kind。

## 3. 非目标

- **11e 兼容矩阵内容**。11d 只定 gate 形状与 fail-closed 行为。
- **C 级验收**（隔离 VM、真机 Debian 13 amd64/arm64）——归 #12；本文只承诺 B 级 fixture 证据。
- **发布通道自动化**：Hub 自有目标 manifest 的获取/签名属 12e 及后续；v1.0 由 root 预置（§5.8），Web 只做选择与执行，不下载 manifest。
- **LKG 回退的 Web 一键入口**（11c-3 语义可用，不新增按钮）。
- **N-1 以上的多代 Hub 回退**（只保留一代，§5.7）。
- **`web → update` 反向导入**，除非引入中立叶子包（§5.9、Q3）。

## 4. 约束（继承 11c-3；C19–C22 为本稿新增）

- **C1 扁平布局**：Hub 备份固定为 `<data-dir>/database-backup/record.json`（0600）+ `payload/`（0700 目录、0600 文件），只保留一代；不复用 Node 的 `<root>/<op32hex>/` 每操作目录语义。
- **C2 记录冻结**：`update.BackupRecord` schema 1、`DisallowUnknownFields`、尾随数据拒绝、≤64 KiB；JSON 字节必须完全一致。**只有一个编码器**：`WriteBackupRecord` 参数化布局与载荷来源（§5.2），不新写平行 writer。
- **C3 状态机**：记录先写 `staged`，只有门控 finalize 后才是 `confirmed`；`failed` 是终态。11d 的门控就是启动身份回读（§5.5），finalize 本身沿用 11c-3，不改语义。
- **C4 完整性顺序钉死**：`VACUUM INTO` 生成副本 → 在**副本**上 `PRAGMA integrity_check` → 才写 `integrity_ok=true`。
- **C5 载荷含秘密**：payload 含订阅凭据、token hash、会话；0700/0600、`meshmux` 属主、永不离机、不进日志/回执。
- **C6 双摘要分离**：`from_package_sha256` = 安装包摘要（installer ledger `artifacts.meshmuxd`）；`from_agent_sha256` = 运行二进制摘要（`buildinfo.Digest()`）。两者来源不同、永不合并、永不互比；Hub 记录要求两者非空，缺失即 `HUB_BACKUP_IDENTITY_MISSING`。`db_schema` 写真实 `PRAGMA user_version`（今天 10）。
- **C7 `database_versions` 写点冻结**：只在 store-open 迁移提交后由启动写者写。健康回读与管理面回读**只消费**，绝不写；旧行只在下一次启动自愈。该行是降级提示，不是迁移门。
- **C8 `SCHEMA_TOO_NEW`**：只 `lstat` 记录存在性，不解析未来 schema；不原地降级。
- **C9 不可逆位在记录上**：`irreversible_approved` 只有 `POST /tasks/db-migration/approve` 一个写者（session + 精确 Origin + CSRF + 字面值 `irreversible_confirm=1` + `operation_id`）。破坏性步骤前必须读位并重验载荷（staged/confirmed + `integrity_ok` + 非空私有 payload + `PayloadSHA256`）；审批是 metadata-only，恢复必须在副本上重跑 `integrity_check`。
- **C10 分级 revert**：停机前完成全部校验 → 停 Web → 换回旧二进制 → 恢复到**新** 0700 目录 → `integrity_check` → 翻 `--data-dir`（drop-in）→ `/healthz` 200 → 旧目录保留到确认。中途失败 = 终态 + 人工指引，原目录不动。
- **C11 in-place down-migration**：只在新表为空且无新 binary 确认写时允许。**11d 显式把 schema 10 → 11**，升级后 `hub_upgrade_operations` 立即可有行，"新表为空"永不成立；因此 11d 的 op 一律只能 restore，不得 DROP 表降级。
- **C12 确认是回读的副作用**：锚比较在 `confirmed` 短路**之前**；已被 revert 的操作永不确认；没有 `confirmUpgrade` 平行裁决。
- **C13 LKG 回退**：重发 LKG 的 candidate revision 走既有 four-task 链（`resurrect-after-delete` 是接受的固有语义，文档须写明）。
- **C14 空间下限重推导**：Node 的 1024 MiB 常量不覆盖 Hub DB 载荷（§5.9）。
- **C15 启动稳定码**：只有 `SCHEMA_TOO_NEW` 记 `detail`（记录路径，无秘密）；其他只记稳定码。
- **C16 执行面**：无新 protocol kind（`upgrade.*` 继续拒绝）、无新公开 CLI、固定 argv、无 shell、每写带 `operation_id`、回执诚实（queued/gated/applied/failed/rolled_back，applied 只由回读证明）、manifest pin + SHA-256 先于执行、日志脱敏。
- **C17 模块方向**：`internal/update` 不得 import `internal/web`；今天唯一反向边是 `web → update`（仅为 `BackupRecord`）。
- **C18 D2/D5**：孤儿兜底是纯 30 分钟年龄（不查 Hub）；GC 只在 confirmed 之后的下一次升级或显式清理时发生。
- **C19 执行基座**：Web（`meshmux`，`CapabilityBoundingSet=`、`NoNewPrivileges=true`、`ProtectSystem=strict`）没有任何特权。**不引入 setuid/文件能力二进制**（11c-2 对 Agent 已排除，Hub 自有裁决相同）、**不给 Web 授 polkit**、**不让 Web 构造 ExecStart 或单元属性**。唯一触发是 root 属主的 path unit 监视一个 meshmux 可写目录。
- **C20 信任锚在执行侧**：目标 manifest 只能来自 root 属主文件；Web 给的 target/digest 只是选择，不是授权。执行体必须是按该 manifest 摘要校验过的 staged 包，并对 `/proc/self/exe` 重算 `--expected-sha256`。
- **C21 回读单向**：`confirmed` 只由“running 身份 == 记录 target”证明，不由 result 文件、unit 退出码或 UI 证明；`database_versions` 只由启动写。
- **C22 写者固定**：root unit 只写二进制、`/etc/meshmux`、`/etc/systemd/system`、result 文件与 `hub-upgrade` 文件；不写 DB。Web 只写 data-dir 内的记录/载荷/journal 与 `/run/meshmux-hub/requests/` 的请求文件；不写二进制与 unit。

## 5. 设计

### 5.1 执行基座（本稿核心决定）

第 1 稿的 `systemd-run` 前提不成立：向 systemd 提交 transient 单元需要 `org.freedesktop.systemd1.manage-units` 授权，而 polkit 规则**无法约束 transient 单元的 ExecStart**；给 meshmux 这条授权等于让它指定任意 root 命令，且不存在可收窄的写法。11c-2 能这么做是因为调用者 Agent 本来就是 root。

**选择：root 属主静态 oneshot + 校验请求文件 + path unit 触发。** 不用 `systemd-run`，不写 polkit 规则，不用常驻 root helper socket，不用 setuid。

installer 写入两个 root:root 0644 单元（`meshmux-hub-dispatch.path` enable，service 不 enable）、一条 tmpfiles 规则（`d /run/meshmux-hub 0730 root meshmux`、`d /run/meshmux-hub/requests 0730 root meshmux`）：

```
# meshmux-hub-dispatch.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/meshmuxd __internal-hub-dispatch --request-dir /run/meshmux-hub/requests
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run/meshmux-hub /usr/local/libexec /var/lib/meshmux /var/lib/meshmux-installer /etc/meshmux /etc/systemd/system
PrivateTmp=yes
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE

# meshmux-hub-dispatch.path
[Path]
DirectoryNotEmpty=/run/meshmux-hub/requests
```

- **请求目录固定在 `/run` 而不是 data-dir**：§5.7 会翻转 `--data-dir`，单元 ExecStart 不能随之改变；请求只是短命意图，重启丢失即由 §5.5 的超时判定收尾。dispatcher 处理成功后把请求 rename 到 `<data-dir>/hub-upgrade/requests.done/`，目录恢复为空以便 path unit 重新武装。
- Web 只写一个 0600 请求文件（temp + fsync + rename）并先提交 `queued`；path unit 与 oneshot 都由 PID 1 触发，**Web 不作任何特权调用**。第 1 稿的 `--no-block` 阻塞问题因此整体消失；等价钉死是“先提交 `queued`，后 rename 请求文件”（回执先于交接）。
- **请求文件不是授权**：`{schema:1, kind:"update"|"restore", operation_id:"<32hex>", data_dir:"<绝对路径>"}`，≤1 KiB、严格 JSON、`O_NOFOLLOW`、属主 == meshmux、0600。`data_dir` 必须是 clean 绝对路径且**等于当前 `meshmux-web.service`（含 drop-in）`--data-dir` 的值**（root 读单元文本比对），Web 无法用它指向别处。目标、摘要、路径全部由 root 侧从冻结记录与 root manifest 重新推导。
- **dispatcher 不执行升级写**：严格读 journal（§5.5）+ 冻结记录（root 读端按 meshmux 属主校验，§5.9）→ 校验 state/target/摘要 → 读 root manifest 重算 `package_sha256` → 按 fd 校验 `<data-dir>/upgrade/meshmuxd-<target>-<arch>` 字节 → 把**已校验字节**复制到 root-only 的 `/var/lib/meshmux-installer/upgrade/exec-<op32hex>`（EXDEV 时复制 + fsync）→ `exec` 该副本。校验后再按路径打开会被 Web 换字节（TOCTOU），所以 exec 的是校验过的副本。
- 真正改系统的代码是 staged 包自己的 `__internal-hub-update` / `__internal-hub-restore`，启动即对 `/proc/self/exe` 重算 `--expected-sha256`（11c-2 先例）。**单元 ExecStart 是固定 dispatcher，这是对“ExecStart 必须是 staged 包”这一不变量在静态单元下的等价实现**：static 单元无法随 target 改变 ExecStart，而让 Web 构造 argv 正是要消除的特权面；不变量因此钉在 exec 边界——dispatcher 本身不做任何升级写，升级写体是 root manifest 摘要钉死并自校验的 staged 包，已安装二进制只承担固定调度。
- **新增特权面登记（自有评审项 R-SURFACE，见 §6.11）**：1 个 root oneshot + 1 个 path unit + 1 个 meshmux 可写请求目录；它们能造成的唯一效果是“执行一份由 root manifest 摘要钉死的发布包”。
- dispatcher 见到 >1 个请求文件一律拒绝并写 `HUB_HANDOFF_BUSY`；单个请求校验失败时写 result `failed` + 稳定码（能解析出 op 时）再退出，无法解析者移到 `requests.done/rejected-<unix>` 并只记日志；单飞主判定在 Web（§5.2）。

### 5.2 Producer：备份、交接与单飞

`/tasks` 边界上的三步管理员 mutation（都走既有 `app.mutation`）：

| 路由 | 输入 | 作用 | 回执 |
| --- | --- | --- | --- |
| `POST /tasks/hub-upgrade/backup` | `target_version` | 解析并校验 root manifest，生成 `operation_id`，建 op journal（`backing_up`），执行 VACUUM→校验→staged 记录 | `status=staged`、`operation_id`、`from_version`、`db_schema`、`integrity_ok` |
| `POST /tasks/hub-upgrade/apply` | `operation_id` | 再校验记录/root manifest 一致、不可逆位、空间；stage 目标包；提交 `queued` + 请求文件 | `status=queued`、`target_version` |
| `POST /tasks/hub-upgrade/restore` | `operation_id` | §5.7（仅 `failed`/`partial`/`verifying`） | `status=restoring` |

目标与摘要在 backup 时确定（冻结记录不允许空字段），apply 不接收 digest、只做再校验；页面流程因此固定为“选目标（列出 root 预置且校验通过的 manifest）→ 备份 → 如不可逆先写确认位 → 提交”。apply 在 manifest `database_migration=irreversible` 而记录 `irreversible_approved=false` 时返回 `IRREVERSIBLE_CONFIRM_REQUIRED`，零变更。

**单飞（C18/D5）**：任一 op 处于非终态（`backing_up|backed_up|queued|applying|restarting|verifying|partial`）或当前记录 `irreversible_approved=true` 时，`backup` 一律 `UPDATE_BACKUP_MISMATCH`（沿用 11c-3 的“已有未完成来源”语义）零变更；不做并发备份。`restored.json` 不阻塞新备份（它只禁止把携带记录当恢复源，§5.7），新 staged 记录落盘时一并清除。

**顺序（rotate before replace，钉死）：**

1. 生成 `operation_id`（32 位小写 hex，`crypto/rand`）；解析并校验 root manifest（§5.8），得 `manifest_sha256`/`package_sha256`。
2. **把运行中的二进制 stage 成旧包**：`buildinfo.Digest()` 读 `/proc/self/exe` → 复制到 `<data-dir>/upgrade/meshmuxd-<from_version>-<arch>`（0755，fsync + rename），回读摘要必须 == `from_agent_sha256`。失败 `HUB_BACKUP_BINARY_STAGE_FAILED`。**没有这一步，恢复默认就是 `HUB_RESTORE_BINARY_MISSING`。**
3. `payload.part/` 建 0700；`VACUUM INTO '<payload.part>/meshmux.db'`（事务之外；目标必须不存在；路径是固定常量 + `op32hex` 派生）。
4. 只读打开副本 → `PRAGMA integrity_check` 必须 `ok`。
5. 计算 `meshmux.db` 的 SHA-256，`payload_files=1`。
6. `payload.part`→`payload`；写 `record.json.part`→fsync→rename；`state=staged`、`integrity_ok=true`。
7. **只有 staged 记录落盘后**才回收旧一代（先 rename 到 `.trash-<unix>` 再 `RemoveAll`）。失败一律删 `.part`、旧代原样保留、回执 `failed` + 稳定码。

**字段映射：**

| 字段 | 值 |
| --- | --- |
| `from_version` | `buildinfo.Version` |
| `target_version` | 请求的目标版本（== root manifest `version`） |
| `db_schema` | 真实 `PRAGMA user_version`（今天 10） |
| `policy_schema` | `upgrade.PolicySchema`（8） |
| `manifest_sha256` / `package_sha256` | root manifest 字节摘要 / 该 manifest 中 `meshmuxd-<arch>` 的摘要 |
| `from_package_sha256` | installer ledger `artifacts.meshmuxd`（安装包摘要，C6） |
| `from_agent_sha256` | `buildinfo.Digest()`（运行二进制摘要，C6） |
| `payload_path` / `payload_files` | `<data-dir>/database-backup/payload` / 1 |

**C2 的落地**：不新增 `WriteHubBackupRecord`。把既有 `WriteBackupRecord` 参数化为 `WriteBackupRecord(root, spec, layout, payload)`：`layout ∈ {LayoutFlat, LayoutPerOp}`，`payload ∈ {PayloadTree, PayloadSingleDB}`；两种布局共用同一个 `encodeBackupRecord` 与同一套状态/权限校验，测试对两种布局断言 `record.json` **逐字节相同**。扁平布局拒绝 `<data-dir>/database-backup/<op32hex>/` 残留（不采用、不迁移）。

### 5.3 版本身份（单一来源）

- 新增 `internal/buildinfo`（只 import 标准库）：`Version` 由 `-ldflags -X .../internal/buildinfo.Version` 注入，缺省 `1.0.0-dev`；`Digest()` 打开 `/proc/self/exe`（不是 `os.Executable()`）算 SHA-256，上限 128 MiB，失败返回 `HUB_DIGEST_UNAVAILABLE`，不猜。
- **单一来源**：`node.CurrentAgentVersion` 改为 `var = buildinfo.Version`；`upgrade.ForArch`/`ForArchSet` 继续打它，所以 Agent 与 Hub 的 manifest 投影仍逐字节相同，不允许两条路径各自注入版本。**manifest 字节/摘要影响**：`version` 在 canonical JSON 内，改 ldflags 版本等于改所有 manifest 摘要；fixture 金标与任何 pin 必须与版本注入同一次提交重算。
- `confirmDatabaseVersion` 改写 `buildinfo.Version`。旧行（`1.0.0-dev`）**只在下一次启动自愈**，健康/管理面回读不改它。

### 5.4 健康与身份回读

- `GET /healthz` 保持 **SELECT 1** 契约：200 `{"status":"ok"}` / 503，不带 DB 身份语义、不写。Caddy 与安装器依赖这个形状。
- 身份回读搬到管理面：`GET /tasks` 的 Hub 区块（仅认证管理员）读取 `PRAGMA user_version` 与 `database_versions` 行；30s 有界定时器刷新同一份只读快照。**所有写仍只在启动**。
- 判定（只产出管理面事件，不改变 `/healthz`）：

| `user_version` | `database_versions` 行 | 结果 |
| --- | --- | --- |
| ≠ 本构建 schema | 任意 | `SCHEMA_READBACK_FAILED`（管理面；健康仍 200） |
| = | 不存在 | `DATABASE_UNCONFIRMED`（管理面；不是启动码） |
| = | `(last_good_version, last_good_schema) == (buildinfo.Version, schema)` | 身份确认 |
| = | 存在但不匹配 | `DATABASE_VERSION_MISMATCH` 事件，不写 |

- 存在 `verifying` 的 op 时，回读额外把该行与 `journal.target_version`/`journal.package_sha256` 比对；不一致即 `DATABASE_VERSION_MISMATCH`（只读消费，正好是 11c-3 想要的“row vs 记录 target”核对，但**不写行**）。
- `database_versions` 是降级提示不是迁移门（C7）：门仍是启动时 `user_version` 比较。身份不匹配不拒绝服务——服务确实可用，只是自述未确认。
- **观察不依赖浏览器**，但也不依赖请求：启动对账 + 30s 定时器推进（§5.5）。第 1 稿“只有 request 触发”的写法是错的，本稿删除。

### 5.5 Apply、journal、对账与确认

**op journal 是权威，DB 表是镜像。** 恢复会把 DB 带回 schema 10（`hub_upgrade_operations` 不存在），所以 op 状态必须跨 schema 与 data-dir 存活：

- `<data-dir>/hub-upgrade/ops/<op32hex>.json`（0600，schema 1）：`operation_id`、`kind`、`state`、`target_version`、`from_version`、`manifest_sha256`、`package_sha256`、`db_schema`、`backup_generation`、`error_code`、`updated_at`。Web 写；恢复时随 `hub-upgrade/` 带入新 data-dir。`backup_generation` 由 Web 在每次成功 backup 时自增（记录无此字段，C2 冻结）。
- `hub_upgrade_operations`（schema 11，纯加法）是镜像，供 SQL 查询：同名列 + `detail`/`created_at`/`updated_at`。锚字段与记录同源，写入时断言与冻结记录相等；dispatcher 只读 journal 与记录，从不读 DB。

```
hub_upgrade_operations(
  operation_id TEXT PRIMARY KEY, target_version TEXT NOT NULL, from_version TEXT NOT NULL,
  state TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
  manifest_sha256 TEXT NOT NULL, package_sha256 TEXT NOT NULL, db_schema INTEGER NOT NULL,
  backup_generation INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
)
```

不复用 `agent_tasks`（`node_id` 外键、Agent 协议语义、单飞判定与 allowlist 都会被污染），也不复用候选修订链。

状态机（一个 `operation_id` 从备份穿到确认）：`backing_up → backed_up → queued → applying → restarting → verifying → confirmed | reverted | failed`，只向前；`partial` 由 `applying/restarting/verifying/failed` 在“已改盘但无法完成”时进入，需要人工或 restore。`backed_up` 之前不得交接。

**交接（按序）**：(1) 记录/root manifest/不可逆位/空间再校验；(2) stage 目标包（§5.8：先空间检查，`.part`+摘要+fsync+rename，幂等复用），失败 → `failed HUB_BACKUP_STAGE_FAILED`，零其他变更；(3) 提交 `queued` 到 journal（fsync+rename）；(4) 写 `/run/meshmux-hub/requests/<op32hex>.json`（temp+rename），失败 → `failed HUB_HANDOFF_WRITE_FAILED`。此后不存在同步等待，页面可关。

**对账（启动 + 30s 定时器；覆盖全部非终态）：**

| journal 状态 | 条件 | 动作 |
| --- | --- | --- |
| `queued` | 无 result 且 age > 120s | `failed HUB_HANDOFF_TIMEOUT`，删除请求文件以便重试（这修掉“queued 永久悬挂”） |
| `queued`/`applying` | result `accepted`/`swapping` | 置 `applying`；age > 30min 无进展 → `failed HUB_UPGRADE_ORPHANED`（C18 纯年龄） |
| `queued`/`applying`/`restarting` | result `restarting`/`restart-accepted` | 置 `restarting`，按身份判定（下条） |
| `restarting` | 身份 == target | `verifying` → 确认 |
| `restarting` | 身份 == from | `failed HUB_UPGRADE_NOT_APPLIED` |
| `verifying` | — | 确认或 `failed HUB_UPGRADE_VERIFY_MISMATCH` |
| 任意 | result `failed`/`partial` | 应用该终态 |

**`confirmed` 判定（唯一）**：`buildinfo.Version == journal.target_version && buildinfo.Digest() == journal.package_sha256`。`from_*` 只用于恢复/重钉核对，**永不**与升级后的运行值比较（升级后 running 就是 target，`from_*` 必然不等）。判定只在启动对账执行；定时器只推进状态与超时，不确认。确认时调用 11c-3 既有 finalize 把备份记录置 `confirmed`（语义不改，GC 仍只在其后），并写 DB 镜像。`reverted` 终态不被后续启动覆盖（C12）。

**重启后查询**：`GET /tasks` 的 Hub 区块读 journal + result；无内存依赖。

### 5.6 升级执行体（staged 包，含 Line 重钉）

```
<data-dir>/upgrade/meshmuxd-<target>-<arch> __internal-hub-update
  --target <semver> --expected-sha256 <64hex> --operation-id <op32hex>
  --data-dir <data-dir> --from-version <semver>
```

逐字节 pin。步骤固定、先写后做：

1. 校验 argv 形状与 `/proc/self/exe` 摘要 == `--expected-sha256`；不符 `HUB_UPDATE_DIGEST_MISMATCH`，零写。
2. 严格读冻结记录、journal 与 root manifest：journal `state ∈ {queued, applying}`、记录 `state=staged`、`operation_id`/`target`/`package_sha256`/`manifest_sha256` 与 argv 及 manifest 字节一致；不符 `HUB_MANIFEST_PACKAGE_MISMATCH` 或 `UPDATE_BACKUP_MISMATCH`。
3. **Line 预检（任何写之前）**：存在 co-located Line 时，ledger `shared_binaries.meshmuxd.sha256` 与 `/etc/meshmux/agent.json` 的 `agent_sha256` 必须都等于当前 `/usr/local/libexec/meshmuxd` 的摘要，否则 `HUB_SHARED_BINARY_PRECHECK_FAILED` 终态、零写。
4. 结果文件写 `accepted`（交接回执），再写 `swapping`（先写后做）。
5. 同目录 `meshmuxd.new`（写自身字节、0755、fsync）→ rename 覆盖 `/usr/local/libexec/meshmuxd` → fsync 目录。
6. **Line 重钉**：原子改写 `/etc/meshmux/agent.json` 的 `agent_version`/`agent_sha256` 与 Hub ledger `shared_binaries.meshmuxd.sha256`（temp+fsync+rename）；Line 单元 active 时 `systemctl restart meshmux-agent.service`，不存在则跳过并在 result 注明。
7. 结果文件写 `restarting`（**在 restart 之前**，沿用 `install_cmd.go:88-96` 的 `installed-awaiting-restart` 先例），然后 `systemctl restart meshmux-web.service`；成功后补写 `restart-accepted`（尽力而为）。
8. 失败回退：第 5–7 步任一失败 → 用 backup 时 stage 的旧包（摘要 == `from_agent_sha256`）换回二进制、恢复旧 pin、重启 Line，写 `failed` + `HUB_SHARED_BINARY_REPIN_FAILED`/`HUB_UPGRADE_RESTART_FAILED`；换回也失败 → `partial`，不重启 Web，人工指引。
9. 不写 DB、不写 unit 文件、不写 journal；成功后删除 `/var/lib/meshmux-installer/upgrade/exec-<op>` 副本（失败/崩溃时由下一次成功 op 或显式清理回收）。单元是 `meshmux-web.service` 的兄弟，重启 Web 不影响它继续跑。

### 5.7 Restore executor

执行体是**旧**包：`<data-dir>/upgrade/meshmuxd-<from_version>-<arch> __internal-hub-restore --expected-sha256 <from_agent_sha256> --operation-id <op32hex> --data-dir <data-dir> --restore-dir <data-dir>/restore-<op32hex>-<unix>`（固定 argv，独立字节 pin，首步同样自校验 `/proc/self/exe`）。用与待恢复库同代的二进制，天然避免“新二进制打开旧库”的误迁移。

**停机前（失败 = 零停机零变更）：**

1. 严格读记录与 journal；journal `state ∈ {failed, partial, verifying}`、记录 `state ∈ {staged, confirmed}`、`integrity_ok`、`payload_files>0`。
2. 重算 `payload/meshmux.db` 的 SHA-256 == `PayloadSHA256`（`integrity_check` 不等于“字节正确”）。
3. 建新目录 0700；把副本落入新目录，并在**副本**上 `PRAGMA integrity_check`。
4. **用原始只读连接**（`mode=ro&immutable=1`，不经 store-open/迁移）读副本自身的 `user_version` 与 `database_versions` 行，与记录的 `from_version`/`db_schema` 比较；不等或行缺失 → `CONFIG_CONFLICT`，停机前返回。第 1 稿用新二进制打开 schema 10 副本必然不一致，这是恒定误报。
5. 旧包存在且摘要 == `from_agent_sha256`，否则 `HUB_RESTORE_BINARY_MISSING`（producer 已保证不再默认缺）。
6. 解析当前 web 单元的单行 `ExecStart` 形状，生成 drop-in 临时文件；形状不符 `HUB_RESTORE_UNIT_SHAPE_INVALID`。
7. 空间检查（§5.9）。

**停机后：** 停 Web → 旧包换回二进制（同目录 `meshmuxd.new` + rename）→ Line 重钉回 `from_*` 并重启 → 写 `/etc/systemd/system/meshmux-web.service.d/10-data-dir.conf`（`ExecStart=` 复位 + 重写同一 argv、仅 `--data-dir` 改变；temp+fsync+rename+fsync 目录）→ `daemon-reload` → `start` → 轮询 `/healthz` 200（60s；SELECT 1 契约，只证存活）→ 原始只读连接核对恢复库身份 → result `restored`。data-dir 翻转**只用 drop-in**，基础单元不动；不再有“改写 ExecStart 或读 `hub-data-dir` 文件”的二选一。

- 新建目录、恢复库、携带的 `database-backup/` 与 `hub-upgrade/` 全部 `chown -R meshmux:meshmux`。
- **携带记录的限制**：`record.json` 按字节原样保留（C2），其 `payload_path` 仍指旧 data-dir，且其 state 不能代表恢复后事实；因此只可作 `SCHEMA_TOO_NEW` 的 existence-only 指引，不得作为下一次恢复源。启动对账见到 result `restored` 时写 `hub-upgrade/restored.json` 标记并把 journal 置 `reverted`（终态）；读取端见到标记即拒绝把携带记录当 rollback source，新 staged 记录落盘时清除标记。
- 恢复后 DB 是 schema 10，op 镜像消失；op 事实来自 journal + result（已随目录携带），UI 读它们。
- 中途失败 = 终态 + 人工指引，原目录不动，Web 保持 down；不自动重试。若二进制/pin 已改，先换回再落 `partial`。
- 二进制回退只对“加法迁移”的库成立（C11）；11d 自己的 op 永远走这条 restore。
- **LKG 语义适用范围**：11c-3 的“重发 LKG candidate revision”是 Line/Out 的回退机制，11d 原样保留；Hub 没有 candidate revision 链，只有 restore 一条路，不得把 four-task 链套到 Hub。

### 5.8 Manifest 与 pin lifting（含不可逆来源）

- Hub 只为**可认证**的 manifest 发 pin：自己构建的 set（`upgrade.ForArchSet()`，今天的行为）或 root 预置并通过下表校验的目标 manifest（pin 提升）；绝不解析、转发或信任 Web 提交的 manifest 字节。
- **Hub 自己的目标**（新增，必须显式）：

| 项 | 值 |
| --- | --- |
| 源 | `/var/lib/meshmux-installer/upgrade/manifest-<target>.json`，root:root 0755/0644；由安装/运维以 root 预置；Web 不可写 |
| 认证（信任前） | 严格 JSON + `upgrade.Manifest.Validate` + `version == target` + 本架条目 + `policy_schema == upgrade.PolicySchema` + `version > running`；字节 SHA-256 冻结进记录 |
| 包来源 | 该 manifest 的 `components[meshmuxd-<arch>].Source`；生产形态是固定 GitHub release asset（`…/releases/download/v<target>/…`，拒绝 `latest`/`main`/可变标签），但 **12e 之前 `meshmuxd` 仍是 `file://` dev pin，见 §8** |
| 谁 stage 包 | **Web 在 apply 阶段**（backup 不下载）：先 `HUB_SPACE_INSUFFICIENT` 检查 → `.part` 下载/复制 → 摘要校验 → fsync → rename 为 `meshmuxd-<target>-<arch>`；已存在且摘要相同则幂等复用，摘要不符删掉重取 |
| `MANIFEST_UNAVAILABLE` 推导 | 文件缺失/不可读/非 root 属主或非 0644/JSON 或 Validate 失败/版本不等/架构缺失/policy_schema 不符/版本 ≤ running → 零写入 |

信任链完整形状：root 属主 manifest（锚）→ 摘要 → staged 包字节 → dispatcher 校验 → exec 副本自校验。Web 只能选择“root 已认可的目标”，不能提供字节或摘要。

- pin 提升 gate（形状；矩阵内容 11e）：目标 manifest 可被认证，且 `Compatibility(target, running, arch, dbschema)` 为 true；矩阵不可用同样 fail-closed。Hub 升完后 running 前移，自然解锁对 Line/Out 的更新 pin。
- **不可逆来源字段**：manifest 增可选 `database_migration` ∈ {`additive`（缺省）, `irreversible`}，由 `upgrade.Manifest.Validate` 校验；缺省即不可逆=false。字段在 manifest 字节内，因此被 `manifest_sha256` 钉住。`irreversible` 时 apply 必须见到记录 `irreversible_approved=true`，否则 `IRREVERSIBLE_CONFIRM_REQUIRED` 零变更（与 §5.2 apply、§5.11 同一条件）。
- co-located Line 的共享二进制**不再“保持原样”**：§5.6 第 3/6 步即协调重钉；`SHARED_BINARY_MISMATCH` 仍是最后防线，不再是 11d 的挡箭牌。

### 5.9 空间 / 属主 / 日志 / ledger

```
hubRequiredSpace = 128 MiB (目标包) + 2×dbSize (VACUUM 副本+旧代)
                 + 128 MiB (旧包) + dbSize (恢复新目录) + 256 MiB (journal/result/余量/exec 副本)
hubSpaceFloor    = max(hubRequiredSpace, 1 GiB)   # 1 GiB = 安装器既有预检下限
```

`HUB_SPACE_INSUFFICIENT` 在每次复制/下载前检查（备份副本、目标包 stage、恢复目录），零变更；公式单测钉住。

| 路径 | 属主/模式 | 写者 |
| --- | --- | --- |
| `/var/lib/meshmux` | meshmux 0700 | installer |
| `database-backup/`、`payload/` | meshmux 0700 / 文件 0600 | Web |
| `record.json` | meshmux 0600 | Web |
| `upgrade/`（两代包） | meshmux 0700 / 包 0755 | Web |
| `hub-upgrade/ops/` | meshmux 0700 / 0600 | Web |
| `hub-upgrade/results/` | root:meshmux 0750 / 文件 0640 | root unit（Web 只读，不能改/删） |
| `hub-upgrade/requests.done/` | root:root 0700 | dispatcher |
| `/run/meshmux-hub/requests/` | root:meshmux 0730 / 文件 0600 | Web；dispatcher 消费 |
| `/var/lib/meshmux-installer/upgrade/manifest-*.json`、`exec-*` | root:root 0755/0644、0700 | root |
| `/etc/meshmux/agent.json`、ledger | root 0640/0600 | root unit |

- `ownedByCurrentUser` 不能用于跨 uid：Hub 读端参数化为 `expectedOwner`（Web 进程 = meshmux；root unit = meshmux），仍要求 0600/0700；root 不得以“反正能读”绕过属主检查。
- **能力集是 Hub 自有裁决**：`CAP_CHOWN`（恢复族把新 data-dir 整树归还 meshmux；结果目录/文件定属主）与 `CAP_DAC_OVERRIDE`（root 单元要读 meshmux 0600 的 record/payload、要往 meshmux 0700 的 data-dir 写 result）都需要；11c-2 排除 DAC_OVERRIDE 是因为它的写集全是 root 属主，Hub 跨 uid，前提不同。真正的边界仍是固定 argv、枚举的 `ReadWritePaths`、root 属主 manifest 与 `expectedOwner` 校验——能力集不是授权，DAC_OVERRIDE 不改变“只能执行 root 认可的那一份包”。
- 日志：op id、阶段、稳定码、版本、摘要；不记 token、订阅 URL、DB 内容；只有 `SCHEMA_TOO_NEW` 记 detail（记录路径）。
- 稳定码分组：**启动** `SCHEMA_TOO_NEW`(detail)、`SCHEMA_READBACK_FAILED`、`SCHEMA_CONFIRM_FAILED`、`HUB_DIGEST_UNAVAILABLE`；**健康** `DATABASE_UNAVAILABLE`（503，仅 SELECT 1）；**管理面/执行** `DATABASE_UNCONFIRMED`、`DATABASE_VERSION_MISMATCH`、`MANIFEST_UNAVAILABLE`、`HUB_MANIFEST_PACKAGE_MISMATCH`、`IRREVERSIBLE_CONFIRM_REQUIRED`、`HUB_SPACE_INSUFFICIENT`、`HUB_BACKUP_*`、`HUB_HANDOFF_*`、`HUB_UPDATE_*`、`HUB_UPGRADE_*`、`HUB_SHARED_BINARY_*`、`HUB_RESTORE_*`、`UPDATE_BACKUP_MISMATCH`、`CONFIG_CONFLICT`。
- ledger：`readStateAt` strict 读不动；Hub 从 `shared_binaries.meshmuxd.sha256`（二进制）与 `artifacts.meshmuxd`（包）分别取 `from_agent`/`from_package`；任一缺失即 `HUB_BACKUP_IDENTITY_MISSING`（Hub 不接受空 from_*）。
- 模块边界：若 Hub confirmer 需要 `update` 反向调用 `web` 类型，就把 `BackupRecord` 移到中立叶子包 `internal/backup`，JSON 与 schema 冻结不变（Q3）。

### 5.10 顺序：Hub 先升

1. Hub 完成 §5.2–§5.7 并到达 `confirmed`（新 Hub 在服务，启动身份已确认）。
2. 只有此时 `/tasks` 才允许为 Line/Out 批准比**旧** Hub 更新的目标（running 前移，§5.8 gate 自动成立）。
3. Line/Out 走既有 four-task 链，语义不变。

反向顺序被机制挡住：旧 Hub 的 `pinnedManifest` 只认自己运行的版本，无法为节点 pin 更新目标（今天的 `MANIFEST_UNAVAILABLE` 分支就是闸门）；11d 把它变成“Hub 升完后自动解锁”。Hub 升级期间对 co-located Line 只做 §5.6 的协调重钉，不改它的配置 revision。

### 5.11 Irreversible UX

既有 `/tasks` 页新增“Hub 自升级”区块，所有写都走既有 `app.mutation`（session + 精确 Origin + CSRF，回执带 `operation_id`），不新增外部写入面：

| 路由 | 说明 |
| --- | --- |
| `POST /tasks/hub-upgrade/backup` | §5.2 预升级备份；回执给出 `operation_id` |
| `POST /tasks/hub-upgrade/apply` | 提交升级（同一 `operation_id`；目标已由备份固定） |
| `POST /tasks/hub-upgrade/restore` | §5.7 |
| `POST /tasks/db-migration/approve` | **不变**：只接受 `backup_operation_id` + 字面值 `irreversible_confirm=1` |

页面显示记录状态（state、`from_version`、`db_schema`、payload 文件数、`integrity_ok`）、不可逆警告、恢复入口、op id 与 result 阶段；不可逆时 apply 前要求先写确认位并显示当前位值。**修悬空文案**：备份回执的 `operation_id` 就是 `POST /tasks/db-migration/approve` 需要的 `backup_operation_id`，`server_database_migration.go` 的提示改指本页（写入路径不动）。apply 在破坏性步骤前读位 + `verifyDatabaseBackupPayload`，不满足即 `IRREVERSIBLE_CONFIRM_REQUIRED`，无 flag/环境变量绕过。

## 6. 测试计划（B 级，fixture-friendly）

1. **Producer 顺序**：VACUUM → 副本 `integrity_check` → staged 记录；检查失败断言旧代保留、`.part` 清理、零记录写入；运行二进制已 stage 成旧包且摘要 == `from_agent_sha256`。
2. **载荷与双摘要**：payload 0700/0600、`payload_files=1`；`from_package` 来自 ledger、`from_agent` 来自 `/proc/self/exe`，断言两者不相等时不被合并、任一缺失即 `HUB_BACKUP_IDENTITY_MISSING`。
3. **C2 单写者**：同一身份下两种布局的 `record.json` **逐字节相同**；扁平布局拒绝 `<op32hex>/` 残留。
4. **健康契约**：`/healthz` 只 SELECT 1——身份不匹配/行缺失/`user_version` 异常都不改变 200/503，且测试统计 DB 写次数为 0。
5. **身份回读矩阵**（管理面 + 定时器）与 `HUB_DIGEST_UNAVAILABLE`（`/proc/self/exe` 不可读）。
6. **`SCHEMA_TOO_NEW` 端到端**：子进程 + 高 `user_version` fixture，断言退出码、稳定码、detail 只含记录路径。
7. **不可逆矩阵**：manifest `database_migration` 缺省/`irreversible`；无位拒绝、有位通过、位在但载荷被删拒绝；`IRREVERSIBLE_CONFIRM_REQUIRED` 零变更。
8. **恢复**：`PayloadSHA256` 不符 → 停机前拒绝；schema 10 副本 + schema 11 执行体 → `CONFIG_CONFLICT` 在**停机前**返回（不误报）；旧包缺失 → `HUB_RESTORE_BINARY_MISSING`；happy path 含 drop-in 翻转、chown、`database-backup/`+`hub-upgrade/` 携带、`restored.json` 生效。
9. **op journal**：非法迁移拒绝；终止态不被覆盖；恢复后 DB 无表而 journal 仍可读、单飞仍生效。
10. **argv 字节 pin**：`__internal-hub-dispatch`/`-update`/`-restore` 全 argv 逐字节；非法 target/digest/op 拒绝。
11. **R-SURFACE**：`systemd-analyze verify` 三个单元文件（service/path/tmpfiles）；单元文件 root:root 0644；meshmux 不能写 `/var/lib/meshmux-installer/upgrade`；未知 target 的请求 → `MANIFEST_UNAVAILABLE` 且**未 exec**；staged 字节 ≠ manifest 摘要 → 未 exec；校验后换字节（TOCTOU）→ exec 副本仍拒绝；`.path` 缺失时 `queued` 超时成 `HUB_HANDOFF_TIMEOUT`。
12. **对账**：`queued` 超时、`applying` 30min 孤儿、`restarting` 且 running==from → `HUB_UPGRADE_NOT_APPLIED`、确认要求 version 与 digest 同时等于 target/`package_sha256`。
13. **空间**：公式含 2×DB、旧包、exec 副本；`max(…, 1 GiB)` 单测；不足时每次复制前 `HUB_SPACE_INSUFFICIENT`。
14. **Line 重钉**：happy path（agent.json+ledger+restart）；重钉失败 → 旧二进制+旧 pin 恢复、Web 未重启、稳定码；预检不符 → 零写。

## 7. 风险与回退

| 风险 | 缓解 |
| --- | --- |
| 二进制半写 / 换坏 | 同目录 `meshmuxd.new` + rename + fsync；旧包在 backup 时已 stage，可回退 |
| Line 与 Hub 分裂（半重钉） | 同 unit 内“换二进制→重钉→重启 Line”顺序；失败按 §5.6-8 换回旧包与旧 pin |
| VACUUM 期间并发写 | `VACUUM INTO` 事务一致快照；WAL fixture 证明 |
| 双份 DB 撑爆磁盘 | §5.9 峰值项 + `max(…, 1 GiB)`，不足即 fail-closed |
| 恢复后 data-dir 身份不符 | 停机前只读比对 → `CONFIG_CONFLICT`，保留两份目录 |
| root 单元读不到 meshmux 0600 文件 | `CAP_DAC_OVERRIDE` + 参数化 `expectedOwner` 读端（字节可达 ≠ 授权，属主/模式仍校验） |
| root 写的 result 读不到 | `results/` 定属主 root:meshmux 0750、文件 0640；unit 是唯一写者，Web 只读 |
| `.path`/单元缺失 | `queued` 120s 超时 → `failed`，可重试；不产生半执行 |
| 恢复后 Web 起不来 | 终态 + 人工指引；旧目录保留；不自动重试 |
| 旧包被 GC | 空间公式强制保留；缺失即 `HUB_RESTORE_BINARY_MISSING` |

回退原则：**不自动回退 Hub 二进制**（唯一例外是 §5.6-8 的“重钉失败换回”，因为此时 Web 尚未重启、系统处于不一致中间态）。Hub 自身回退只有 restore 一条路；Line/Out 的 LKG 仍走 11c-3 重发链。

## 8. 后续

- **12e 阻塞（明示）**：`meshmuxd` 仍是 `file://` dev pin，没有 GitHub release asset，也没有目标 manifest 的预置/签名通道。在此之前生产 Hub 自升级只会得到 `MANIFEST_UNAVAILABLE`；本文的 B 级 fixture 只验证形状，**不得**据此声称“Web 统一升级可用”。
- **11e**：兼容矩阵内容接入 §5.8 的 gate 形状；矩阵缺失 fail-closed。
- **#12**：C 级隔离 VM/真机验收（Debian 13 amd64/arm64），覆盖 `VACUUM INTO` 真快照、path unit/oneshot 行为、恢复后 Caddy/Headscale 联通。
- 后续可把“root 预置 manifest”替换为签名发布通道；届时 §5.8 的 gate 形状与 §5.1 的执行基座不变。

## 9. 开放问题（不阻塞，最多 3）

1. **Q1 精确写集**：是否只需 `/run/meshmux-hub /usr/local/libexec /var/lib/meshmux /var/lib/meshmux-installer /etc/meshmux /etc/systemd/system`？若还需 journal 目录或其它路径，用 `systemd-analyze verify` 与真机 `EROFS` 证据补齐并同步改单元。
2. **Q2 恢复后的 journal/镜像和解**：schema 10 期间只有 journal，下一次升级重建表时是“按 journal 回填”还是“只保留最近一代”？本文要求回填最近一代以保证 UI 连续，具体规则随 11e 定。
3. **Q3 中立包时机**：现在就抽 `internal/backup`（零成本预防），还是等 confirmer 真需要反向导入时再抽（届时要保证 JSON 字节不变）。
