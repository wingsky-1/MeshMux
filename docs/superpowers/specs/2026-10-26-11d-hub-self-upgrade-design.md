# 11d Hub 自升级执行设计（送审）

所属：#11 v1.0.0 Web 统一升级，7 段串行之第 6 段（11c-3 已合入 main，基线 `f82f84c`）。
状态：设计送审。11e（兼容矩阵内容）、C 级 VM/真机验收（归 #12）不在本文范围；本文只消费 11c-3 已冻结的备份/确认/回退接口，**不重定义**其中任何语义。

## 1. 背景与意图（why）

11c-2 让 Line/Out 能自替换，11c-3 定下了 Hub 数据库备份记录、健康门控确认、分级 revert、`database_versions` 与不可逆确认位。但 Hub 本体仍然没有执行者，留下三处真空白：

1. **Hub 自己不能升级**。今天只能按 `WEB_DEVELOPMENT` 手工停服、改 `--data-dir`、换二进制；Web 统一升级在 Hub 这一环断链。
2. **接口有写者没有消费者**。`POST /tasks/db-migration/approve` 的回执让操作员“从 Hub 自升级的备份记录复制 `operation_id`”，但没有任何代码会写这份记录——指引是悬空的；`database_versions` 只有启动写者与测试读者，没有生产读消费者；`server_upgrade_check.go` 明写“Consequence until 11d：本 Hub 只能 pin 自己运行的版本”。
3. **顺序没有被任何机制保证**。新 Hub 才理解新记录/新 schema；若先升 Line/Out，旧 Hub 可能读不懂回执。11d 必须把“Hub 先升”做成执行顺序，而不是文档约定。

因此 11d 的实质是：**在 Hub 上补一条与 11c-2 同构、但根路径与写集完全不同的受限执行链**，并让它在浏览器关闭、Web 重启、升级失败三种情况下都可解释、可恢复。

## 2. 目标

1. Hub 自升级闭环：预升级备份 → 固定 argv 的 transient unit 换二进制 → 重启 Web → 健康回读 → 确认或进入恢复。
2. **Hub 先升**：Hub 升级完成并确认后，才允许对 Line/Out 批准比旧 Hub 更新的目标（§5.7 的 pin 提升）。
3. **浏览器关闭不中断**：执行由 Hub 进程与 systemd 托管的一次性单元推进，任何页面轮询、连接存活都不是执行前提。
4. **重启后可查询**：Web 重启后从 Hub 数据库恢复操作状态与回执，不需要内存状态。
5. 恢复路径可用：恢复备份 → 新 0700 目录 → `integrity_check` → 翻 `--data-dir` → `/healthz` 200。
6. 消费 11c-3 的备份记录、确认位、`database_versions`、`SCHEMA_TOO_NEW` 与空间规则；不新增协议种类、不新增公开 CLI。

## 3. 非目标

- **11e 兼容矩阵内容**（Hub×Agent×组件组合）。11d 只定 gate 形状与 fail-closed 行为。
- **C 级验收**（隔离 VM、真机 Debian 13 amd64/arm64）——归 #12；本文只承诺 B 级 fixture 证据。
- **co-located Line 共享二进制重钉落地**：11d 只保证不破坏 `SHARED_BINARY_MISMATCH` 与共享路径，实际重钉随 Line 升级段完成。
- **LKG 回退的 Web 一键入口**：11d 保留 11c-3 的“重发 LKG candidate revision”语义可用，但不新增 UI 按钮。
- **N-1 以上的多代 Hub 回退**：只保留一代（§5.1）。
- **`web → update` 反向导入**，除非引入中立叶子包（§5.8 末、Q3）。

## 4. 约束（不可谈判，全部继承 11c-3）

- **C1 扁平布局**：Hub 备份固定为 `<data-dir>/database-backup/record.json`（0600）+ `payload/`（0700 目录、0600 文件）；**只保留一代**。不得复用 Node 的 `<root>/<op32hex>/` 每操作目录语义。
- **C2 记录冻结**：`update.BackupRecord` schema 1、`DisallowUnknownFields`、尾随数据拒绝、≤64 KiB。即使将来类型搬家，JSON 字节必须保持完全一致。
- **C3 状态机**：记录先写 `staged`，只有健康门控 finalize 之后才能变 `confirmed`；`failed` 是终态。
- **C4 完整性顺序钉死**：`VACUUM INTO` 生成副本 → 在**副本**上跑 `PRAGMA integrity_check` → 才写 `integrity_ok=true`。顺序不可交换，不允许对源库跑检查来替代。
- **C5 载荷含秘密**：payload 含订阅凭据、token hash、会话；0700/0600、root 属主、永不离机，不进日志、不进回执。
- **C6 双摘要分离**：`from_package_sha256` 与 `from_agent_sha256` 由 Hub 分别提供（Node 侧把两者混成一个值，Hub 不得照抄）；`db_schema` 写真实 `PRAGMA user_version`（今天 10），不是 Node 常量 0。
- **C7 `database_versions`**：单行 `id=1`，今天在 store-open 迁移提交后写；11d 必须在 Hub 健康回读时**再确认**（serving 证据）。该行是**降级提示**，不是迁移门；迁移门仍是 `user_version` 比较。
- **C8 `SCHEMA_TOO_NEW`**：只 `lstat` 记录存在性，不解析未来 schema；不原地降级。
- **C9 不可逆位在记录上**：`irreversible_approved` 只有 `POST /tasks/db-migration/approve` 一个写者，且只接受字面值 `irreversible_confirm=1`（session + 精确 Origin + CSRF + `operation_id`）。破坏性步骤执行前必须读该位并重新确认载荷存在（staged + `integrity_ok` + 非空私有 payload）；审批检查是 metadata-only，所以恢复步骤必须在打开副本后重跑 `integrity_check`。
- **C10 分级 revert**：停 Web → 恢复到**新** 0700 目录 → `integrity_check` → 翻 `--data-dir`（**携带 `database-backup/`**）→ `/healthz` 200 → 旧目录保留到确认。中途失败 = 终态 + 人工指引，原目录不动，Web 保持 down。不自动重试失败的恢复。
- **C11 in-place down-migration** 仅当新表为空且无新 binary 确认写；否则只能 restore。迁移只做加法（新列 `NOT NULL` 带 `DEFAULT`）。
- **C12 确认是回读的副作用**：锚比较在 confirmed 短路**之前**；已被 revert 的操作永不确认。没有 `confirmUpgrade` 平行裁决。
- **C13 LKG 回退**：重发 LKG 的 candidate revision 走既有 four-task 链（`resurrect-after-delete` 是接受的固有语义，须在文档中写明）。
- **C14 空间下限重推导**：Node 的 1024 MiB 常量不覆盖 Hub DB 载荷（§5.8）。
- **C15 启动稳定码**：只有 `SCHEMA_TOO_NEW` 记 `detail`（记录路径，无秘密）；其他只记稳定码。
- **C16 执行面**：无新 protocol kind（`upgrade.*` 继续拒绝）、无新公开 CLI、固定 argv、无 shell、每写带 `operation_id`、回执诚实（queued/gated/applied/failed/rolled_back，applied 只由回读证明）、manifest pin + SHA-256 先于执行、日志脱敏。
- **C17 模块方向**：`internal/update` 不得 import `internal/web`。今天唯一的边是 `web → update`（仅为 `BackupRecord` 类型）。
- **C18 D2/D5**：孤儿兜底仍是**纯 30 分钟年龄**（不查 Hub）；GC 只在 confirmed 之后的下一次升级或显式清理时发生。

## 5. 设计

### 5.1 Producer：Hub 数据库备份作业

**触发点：显式预升级步骤，不是 `approveUpgrade` 钩子，也不是独立公开 endpoint。**

- 不做 `approveUpgrade` 钩子：那条路径属于 Line/Out 的任务批准，Hub 自升级是独立操作，混入会让“批准一个节点”产生本地 DB 大拷贝，且失败会污染节点任务的回执。
- 不做独立公开 endpoint：会新增一个外部写入面（CSRF/Origin/限速/幂等都要重做）。复用 `/tasks` 边界上的管理员 mutation，天然满足 C9 的会话/Origin/CSRF 要求，并能在回执里直接返回 `operation_id`——正好修掉今天“让操作员去找一个不存在的记录”的悬空文案。
- **不复用 per-op 目录函数**：`RequireBackupDir` / `WriteBackupRecord` 绑定 `<root>/<op32hex>/{record.json,payload}`，会直接违反 C1；`WriteBackupRecord` 还按 Node 语义写 `db_schema=0`、从安装器快照拷贝整棵文件树，Hub 需要的是单文件 DB 副本与真实 `user_version`。因此新增 `WriteHubBackupRecord`（`internal/update/hubbackup.go`，扁平布局），只复用类型、schema 常量、状态机、私有权限校验与严格读端。

具体形状是 `/tasks` 边界上的**两步**管理员 mutation（都走既有 `app.mutation`）：

| 路由 | 作用 | 回执 |
| --- | --- | --- |
| `POST /tasks/hub-upgrade/backup` | 生成 `operation_id`（同时建 op 记录，`backing_up`），执行 §5.1 的 VACUUM→校验→staged 记录 | `status=staged`、`operation_id`、`from_version`、`db_schema`、`integrity_ok` |
| `POST /tasks/hub-upgrade/apply` | 校验记录与 manifest pin，把同一 op 推进到 `queued` 并启动 transient unit | `status=queued`、`operation_id`、`target_version` |

`apply` 必须显式携带 `operation_id`，且该记录必须满足 `state=staged`、`integrity_ok`、payload 非空、`from_version`/`db_schema` 与运行值一致，否则 `UPDATE_BACKUP_MISMATCH` 零变更（沿用 11c-3 的 handoff 前置语义）。备份与升级分成两步，是因为一次大 DB 拷贝不应与“操作员确认目标版本”绑在同一个不可重入的请求里；两步共享同一个 `operation_id`，所以备份记录、op 记录、result 文件与回执永远指同一件事。

**顺序（rotate before replace，钉死）：**

1. 服务端生成 `operation_id`（32 位小写 hex，`crypto/rand`）。
2. `payload.part/` 建 0700；执行 `VACUUM INTO '<payload.part>/meshmux.db'`（在事务之外；目标文件必须不存在；路径是固定常量 + `op32hex` 派生，不接受任何外来路径，字面量或参数绑定按驱动能力二选一）。
3. 只读打开副本 → `PRAGMA integrity_check` 必须返回 `ok` → 关闭。失败即停。
4. 计算 `meshmux.db` 的 SHA-256，`payload_files = 1`。
5. `payload.part` → `payload`（rename）；写 `record.json.part` → fsync → rename 为 `record.json`；记录 `state=staged`、`integrity_ok=true`。
6. **只有 staged 记录落盘后**才回收旧一代：旧 record + 旧 payload 先 rename 到 `.trash-<unix>`，再 `RemoveAll`。

顺序理由：先删旧代会让 `VACUUM`/校验失败留下零回滚源；先写新代最多短暂出现“新 staged + 旧 confirmed”两份，磁盘峰值 = 2×DB，必须计入 §5.8。失败路径一律删 `.part`、旧代原样保留、回执 `failed` + 稳定码（`HUB_BACKUP_VACUUM_FAILED` / `HUB_BACKUP_INTEGRITY_FAILED` / `HUB_BACKUP_RECORD_FAILED`），除 `.part` 清理外零状态变更。

**字段映射（Hub 侧）：**

| 字段 | 值 |
| --- | --- |
| `from_version` | 运行中 Hub 版本（build-stamped，§5.2） |
| `target_version` | 目标 Hub 版本 |
| `db_schema` | 真实 `PRAGMA user_version`（今天 10） |
| `policy_schema` | `upgrade.PolicySchema`（8） |
| `manifest_sha256` / `package_sha256` | 目标 Hub 的 manifest 与包摘要 |
| `from_package_sha256` | 运行中 Hub 包的摘要（来自 installer ledger 或包文件） |
| `from_agent_sha256` | 运行中 Hub 二进制的摘要（Hub 无独立 Agent 二进制，故两个 `from_*` 都由 Hub 侧分别填写，绝不合并） |
| `payload_path` | `<data-dir>/database-backup/payload`（绝对路径） |
| `payload_files` | 1（`meshmux.db`） |

### 5.2 版本身份

- `node.CurrentAgentVersion` 是 **Agent** 版本，不是 Hub 版本。11c-3 的 `confirmDatabaseVersion` 今天写的是它；11d 修正为 Hub 版本源，并保留一个明确的迁移说明（旧行值会自愈于下一次健康回读）。
- 新增 `internal/buildinfo`（中立叶子包，只 import 标准库）：`Version` 由 `-ldflags -X` 注入，缺省 `1.0.0-dev`；`Digest()` 打开 `/proc/self/exe`（不是 `os.Executable()`，后者可能已被替换/删除）计算 SHA-256，上限 128 MiB，失败返回 `HUB_DIGEST_UNAVAILABLE`，不猜。
- `database_versions.last_good_version` 写 **Hub 版本**；首个生产消费者是 §5.3 的健康回读。

### 5.3 Health re-confirm

扩展 `GET /healthz`：对外形状保持 `{"status":"ok"}`（Caddy 与安装器依赖），内部多一次回读。**不新增 protocol kind，不新增公开诊断端点。**

判定矩阵：

| `user_version` | `database_versions` 行 | 结果 |
| --- | --- | --- |
| ≠ 本构建 schema | 任意 | 503 `SCHEMA_READBACK_FAILED`，不写行 |
| = | 不存在 | 503 `DATABASE_UNCONFIRMED`，不写（启动应已写；缺失说明 store 未走完启动） |
| = | 存在且 `(last_good_version, last_good_schema) == (buildinfo.Version, user_version)` | 200，幂等 re-confirm（只更新 `confirmed_at`） |
| = | 存在但不匹配 | 200 但**不写**，记 `DATABASE_VERSION_MISMATCH` 事件 |

不匹配仍然 200 是刻意的：服务确实可用，只是“身份未确认”，拒绝服务会放大故障；不写行则保证 `database_versions` 不撒谎。

**`database_versions` 是降级提示，不是迁移门**（C7）：真正的门是启动时的 `user_version` 比较（`SCHEMA_TOO_NEW`）。健康回读只负责把“这个版本真的在服务”这一事实写实；它拒绝不了任何启动，也不参与任何降级决策。

**确认是回读的副作用，不是独立裁决**（C12）：锚比较（`from_version`/`from_package_sha256`/`from_agent_sha256`/`db_schema` vs 运行值）必须发生在 `state=confirmed` 的短路**之前**；一个已 `reverted` 的 op 永远不会被后续 confirmed 覆盖。没有 `confirmUpgrade` 平行入口。

**写点语义修正**：ADR-0007 与 `WEB_DEVELOPMENT` 现称“只在启动回读后写”，属 overclaim。11d 改为“写点 = 启动回读（必需）+ 健康回读复核（幂等）”，并明确该行是**降级提示**而非迁移门。为免 healthz 被监控高频轮询触发写放大，用 5 秒内存原子缓存；写只在确认成功时发生。

浏览器关闭安全性：回读由服务进程自身完成，与任何客户端连接无关。

### 5.4 Apply / handoff

**Hub 操作记录（schema 11，纯加法迁移）：**

```
hub_upgrade_operations(
  operation_id TEXT PRIMARY KEY,   -- 32 lowercase hex
  target_version TEXT NOT NULL,
  from_version   TEXT NOT NULL,
  state          TEXT NOT NULL,
  error_code     TEXT NOT NULL DEFAULT '',
  detail         TEXT NOT NULL DEFAULT '',
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
)
```

状态机（**一个 `operation_id` 从备份穿到确认**，沿用 11c-2 的“同一 op 从批准穿到回读”）：`backing_up → backed_up → queued → applying → restarting → verifying → confirmed | reverted | failed`，只向前。op 记录由备份 mutation 创建（`backing_up`），备份成功转 `backed_up`；apply 要求 `backed_up` 并转 `queued`；`failed` 可从 `applying/restarting/verifying` 进入；`reverted` 只能从 `failed/verifying` 经显式恢复进入。`backed_up` 之前不得启动 unit。

不复用 `agent_tasks`：该表 `node_id` 外键指向 `nodes`，`kind` 是 Agent 协议任务；Hub 自身不是 node，塞进去会污染节点任务查询、单飞判定与协议 allowlist。也不复用候选修订链（那是配置发布）。

**Transient unit：选新的 `__internal-hub-update` 固定 argv 族。** 理由：`__internal-update-install` 的语义与写集都是 Node 的（重启 `meshmux-agent.service`、写 `/var/lib/meshmux-agent` 等）；同名分支会让已被单测逐字节 pin 的 argv 与其行为脱节。新名字 + 新 argv，独立 pin。

```
/usr/bin/systemd-run --unit=meshmux-hub-update-<op32hex> --collect
  --property=Type=oneshot --property=Restart=no
  --property=ProtectSystem=strict
  --property=ReadWritePaths=/usr/local/libexec /var/lib/meshmux
  --property=NoNewPrivileges=yes --property=PrivateTmp=yes --property=ProtectHome=yes
  --property=RestrictAddressFamilies=AF_UNIX
  --property=CapabilityBoundingSet=
  /usr/local/libexec/meshmuxd __internal-hub-update
  --target <semver> --manifest-sha256 <hex> --expected-sha256 <hex>
  --operation-id <op32hex> --data-dir /var/lib/meshmux --from-version <semver>
```

升级单元只写 `/usr/local/libexec`（换二进制）与 `/var/lib/meshmux`（result、包缓存），不写 unit 文件、不写 `hub_upgrade_operations` 表、不需要任何 capability；恢复单元另立 argv（§5.5），其写集才含 `/etc/systemd/system`。两族 argv 均逐字节 pin。写集具体值仍待真机 `EROFS` 证据确认（Q1）。

单元体（顺序固定）：

1. 校验 argv 形状（SemVer、64 位 hex、32 位 hex、绝对路径常量）。
2. 打开 `<data-dir>/upgrade/<target>-<arch>`，边读边算 SHA-256，必须等于 `--expected-sha256`，否则 `HUB_UPDATE_DIGEST_MISMATCH` 且不写任何文件。
3. 写同目录 `meshmuxd.new`（0755，fsync）→ `rename` 原子覆盖 `/usr/local/libexec/meshmuxd`。
4. `systemctl restart meshmux-web.service`。
5. 写 `<data-dir>/hub-upgrade/<op32hex>.result.json`（0600，schema 1：`operation_id`/`phase`/`exit`/`error_code`/`at`）。单元不写数据库：Web 是 op 状态的唯一写者（沿用 11c-2 单写者原则），重启后由 Web 读 result 对账。

关键简化：transient unit 是 `meshmux-web.service` 的**兄弟**而非其子进程，重启 Web 不会杀死单元（对比 11c-2 里 updater 曾是 Agent 子进程）。因此不需要 `--no-block` 逃逸技巧。

- **浏览器关闭不中断**：提交后由 Hub 进程交给 systemd，页面只读数据库；没有任何“前端轮询驱动执行”的依赖。
- **重启后对账**：`web.New` 成功后、监听前，扫描 `<data-dir>/hub-upgrade/*.result.json`，把 `applying/restarting` 的 op 推进到 `verifying/confirmed/failed`。**单写者仍是 Web 进程**，transient unit 只写 result 文件（沿用 11c-2 单写者原则）。
- **孤儿兜底**（D2，纯年龄）：一个停在 `applying/restarting/verifying` 且无 result 文件的 op，年龄超过 30 分钟即转 `failed`（`HUB_UPGRADE_ORPHANED`）。只比较本地时间戳，不查网络、不猜测，避免误判正在慢慢跑的真实升级。
- **GC**（D5）：只有 `confirmed` 之后的下一次升级或显式清理才删除旧包与旧 result；`failed/reverted` 的产物保留供人查看。
- **重启后任务查询**：`GET /tasks` 增加“Hub 自升级”区块，读 `hub_upgrade_operations` + result 文件；无内存依赖。

### 5.5 Restore executor

所有 root 写动作（改 unit 文件、停/启服务、换二进制）都只能发生在 transient unit 内——Web 以 `meshmux` 用户运行、`ProtectSystem=strict`，写不了 `/etc` 与 `/usr`。因此恢复与升级同族：`__internal-hub-restore`（固定 argv，独立字节 pin）。

```
/usr/bin/systemd-run --unit=meshmux-hub-restore-<op32hex> --collect
  --property=Type=oneshot --property=Restart=no
  --property=ProtectSystem=strict
  --property=ReadWritePaths=/usr/local/libexec /var/lib/meshmux /etc/systemd/system
  --property=NoNewPrivileges=yes --property=PrivateTmp=yes --property=ProtectHome=yes
  --property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
  --property=CapabilityBoundingSet=CAP_CHOWN
  /usr/local/libexec/meshmuxd __internal-hub-restore
  --operation-id <op32hex> --data-dir /var/lib/meshmux --from-version <semver>
  --restore-dir /var/lib/meshmux/restore-<op32hex>-<unix>
```

`CAP_CHOWN` 与 `AF_INET` 只在恢复族出现：前者用于把新目录归还 `meshmux` 属主，后者用于轮询 `/healthz`。升级族两者都不需要。

步骤（顺序钉死，C10）：

1. 严格读扁平记录（`DisallowUnknownFields`、schema 1、0600、`operation_id` 匹配）；要求 `state ∈ {staged, confirmed}`、`integrity_ok`、`payload_files > 0`。
2. `systemctl stop meshmux-web.service`。
3. 建 `<data-dir>/restore-<op32hex>-<unix>/`（0700，新目录，不覆盖原目录）。
4. 只读打开 `payload/meshmux.db` → `PRAGMA integrity_check` 必须 `ok`（审批检查是 metadata-only，这里必须重跑）。失败 → 终态 `HUB_RESTORE_INTEGRITY_FAILED`，原目录未动，Web 保持 down，人工指引。
5. 把副本落入新目录（0600），并**把 `<data-dir>/database-backup/` 整个带进新目录**——否则恢复后记录消失，`SCHEMA_TOO_NEW` 的指引断链。
6. 翻转 `--data-dir`：改写 `meshmux-web.service` 的 `ExecStart` + `systemctl daemon-reload`（与安装器同源；二选一的备选是固定文件 `/etc/meshmux/hub-data-dir` 由 unit 读取，实现时定一个并 pin）。
7. `systemctl start meshmux-web.service` → 轮询 `http://127.0.0.1:9080/healthz` 直到 200（60 秒上限）。
8. 200 → op 置 `reverted`，旧目录**保留**（不自动删）；非 200/超时 → `failed`（`HUB_RESTORE_HEALTH_FAILED`），旧目录仍保留，Web 可能 down，指引含两条人工路径。

- 中途失败 = 终态 + 人工指引，原目录 untouched，Web stays down；不自动回滚 unit 文件（“再翻一次”需要人确认新目录可信）。
- **`CONFIG_CONFLICT` 刻意路径**：恢复后打开 DB，若 `database_versions.last_good_version` 或 `user_version` 与记录的 `from_version`/`db_schema` 不一致，不自动接受，返回 `CONFIG_CONFLICT` 并保留两份目录——这是 11c-3 里“升级后 ledger/agent.json 合法不一致”的 Hub 对应物。
- **二进制也要回退**：记录只锚定 `from_package_sha256`，不含旧包字节。Hub 必须保留上一代 Hub 包（`<data-dir>/upgrade/<version>-<arch>`）；旧包缺失时恢复只能做“DB 回退 + 当前二进制重跑旧 schema”，且仅当迁移是加法的才可行，否则 `HUB_RESTORE_BINARY_MISSING` 终态。这是 §5.8 空间公式必须计入旧包的原因。
- 不自动重试；`done=false` 保持回执非终态，reverted op 永不被后续 confirmed 覆盖（C12）。
- **LKG 语义的适用范围**：11c-3 的“LKG 回退 = 重发该 LKG 的 candidate revision 走既有 four-task 链”是 **Line/Out** 的回退机制，11d 原样保留、不改写。Hub 自身没有 candidate revision 链（它不是被 Hub 管理的节点），因此 Hub 的回退只有本文的 restore 一条路；不得把 four-task 链硬套到 Hub。`resurrect-after-delete`（重发旧 revision 会临时复活其后的删除）作为回滚的固有语义继续在节点侧成立，文档不声称它被消除。
- **in-place down-migration** 只在新表为空且无新 binary 确认写时允许（C11）；否则一律 restore。11d 新增的 `hub_upgrade_operations` 表正是“新表”，升级后立刻有行，所以真实的 Hub 回退默认走 restore，而不是 DROP 表。

### 5.6 Irreversible UX

在既有 `/tasks` 页加“Hub 自升级”区块。所有写都是既有 `app.mutation` 上的管理员 mutation（session + 精确 Origin + CSRF + 回执 `operation_id`），不新增外部写入面：

| 路由 | 说明 |
| --- | --- |
| `POST /tasks/hub-upgrade/backup` | §5.1 预升级备份；回执给出 `operation_id` |
| `POST /tasks/hub-upgrade/apply` | 提交升级（目标版本 + manifest SHA-256 + 同一 `operation_id`） |
| `POST /tasks/hub-upgrade/restore` | §5.5 恢复（仅允许 `failed`/`verifying` 的 op） |
| `POST /tasks/db-migration/approve` | **不变**（11c-3 已实现）：只接受 `backup_operation_id` + 字面值 `irreversible_confirm=1` |

页面显示：备份记录状态（state、`from_version`、`db_schema`、payload 文件数、`integrity_ok`）、不可逆警告（“此后只能通过恢复备份回到 X，没有原地降级”）、恢复入口、op id 与 result 阶段。目标迁移不可逆时，页面在 apply 前要求先完成确认位写入，并显示当前位值。

**修悬空文案**：备份回执直接返回 `operation_id`，它就是备份记录的 `OperationID`，因此 `POST /tasks/db-migration/approve` 的 `backup_operation_id` 不再是“去别处找的值”，而是本次 Hub 升级的同一个 id。`server_database_migration.go` 的提示文案改为指向本页的 op id，语义与写入路径不动（不重定义 11c-3）。

apply 在破坏性步骤前必须：读位 `irreversible_approved == true` + 重新 `verifyDatabaseBackupPayload`（存在性、私有模式、文件数）。不满足 → `IRREVERSIBLE_CONFIRM_REQUIRED`，零变更。无 flag、无环境变量绕过。

### 5.7 Manifest pin lifting

今天 Hub 只能 pin `node.CurrentAgentVersion`。11d 定义 gate **形状**（矩阵内容归 11e）：允许 pin 比自身新的版本，当且仅当

- 目标 manifest 存在，`schema` 与 `policy_schema` 受支持；
- `version` 是 SemVer 且 `> running`；
- 架构 ∈ `{amd64, arm64}`；
- `package.sha256` 为 64 位小写 hex，来源是固定 GitHub release（拒绝 `latest`/`main`/可变标签）；
- 目标声明了与当前 `user_version` 的兼容（能打开，或承诺只做加法迁移）。

任一项缺失 → `MANIFEST_UNAVAILABLE`（fail-closed），零写入。11e 提供的矩阵以 `Compatibility(target, running, arch, dbschema) (ok bool, reason string)` 形状接入；矩阵不可用同样 fail-closed。

这也是“Hub 先升”的机制：Hub 升到新版本后，running 前移，新 Hub 才能为 Line/Out pin 更新的目标；旧 Hub 不会接受比自己新的 pin。

### 5.8 空间 / 日志 / ledger

Hub 空间公式（替换 Node 的 1024 MiB 常量；DB 大小运行时由 `PRAGMA page_count * page_size` 取得，上限 1 GiB）：

```
hubRequiredSpace = 128 MiB            (staged Hub 包)
                 + 2 × dbSize         (VACUUM 副本 + 旧代并存峰值)
                 + 128 MiB            (上一代 Hub 包，供恢复回退二进制)
                 + dbSize             (恢复新目录)
                 + 256 MiB            (journal / result / ledger / 余量)
```

公式写在代码里并单测断言；不足时 `HUB_SPACE_INSUFFICIENT`，零变更。

日志：只记 `operation_id`、阶段、稳定码、版本、摘要（完整 hex 可记，摘要不是秘密）；`data-dir` 与记录路径可记（`SCHEMA_TOO_NEW` 先例）；绝不记 token、订阅 URL、DB 内容。启动稳定码：`SCHEMA_TOO_NEW`、`DATABASE_UNCONFIRMED`、`HUB_UPGRADE_*`、`HUB_RESTORE_*`、`MANIFEST_UNAVAILABLE`、`IRREVERSIBLE_CONFIRM_REQUIRED`；只有 `SCHEMA_TOO_NEW` 记 `detail`。

ledger：`readStateAt` 的 strict 读不动（11c-3 已做）；11d 只读其中的 Hub 版本/摘要作为 `from_*` 锚，未知字段仍 fail-closed。

模块边界：若 Hub confirmer 需要 `update` 反向调用 `web` 的类型，就把 `BackupRecord` 移到新中立叶子包 `internal/backup`（imports 无内部包），`web` 与 `update` 都 import，JSON 与 schema 冻结不变（Q3）。

### 5.9 顺序：Hub 先升

执行顺序是硬约束，不是建议：

1. Hub 完成 §5.1–§5.4 并到达 `confirmed`（新 Hub 已在服务、健康回读通过）。
2. 只有此时，`/tasks` 才允许为 Line/Out 批准比**旧** Hub 更新的目标（§5.7 的 pin 提升随 running 版本前移而自动成立）。
3. Line/Out 走既有 four-task 链，语义完全不变。

反向顺序被机制挡住：旧 Hub 的 `pinnedManifest` 只认自己运行的版本，因此它无法为任何节点 pin 更新的目标（今天已有的 `MANIFEST_UNAVAILABLE` 分支就是这条闸门）；11d 只是把这个“限制”变成“Hub 升完后自动解锁”。

Hub 升级本身**不触碰** Line/Out：不重发它们的 revision、不改它们的 agent.json、不动 co-located 共享二进制的 pin 一致性检查（`SHARED_BINARY_MISMATCH` 保持原样）。co-located Line 的重钉是 Line 升级段的事。

## 6. 测试计划（B 级，fixture-friendly）

1. **Producer 顺序**：`VACUUM INTO` → 副本 `integrity_check` → staged 记录；注入“检查失败”断言旧代保留、`.part` 清理、零记录写入。
2. **载荷模式与数量**：payload 目录 0700、`meshmux.db` 0600、`payload_files=1`；非私有模式拒绝。
3. **扁平路径拒绝 per-op 布局**：`WriteHubBackupRecord` 遇到 `<data-dir>/database-backup/<op32hex>/` 残留必须拒绝而非采用。
4. **健康回读矩阵**：匹配（写 `confirmed_at`）、行缺失（503 不写）、版本不匹配（200 不写 + 事件）、`user_version` 不符（503 不写）、refused-startup（`SCHEMA_TOO_NEW` 时不产生行）。
5. **`SCHEMA_TOO_NEW` 端到端**：`webcmd` 子进程 + 高 `user_version` fixture，断言退出码、稳定码、`detail` 含记录路径、无其他路径泄漏。
6. **不可逆矩阵**：无位（拒绝）、有位（通过）、位在但 payload 被删（`DB_BACKUP_RECORD_UNVERIFIED`/`CORRUPT`，拒绝）。
7. **恢复**：happy path（新目录 + 翻 data-dir + healthz 200 + `database-backup` 被携带）；中途 `integrity_check` 失败 → 原目录字节不变、Web down、终态。
8. **op 状态机**：合法迁移全链；非法回退（confirmed → applying）拒绝；`reverted` 不被 confirmed 覆盖。
9. **argv 字节 pin**：`__internal-hub-update` 与 `__internal-hub-restore` 全 argv 逐字节断言；非法 target/digest/op 拒绝。
10. **空间下限**：公式单测（含 2×DB 与旧包项）+ 不足时 `HUB_SPACE_INSUFFICIENT`。

## 7. 风险与回退

| 风险 | 缓解 |
| --- | --- |
| 二进制半写 / 换坏 | 同目录 `meshmuxd.new` + `rename` 原子；旧包保留，可手工回退 |
| VACUUM 期间并发写导致副本不一致 | `VACUUM INTO` 是事务一致快照；fixture 在 WAL 下证明（沿用 11c-3 Q3 的“先证”要求） |
| 双份 DB 撑爆磁盘 | §5.8 峰值项；不足即 fail-closed |
| 恢复后 data-dir 身份不符 | `CONFIG_CONFLICT` 刻意路径，保留两份目录 |
| unit 无法启动（无 systemd-run / 权限） | `HUB_UPGRADE_UNIT_FAILED`，零变更 |
| 恢复后 Web 起不来 | 终态 + 人工指引；不自动重试；旧目录保留 |
| 旧 Hub 包被 GC 掉 | 空间公式强制保留上一代；缺失时 `HUB_RESTORE_BINARY_MISSING` 终态 |

回退原则：**不自动回退 Hub 二进制**。Hub 自身的回退只有 §5.5 的 restore 一条路；Line/Out 的 LKG 回退语义仍走 11c-3 的重发链，11d 不改变它。

## 8. 后续

- **11e**：兼容矩阵内容（Hub×Agent×组件×schema 组合），接入 §5.7 的 gate 形状；矩阵缺失时保持 fail-closed。
- **#12**：C 级隔离 VM/真机验收（Debian 13 amd64/arm64），覆盖 `VACUUM INTO` 真实快照、systemd transient 行为、恢复后 Caddy/Headscale 联通。
- 本文不承诺 `v1.0.0` 的“Web 统一升级可用”；11e 与 #12 完成后才可宣告。

## 9. 开放问题（不阻塞，最多 3）

1. **Q1 精确写集**：升级族是否只需 `/usr/local/libexec /var/lib/meshmux`，恢复族再加 `/etc/systemd/system`？若任一族还需要 `/run/systemd`、journal 目录或 `/etc/meshmux`，需在实现时用 `systemd-analyze verify` 与真机 `EROFS` 证据补齐，并同步修订 §5.4/§5.5 的 argv。
2. **Q2 操作记录落点**：独立 `hub_upgrade_operations` 表（本文建议），还是复用既有 tasks 表加 `scope='hub'` 列？前者干净但多一张表，后者省迁移但污染节点任务查询与单飞判定。
3. **Q3 中立包时机**：现在就抽出 `internal/backup`（零成本预防），还是等 Hub confirmer 真的需要反向导入时再抽（少一次搬家，但届时要保证 JSON 字节不变）？
