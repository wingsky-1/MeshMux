# 11d Hub 自升级执行设计（第 6 稿 r6 修订，送审）

所属：#11 v1.0.0 Web 统一升级，7 段串行之第 6 段（11c-3 已合入 main，基线 `f82f84c`）。
状态：设计送审。第 1 稿两份评审均为 NEEDS-REWORK；第 2 稿重做执行基座（§5.1）、对账与确认（§5.4/§5.5）、属主与恢复（§5.7）、manifest 信任链（§5.8），并把 co-located Line 重钉纳入范围（§5.6）。第 3 稿按 NEEDS-REWORK-2 修 MF-1（目标 manifest 门）、MF-2（from_package 真实来源）、MF-3（重钉/双 ledger 预检）、B8（GC 只收 confirmed）及 N1–N7。第 4 稿按最终签收补 MF-3 第 4 个 pin（Line ledger `state.Node.AgentVersion/AgentSHA256`，四处写集全成或全败）并钉死 `from_package_sha256` 读路径（Web 以 `buildinfo.Digest()` 落值、root dispatcher 用 0600/0700 ledger 核对，不给 Web ledger 读权）。**第 5 稿按 owner D1 把 Hub 备份从扁平单槽改为 per-op + `keep=2`（confirmed-only GC），删除 flat 恢复机制；旧二进制的 `SCHEMA_TOO_NEW` 指针保留为“per-op 提交后原子写入的 flat latest 副本”，只作存在性指针、11d 从不读取。** **r5 修正三项**：①保留并收窄 producer 互斥（`LockFlatSlot` 改名 `LockBackupProduce`，只罩 `Busy → generation → WriteOp(backing_up)` 查后写，§5.2/§5.12）；②GC 与指针刷新解耦（confirm 无条件 `keep=2`、显式清理 `keep≥2`，刷新失败只记 `HUB_BACKUP_POINTER_STALE`，绝不跳过 GC，§5.2.1/§5.5）；③补齐 §5.12 的删除清单（`revert.go:605`、flat 绑定的 store/gate 测试与四个 helper），并显式保留 `command_test.go:179` 的扁平指针 fixture。** 11e（兼容矩阵内容）与 C 级 VM/真机验收（归 #12）不在本文范围；本文只消费 11c-3 已冻结的备份/确认/回退接口，不重定义其中任何语义。**r6（owner D3）**：彻底删除 `hub_upgrade_operations` 镜像表——它今天只写不读，且是唯一迫使 schema 10→11 的原因，bump 之后 in-place downgrade 随即失效。journal 文件是唯一操作记录，`user_version` 保持 **10**，后续迁移必须纯加法（C11、§5.5）；Task 7 文档须写明 `mixedVersionGate` 的运维后果（§5.12）。

## 1. 背景与意图

11c-2 让 Line/Out 自替换，11c-3 定了 Hub 数据库备份记录、健康门控确认、分级 revert、`database_versions` 与不可逆确认位，但没有执行者：

1. Hub 自己不能升级：今天只能手工停服、改 `--data-dir`、换二进制，Web 统一升级在 Hub 断链。
2. 有写者没消费者：`POST /tasks/db-migration/approve` 让操作员“从 Hub 自升级的备份记录复制 `operation_id`”，却没有代码写这份记录；`database_versions` 没有生产读消费者；`server_upgrade_check.go` 仍 pin 自己运行的版本。
3. 顺序无机制保证：新 Hub 才懂新记录与 op journal 的语义（11d 不 bump schema，但记录/回执仍随发行版前移），先升 Line/Out 会让旧 Hub 读不懂回执。

还有一条第 1 稿漏掉的硬事实：**Hub 与 co-located Line 共用 `/usr/local/libexec/meshmuxd`**，Line 的 `/etc/meshmux/agent.json`、Line ledger 的 `shared_binaries.meshmuxd` 与 `state.Node.AgentVersion/AgentSHA256`、以及 Hub ledger 的 `shared_binaries.meshmuxd` 都钉住这个二进制。换 Hub 二进制必然触碰 Line，`SHARED_BINARY_MISMATCH` preflight 会拒绝 Line 启动；Line ledger 的 `state.Node` 还会在后续 fixed argv `--from-recorded-state` 与 `agent.json` 比对时触发 `CONFIG_CONFLICT`。11d 必须把“换 Hub”做成一次协调重钉，或显式 fail-closed。

## 2. 目标

1. Hub 自升级闭环：预升级备份 → root 预置目标 manifest → 已校验 staged 包 → 换二进制 + Line 重钉 → 重启 → 启动身份回读确认，失败可恢复。
2. **Hub 先升**：Hub 确认后才允许为 Line/Out pin 更新的目标（§5.8）。
3. 执行与浏览器/页面连接无关：交接后由 PID 1 托管，页面只读磁盘 op journal。
4. 重启后可查询：op journal 随 data-dir 携带；result 文件固定在 data-dir 之外（§5.9，N3），天然跨 schema、跨 data-dir 存活；journal 是唯一操作记录，**不设 DB 镜像表**，任何 schema 版本下都可读（§5.5，D3）。
5. 恢复可用：停机前校验 → 停 Web → 换回旧二进制 → 新 0700 目录 → 翻 data-dir → `/healthz` 200 → 只读身份核对。
6. 消费 11c-3 的备份记录、确认位、`database_versions`、`SCHEMA_TOO_NEW` 与空间规则；不新增公开 CLI、不新增 protocol kind。

## 3. 非目标

- **11e 兼容矩阵内容**。11d 只定 gate 形状与 fail-closed 行为。
- **C 级验收**（隔离 VM、真机 Debian 13 amd64/arm64）——归 #12；本文只承诺 B 级 fixture 证据。
- **发布通道自动化**：Hub 自有目标 manifest 的获取/签名属 12e 及后续；v1.0 由 root 预置（§5.8），Web 只做选择与执行，不下载 manifest。
- **LKG 回退的 Web 一键入口**（11c-3 语义可用，不新增按钮）。
- **N-1 以上的多代 Hub 回退选择**：备份保留 `keep=2` 个 confirmed 代，但 11d 的 restore 仍按当前失败 op 选择，不新增“任意代”入口（§5.7）。
- **`web → update` 反向导入**，除非引入中立叶子包（§5.9、Q3）。

## 4. 约束（继承 11c-3；C19–C22 为本稿新增）

- **C1 per-op 布局**：Hub 备份固定为 `<data-dir>/database-backup/<op32hex>/{record.json,payload/}`（目录 0700、`record.json` 0600、payload 目录 0700/文件 0600），与 Node 的每操作目录语义相同；confirmed-only GC 保留 `keep=2` 代。**扁平单槽布局及其 `recoverFlatSlot` 崩溃恢复机制整体删除，不实现、不迁移**（§5.2、Task 1 删除清单）。`<data-dir>/database-backup/record.json` 仅保留为旧二进制指针副本（§5.2.1），11d 的 restore/verify/GC/approval 从不读取它。
- **C2 记录冻结**：`update.BackupRecord` schema 1、`DisallowUnknownFields`、尾随数据拒绝、≤64 KiB；JSON 字节必须完全一致。**只有一个编码器**：`WriteBackupRecord` 只参数化载荷来源（`PayloadSingleDB` / `PayloadTree`），不再有布局参数（§5.2）；Node 与 Hub 共用同一 per-op 路径与同一编码器。
- **C3 状态机**：记录先写 `staged`，只有门控 finalize 后才是 `confirmed`；`failed` 是终态。11d 的门控就是启动身份回读（§5.5），finalize 本身沿用 11c-3，不改语义。
- **C4 完整性顺序钉死**：`VACUUM INTO` 生成副本 → 在**副本**上 `PRAGMA integrity_check` → 才写 `integrity_ok=true`。
- **C5 载荷含秘密**：payload 含订阅凭据、token hash、会话；0700/0600、`meshmux` 属主、永不离机、不进日志/回执。
- **C6 双摘要分离**：`from_agent_sha256` = 运行二进制摘要（`buildinfo.Digest()`，应等于 Hub ledger `shared_binaries.meshmuxd.sha256`）。`from_package_sha256` = Hub 安装包摘要，**权威来源是 Hub ledger `managed_files["/usr/local/libexec/meshmuxd"]`**；但 Web 无 ledger 读权（目录 root 0700、文件 root 0600，C19），backup 时只能以 `buildinfo.Digest()` 落值——它与 ledger 记录的是安装器 self-copy 的同一份字节（§5.9）。**执行侧核对**：root dispatcher 在任何 `update` exec 前用 `install.ReadState("/")`（`readStateAt`，仍要求 0700/0600）读 ledger，与记录 `from_package_sha256` 比对；缺失/不可读/非 64 hex → `HUB_BACKUP_IDENTITY_MISSING`，不符 → `UPDATE_BACKUP_MISMATCH`，均零 exec。两个字段独立存储、独立校验：`from_agent` 只用于旧包/restore 的字节 pin，`from_package` 只用于 ledger 来源核对，不得互换。Hub 记录要求两者非空。`db_schema` 写真实 `PRAGMA user_version`（今天 10）。**`artifacts.meshmuxd` 在任何 ledger 中都不存在**（`InstallHub` 只 stage caddy+headscale；`PinnedMeshmuxd` 只被 `upgrade/manifest.go:173` 的组件表消费），不得再作为来源。
- **C7 `database_versions` 写点冻结**：只在 store-open 迁移提交后由启动写者写。健康回读与管理面回读**只消费**，绝不写；旧行只在下一次启动自愈。该行是降级提示，不是迁移门。
- **C8 `SCHEMA_TOO_NEW`**：只 `lstat` 扁平指针路径 `<data-dir>/database-backup/record.json` 的存在性，不解析未来 schema；不原地降级。该文件是 per-op 记录发布后写入的 flat latest 副本（§5.2.1），只保证旧二进制的存在性检查仍能命中；11d 不以它作恢复源。
- **C9 不可逆位在记录上**：`irreversible_approved` 只有 `POST /tasks/db-migration/approve` 一个写者（session + 精确 Origin + CSRF + 字面值 `irreversible_confirm=1` + `operation_id`），且只写 `<data-dir>/database-backup/<op32hex>/record.json` 这一份被应用的 per-op 记录；扁平指针副本只按字节复制 per-op 记录（confirm 时可能因此带上该位），11d 从不在其上做授权判断，旧 approve 也不因它获权。破坏性步骤前必须读位并重验载荷（staged/confirmed + `integrity_ok` + 非空私有 payload + `PayloadSHA256`）；审批是 metadata-only，恢复必须在副本上重跑 `integrity_check`。
- **C10 分级 revert**：停机前完成全部校验 → 停 Web → 换回旧二进制 → 恢复到**新** 0700 目录 → `integrity_check` → 翻 `--data-dir`（drop-in）→ `/healthz` 200 → 旧目录保留到确认。中途失败 = 终态 + 人工指引，原目录不动。
- **C11 in-place down-migration**：11c-3 的判据仍是“新表为空且无新 binary 确认写时允许”；**11d 不新增表、不 bump schema**：`user_version` 保持 **10**，不实现 10→11 迁移（`migrateSchema11` 与 `hub_upgrade_operations` DDL 整体删除，§5.5），op 状态只在 journal。因此升级与 restore 前后 DB 同为 schema 10，“新表为空”恒成立，in-place downgrade 始终可用（扁平指针与 `SCHEMA_TOO_NEW` 只作旧二进制诊断，C8）。**后续迁移必须保持纯加法**（只加表/列/索引，不改不删既有 schema）；任何破坏性变更都会让 in-place downgrade 失效，须单独 owner 决定。
- **C12 确认是回读的副作用**：锚比较在 `confirmed` 短路**之前**；已被 revert 的操作永不确认；没有 `confirmUpgrade` 平行裁决。
- **C13 LKG 回退**：重发 LKG 的 candidate revision 走既有 four-task 链（`resurrect-after-delete` 是接受的固有语义，文档须写明）。
- **C14 空间下限重推导**：Node 的 1024 MiB 常量不覆盖 Hub DB 载荷（§5.9）。
- **C15 启动稳定码**：只有 `SCHEMA_TOO_NEW` 记 `detail`（记录路径，无秘密）；其他只记稳定码。
- **C16 执行面**：无新 protocol kind（`upgrade.*` 继续拒绝）、无新公开 CLI、固定 argv、无 shell、每写带 `operation_id`、回执诚实（queued/gated/applied/failed/rolled_back，applied 只由回读证明）、manifest pin + SHA-256 先于执行、日志脱敏。
- **C17 模块方向**：`internal/update` 不得 import `internal/web`；今天唯一反向边是 `web → update`（仅为 `BackupRecord`）。
- **C18 D2/D5（与 B8 对齐）**：孤儿兜底是纯 30 分钟年龄（不查 Hub）；GC 只在 confirmed 之后的下一次升级或显式清理时发生，且**候选集只有 `state=confirmed` 的代**（`GCBackups` 现行为：`staged`/`failed` 永不入选，`backup.go:336-340`）。`failed`/`staged` 记录必须活到被确认或显式清理，否则“失败仍有回退源”不成立。11d 的 Hub 用 per-op 布局并保留 `keep=2`（Node 的 `KeepConfirmed=1` 不变）；最新两代 confirmed 与任何 staged/failed 记录永不被回收，回收前按 per-op 路径先 rename 到 `.trash-<unix>` 再删。扁平布局的 `keep=1` 与 flat-GC 特例删除。**GC 与指针刷新解耦**：confirm 无条件执行 `keep=2` 回收，显式清理按 `keep≥2` 回收；指针刷新失败只记 `HUB_BACKUP_POINTER_STALE`，绝不以“跳过 GC”当代价（§5.2.1）。
- **C19 执行基座**：Web（`meshmux`，`CapabilityBoundingSet=`、`NoNewPrivileges=true`、`ProtectSystem=strict`）没有任何特权。**不引入 setuid/文件能力二进制**（11c-2 对 Agent 已排除，Hub 自有裁决相同）、**不给 Web 授 polkit**、**不让 Web 构造 ExecStart 或单元属性**。唯一触发是 root 属主的 path unit 监视一个 meshmux 可写目录。
- **C20 信任锚在执行侧**：目标 manifest 只能来自 root 属主文件；Web 给的 target/digest 只是选择，不是授权。执行体必须是按该 manifest 摘要校验过的 staged 包，并对 `/proc/self/exe` 重算 `--expected-sha256`。
- **C21 回读单向**：`confirmed` 只由“running 身份 == 记录 target”证明，不由 result 文件、unit 退出码或 UI 证明；`database_versions` 只由启动写。
- **C22 写者固定**：root unit 只写二进制、`/etc/meshmux`、`/etc/systemd/system`、`/var/lib/meshmux-installer/hub-upgrade/results/`（result）、`/var/lib/meshmux-installer/upgrade` 与两个 installer ledger（`state.json`、`local-line/state.json`）；不写 DB。Web 只写 data-dir 内的记录/载荷/journal 与 `/run/meshmux-hub/requests/` 的请求文件；不写二进制、unit、result、ledger。

## 5. 设计

### 5.1 执行基座（本稿核心决定）

第 1 稿的 `systemd-run` 前提不成立：向 systemd 提交 transient 单元需要 `org.freedesktop.systemd1.manage-units` 授权，而 polkit 规则**无法约束 transient 单元的 ExecStart**；给 meshmux 这条授权等于让它指定任意 root 命令，且不存在可收窄的写法。11c-2 能这么做是因为调用者 Agent 本来就是 root。

**选择：root 属主静态 oneshot + 校验请求文件 + path unit 触发。** 不用 `systemd-run`，不写 polkit 规则，不用常驻 root helper socket，不用 setuid。

installer 写入两个 root:root 0644 单元（`meshmux-hub-dispatch.path` enable，service 不 enable）、一条 tmpfiles 规则（`d /run/meshmux-hub 0730 root meshmux`、`d /run/meshmux-hub/requests 0730 root meshmux`、`d /run/meshmux-hub/requests.done 0700 root root`、`d /var/lib/meshmux-installer/hub-upgrade 0755 root root`、`d /var/lib/meshmux-installer/hub-upgrade/results 0750 root meshmux`）：

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
[Unit]
After=systemd-tmpfiles-setup.service

[Path]
DirectoryNotEmpty=/run/meshmux-hub/requests
```

- **请求目录固定在 `/run` 而不是 data-dir**：§5.7 会翻转 `--data-dir`，单元 ExecStart 不能随之改变；请求只是短命意图，重启丢失即由 §5.5 的超时判定收尾。dispatcher 处理成功后把请求 rename 到 `/run/meshmux-hub/requests.done/`（同一 tmpfs，root:root 0700），目录恢复为空以便 path unit 重新武装；不写 data-dir，因此 data-dir 翻转不影响它。
- Web 只写一个 0600 请求文件（temp + fsync + rename）并先提交 `queued`；path unit 与 oneshot 都由 PID 1 触发，**Web 不作任何特权调用**。第 1 稿的 `--no-block` 阻塞问题因此整体消失；等价钉死是“先提交 `queued`，后 rename 请求文件”（回执先于交接）。
- **请求文件不是授权**：`{schema:1, kind:"update"|"restore", operation_id:"<32hex>", data_dir:"<绝对路径>"}`，≤1 KiB、严格 JSON、`O_NOFOLLOW`、属主 == meshmux、0600。`data_dir` 必须是 clean 绝对路径且**等于当前 `meshmux-web.service`（含 drop-in）`--data-dir` 的值**（root 读单元文本比对），Web 无法用它指向别处。目标、摘要、路径全部由 root 侧从冻结记录与 root manifest 重新推导。
- **dispatcher 不执行升级写**：按请求里的 `operation_id` 严格读 `<data-dir>/database-backup/<op32hex>/record.json`（root 读端按 meshmux 属主校验，§5.9；**不扫目录、不读扁平指针副本、不运行任何恢复逻辑**）→ 读 journal（§5.5）→ 校验 state/target/摘要/记录与 journal 同名同一 op → **`kind:"update"` 时用 `install.ReadState("/")`（0600/0700）核对记录 `from_package_sha256`**（C6；`restore` 不查该字段，失败后 ledger 可能已前移）→ 读 root manifest 重算 `package_sha256` → 按 fd 校验 `<data-dir>/upgrade/meshmuxd-<target>-<arch>` 字节 → 把**已校验字节**复制到 root-only 的 `/var/lib/meshmux-installer/upgrade/exec-<op32hex>`（EXDEV 时复制 + fsync）→ `exec` 该副本。校验后再按路径打开会被 Web 换字节（TOCTOU），所以 exec 的是校验过的副本。per-op 读是纯只读，**root 进程不再因读记录而写 Web 属主目录**（扁平布局的 `recoverFlatSlot` 副作用删除；Web 进程内 producer 互斥改名 `LockBackupProduce` 并收窄到 §5.2 的查后写，root dispatcher 侧不需要也不获取任何锁）。
- **restore 走同一条 dispatch 边界（N1）**：`kind:"restore"` 时 dispatcher 校验对象是**旧包** `<data-dir>/upgrade/meshmuxd-<from_version>-<arch>`，摘要必须等于记录的 `from_agent_sha256`（不是 target、不读 root manifest），同样复制到 root-only 的 `exec-<op32hex>` 后 `exec` 副本；`--restore-dir`、`--data-dir`、`--expected-sha256` 全部由 dispatcher 从冻结记录与 journal 推导，Web 只给 `kind`/`operation_id`/`data_dir`。restore 的 `exec` 副本与 update 的 `exec` 副本同名规则，成功后删除。
- 真正改系统的代码是 staged 包自己的 `__internal-hub-update` / `__internal-hub-restore`，启动即对 `/proc/self/exe` 重算 `--expected-sha256`（11c-2 先例）。**单元 ExecStart 是固定 dispatcher，这是对“ExecStart 必须是 staged 包”这一不变量在静态单元下的等价实现**：static 单元无法随 target 改变 ExecStart，而让 Web 构造 argv 正是要消除的特权面；不变量因此钉在 exec 边界——dispatcher 本身不做任何升级写，升级写体是 root manifest 摘要钉死并自校验的 staged 包，已安装二进制只承担固定调度。
- **新增特权面登记（自有评审项 R-SURFACE，见 §6.11）**：1 个 root oneshot + 1 个 path unit + 1 个 meshmux 可写请求目录；它们能造成的唯一效果是“执行一份由 root manifest 摘要钉死的发布包”。边界逐条钉死：
  - `meshmux` **不能写 `/etc/systemd/system`**（任何 drop-in 都等于 root RCE）；只有 dispatcher 以 root `exec` 出的 restore 执行体（旧包，摘要 == `from_agent_sha256`）写 §5.7 的 `10-data-dir.conf`。
  - 请求里的 `data_dir` 若与当前 `meshmux-web.service`（含 drop-in）的 `--data-dir` 不符即拒绝（**伪造 data_dir 不生效**）。
  - 请求文件 `O_NOFOLLOW` 打开，`lstat` 拒绝符号链接，rename 目标在 `/run/meshmux-hub/requests/` 内（**symlink 换位拒绝**）。
  - `.path` 必须 `After=systemd-tmpfiles-setup.service`，否则 tmpfiles 未建目录时 path unit 永不武装。
  - 一次触发看到 >1 个请求文件时：**全部拒绝并 drain**（逐个移到 `requests.done/rejected-<unix>-<原名>`），否则 `.path` 因目录非空而**永不重新武装**；本稿不做“留一个待处理”。
- dispatcher 见到 >1 个请求文件：一个都不 exec，全部移到 `/run/meshmux-hub/requests.done/rejected-<unix>-<原名>`（drain，保证 `.path` 能重新武装），能解析出 op 的写 result `failed HUB_HANDOFF_BUSY`，其余只记日志；单个请求校验失败时写 result `failed` + 稳定码再退出，无法解析者同样移入 `rejected-<unix>-<原名>`；单飞主判定在 Web（§5.2），drain 只是兜底。

### 5.2 Producer：备份、交接与单飞

`/tasks` 边界上的三步管理员 mutation（都走既有 `app.mutation`）：

| 路由 | 输入 | 作用 | 回执 |
| --- | --- | --- | --- |
| `POST /tasks/hub-upgrade/backup` | `target_version` | 在 `LockBackupProduce` 临界区内完成单飞读、生成 `operation_id` 与 `backup_generation`、写 `backing_up`（§5.2 第 1 步），随后锁外解析并校验 root manifest、执行 VACUUM→校验→staged 记录 | `status=staged`、`operation_id`、`from_version`、`db_schema`、`integrity_ok` |
| `POST /tasks/hub-upgrade/apply` | `operation_id` | 再校验记录/root manifest 一致、不可逆位、空间；stage 目标包；提交 `queued` + 请求文件 | `status=queued`、`target_version` |
| `POST /tasks/hub-upgrade/restore` | `operation_id` | §5.7（仅 `failed`/`partial`/`verifying`） | `status=restoring` |

目标与摘要在 backup 时确定（冻结记录不允许空字段），apply 不接收 digest、只做再校验；页面流程因此固定为“选目标（列出 root 预置且校验通过的 manifest）→ 备份 → 如不可逆先写确认位 → 提交”。apply 在 manifest `database_migration=irreversible` 而记录 `irreversible_approved=false` 时返回 `IRREVERSIBLE_CONFIRM_REQUIRED`，零变更。

**单飞（C18/D5）**：任一 op 处于非终态（`backing_up|backed_up|queued|applying|restarting|verifying|partial`）或**最新可读 per-op 记录** `irreversible_approved=true` 时，`backup` 一律 `HUB_UPGRADE_BUSY`（**自有稳定码**，不复用 11c-3 的 `UPDATE_BACKUP_MISMATCH`；后者只表示记录身份/来源不符），零变更；不做并发备份。**“最新”定义为 journal-backed**：取 `hub-upgrade/ops/` 中 `backup_generation` 最大、且其 `<database-backup>/<op32hex>/record.json` 可读的 update op（同值按 `updated_at`、再按 op id 决胜）；**不得用 `database-backup/` 目录扫描或 `mtime` 推断**。最新 op 没有记录（例如提交前失败）时顺延到下一个 generation；全无则视为无当前记录。`backup_generation` 在 `backing_up` 时分配为“所有可读 journal op 的最大值 + 1”（首个为 1，失败/回滚不回收编号），GC 不重编号，因此“最新”跨 restore 仍稳定；journal 不可读时 fail-closed `HUB_BACKUP_JOURNAL_FAILED`，零备份。dispatcher 侧的“请求目录已有请求”另用 `HUB_HANDOFF_BUSY`（§5.1），两者语义不同、不互相顶替。`restored.json` 不阻塞新备份（它只禁止把携带记录当恢复源，§5.7），新 staged 记录落盘时一并清除。

**producer 互斥（保留，收窄并改名；不要再删）**：`Busy() → nextBackupGeneration() → WriteOp(backing_up)` 是**查后写**（check-then-act）：两次读 journal 与一次写 journal 之间若不互斥，两个并发 `POST /tasks/hub-upgrade/backup` 可能都读到“不忙”、拿到同一个 `max+1`，于是同一 generation 有两份 op、单飞判定被绕过。Web 是并发的（`net/http` 每请求一个 goroutine，没有全局互斥），因此必须在 Web 进程内保留一把**进程级 producer 互斥**：`internal/hubupgrade` 的包级 `sync.Mutex`，函数名从 `LockFlatSlot` 改为 **`LockBackupProduce`**（语义已不是“flat slot”，注释同步改写），获取后返回 unlock。**覆盖范围恰好是这一段的查后写**：`Busy` 读 → `nextBackupGeneration` 读 → `WriteOp(backing_up)` 写，三者同一临界区；拿到 `backing_up` 落盘后即可释放，后续 VACUUM/复制/stage 不进锁（它们只写本 op 自己的目录，互不冲突），`backed_up` 写入也不需锁（此后该 op 已被 `Busy` 看见，新 backup 自然 `HUB_UPGRADE_BUSY`）。跨进程互斥**不**由它承担——那仍由 store 的 data-dir flock 保证（同一 data-dir 只有一个 meshmux Web 进程），锁不是可重入的，持有者不得再调 `CreateBackup`。它也与读端无关：per-op 记录只经 rename 替换，11c-3 Node 路径已证明无锁读安全，approve/`/tasks` 读不需要这把锁。

**顺序（rotate before replace，钉死）：**

1. **`LockBackupProduce` 临界区（只罩查后写）**：生成 `operation_id`（32 位小写 hex，`crypto/rand`，锁外）→ 进锁 → `Busy` 单飞读 → `nextBackupGeneration` 读 → `WriteOp(backing_up)` 写（fsync+rename）→ 出锁。锁内不得复用进入前的缓存结论，必须重读 journal。`backing_up` 落盘后**立即释放锁**；解析并校验 root manifest（§5.8，得 `manifest_sha256`/`package_sha256`）在锁外进行。
2. **把运行中的二进制 stage 成旧包**：`buildinfo.Digest()` 读 `/proc/self/exe` → 复制到 `<data-dir>/upgrade/meshmuxd-<from_version>-<arch>`（0755，fsync + rename），回读摘要必须 == `from_agent_sha256`。失败 `HUB_BACKUP_BINARY_STAGE_FAILED`。**没有这一步，恢复默认就是 `HUB_RESTORE_BINARY_MISSING`。**
3. `backup.Dir(root, op)` 建 `<data-dir>/database-backup/<op32hex>/`（0700）与 `payload.part/`；先删同 op 的陈旧 `payload.part`（不触碰已提交的 `payload`/`record.json`）；`VACUUM INTO '<op-dir>/payload.part/meshmux.db'`（事务之外；目标必须不存在；路径由固定常量 + `op32hex` 派生）。
4. 只读打开副本 → `PRAGMA integrity_check` 必须 `ok`。
5. 计算 `meshmux.db` 的 SHA-256，`payload_files=1`。
6. **per-op 原子提交**：`payload.part`→`payload`；`record.json.part`→fsync→rename 为 `<op-dir>/record.json`；fsync op 目录与 `database-backup/`；`state=staged`、`integrity_ok=true`。至此 per-op 记录是唯一权威。
7. journal `backed_up`（带第 1 步分配的 `backup_generation`）；随后写扁平指针副本（§5.2.1）。指针写失败**不改变** `backed_up`，只记 `HUB_BACKUP_POINTER_STALE` 并保留上一份指针。
8. **此时不回收任何旧代（B8）**：GC 候选只有 `state=confirmed` 的代（`backup.go:336-340`），且按 C18 只在“确认之后的下一次升级或显式清理”执行；staged 落盘时删旧代会让当前升级的 N-1 在确认前消失。`keep=2` 的回收由 Task 5 在 confirm 之后无条件执行（与指针刷新成败无关，§5.2.1）；staged/failed 与最新两代 confirmed 永不被回收。失败一律删 `.part`、旧代原样保留、回执 `failed` + 稳定码。

**字段映射：**

| 字段 | 值 |
| --- | --- |
| `from_version` | `buildinfo.Version` |
| `target_version` | 请求的目标版本（== root manifest `version`） |
| `db_schema` | 真实 `PRAGMA user_version`（今天 10） |
| `policy_schema` | `upgrade.PolicySchema`（8） |
| `manifest_sha256` / `package_sha256` | root manifest 字节摘要 / 该 manifest 中 `meshmuxd-<arch>` 的摘要 |
| `from_package_sha256` | backup 时 Web 以 `buildinfo.Digest()` 落值（= 安装器 self-copy 的同一份字节；Web 不读 ledger）；权威值仍是 Hub ledger 的 `managed_files["/usr/local/libexec/meshmuxd"]`，由 root dispatcher 在 update exec 前用 `install.ReadState("/")` 核对（C6） |
| `from_agent_sha256` | `buildinfo.Digest()`（运行二进制摘要，C6）；应与 `shared_binaries.meshmuxd.sha256` 相等（`hub_apply.go:119-132` 同一次 apply 写两者） |
| `payload_path` / `payload_files` | `<data-dir>/database-backup/<op32hex>/payload` / 1 |

**C2 的落地**：不新增 `WriteHubBackupRecord`。既有 `WriteBackupRecord(root, spec, payload)` 只参数化载荷来源：`payload ∈ {PayloadSingleDB, PayloadTree}`；Hub 用 `PayloadSingleDB`（单 `meshmux.db`，摘要取原始文件 SHA-256），Node 用 `PayloadTree`。路径固定为 per-op `<root>/<op32hex>/{record.json,payload}`，两种载荷共用同一个 `encodeBackupRecord`、同一套状态/权限校验与同一 `verifyPayload` 路径钉死；**不再有 `LayoutFlat` / `LayoutPerOp` 参数**。payload kind 不写入记录，因此同一 `spec` 下 Node 与 Hub 的 `record.json` 逐字节相同；测试用同一金标断言键序/尾随字节，不做“两种布局除 `payload_path` 外相同”的比较。扁平单槽的 `<root>/record.json`、`<root>/payload` 与 `<root>/payload.part` 路径不再被记录层使用；`<root>/record.json` 只是 §5.2.1 的指针副本。

#### 5.2.1 旧二进制指针：flat latest 副本（D1 附属决定）

11c-3 冻结的 `schemaTooNew`（`internal/web/store_database_gate.go`）只对**扁平路径** `<data-dir>/database-backup/record.json` 做 existence-only `Lstat`，不解析、不校验属主/模式。改为 per-op 后该路径默认不存在。**决定 (a)：per-op 提交成功后另写一份 flat latest 副本**，只作旧二进制的存在性指针；除冻结的 `schemaTooNew` existence-only `Lstat` 外，11d 的 `Read`/`Verify`/`Confirm`/restore/dispatcher/GC 都按 `<op32hex>/record.json` 工作，**从不读取该副本**。

- **写序（钉死）**：① 第 6 步 per-op `record.json` rename + fsync 完成；② journal `backed_up`；③ 读回该 per-op 记录的**原始字节**，写 `<root>/record.json.part`（0600，`O_EXCL`；先删同目录陈旧 `.part`）→ fsync → rename 为 `<root>/record.json` → fsync `<root>`。副本内容与 per-op 记录逐字节相同，`payload_path` 仍指 `<root>/<op32hex>/payload`。**confirm 成功后按同一 temp+fsync+rename 步骤刷新一次副本**（此时内容是 confirmed 记录）；approve 不回写，故副本的 state/位可能滞后，但它只供旧二进制的存在性检查，11d 从不以它授权。
- **崩溃语义**：①之前崩溃 → 无 per-op 记录，指针不变；①之后、③之前崩溃 → per-op 是权威，指针仍是上一代（或不存在）；③的 temp 写/rename 之间崩溃 → 旧指针或新指针二选一，`.part` 残留由下一次③先删。**没有 `recoverFlatSlot`、没有 trash/orphan 回滚、没有跨进程锁**（Web 进程内的 `LockBackupProduce` 只罩 §5.2 的 `Busy → generation → WriteOp(backing_up)`，与这里无关）：11d 对该副本无读者、无授权，任何中间态都不影响 11d 的正确性。
- **失败语义**：③失败只记 `HUB_BACKUP_POINTER_STALE`（op id + 稳定码，无秘密），journal 保持 `backed_up`，per-op 记录/载荷不变；下一次成功 backup 或 confirm 重试。**指针刷新与 GC 解耦（钉死）**：confirm 无条件执行 `keep=2` 回收，显式清理按其 `keep`（钉 `≥2`）回收——**刷新失败都不跳过 GC**，只多记一条 `HUB_BACKUP_POINTER_STALE`。安全性来自候选集本身：GC 只收 `state=confirmed` 且按 `backup_generation` 保留最新两代，而指针目标必落在这两者之内——要么是**最新 staged**（`staged` 永不入选），要么是**最新 confirmed**（在 `keep=2` 内），因此不可能是回收候选；唯一例外是刷新失败后指针仍指向**更老的 confirmed 代**，此时回收它只会让指针短暂指向一个已删除的旧代，指针本就是 existence-only 诊断副本、11d 从不读取，最坏结果是旧二进制的提示指向不存在的文件（下次成功刷新即自愈）。**Hub 侧的 `keep` 不得小于 2**（显式清理同样钉 `keep≥2`，绝不传 0/1）：`keep<2` 会回收刚被刷新为指针目标的最新 confirmed 代，把“诊断指针存在”变成“指针指向已删记录”。因此**Hub 的 GC 调用点**只允许 `2` 和 `max(2, 期望值)`，`internal/hubupgrade` 的清理入口对 `keep<2` 直接返回参数错误，不允许调用方自行下调。该约束是**调用点级**，不是包级：`internal/backup.GC` 仍是参数化函数，Node 的 `GCBackups(root, KeepConfirmed=1)` 与 §4 C18 完全不变（Node 没有扁平指针副本，也就没有“指针目标被回收”的问题）。GC 只扫 `<op32hex>/` 目录，`record.json` 永不是候选。
- **旧二进制可见行为**：存在副本时，`schemaTooNew` 仍返回 “restore the verified database backup record `<data-dir>/database-backup/record.json`”，操作员打开即看到 `operation_id` 与 per-op `payload_path`；副本是合法 schema-1 `BackupRecord`，旧 `readDatabaseBackupRecord` 可严格解码，但其 `verifyDatabaseBackupPayload` 会因 `payload_path != <root>/payload` 拒绝——旧 approve 在这条降级边界上 fail-closed，11d 也从不把副本上的位当授权。副本缺失（首次 backup 的指针写失败）时旧二进制退回 “no verified database backup record exists at …”，只丢诊断指针，不丢恢复源。
- **为什么不选 (b)/(c)**：(b) 的指针形状会被旧 `BackupRecord` 严格解码成 `DB_BACKUP_RECORD_CORRUPT`，而 `schemaTooNew` 的文案仍称它是“verified record”，等于让冻结文案说谎；(c) 最省事但把唯一跨 11d 降级边界的诊断指针主动丢掉。**(a) 只多一个 0600 原子写路径（backup 与 confirm 各执行一次），不新增编码器、读路径或恢复机制，且明确无读权**，是三个选项里最小且不骗人的一个。

### 5.3 版本身份（单一来源）

- 新增 `internal/buildinfo`（只 import 标准库）：`Version` 由 `-ldflags -X .../internal/buildinfo.Version` 注入，缺省 `1.0.0-dev`；`Digest()` 打开 `/proc/self/exe`（不是 `os.Executable()`）算 SHA-256，上限 128 MiB，失败返回 `HUB_DIGEST_UNAVAILABLE`，不猜。
- **单一来源（N7，定案）**：`node.CurrentAgentVersion` 今天是一个导出 `const`（`internal/node/config.go:50`）。**不要**改成可写 `var`：包级可写变量会被任意包在运行时改写，manifest 投影、`database_versions` 身份与升级确认会一起漂移，且没有任何编译期保护。改为**函数**：`func CurrentAgentVersion() string { return buildinfo.Version }`（`internal/node` → `internal/buildinfo`，buildinfo 只 import 标准库，无环），调用点机械改为 `node.CurrentAgentVersion()`（`upgrade/manifest.go:86,95`、`web/config.go:124`、`web/store_database_gate.go:118`、`web/server_upgrade_check.go:392` 等）。函数返回只读值，无法被赋值，也不需要 `const` 与 ldflags 两份注入。**manifest 字节/摘要影响**：`version` 在 canonical JSON 内，改 ldflags 版本等于改所有 manifest 摘要；fixture 金标与任何 pin 必须与版本注入同一次提交重算（爆炸半径 = 全部 manifest 摘要 + `database_versions` 身份，测试整批重算而非逐点修补）。
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

**op journal 是唯一操作记录，没有 DB 镜像表（owner D3）。** 恢复会把 DB 带回升级前的同一 schema，而 op 事实必须跨 schema 与 data-dir 存活，所以状态只落文件：

- `<data-dir>/hub-upgrade/ops/<op32hex>.json`（0600，schema 1）：`operation_id`、`kind`、`state`、`target_version`、`from_version`、`manifest_sha256`、`package_sha256`、`db_schema`、`backup_generation`、`error_code`、`updated_at`。Web 写；恢复时随 `hub-upgrade/` 带入新 data-dir。`backup_generation` 在 `backing_up` 时分配为“现有可读 journal op 的最大值 + 1”（首个为 1；失败/回滚不回收编号，GC 不重编号），是 journal-backed 的“最新”判定依据（§5.2）；记录本身仍无此字段（C2 冻结），关联只靠 `operation_id`。

**为什么删除 `hub_upgrade_operations`**：该表今天只写不读，没有 SQL 消费者；它又是唯一迫使 schema 10→11 的原因，而一旦 bump，“新表为空”永不成立、in-place downgrade 随之失效（C11）。journal 文件随 data-dir 存活、不依赖 `user_version`，restore 路径**不打开 DB 就能读 op**（跨 schema 可读是特性，§5.7），因此整段删除：表 DDL、`migrateSchema11`、`upsert`/`list` 写读端，以及“镜像写失败不阻塞 confirm”的语义。代价只是失去 SQL 排序/过滤——`GET /tasks` 直接解析 ≤ 数十份 JSON；单飞与“最新”判定本来就必须 journal-backed（§5.2），不存在第二真相。dispatcher 只读 journal 与记录，从不读 DB。

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

上表所有 “result” 都指固定路径 `/var/lib/meshmux-installer/hub-upgrade/results/<op32hex>.json`（§5.9 N3），**不是** `<data-dir>/hub-upgrade/results/`；读端只接受该常量路径，且只把它当进度提示（C21）。

**`confirmed` 判定（唯一）**：`buildinfo.Version == journal.target_version && buildinfo.Digest() == journal.package_sha256`。`from_*` 只用于恢复/重钉核对，**永不**与升级后的运行值比较（升级后 running 就是 target，`from_*` 必然不等）。判定只在启动对账执行；定时器只推进状态与超时，不确认。确认时调用 11c-3 既有 finalize 把**该 op 的 per-op 记录**置 `confirmed`（语义不改，也不写任何 DB 行）；随后按 §5.2.1 刷新扁平指针副本，**无论刷新成功与否都执行 `backup.GC(root, 2)`**（confirmed-only；staged/failed 与最新两代永不入选）。刷新失败只记 `HUB_BACKUP_POINTER_STALE`，**不跳过 GC**：指针目标要么是刚确认的这一代（最新 confirmed，在 `keep=2` 内），要么是最新 staged（永不入选），要么（刷新失败且指针滞后）是更老的 confirmed，而 11d 从不读该副本，回收它只让旧二进制的提示短暂失效，不影响任何恢复源（§5.2.1）。`RequireBackupDir`/`VerifyBackupRecord`/`readBackupRecord` 固定解析 `<root>/<op32hex>/record.json`，**不再接受 layout 参数**；11c-3 的 Node 路径与 11d 的 Hub 路径因此是同一条读路径（原 N5 的 flat/per-op 双布局分叉删除）。`reverted` 终态不被后续启动覆盖（C12）。

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
3. **Line 预检（任何写之前，MF-3）**：存在 co-located Line 时，**四个来源都要读并都对**：
   - Hub ledger `/var/lib/meshmux-installer/state.json`：`shared_binaries.meshmuxd.sha256` == 当前 `/usr/local/libexec/meshmuxd` 摘要（`apply.go:288` 的 `checkLocalLineSharedBinaryForExecutable` 同源）；
   - Line ledger `/var/lib/meshmux-installer/local-line/state.json`：`shared_binaries.meshmuxd.sha256` 同样 == 当前摘要（`hub_stage.go:123` → `local_line.go:295-308` 的 `checkLocalLineSharedBinary`）；
   - Line ledger 的 `state.Node.AgentVersion`/`AgentSHA256` == `from_version` / 当前摘要（co-located Line 在 `node_stage.go:98-100` 用共享二进制摘要写入，`node_verify_tail.go:120` 持久化；缺失、空版本或非 64 hex 同样失败）；
   - `/etc/meshmux/agent.json` 的 `agent_sha256` 与 `agent_version` 同样 == 当前摘要 / `from_version`。
   另需当前 `/usr/local/libexec/meshmuxd` 摘要 == 记录 `from_agent_sha256`（回退目标必须就是现运行字节）。任一不符 → `HUB_SHARED_BINARY_PRECHECK_FAILED` 终态、零写。**只查 Hub ledger 不够**：Line ledger 是 Line 自己的启动预检输入，漏读会让升级后 Line 永久 `SHARED_BINARY_MISMATCH` 锁死（repair 也被同一条预检挡住）。**只重钉两个 ledger 的 `shared_binaries` 加 `agent.json` 也不够**：漏掉 Line ledger `state.Node` 会让下一次 fixed argv `--from-recorded-state` 在 `checkRecordedAgentConfig`（`node_recorded.go:95-96`；`recordedNodeConfig` 由 `node_apply.go:64-76` 调用）读到旧对，报 `CONFIG_CONFLICT`。
4. 结果文件写 `accepted`（交接回执），再写 `swapping`（先写后做）。
5. 同目录 `meshmuxd.new`（写自身字节、0755、fsync）→ rename 覆盖 `/usr/local/libexec/meshmuxd` → fsync 目录。
6. **Line 重钉写四处（MF-3）**：① Hub ledger `shared_binaries.meshmuxd.sha256` 与 `managed_files["/usr/local/libexec/meshmuxd"]`（`/var/lib/meshmux-installer/state.json`，同一文件一次 temp+fsync+rename；后者是下一次 `from_package` 核对与 installer repair 的输入，必须同步前移）；② Line ledger `shared_binaries.meshmuxd.sha256`（`/var/lib/meshmux-installer/local-line/state.json`）；③ Line ledger `state.Node.AgentVersion`/`AgentSHA256`（target 版本 / `--expected-sha256`；只改这两个字段与 `updated_at`，其余 Node 字段和 `status` 原样；②③ 必须同一文件一次 temp+fsync+rename，不能分两次写，并同步 `managed_files["/etc/meshmux/agent.json"]` 为新字节摘要——新 `agent.json` 用 `nodeManagedFiles` 同一编码渲染）；④ `/etc/meshmux/agent.json` 的 `agent_version`/`agent_sha256`。四处 pin 与两处 `managed_files` 的旧值在写前全部读入内存；三个文件各自 temp+fsync+rename；**四个 pin 都成功才算重钉完成**，任一失败走第 8 步回退（**四处 pin 与两处 managed_files 全部改回旧值**，不是只回滚已写的那几处）。Line 单元 active 时 `systemctl restart meshmux-agent.service`，不存在则跳过并在 result 注明。
7. 结果文件写 `restarting`（**在 restart 之前**，沿用 `install_cmd.go:88-96` 的 `installed-awaiting-restart` 先例），然后 `systemctl restart meshmux-web.service`；成功后补写 `restart-accepted`（尽力而为）。
8. 失败回退：第 5–7 步任一失败 → 用 backup 时 stage 的旧包（摘要 == `from_agent_sha256`）换回二进制、把**四处 pin 全部改回旧值**（Hub ledger `shared_binaries` + `managed_files`、Line ledger `shared_binaries` + `state.Node` 对 + `managed_files`、`agent.json`）、重启 Line，写 `failed` + `HUB_SHARED_BINARY_REPIN_FAILED`/`HUB_UPGRADE_RESTART_FAILED`；二进制或任一字段写回失败 → `partial`，不重启 Web，人工指引。
9. 不写 DB、不写 unit 文件、不写 journal；成功后删除 `/var/lib/meshmux-installer/upgrade/exec-<op>` 副本（失败/崩溃时由下一次成功 op 或显式清理回收）。单元是 `meshmux-web.service` 的兄弟，重启 Web 不影响它继续跑。

### 5.7 Restore executor

执行体是**旧**包：`<data-dir>/upgrade/meshmuxd-<from_version>-<arch> __internal-hub-restore --expected-sha256 <from_agent_sha256> --operation-id <op32hex> --data-dir <data-dir> --restore-dir <data-dir>/restore-<op32hex>-<unix>`（固定 argv，独立字节 pin，首步同样自校验 `/proc/self/exe`）。该 argv 由 dispatcher 从冻结记录推导并对旧包重算 `from_agent_sha256` 后才 exec（§5.1 N1 条），Web 不能提供这些参数。用与待恢复库同代的二进制，天然避免“新二进制打开旧库”的误迁移。

**停机前（失败 = 零停机零变更）：**

1. 按 journal 的 `operation_id` 严格读 `<data-dir>/database-backup/<op32hex>/record.json`（不扫目录、不读扁平指针副本）；journal `state ∈ {failed, partial, verifying}`、记录 `state ∈ {staged, confirmed}`、`integrity_ok`、`payload_files>0`。`staged` 是**合法恢复源**（升级失败时它就是最近一代），与 B8 一致：GC 只收 `confirmed`，`staged`/`failed` 记录及其载荷永不在恢复前被回收。
2. 重算 `<op-dir>/payload/meshmux.db` 的 SHA-256 == `PayloadSHA256`（`integrity_check` 不等于“字节正确”）。
3. 建新目录 0700；把副本落入新目录，并在**副本**上 `PRAGMA integrity_check`。
4. **用原始只读连接**（`mode=ro&immutable=1`，不经 store-open/迁移）读副本自身的 `user_version` 与 `database_versions` 行，与记录的 `from_version`/`db_schema` 比较；不等或行缺失 → `CONFIG_CONFLICT`，停机前返回。第 1 稿用新二进制打开 schema 10 副本必然不一致，这是恒定误报。
5. 旧包存在且摘要 == `from_agent_sha256`，否则 `HUB_RESTORE_BINARY_MISSING`（producer 已保证不再默认缺）。
6. 解析当前 web 单元的单行 `ExecStart` 形状，生成 drop-in 临时文件；形状不符 `HUB_RESTORE_UNIT_SHAPE_INVALID`。
7. 空间检查（§5.9）。

**停机后：** 停 Web → 旧包换回二进制（同目录 `meshmuxd.new` + rename）→ **四处 pin 改回 `from_*`**（Hub ledger `shared_binaries` + `managed_files` + Line ledger `shared_binaries` + Line ledger `state.Node` 的 `AgentVersion/AgentSHA256` + Line ledger `managed_files` + `agent.json`，同 §5.6-6 写集，全成或全败）并重启 Line → 写 `/etc/systemd/system/meshmux-web.service.d/10-data-dir.conf`（`ExecStart=` 复位 + 重写同一 argv、仅 `--data-dir` 改变；temp+fsync+rename+fsync 目录）→ `daemon-reload` → `start` → 轮询 `/healthz` 200（60s；SELECT 1 契约，只证存活）→ 原始只读连接核对恢复库身份 → result `restored`。data-dir 翻转**只用 drop-in**，基础单元不动；不再有“改写 ExecStart 或读 `hub-data-dir` 文件”的二选一。

- 新建目录、恢复库、携带的 `database-backup/` 与 `hub-upgrade/` 全部 `chown -R meshmux:meshmux`。
- **携带记录的限制**：`database-backup/<op32hex>/record.json` 与扁平指针副本都按字节原样保留（C2），其 `payload_path` 仍指旧 data-dir，且其 state 不能代表恢复后事实；因此只可作 `SCHEMA_TOO_NEW` 的 existence-only 指引（实际命中的是扁平指针副本），**per-op 记录也不得作为下一次恢复源**。启动对账见到 result `restored` 时写 `hub-upgrade/restored.json` 标记并把 journal 置 `reverted`（终态）；读取端见到标记即拒绝把任何携带记录当 rollback source，新 staged 记录落盘时清除标记。
- 恢复后 DB 仍是 schema 10（11d 不 bump schema，C11），没有镜像表需要和解；op 事实只来自 journal（随目录携带）+ result（固定 root 路径，§5.9 N3，不经 data-dir），UI 直接读它们。**restore 全程不打开 DB 读 op**——这正是删除镜像表的收益（D3）：journal 的文件格式与 `user_version` 无关，恢复到任一 schema 都读得懂。
- 中途失败 = 终态 + 人工指引，原目录不动，Web 保持 down；不自动重试。若二进制/pin 已改，先换回再落 `partial`。
- 二进制回退只对“加法迁移”的库成立（C11）；11d 自己的 op 永远走这条 restore。
- **LKG 语义适用范围**：11c-3 的“重发 LKG candidate revision”是 Line/Out 的回退机制，11d 原样保留；Hub 没有 candidate revision 链，只有 restore 一条路，不得把 four-task 链套到 Hub。
- **`keep=2` 不改变 restore 选择**：多保留的一代 confirmed 只是留在 `<data-dir>/database-backup/` 的恢复源；11d 仍只按 journal 当前失败 op 的 `operation_id` 恢复，不自动回退到更早的 confirmed 代，也不新增代选择入口。

### 5.8 Manifest 与 pin lifting（含不可逆来源）

- Hub 只为**可认证**的 manifest 发 pin：自己构建的 set（`upgrade.ForArchSet()`，今天的行为）或 root 预置并通过下表校验的目标 manifest（pin 提升）；绝不解析、转发或信任 Web 提交的 manifest 字节。
- **Hub 自己的目标**（新增，必须显式）：

| 项 | 值 |
| --- | --- |
| 源 | `/var/lib/meshmux-installer/upgrade/manifest-<target>.json`，root:root 0755/0644；由安装/运维以 root 预置；Web 不可写 |
| 认证（信任前，MF-1） | **不调用 `upgrade.Manifest.Validate`**——它是“本运行构建的自检”，会把目标组件表与编译期 `pinnedComponents` 逐字节比对（`manifest.go:195-238`），任何真正的更新版本必然被拒。改用 11c-2 已落地的**目标门** `validateTarget`（`internal/update/update.go:375-399`）同形状：`schema == upgrade.Schema`、`version == target`（且是 SemVer）、`architecture == runtime.GOARCH`、存在 `components[meshmuxd-<arch>]` 且 `SHA256` 为 64 位小写 hex、`trustedSource`（release 必须 `https://github.com/`；dev 必须 `dev-` 版本 + `file://`/`https://`）；再加 `policy_schema == upgrade.PolicySchema` 与 `version > running`。字节 SHA-256 冻结进记录 |
| `database_migration` 字段位置（MF-1） | 该字段**骑上面那个目标门**，不是 `Manifest.Validate`：11d 把它加进 `upgrade.Manifest`（`json:"database_migration,omitempty"`），目标门在解析后校验 `∈ {additive, irreversible}`（缺省 = `additive`），并随 manifest 字节一起纳入 `manifest_sha256`。目标 manifest 的解析必须**严格**（`DisallowUnknownFields` + 尾随数据拒绝，同 `update` 包既有写法），未知字段即 `MANIFEST_UNAVAILABLE`；11d 是该字段的第一个消费者，后续新增字段必须与消费端同发行版引入且目标版本 ≥ 该发行版（否则 fail-closed，不会静默误读） |
| 包来源 | 该 manifest 的 `components[meshmuxd-<arch>].Source`；生产形态是固定 GitHub release asset（`…/releases/download/v<target>/…`，拒绝 `latest`/`main`/可变标签），但 **12e 之前 `meshmuxd` 仍是 `file://` dev pin，见 §8** |
| 谁 stage 包 | **Web 在 apply 阶段**（backup 不下载）：先 `HUB_SPACE_INSUFFICIENT` 检查 → `.part` 下载/复制 → 摘要校验 → fsync → rename 为 `meshmuxd-<target>-<arch>`；已存在且摘要相同则幂等复用，摘要不符删掉重取 |
| `MANIFEST_UNAVAILABLE` 推导 | 文件缺失/不可读/非 root 属主或非 0644/JSON 解析失败/目标门失败（schema、version≠target、arch、组件缺失或摘要非 64hex、来源类别不符、policy_schema 不符、版本 ≤ running、`database_migration` 非法）→ 零写入 |

信任链完整形状：root 属主 manifest（锚）→ 摘要 → staged 包字节 → dispatcher 校验 → exec 副本自校验。Web 只能选择“root 已认可的目标”，不能提供字节或摘要。

- pin 提升 gate（形状；矩阵内容 11e）：目标 manifest 可被认证，且 `Compatibility(target, running, arch, dbschema)` 为 true；矩阵不可用同样 fail-closed。Hub 升完后 running 前移，自然解锁对 Line/Out 的更新 pin。
- **不可逆来源字段**：manifest 增可选 `database_migration` ∈ {`additive`（缺省）, `irreversible`}，由 §5.8 的**目标门**（不是 `Manifest.Validate`）校验；缺省即不可逆=false。字段在 manifest 字节内，因此被 `manifest_sha256` 钉住。`irreversible` 时 apply 必须见到记录 `irreversible_approved=true`，否则 `IRREVERSIBLE_CONFIRM_REQUIRED` 零变更（与 §5.2 apply、§5.11 同一条件）。
- co-located Line 的共享二进制**不再“保持原样”**：§5.6 第 3/6 步即协调重钉；`SHARED_BINARY_MISMATCH` 仍是最后防线，不再是 11d 的挡箭牌。

### 5.9 空间 / 属主 / 日志 / ledger

```
hubRequiredSpace = 128 MiB (目标包) + 3×dbSize (VACUUM/暂存副本 + 2 个已确认代)
                 + 128 MiB (旧包) + dbSize (恢复新目录) + 256 MiB (journal/result/余量/exec 副本)
hubSpaceFloor    = max(hubRequiredSpace, 1 GiB)   # 1 GiB = 安装器既有预检下限
```

`HUB_SPACE_INSUFFICIENT` 在每次复制/下载前检查（备份副本、目标包 stage、恢复目录），零变更；公式单测钉住。`keep=2` 把备份库的峰值从 2×dbSize 提到 3×dbSize（最新/暂存 1 + 已确认旧代 2），恢复新目录另加 1×dbSize；扁平单槽的 1 代假设删除。

| 路径 | 属主/模式 | 写者 |
| --- | --- | --- |
| `/var/lib/meshmux` | meshmux 0700 | installer |
| `database-backup/<op32hex>/`、`payload/` | meshmux 0700 / 文件 0600 | Web |
| `<op32hex>/record.json` | meshmux 0600 | Web |
| `database-backup/record.json`（旧二进制指针副本） | meshmux 0600 | Web（§5.2.1；11d 从不读取） |
| `upgrade/`（两代包） | meshmux 0700 / 包 0755 | Web |
| `hub-upgrade/ops/` | meshmux 0700 / 0600 | Web |
| `/var/lib/meshmux-installer/hub-upgrade/results/` | root:meshmux 0750 / 文件 0640 | root unit；**在 Web data-dir 之外**（N3） |
| `/run/meshmux-hub/requests.done/` | root:root 0700 | dispatcher |
| `/run/meshmux-hub/requests/` | root:meshmux 0730 / 文件 0600 | Web；dispatcher 消费 |
| `/var/lib/meshmux-installer/upgrade/manifest-*.json`、`exec-*` | root:root 0755/0644、0700 | root |
| `/var/lib/meshmux-installer/state.json`、`local-line/state.json` | 目录 root:root 0700 / 文件 root:root 0600 | installer / root unit；**Web 不可读**（`from_package` 由 dispatcher 核对） |
| `/etc/meshmux/agent.json` | root:root 0600 | root unit |

- **result 文件位置（N3）**：`results/` **不放在 `hub-upgrade/` 下**。父目录 `hub-upgrade/` 是 Web 可写（journal 写在那里），Web 就能 rename `results/` 整个目录、用自己的文件替换 root 写的 result，从而伪造“accepted/restarting/restored”证据。因此 result 固定在 `/var/lib/meshmux-installer/hub-upgrade/results/`（root:meshmux 0750，父目录 root:root 0755），Web 只能读不能改/删/换父目录。**即使如此，result 仍只是不可信证据**：`confirmed` 只由 §5.5 的 running 身份判定（C21），dispatcher 只把 result 当“是否需要再跑一次”的提示，从不据它授权任何写。
- `ownedByCurrentUser` 不能用于跨 uid：Hub 读端参数化为 `expectedOwner`（Web 进程 = meshmux；root unit = meshmux），仍要求 0600/0700；root 不得以“反正能读”绕过属主检查。
- **能力集是 Hub 自有裁决**：`CAP_CHOWN`（恢复族把新 data-dir 整树归还 meshmux；结果目录/文件定属主）与 `CAP_DAC_OVERRIDE`（root 单元要读 meshmux 0600 的 record/payload、要往 meshmux 0700 的 data-dir 写 result）都需要；11c-2 排除 DAC_OVERRIDE 是因为它的写集全是 root 属主，Hub 跨 uid，前提不同。真正的边界仍是固定 argv、枚举的 `ReadWritePaths`、root 属主 manifest 与 `expectedOwner` 校验——能力集不是授权，DAC_OVERRIDE 不改变“只能执行 root 认可的那一份包”。
- 日志：op id、阶段、稳定码、版本、摘要；不记 token、订阅 URL、DB 内容；只有 `SCHEMA_TOO_NEW` 记 detail（记录路径）。
- 稳定码分组：**启动** `SCHEMA_TOO_NEW`(detail)、`SCHEMA_READBACK_FAILED`、`SCHEMA_CONFIRM_FAILED`、`HUB_DIGEST_UNAVAILABLE`；**健康** `DATABASE_UNAVAILABLE`（503，仅 SELECT 1）；**管理面/执行** `DATABASE_UNCONFIRMED`、`DATABASE_VERSION_MISMATCH`、`MANIFEST_UNAVAILABLE`、`HUB_MANIFEST_PACKAGE_MISMATCH`、`IRREVERSIBLE_CONFIRM_REQUIRED`、`HUB_SPACE_INSUFFICIENT`、`HUB_UPGRADE_BUSY`、`HUB_BACKUP_*`（含 `HUB_BACKUP_JOURNAL_FAILED`、`HUB_BACKUP_POINTER_STALE`）、`HUB_HANDOFF_*`（含 `HUB_HANDOFF_BUSY`）、`HUB_UPDATE_*`、`HUB_UPGRADE_*`、`HUB_SHARED_BINARY_*`、`HUB_RESTORE_*`、`UPDATE_BACKUP_MISMATCH`、`CONFIG_CONFLICT`。
- ledger（MF-2）：`readStateAt` strict 读不动，**权限也不动**：目录 root:root 0700、文件 root:root 0600（`apply.go:331` / `apply.go:161`）；Web 不 import `internal/install`，也不为读 ledger 获得任何遍历权。Hub **没有** `artifacts.meshmuxd`（`InstallHub` 只 stage caddy+headscale，`PinnedMeshmuxd` 只被 `upgrade/manifest.go:173` 的组件表消费，从不进 ledger）。实际来源与核对：
  - `from_package_sha256` ← backup 时 Web 只能取 `buildinfo.Digest()`（与安装器 self-copy 的同一份字节相同）；**权威来源**是 Hub ledger `managed_files["/usr/local/libexec/meshmuxd"]`（`hub_apply.go:119-132` 每次 apply 写），由 root dispatcher 用 `install.ReadState("/")`（严格 0600/0700）读后与记录比对；缺失/不可读/非 64 hex → `HUB_BACKUP_IDENTITY_MISSING`，与记录不符 → `UPDATE_BACKUP_MISMATCH`，零 exec。Web 读端不存在；记录仍只由 Web 在 backup 时冻结一次（C2），执行侧不补写、不回填。
  - `from_agent_sha256` ← `buildinfo.Digest()`，且应等于 Hub ledger `shared_binaries.meshmuxd.sha256`（同一次 apply 写两者；两者不等说明盘上二进制已漂移，`HUB_BACKUP_IDENTITY_MISSING`）。
  - **实践中两者相等**：Hub 的 `from_package` 就是安装器 self-copy 的同一份字节（`copyExecutable` 从 `/proc/self/exe` 复制），所以“不同来源”是模型约束不是常态。仍必须保留**记录两字段不等**与**ledger 与记录不等**两个 fixture（手工构造），证明代码不合并、不互替、不假设相等。
  - 任一缺失或非 64 hex → `HUB_BACKUP_IDENTITY_MISSING`（Hub 不接受空 from_*）。
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
| `POST /tasks/db-migration/approve` | 路由/表单**不变**（`backup_operation_id` + 字面值 `irreversible_confirm=1`）；记录读写改指 `<data-dir>/database-backup/<op32hex>/record.json`，扁平指针副本不参与 |

页面显示记录状态（state、`from_version`、`db_schema`、payload 文件数、`integrity_ok`）、不可逆警告、恢复入口、op id 与 result 阶段；`/tasks` 摘要里的“当前记录”与单飞判定同源（journal 最高 `backup_generation`，§5.2），**不扫 `database-backup/` 目录**；approve/apply 则按表单/journal 的 `operation_id` 精确读 per-op 记录。不可逆时 apply 前要求先写确认位并显示当前位值。**修悬空文案**：备份回执的 `operation_id` 就是 `POST /tasks/db-migration/approve` 需要的 `backup_operation_id`，`server_database_migration.go` 的提示改指本页（路由/写入语义不动，只改记录路径）。apply 在读位时**只读该 operation_id 的 per-op 记录**（不取“最新”、不扫目录、不读扁平副本），并重验 `verifyDatabaseBackupPayload`，不满足即 `IRREVERSIBLE_CONFIRM_REQUIRED`，无 flag/环境变量绕过。

### 5.12 实现任务改写（Task 1/3/4/5/7，按已落地分支核对）

**删除清单（完整；除下表“显式保留”外，其余 flat 代码/测试一并删除）**

| 位置 | 删除项 |
| --- | --- |
| `internal/backup/record.go` | `Layout` 类型、`LayoutPerOp`/`LayoutFlat`、`Paths` 的 layout 参数（`Path`/`Dir` 固定 per-op） |
| `internal/backup/store.go` | `ReadFlat`、`recoverFlatSlot`、`flatSlot`、`publishFlatSlot`、`restoreRetiredPayload`、`reachFlatCrashPoint`、`gcFlat`、`rejectPerOpResidue`、`holdingDir` 的 flat 分支、flat-only 的 `PayloadTrashPrefix`/`PayloadOrphanPrefix`/`RecordTrashPrefix`/`flatCrashPoint`；`Dir/Write/Verify/Read/Confirm/GC` 去 layout 参数（`gcPerOp` 保留 `.trash-<unix>` rename） |
| `internal/update/backup.go` | 包装层去 layout（固定 per-op + `PayloadTree`） |
| `internal/update/revert.go:605` | `backup.Confirm(..., backup.LayoutPerOp, ...)` 的 **layout 实参**（`Confirm` 已无该参数；只删实参，不改调用顺序/语义） |
| `internal/web/store_database_gate.go` | `readDatabaseBackupRecord` 改 `backup.Read(root, operationID, expectedOwner)` 读 `<root>/<op>/record.json`；`verifyDatabaseBackupPayload` 的 payload 根改 `<root>/<op>/payload`；approve 只写该 per-op 文件；`schemaTooNew` 的扁平 `Lstat` 保持冻结不动 |
| `internal/backup/store_test.go` | `TestSingleDBPayloadRequiresCheck`、`TestExpectedOwnerEnforced`（两例都以 flat fixture 为主体）、`TestFlatWriteCrashWindowsRecover`、`TestGCFlatKeepsOneGeneration`、`TestConfirmFlatLayoutReadsRootRecord`；**flat-only 的四个 helper** `writeDB`、`stageDB`、`crashWrite`、`assertNoSlotLeftovers`（随上述用例删除后无调用者） |
| `internal/backup/record_test.go` | `TestRecordByteCompatAcrossLayouts`、`TestFlatPayloadPathPinned`、`TestFlatRejectsPerOpResidue`；`TestReadRejectsUnknownFieldAndTrailingData` 的 **`flat` 子用例**（只留 `per-op` 一条，删 `layout Layout` 字段与 `LayoutFlat` 分支）；`TestSingleDBPayloadSHA256IsFileDigest`（fixture 用 `writeDB`=flat；per-op 单 DB 摘要由 `TestBackupPublishesPerOpThenPointer` 与 restore 的 `PayloadSHA256` 重算覆盖）。**注**：后两例在评审单里记于 `store_test.go` 名下，实际文件是 `record_test.go`（同一包），删除范围以本行为准 |
| `internal/web/store_database_gate_test.go` | `hubDatabaseRecord` fixture（建 `<data-dir>/database-backup/payload/meshmux.db`、配 `databaseBackupRecordName` 扁平记录）改为 per-op 形态：`<root>/<op32hex>/{record.json,payload/}`、`PayloadPath=<root>/<op32hex>/payload`；`TestSchemaTooNewNamesTheBackupRecord`/`TestOldBinaryRefusesNewSchema` 里的 `recordPath` **仍是扁平指针路径**（钉 `schemaTooNew` 的 `Lstat`，不改）；`readStoredDatabaseRecord` 调用点随 fixture 返回的 path |
| `internal/web/server_database_migration_test.go` | `:92` 的 `approved.BackupRecord != recordPath` 回执路径断言随 `approveIrreversibleMigration` 的 `RecordPath` 一起前移到 `<root>/<op32hex>/record.json`；矩阵用例（`:118`/`:201` 的 `hubDatabaseRecord` 调用与 `empty payload directory`/`public payload directory`/`symlinked record` 三个 `write` 回调）经 `filepath.Dir(path)` 自动落在 op 目录，表达式无需改写但要断言作用对象是 `<op32hex>/` 而非扁平目录 |
| `internal/hubupgrade/lock.go` | **不删除**：`LockFlatSlot` 改名 **`LockBackupProduce`**，注释从“flat slot 读写互斥”改写为“producer 查后写互斥”（§5.2），`sync.Mutex` 保留 |

**显式保留（不得改动）**：`internal/webcmd/command_test.go:179` 的扁平指针 fixture（`filepath.Join(dir, "database-backup", "record.json")` + `{"schema":99}`）。它钉的是 `schemaTooNew` 冻结的 existence-only `Lstat` 形状（C8/§5.2.1），与 per-op 布局无关；改它会删掉旧二进制降级边界的唯一证据。

**覆盖不得净损失**：上表删掉的每条性质都要有 per-op 承接者——`PayloadSingleDB` 缺 `Check` 必须拒（`store.go:667` 的校验不能只留 flat 测试）→ 新增 `TestPerOpSingleDBRequiresCheck`；记录严格解码 → 保留 `TestReadRejectsUnknownFieldAndTrailingData` 的 per-op 半条；跨 uid owner → `TestDispatchReadsMeshmuxOwnedRecord` 与 `Read`/`Verify` 的 `expectedOwner` 断言。

- **Task 1**：按上表执行 `internal/backup` 与 `internal/update/backup.go` 的删除；`Path`/`Dir` 固定 per-op。**不要**动 `lock.go`（Task 3 才改）。
- **Task 1 测试**：按上表删除，并补 `TestPerOpSingleDBRequiresCheck`（per-op `PayloadSingleDB` 无 `Check` 即 `UPDATE_BACKUP_CORRUPT`、不留 `payload.part`）；`TestSingleDBIntegrityFailureKeepsOldGeneration` 改成“失败不动上一个 per-op 代”（用 `writeTree` 造旧代）；保留 `TestGCOnlyConfirmedGenerations`/`TestGCTrashRenameFailureRetains`，新增 `TestGCKeepTwoConfirmed`、`TestGCNeverCollectsNewestOrStaged`、`TestHubCleanupRejectsKeepBelowTwo`（`internal/hubupgrade` 的清理入口拒绝 `keep<2`；`internal/backup.GC` 本身仍参数化，Node 的 `keep=1` 不受影响，§5.2.1）。
- **Task 3（`feat/11d-3-hub-backup`）**：`CreateBackup` 的 `LockFlatSlot()` 改 **`unlock := LockBackupProduce(); defer unlock()`**，临界区收窄到 `Busy → nextBackupGeneration → WriteOp(backing_up)`（§5.2 第 1 步；manifest 解析与第 2–7 步在锁外）；新增 `TestBackupProduceSerialized`（并发两次 `CreateBackup`，断言只有一个 `backing_up`/一个 generation，另一个 `HUB_UPGRADE_BUSY`，旧 `TestFlatRecordAccessSerialized` 按此改写）。随后 `backup.Dir(root, op)` + `VACUUM INTO '<op>/payload.part/meshmux.db'` + `backup.Write(root, spec, PayloadSingleDB)`；per-op 提交并写 journal `backed_up` 后调用新 `internal/hubupgrade/pointer.go` 的 `PublishFlatPointer(root, op)`（读回 per-op 原始字节、temp+fsync+rename，失败仅 `HUB_BACKUP_POINTER_STALE`）。单飞“当前记录”由 `journal.LatestBackup(dataDir)`（max generation，journal-backed，按 §5.2 跳过无记录/不可读的 op）取 op 后 `backup.Read`，不再 `ReadFlat`。`backup_generation` 在 `backing_up` 时按 §5.2 分配。**Task 3 不 GC**。
- **Task 3 测试**：删 `TestReadFlatReturnsTheSlotWithoutAnOperationID` 与所有 flat 路径/单槽断言；新增 `TestBackupPublishesPerOpThenPointer`、`TestBackupPointerFailureKeepsBackedUp`、`TestLatestIsJournalBacked`、`TestBackupProduceSerialized`；`TestBackupNeverCollectsBeforeConfirm` 保留并断言 `GC` 未被调用。
- **Task 4（`feat/11d-4-dispatch`）**：`dispatch.go` 的记录读取改为 `backup.Read(filepath.Join(request.DataDir, DatabaseBackupDir), request.OperationID, cfg.RecordOwner)`；删除“flat 读会跑 `recoverFlatSlot`、跨进程锁不覆盖”的注释。**dispatcher 不获取 `LockBackupProduce`**（它不写 journal，也不参与单飞判定；per-op 记录只经 rename 替换，11c-3 Node 路径已证明无锁读安全）。请求/结果/argv/ledger 逻辑不变；记录必须与 journal 同一 `operation_id`。
- **Task 4 测试**：`TestDispatchReadsMeshmuxOwnedRecord` 改 per-op；新增 `TestDispatchReadsRequestedOperation`（plant 更新 op 目录不影响选择）、`TestDispatchReadDoesNotWriteDataDir`（无 trash/orphan/恢复副作用）、`TestDispatchNeverTakesProduceLock`（持锁时 dispatcher 读仍能完成，证明无共享锁）；删 `ReadFlat` fixture 与 `LockFlatSlot` 引用。
- **Task 5（确认）**：`backup.Confirm(root, op, target, pkg, now)` 后按 §5.2.1 刷新扁平指针，**无论刷新成败都** `backup.GC(root, 2)`（失败只记 `HUB_BACKUP_POINTER_STALE`，不跳过 GC；§5.2.1/§5.5）。GC 只收 `confirmed`、最新两代保留、staged/failed 不动；Hub 的显式清理入口拒绝 `keep<2`（`internal/backup.GC` 保持参数化，Node `keep=1` 不变）。**不写 DB**：`backup_generation` 等 op 字段只在 journal（D3）。
- **Task 7（文档）**：必须写明 `mixedVersionGate` 的运维后果——Hub 升到 target 后，co-located Line 若仍报旧 `AgentVersion`（未重启或未完成 §5.6 重钉），携带 resolved route 的 v3 发布会被拒为 `UPGRADE_AGENT_INCOMPATIBLE`；先把 Line 的共享二进制与四处 pin 对齐再发布，不得把它当故障绕过或强推旧目标。
- **不做（r6，owner D3）**：不新增 `migrateSchema11`、`hub_upgrade_operations` DDL、`upsert`/`list` 写读端，也不做任何 schema 迁移；store-open 的 `user_version` 保持 10（§5.5、C11）。op 状态只落 `hub-upgrade/ops/<op32hex>.json`，确认只改 per-op 记录。

## 6. 测试计划（B 级，fixture-friendly）

**本轮改写的测试 ID**：#1、#3、#6、#7、#8、#9、#11、#13、#15、#17 的固定含义改为 per-op/`keep=2`；#3、#17 的 flat 断言删除，#6 增加 flat 指针 fixture，#7 增加“flat 副本的位不影响 apply”；新增 #19（旧二进制指针）与 #20（producer 互斥 / GC 与刷新解耦）。未列出的 ID 语义不变。

1. **Producer 顺序**：VACUUM → `<op-dir>/payload.part` 副本 `integrity_check` → per-op `staged` 记录 → journal `backed_up` → flat `record.json` 副本；检查失败断言**旧 per-op 代**保留、`.part` 清理、零记录写入；运行二进制已 stage 成旧包且摘要 == `from_agent_sha256`。`TestBackupPublishesPerOpThenPointer` 断言 flat 副本字节 == per-op 记录字节，且指针写入发生在 per-op rename+fsync 之后。
2. **载荷与双摘要**：payload 0700/0600、`payload_files=1`；`from_package` 与 `from_agent` 都由 Web 取 `/proc/self/exe`（`buildinfo.Digest()`），Web 不读 ledger；root dispatcher 读 Hub ledger `managed_files["/usr/local/libexec/meshmuxd"]` 核对 `from_package`。fixture：记录两字段不等 → 不被合并、不互替（`from_agent` 只用于 restore 字节 pin）；ledger 与记录不等 → `UPDATE_BACKUP_MISMATCH` 零 exec；缺 `managed_files` 项或非 64 hex → `HUB_BACKUP_IDENTITY_MISSING`；断言 Web 端从不读 ledger、代码**从不**读 `artifacts.meshmuxd`（该键不存在时不得报错也不得被当成空来源）。
3. **C2 单写者**：只有一个 per-op 路径与一个 `encodeBackupRecord`；payload kind 不写入记录，因此同一 `spec` 下 Node（`PayloadTree`）与 Hub（`PayloadSingleDB`）的 `record.json` 逐字节相同，`payload_path` 固定为 `<root>/<op32hex>/payload`；**删除** `LayoutFlat` 字节比较、flat `payload_path == <root>/payload` 与“拒绝 per-op 残留”三条断言（它们钉的是已删除的扁平布局）。
4. **健康契约**：`/healthz` 只 SELECT 1——身份不匹配/行缺失/`user_version` 异常都不改变 200/503，且测试统计 DB 写次数为 0。
5. **身份回读矩阵**（管理面 + 定时器）与 `HUB_DIGEST_UNAVAILABLE`（`/proc/self/exe` 不可读）。
6. **`SCHEMA_TOO_NEW` 端到端**：子进程 + 高 `user_version` fixture，断言退出码、稳定码、detail 只含**扁平指针路径** `<data-dir>/database-backup/record.json`；无指针时退回 “no verified database backup record exists at …”。同时断言 `schemaTooNew` 不解析指针、不检查 per-op 目录即可返回。
7. **不可逆矩阵**：manifest `database_migration` 缺省/`irreversible`；无位拒绝、有位通过、位在但载荷被删拒绝；`IRREVERSIBLE_CONFIRM_REQUIRED` 零变更；位只写在 `<op>/record.json`，修改 flat 副本的位不影响 apply。
8. **恢复**：`PayloadSHA256` 不符 → 停机前拒绝；schema 10 副本 + 更高 schema 执行体（模拟未来 bump）→ `CONFIG_CONFLICT` 在**停机前**返回（不误报）；旧包缺失 → `HUB_RESTORE_BINARY_MISSING`；happy path 含 drop-in 翻转、chown、`database-backup/<op>/`+扁平指针+`hub-upgrade/` 携带、`restored.json` 生效；恢复源只从 journal 的 op id 解析（DB 无镜像表，恢复后 `user_version` 仍为 10）。
9. **op journal**：非法迁移拒绝；终止态不被覆盖；恢复后 DB 仍为 schema 10（无新增表）而 journal 仍可读、单飞仍生效；**store-open 不执行任何 10→11 迁移，`user_version` 保持 10（`migrateSchema11`/表 DDL 不存在）**；`backup_generation` 为 max+1、失败不回收编号、GC 不重编号；最新 per-op 由 journal 决定（planted 新目录/新 mtime 不改写“最新”）。
10. **argv 字节 pin**：`__internal-hub-dispatch`/`-update`/`-restore` 全 argv 逐字节；非法 target/digest/op 拒绝。
11. **R-SURFACE**：`systemd-analyze verify` 三个单元文件（service/path/tmpfiles）；单元文件 root:root 0644；`.path` 含 `After=systemd-tmpfiles-setup.service`；meshmux 不能写 `/etc/systemd/system`（planted drop-in 必须 EACCES/EROFS）与 `/var/lib/meshmux-installer/upgrade`；伪造 `data_dir` 的请求被拒（不等于当前 `--data-dir`）；请求文件为符号链接被拒；未知 target 的请求 → `MANIFEST_UNAVAILABLE` 且**未 exec**；staged 字节 ≠ manifest 摘要 → 未 exec；校验后换字节（TOCTOU）→ exec 副本仍拒绝；`.path` 缺失时 `queued` 超时成 `HUB_HANDOFF_TIMEOUT`；>1 个请求 → `HUB_HANDOFF_BUSY` 且目录被 drain（path 能重新武装）；restore 请求校验的是 `from_agent_sha256` 而非 target；dispatcher 按请求 op id 读记录（plant 一个更新的 op 目录不改变所选记录），且读路径**不写** data-dir（无 trash/orphan 副作用）、**不获取** `LockBackupProduce`（持锁时 dispatch 读仍完成，`LockFlatSlot` 名字不再存在）。
12. **对账**：`queued` 超时、`applying` 30min 孤儿、`restarting` 且 running==from → `HUB_UPGRADE_NOT_APPLIED`、确认要求 version 与 digest 同时等于 target/`package_sha256`。
13. **空间**：公式含 3×DB（最新/暂存 + 2 个已确认代）、旧包、恢复副本、exec 副本；`max(…, 1 GiB)` 单测；不足时每次复制前 `HUB_SPACE_INSUFFICIENT`。
14. **Line 重钉（MF-3）**：happy path 断言**四处**同时更新（Hub ledger `shared_binaries` + Line ledger `shared_binaries` + Line ledger `state.Node` 版本/摘要 + `agent.json`）且两处 `managed_files` 同步前移，然后 restart；只改 Hub ledger 的 fixture → 后续 `checkLocalLineSharedBinary`（`local_line.go:295-308`）必须报 `SHARED_BINARY_MISMATCH`；**故意让 Line ledger `state.Node` 保持旧对** → 后续 fixed argv `install --repair --non-interactive --from-recorded-state`（`install_cmd.go:191-201`）在 `checkRecordedAgentConfig`（`node_recorded.go:95-96`）报 `CONFIG_CONFLICT`（证明第 4 pin 必需）；四处写入任一失败 → 旧二进制 + 四处旧 pin 与两处 `managed_files` 全量恢复、Web 未重启、稳定码；写完后第二次备份仍能通过 `from_package` 核对，Line 后续 repair 不因 `managed_files[agent.json]` 报 `MANAGED_FILE_DRIFT`；预检时 Hub ledger / Line ledger shared / Line `state.Node` / `agent.json` 任一不符 → 零写。
15. **GC 候选（B8）**：`staged`/`failed` 记录在 `GCBackups(root, 2)` 后仍存在（`backup.go:336-340` 现行为）；只有**超过两代**的 `confirmed` 才被回收，最新两代 confirmed 永不入选；`failed`/`staged` 记录可作为 restore 源（§5.7-1），确认前不被任何路径回收；回收按 per-op 路径 `.trash-<unix>` rename 失败即保留；**指针刷新失败不跳过 GC**（断言刷新失败后多余 confirmed 代仍被回收，只多一条 `HUB_BACKUP_POINTER_STALE`）；Hub 清理入口拒绝 `keep<2`（§5.2.1，`internal/backup.GC` 本身仍参数化）；**删除** `TestGCFlatKeepsOneGeneration` 等 flat no-op 断言。
16. **目标 manifest 门（MF-1）**：用“更新版本 + 组件表与运行构建不同”的 manifest 断言通过目标门（证明没有走 `Manifest.Validate` 的编译期表比对）；`database_migration` 缺省/`irreversible` 都通过门；非法值拒绝；`version != target`、arch 不符、摘要非 64 hex、来源类别不符、`version <= running` 各自 `MANIFEST_UNAVAILABLE`。
17. **finalize 路径**：confirm 走与 writer 相同的 per-op 路径 `<root>/<op32hex>/record.json`，断言不会读 `<root>/record.json`（扁平指针副本）；**原 N5 的 layout 参数与 flat/per-op 双分支断言删除**。confirm 成功后 `GC(root, 2)` 只收 confirmed 超两代。
18. **result 位置（N3）**：root unit 写到 `/var/lib/meshmux-installer/hub-upgrade/results/`；Web 对该目录无写权；Web 改写 `hub-upgrade/` 下同名文件不影响 dispatcher 判定（它只读固定 root 路径）。
19. **旧二进制指针**：per-op 提交后 flat 副本存在、0600、字节 == per-op 记录；在①之后③之前注入崩溃 → per-op 可读、旧指针保留；③的 temp/rename 之间崩溃 → 旧/新指针二选一、无 `recoverFlatSlot` 调用；confirm 后副本刷新为 confirmed 记录；**刷新失败时 GC 照常执行**（断言 `GC` 被调用、多余代被回收、只记 `HUB_BACKUP_POINTER_STALE`）；删除/损坏 flat 副本不影响 11d 的 `Read`/`Verify`/`Confirm`/restore/GC（证明无读权）；旧 `schemaTooNew` fixture（含 `command_test.go:179` 的扁平 `record.json`）仍命中 detail；旧 `verifyDatabaseBackupPayload` 对 per-op `payload_path` 报 `DB_BACKUP_RECORD_CORRUPT`（fail-closed）。
20. **producer 互斥与 GC 解耦**：并发两次 `CreateBackup` 只产生一个 `backing_up`、一个 generation，另一个 `HUB_UPGRADE_BUSY`（持锁重读 journal，不复用锁外结论）；持 `LockBackupProduce` 时 dispatcher 读与 approve 读都不阻塞（锁只罩 producer 查后写）；confirm 的指针刷新失败时 `GC(root, 2)` 仍执行（与 #15 同断言）；Hub 清理入口拒 `keep<2`。

## 7. 风险与回退

| 风险 | 缓解 |
| --- | --- |
| 二进制半写 / 换坏 | 同目录 `meshmuxd.new` + rename + fsync；旧包在 backup 时已 stage，可回退 |
| Line 与 Hub 分裂（半重钉） | 同 unit 内“换二进制→四处重钉→重启 Line”顺序；失败按 §5.6-8 换回旧包与四处旧 pin |
| 漏钉 Line ledger（`shared_binaries` 或 `state.Node`） | §5.6-3 预检同时读 Hub ledger、Line ledger 的 `shared_binaries` 与 `state.Node`、`agent.json`；任一不符零写（漏 `state.Node` 会让下一次 `--from-recorded-state` 报 `CONFIG_CONFLICT`，升级链锁死） |
| Web 读不到 root ledger | 不放开 0600/0700：backup 以 `buildinfo.Digest()` 落 `from_package`，root dispatcher 用 `install.ReadState("/")` 核对；缺失/不符零 exec（§5.9） |
| Web 伪造 result 证据 | result 固定在 `/var/lib/meshmux-installer/hub-upgrade/results/`（Web data-dir 之外，Web 不可写）；且 `confirmed` 只由 running 身份判定（C21） |
| VACUUM 期间并发写 | `VACUUM INTO` 事务一致快照；WAL fixture 证明 |
| 多代 DB 撑爆磁盘 | §5.9 峰值项（3×dbSize 备份库 + 恢复副本）+ `max(…, 1 GiB)`，不足即 fail-closed |
| 旧二进制指针丢失/过期 | 指针只在 per-op 提交/confirm 后写、11d 从不读取；失败仅 `HUB_BACKUP_POINTER_STALE`，per-op 恢复源不受影响；GC 与刷新解耦，刷新失败不阻塞 `keep=2` 回收（`keep≥2` 保证指针目标类型永在候选集外） |
| 并发两次 backup 绕过单飞 | 进程级 `LockBackupProduce`（`sync.Mutex`）罩住 `Busy → generation → WriteOp(backing_up)`；跨进程由 data-dir flock 保证 |
| 恢复后 data-dir 身份不符 | 停机前只读比对 → `CONFIG_CONFLICT`，保留两份目录 |
| root 单元读不到 meshmux 0600 文件 | `CAP_DAC_OVERRIDE` + 参数化 `expectedOwner` 读端（字节可达 ≠ 授权，属主/模式仍校验） |
| root 写的 result 读不到 | `results/` 在 `/var/lib/meshmux-installer/hub-upgrade/`（Web data-dir 之外）定属主 root:meshmux 0750、文件 0640；unit 是唯一写者，Web 只读（且 result 从不作授权，C21） |
| `.path`/单元缺失 | `queued` 120s 超时 → `failed`，可重试；不产生半执行 |
| 恢复后 Web 起不来 | 终态 + 人工指引；旧目录保留；不自动重试 |
| 旧包被 GC | 空间公式强制保留；缺失即 `HUB_RESTORE_BINARY_MISSING` |

回退原则：**不自动回退 Hub 二进制**（唯一例外是 §5.6-8 的“重钉失败换回”，因为此时 Web 尚未重启、系统处于不一致中间态）。Hub 自身回退只有 restore 一条路；Line/Out 的 LKG 仍走 11c-3 重发链。

## 8. 后续

- **12e 阻塞（明示）**：`meshmuxd` 仍是 `file://` dev pin，没有 GitHub release asset，也没有目标 manifest 的预置/签名通道。在此之前生产 Hub 自升级只会得到 `MANIFEST_UNAVAILABLE`；本文的 B 级 fixture 只验证形状，**不得**据此声称“Web 统一升级可用”。
- **11e**：兼容矩阵内容接入 §5.8 的 gate 形状；矩阵缺失 fail-closed。
- **#12**：C 级隔离 VM/真机验收（Debian 13 amd64/arm64），覆盖 `VACUUM INTO` 真快照、path unit/oneshot 行为、恢复后 Caddy/Headscale 联通。
- 后续可把“root 预置 manifest”替换为签名发布通道；届时 §5.8 的 gate 形状与 §5.1 的执行基座不变。
- **D2（root-side recovery + watchdog）已接受为 11d 范围**，但由独立的 plan/task change 落地，不在本设计稿展开。

## 9. 开放问题（不阻塞，最多 3）

1. **Q1 精确写集**：是否只需 `/run/meshmux-hub /usr/local/libexec /var/lib/meshmux /var/lib/meshmux-installer /etc/meshmux /etc/systemd/system`？若还需 journal 目录或其它路径，用 `systemd-analyze verify` 与真机 `EROFS` 证据补齐并同步改单元。
2. **Q3 中立包时机**：现在就抽 `internal/backup`（零成本预防），还是等 confirmer 真需要反向导入时再抽（届时要保证 JSON 字节不变）。
