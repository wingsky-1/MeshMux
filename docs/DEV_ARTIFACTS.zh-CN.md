# 开发构建制品与 Hub 自升级（#12e dev lane）

本文只描述**隔离 fixture/VM 上**打通开发构建与 Hub 自升级命令链的步骤，不是发行流程，也不是现网操作许可。首个公开稳定版仍是 `v1.0.0`；正式发行资产、GitHub Release 下载来源与生产 root manifest 发布/签名通道仍由 #12e 的发布部分负责。未经用户单独批准，不得在现网执行本文任何 `apply`、重启或迁移。

## 1. 版本规则

开发构建使用 SemVer 2.0.0 预发布形式，禁止无版本号的 `dev` 戳：

```
1.0.0-dev.<UTC 日期>[.<git 提交数>]      例：1.0.0-dev.20261027.13
```

- `buildinfo.Version` 是唯一版本来源；默认值 `1.0.0-dev.0` 仍是合法预发布，不会被误判为发行版。
- 构建时经 `-ldflags -X` 注入，与发行构建同一注入点：

  ```sh
  make dev-artifacts DEV_VERSION=1.0.0-dev.20261027.13
  ```

- `make dev-artifacts` 默认 `DEV_VERSION=1.0.0-dev.$(date -u +%Y%m%d).$(git rev-list --count HEAD)`，不要手改源码里的默认值来伪装版本。
- `versions.IsDevVersion` 接受 `X.Y.Z-dev.N` 与过渡的 `dev-<stamp>`，拒绝 `1.0.0-rc.1`、`1.0.0-devfoo` 与空版本；manifest/update 的 dev 门禁统一使用它。
- dev 版本**永远不会**被当作发行版：`Dev: true` 的组件只允许 `file://` 或 `https://` 来源，不能声称 GitHub release。

## 2. 构建 dev 制品

```sh
make dev-artifacts DEV_VERSION=1.0.0-dev.20261027.13
# 默认输出：
#   dist/dev/meshmuxd-linux-amd64
#   dist/dev/meshmuxd-linux-arm64
#   dist/dev/SHA256SUMS
```

- 输出目录可用 `DEV_OUT_DIR=...` 覆盖；`DEV_ARCHES` 固定为 `amd64 arm64`（`internal/cli/versions` 的矩阵）。
- 构建固定 `CGO_ENABLED=0 GOOS=linux`、`-trimpath -buildvcs=false`：同一提交 + 同一 `DEV_VERSION` 的字节可复现，摘要才有意义。
- `make dev-checksums` 只从已有制品重算 `SHA256SUMS`；`make clean-dev-artifacts` 删除 `dist/dev`。
- 目标机不安装 Go；制品是 ELF 可执行文件，amd64/arm64 各一份，Hub、Line、Out 共用同一个 `meshmuxd` 二进制。

## 3. 两个 drop，不要混用

| drop | 路径 | 内容 | 用途 |
| --- | --- | --- | --- |
| 运行 drop | `/var/lib/meshmux-dev/` | 与**正在运行**的 Hub 完全相同的两个架构制品 + `SHA256SUMS` | 运行中 Hub 为 Agent/Line 提供本机构建的 `meshmuxd` pin |
| 目标 drop | `/var/lib/meshmux-dev-target/` | 只放本机架构的**升级目标**制品 | root manifest 交给 Hub 自升级执行体去暂存/替换 |

部署运行 drop（root-owned，Web 只读）：

```sh
sudo scripts/dev-artifacts-deploy.sh dist/dev
sha256sum /usr/local/libexec/meshmuxd   # 必须等于 drop 中本机架构的制品摘要
```

服务出的 manifest 中，本机架构的 pin 取 `/proc/self/exe` 的摘要；另一架构的摘要取 `SHA256SUMS`。因此运行 drop 必须是**当前运行构建**，否则另一架构的 pin 会指错字节。`scripts/dev-artifacts-deploy.sh` 会校验摘要、owner/mode、安装后回读，并在 Hub 已安装时强制本机架构制品与 `/usr/local/libexec/meshmuxd` 一致；不一致直接拒绝，升级目标应改用 `scripts/dev-root-manifest.sh`，升级成功后重新部署匹配的新 drop。

部署目标 drop 和 root manifest：

```sh
make dev-artifacts DEV_VERSION=1.0.0-dev.20261028.14 DEV_OUT_DIR=dist/dev-target
sudo scripts/dev-root-manifest.sh 1.0.0-dev.20261028.14 dist/dev-target
```

脚本只接受 `X.Y.Z-dev.N`、固定 `amd64/arm64`、本机 Debian 架构；校验目标制品对 `SHA256SUMS` 的摘要、ELF 头；在本机架构上还会执行隐藏的零参数 `__internal-agent-version`，证明制品确实以该版本构建。随后它以 root 身份安装：

```
/var/lib/meshmux-dev-target/meshmuxd-linux-<arch>             0755 root:root
/var/lib/meshmux-installer/upgrade/manifest-<target>.json     0644 root:root
```

目标 drop 与运行 drop 分离是有意的：升级目标不能替换运行中的 release catalog，否则 agent 会在 Hub 尚未升级时看到目标字节。

## 4. root manifest 的形状与门禁

`manifest-<target>.json` 是 Hub 的信任锚，不是 Web 输入。`scripts/dev-root-manifest.sh` 生成的最小 dev 形态如下（字段名必须与 `upgrade.Manifest`/`upgrade.Component` 的 Go JSON 一致）：

```json
{
  "schema": "meshmux-release/v1",
  "version": "1.0.0-dev.20261028.14",
  "architecture": "amd64",
  "policy_schema": 8,
  "components": [
    {
      "Name": "meshmuxd",
      "Version": "1.0.0-dev.20261028.14",
      "Architecture": "amd64",
      "Source": "file:///var/lib/meshmux-dev-target/meshmuxd-linux-amd64",
      "SHA256": "<64 位小写十六进制>",
      "Format": "elf",
      "Dev": true
    }
  ],
  "database_migration": "additive"
}
```

Hub 侧 `hubupgrade.ReadRootManifest` 在备份/交接时重新执行门禁，任一项不符都以 `MANIFEST_UNAVAILABLE` 零写入拒绝：

- 目录 `/var/lib/meshmux-installer/upgrade` 必须是 root 属主、无 group/world write 的真实目录（不是 symlink）。
- 文件必须是 root 属主、精确 `0644` 的普通文件（不是 symlink），不超过 1 MiB。
- 严格 JSON：拒绝未知字段与尾随数据。
- `schema` 必须为 `meshmux-release/v1`；`policy_schema` 必须为 `8`。
- 目标版本必须是合法 SemVer 预发布，且**严格新于**当前运行版本；`1.0.0-dev.0` 不能升级到 `1.0.0-dev.0`。
- `components` 里必须有一个 `meshmuxd`，架构等于运行架构，`SHA256` 为 64 位小写十六进制；`Dev: true` 时版本必须是 dev 预发布，来源必须是 `file://` 或 `https://`。
- `database_migration` 只能是 `additive`（默认）、`irreversible` 或空；`irreversible` 还要求操作员在 `POST /tasks/db-migration/approve` 写入确认位。

`database_migration=additive` 表示目标不搬动不可逆数据；它不会替操作员保证迁移一定成功。失败路径仍是 per-op 备份恢复。

### 迁移前数据库副本（新增）

`store.Migrate` 在第一个 schema leg 之前自动复制旧库：

```
<data-dir>/pre-migration/meshmux-v<from_schema>-<unix>.db   0600
```

- 只在 `0 < user_version < DatabaseSchemaVersion`（当前 17）时生成；全新库和已是最新 schema 的库不复制。
- 用 `VACUUM INTO` 生成 `.part`，`0600`，read-only + `immutable=1` 校验 `integrity_check` 与迁移前 `user_version`，fsync 后 rename。
- 无法生成/校验副本时以 `SCHEMA_BACKUP_FAILED` 拒绝迁移，原库保持字节不变；保留最新 2 份。
- 这是**启动时 schema 迁移**的兜底，不替代 11d 的 per-op `database-backup`（Web 升级的备份/恢复契约）。

## 5. 隔离环境端到端步骤（B 级）

前提：一次性 Debian 13 amd64/arm64 VM；已按 `docs/INSTALL_HUB.zh-CN.md` 的隔离流程安装 Hub（域名、TLS 与固定组件按该文档准备）；全程不接现网。

1. **安装基线构建**：用运行 drop 的制品安装 Hub。

   ```sh
   install -m 0755 dist/dev/meshmuxd-linux-$(dpkg --print-architecture) /root/meshmux
   sudo /root/meshmux install hub --yes --management-domain ... --subscription-domain ... --headscale-domain ...
   sudo scripts/dev-artifacts-deploy.sh dist/dev
   ```

   此时 `/usr/local/libexec/meshmuxd` 与本机架构的 `dist/dev/meshmuxd-linux-<arch>` 字节一致。

2. **构建并放置目标**：

   ```sh
   make dev-artifacts DEV_VERSION=1.0.0-dev.20261028.14 DEV_OUT_DIR=dist/dev-target
   sudo scripts/dev-root-manifest.sh 1.0.0-dev.20261028.14 dist/dev-target
   ```

3. **Web 发起备份**：管理员登录 `/tasks`，在“Hub 自升级”填目标版本 `1.0.0-dev.20261028.14`，提交“创建 Hub 数据库备份”。回执 `status=staged`，记下 32 位 `operation_id`；备份写到 `<data-dir>/database-backup/<op>/`，扁平指针为 `<data-dir>/database-backup/record.json`。

4. **交接**：同一页面对该操作点“交接升级（排队）”。`status=queued` 只表示 journal 与 `/run/meshmux-hub/requests/<op>.json` 已写入，**不代表已开始或已生效**。若返回 `MANIFEST_UNAVAILABLE`，先核对第 4 节门禁与目标版本是否严格更新；若返回 `HUB_SPACE_INSUFFICIENT`，清理空间后重试同一 `operation_id`。

5. **等待 root 执行体**：systemd path unit `meshmux-hub-dispatch.path` 消费请求，root dispatcher 重新校验 journal/记录/manifest，staged 目标包到 `<data-dir>/upgrade/meshmuxd-<target>-<arch>`，再以固定 argv 执行 `__internal-hub-update`。执行体完成版本绑定、数据库 pre-flight、Line 四 pin 预检、claim、二进制替换、pin 重钉与 `meshmux-web.service` 重启。

6. **确认**：重启后的 Hub 在启动对账中读 journal `verifying` 与运行身份；版本与摘要匹配才转 `confirmed`。在 `/tasks` 看到确认，且 `/usr/local/libexec/meshmuxd __internal-agent-version` 输出目标版本。若页面停在 `verifying`，说明启动对账没跑或身份未匹配：检查 journal、root 写入的 `/var/lib/meshmux-installer/hub-upgrade/results/<op>.json` 与 Web 日志；不要用 ticker 期待自动确认（只有启动 pass 能确认）。

7. **升级后**：重新部署与新运行构建匹配的 drop，保证服务出的双架构 set 一致：

   ```sh
   sudo scripts/dev-artifacts-deploy.sh dist/dev-target
   sha256sum /usr/local/libexec/meshmuxd   # 应等于 dist/dev-target 中本机架构制品
   ```

预期证据：`operation_id` 贯穿备份/交接/结果；`/tasks` 显示 confirmed；运行版本与摘要等于目标；失败时 journal 为 `failed`/`partial` 并可用该 per-op 备份做有损恢复。**这仍是 B 级 fixture/VM 形状证据，不等于现网真机验收。**

## 6. 失败与回退

- **未交接前失败**（manifest/空间/记录校验）：零写入，修复后重试同一 `operation_id`。
- **交接后替换前失败**：执行体在第一次系统写入前失败，不写 result，journal 保持 `queued`/超时；按 stable code 与 stderr 的 operation id 排查。
- **替换后失败**：执行体按旧包回滚二进制与四处 pin，写 `partial`；`/tasks` 提供该操作的有损恢复入口（只按该 per-op 副本恢复到新 data-dir，`snapshot_at` 之后的写入丢失）。
- **schema 迁移失败**：`SCHEMA_BACKUP_FAILED` 或迁移错误会阻止启动；用 `<data-dir>/pre-migration/` 的最新副本做人工恢复来源，并保留原目录现场。
- **不要**在没有 per-op 备份或 root manifest 的情况下手工 `cp` 目标二进制到 `/usr/local/libexec/meshmuxd`；这会绕过摘要、版本绑定、Line pin 与回滚链。

## 7. 现网步骤（待用户单独批准，本 PR 未执行）

1. 由发布负责人构建并签署**正式** `meshmuxd` GitHub Release 资产（不是本文的 dev drop），在 `internal/cli/install` 切换 release pin。
2. root 在目标 Hub 预置 `manifest-<target>.json`，内容与签名/发布流程见 #12e 的发布部分；目录/文件 owner 与 mode 必须满足第 4 节。
3. 管理员在 `/tasks` 依次执行备份 → 交接 → 重启 → 确认；操作前另行取得现网变更批准，记录 `operation_id`、目标版本、备份路径与回滚负责人。
4. 失败时按第 6 节恢复；恢复是有损的，快照之后的变更必须重做。

在正式发布资产与生产 manifest 通道落地前，生产 Hub 自升级只会得到 `MANIFEST_UNAVAILABLE`，这是有意的 fail-closed。

## 8. 清理

```sh
make clean-dev-artifacts
sudo rm -rf /var/lib/meshmux-dev /var/lib/meshmux-dev-target
sudo rm -f /var/lib/meshmux-installer/upgrade/manifest-<target>.json
```

只在一台可销毁主机上删除这些路径；不要清理 `/var/lib/meshmux-installer/upgrade` 中其他操作者预置的正式 manifest，也不要删除 `/var/lib/meshmux/pre-migration/` 中仍可能需要的恢复副本。

## 9. 证据级别与未完成

- 本 lane 已提供：dev 版本注入、双架构 dev 制品、可校验的派生 pin、root manifest 生成脚本、迁移前自动副本，以及相关 Go 单测。
- 仍缺：GitHub Release 正式资产表与签名/发布流程；真实 Debian 13 VM 上 path unit、`ReadWritePaths`、真实 systemd 重启与 `/healthz` 的 C 级链路；混版本舰队与真实客户端复验。这些归 #12。
- 不要把脚本存在、单测通过或一次 VM 手工运行写成“现网升级已可用”。
