# 测试与环境变量

本文只记录**测试与 CI 代码实际读取**的 `MESHMUX_*` 环境变量。下列 file:line 以合入时基线为准，仅供定位；代码变动后以 `grep` 重新核对，不以本文行号为准。

判定口径：以 `os.Getenv` / `os.LookupEnv` / `syscall.Getenv` 及脚本中真实的取值语句为准，不按名字前缀猜测。仓库当前只使用 `os.Getenv`，没有 `LookupEnv` 或 `syscall.Getenv` 调用。

## 1. 结论与边界

- 26 个变量由 Go 测试通过 `os.Getenv` 读取，全部位于 `*_test.go`；生产进程（`cmd/`、`internal/` 的非测试文件）不读取任何 `MESHMUX_*` 环境变量，因此这些变量不是运行时配置。
- 3 个变量只由测试脚本自身读取（Node/Shell），见第 3 节。
- 所有变量未设置时都不会导致生产行为变化；测试侧要么 `t.Skip`，要么由调用方显式设置（第 2 节“未设置时默认行为”）。
- 变量只在对应 workflow 的隔离容器/一次性 VM 内使用，不依赖仓库 secrets，符合 [CI_HUB_VALIDATION](CI_HUB_VALIDATION.zh-CN.md) 的 L1/L2/L3 分层。

## 2. Go 测试读取的变量

“生效范围”中的 job 名指 `.github/workflows/` 里的 workflow/job；括号内为设置方（脚本:行）。

| 变量名 | 读取点 file:line | 用途 | 生效范围（单测 / VM / CI job） | 未设置时的默认行为 |
| --- | --- | --- | --- | --- |
| `MESHMUX_TEST_PROCESS` | `cmd/meshmux-web/main_test.go:154` | 子进程 helper 开关；仅当值为 `1` 时 `TestServiceHelperProcess` 启动真实 Web 服务 | 单测：`cmd/meshmux-web` 包（`ci` / `go` job）；由同文件 `:33` 的父测试设置 | 非 `1`（含未设置）时 helper 立即 `return`，父测试不受影响 |
| `MESHMUX_TEST_ADDR` | `cmd/meshmux-web/main_test.go:157` | helper 的 `--listen` / `--origin` 地址 | 同上 | 无内置默认值；只在 helper 进程读取，父测试总会写入随机回环端口 |
| `MESHMUX_TEST_DIR` | `cmd/meshmux-web/main_test.go:159` | helper 的 `--data-dir` | 同上 | 无内置默认值；父测试总会写入临时目录 |
| `MESHMUX_HUB_SYSTEM_VM` | `internal/install/vm_test.go:21` | Hub 全系统 VM 验收总开关 | VM / `hub-vm` job `debian13-systemd`，profile `hub`（`scripts/ci-hub-vm.sh:132` 设置） | 非 `1` 时 `TestHubSystemVM` `t.Skip`，普通 `go test ./...` 不会执行 |
| `MESHMUX_HUB_SYSTEM_PHASE` | `internal/install/vm_test.go:87` | 阶段选择：`install` 首装，`post-reboot` 重启后持久性 | 同上（`scripts/ci-hub-vm.sh:132` 传 `install`，`:147` 传 `post-reboot`） | 无默认值；空值落入 `internal/install/vm_test.go:170` 的 `invalid VM-only phase` 致命失败 |
| `MESHMUX_LOCAL_LINE_VM` | `internal/install/local_line_vm_test.go:41` | 同机 Line 生命周期 VM 验收开关 | VM / `hub-vm` job，profile `hub`（`scripts/ci-hub-vm.sh:156,170` 设置） | 非 `1` 时 `TestLocalLineSystemVM` `t.Skip` |
| `MESHMUX_LOCAL_LINE_PHASE` | `internal/install/local_line_vm_test.go:50` | 阶段选择：`install` / `post-reboot` | 同上 | 空值默认 `install`（`:51-53`）；其他值致命失败 |
| `MESHMUX_NODE_SYSTEM_VM` | `internal/install/node_vm_test.go:45` | Node 全系统 VM 验收开关 | VM / `hub-vm` job，profiles `edge`、`out`（`scripts/ci-node-vm.sh:260,277`）；本地 docker harness `scripts/ci-node-local.sh:113,122` | 非 `1` 时 `TestNodeSystemVM` `t.Skip` |
| `MESHMUX_NODE_ROLE` | `internal/install/node_vm_test.go:54` | 被测节点角色：`edge` 或 `out` | 同上 | 无默认值；空值或其他值在 `:56` 致命失败（`fixture role must be edge or out`） |
| `MESHMUX_NODE_PHASE` | `internal/install/node_vm_test.go:58` | 阶段选择：`install` / `post-reboot` | 同上 | 无默认值；空值或其他值在 `:60` 致命失败 |
| `MESHMUX_NODE_FIXTURE_STATUS` | `internal/install/node_vm_test.go:62` | runner 侧 Hub fixture 产出的 `node-fixture.json` 路径（guest 内为 `/tmp/node-fixture.status`） | 同上（`scripts/ci-node-vm.sh:260,277` 设置；`:242` 把 runner 侧文件复制为 guest 的 `/tmp/node-fixture.status`） | 空值在 `:65` 致命失败；status 与 CA 路径都必需 |
| `MESHMUX_NODE_FIXTURE_CA` | `internal/install/node_vm_test.go:63` | fixture 私有 CA 证书路径，装入 guest 系统信任库 | 同上（`scripts/ci-node-vm.sh:260,277` 设置；`:243` 复制为 guest 的 `/tmp/node-fixture-ca.crt`） | 空值在 `:65` 致命失败 |
| `MESHMUX_NODE_MESHMUX_BIN` | `internal/install/node_vm_test.go:82` | 被测 `meshmux` 可执行文件路径 | 本地 docker harness `scripts/ci-node-local.sh:113,122`；`hub-vm` 不设置，使用 guest 默认布局 | 默认 `/tmp/meshmux`（`:83-85`） |
| `MESHMUX_NODE_FIXTURE_DIR` | `internal/install/node_ci_test.go:41` | 把 Node 候选、ACL、unit、jail 渲染到指定目录 | L2 / `hub-components` job `debian13`，step “Debian 13 Node component configuration checks (Issue #6 PR-B L2)”（`scripts/ci-node-components.sh:38` 设置） | 空值时 `TestWriteNodeComponentFixtures` `t.Skip`，普通单测不写文件 |
| `MESHMUX_HUB_FIXTURE_DIR` | `internal/install/ci_test.go:57` | 把 Hub 候选配置渲染到指定目录 | L2 / `hub-components` job `debian13`，step “Debian 13 official component configuration checks”（`scripts/ci-hub-components.sh:51` 设置） | 空值时 `TestWriteComponentFixtures` `t.Skip` |
| `MESHMUX_SINGBOX_TEST_BINARY` | `internal/subscription/export_integration_test.go:86`（常量 `envSingBoxBinary`，`:20`） | 真实 sing-box 客户端二进制，用于导入导出的订阅配置 | L2 / `subscription-clients` job `clients`（`scripts/ci-subscription-clients.sh:175` 设置） | 两个客户端变量都未设置时 `t.Skip`；只设置一个在 `:92-96` 致命失败；路径必须绝对且可执行 |
| `MESHMUX_MIHOMO_TEST_BINARY` | `internal/subscription/export_integration_test.go:87`（常量 `envMihomoBinary`，`:21`） | 真实 mihomo 客户端二进制 | 同上（`scripts/ci-subscription-clients.sh:176` 设置） | 同上 |
| `MESHMUX_REALITY_CHECK_BINARY` | `internal/node/reality_check_test.go:30` | 固定版本 sing-box，供 `TestRealityNativeCheck` 校验候选 REALITY 配置 | L2 / `hub-components` job，step “Debian 13 native REALITY acceptance fixture (Issue #7 first PR L2)”（`scripts/ci-node-reality.sh:197` 设置）；`hub-vm` profiles `edge`/`out`（`scripts/ci-node-vm.sh:191` 设置） | 空值时 `t.Skip`；非绝对路径、非常规文件或摘要不匹配时致命失败 |
| `MESHMUX_REALITY_INTEGRATION_BINARY` | `internal/node/reality_integration_test.go:165`（常量 `realityIntegrationBinaryEnv`，`:75`） | 同上，供 `TestRealityIntegrationHandshakeAcceptsAndDeniesCredentials` 做真实握手 | 同上（`scripts/ci-node-reality.sh:198`、`scripts/ci-node-vm.sh:192` 设置） | 空值时 `t.Skip`；摘要必须匹配 in-tree pin |
| `MESHMUX_REALITY_PIN_DIR` | `internal/node/reality_integration_test.go:590` | 把 in-tree release pin 渲染为 `releases.tsv` 供 CI 下载校验 | L2 / `hub-components` job，REALITY step（`scripts/ci-node-reality.sh:103` 设置） | 空值时 `TestWriteRealityReleasePin` `t.Skip` |
| `MESHMUX_WEBCMD_HELPER` | `internal/webcmd/command_test.go:26`（常量 `helperEnv`，`:19`） | webcmd 子进程 helper 开关；仅 `1` 时执行 `Run` | 单测：`internal/webcmd` 包（`ci` / `go` job）；由同文件 `:44` 设置 | 非 `1` 时 helper `return`，父测试不受影响 |
| `MESHMUX_WEBCMD_ARGS` | `internal/webcmd/command_test.go:30`（常量 `argsEnv`，`:20`） | helper 接收的 JSON 参数数组 | 同上 | 无内置默认值；父测试总会写入；JSON 非法时以退出码 97 失败 |
| `MESHMUX_NODE_HUB_FIXTURE_DIR` | `internal/web/node_fixture_test.go:47` | 启动真实 Web Hub fixture（持久 SQLite + 私有 CA）的数据目录 | VM / `hub-vm` profiles `edge`/`out`（`scripts/ci-node-vm.sh:210`）；本地 docker harness `scripts/ci-node-local.sh:101` | 空值时 `TestNodeHubFixture` `t.Skip`，普通单测不监听端口 |
| `MESHMUX_NODE_HUB_FIXTURE_ROLE` | `internal/web/node_fixture_test.go:51` | fixture 节点角色：`edge` 或 `out` | 同上 | 无默认值；空值或其他值在 `:53` 致命失败 |
| `MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST` | `internal/web/node_fixture_test.go:172` | fixture 对外 Origin 主机名白名单 | 同上（`scripts/ci-node-vm.sh:210` 设为 `10.0.2.2`，走 QEMU slirp） | 空值默认 `127.0.0.1`（`:173-175`）；只接受 `127.0.0.1` 与 `10.0.2.2` |
| `MESHMUX_NODE_HUB_FIXTURE_SSH_PORT` | `internal/web/node_fixture_test.go:235` | fixture 对外公布的 SSH 端口 | 同上（`scripts/ci-node-vm.sh:210`、`scripts/ci-node-local.sh:101` 设为 `22`） | 空值默认 `2222`（`:236-238`）；必须在 1–65535 且不等于 VLESS 端口 8443 |

合计：26 个变量、26 处 `os.Getenv` 读取行（其中 5 个变量的读取调用以包级常量作参数，常量定义位置已列在读取点后）。

## 3. 仅由脚本自身读取的变量

这些变量不影响 Go 测试，也不是运行时配置；设置方与读取方是同一脚本。

| 变量名 | 读取点 file:line | 用途 | 生效范围 | 未设置时的默认行为 |
| --- | --- | --- | --- | --- |
| `MESHMUX_WEB_BINARY` | `scripts/browser-smoke.cjs:9`（`process.env`） | 浏览器冒烟测试启动的 Web 可执行文件 | `ci` job `web-preview`，step “Browser flow and responsive screenshots”；workflow 不设置 | 默认 `/tmp/meshmux-web`，由同 job 的 `go build -o /tmp/meshmux-web` 产出 |
| `MESHMUX_LOCAL_IMAGE` | `scripts/ci-node-local.sh:28`（`${VAR:-默认}`） | 本地 L3 docker harness 使用的镜像 | 仅本地 `bash scripts/ci-node-local.sh`，参数为 `edge` 或 `out`；没有 workflow 调用 | `meshmux/node-l3local:13` |
| `MESHMUX_LOCAL_BASE` | `scripts/ci-node-local.sh:29`（`${VAR:-默认}`） | 本地 harness 的基础镜像 | 同上 | `debian:13` |

## 4. 已排除的 lookalike

- `MESHMUX_BINARY_INVALID`：稳定错误码，不是环境变量，没有读取点。证据：`internal/install/apply.go:348,744`、`internal/install/local_line.go:334,390,394,416,420`、`internal/install/node_apply.go:281` 均把它作为 `InstallError.Code` 或 `errors.New` 的文本。
- 其他含 `MESHMUX_` 的命中若出现在脚本、注释或文档里，只是上述变量名的设置方或引用，不是独立变量；表内不重复收录。
- 生产代码不读取 `MESHMUX_*`：`grep -rn 'os.Getenv\|os.LookupEnv\|syscall.Getenv' --include='*.go'` 的全部命中都在 `*_test.go`。

## 5. 如何本地跑测试

常规本地流程（gofmt、vet、test、race、build）见 [DEVELOPMENT](DEVELOPMENT.zh-CN.md) 的“本地运行”小节，本文不重复。

- 全量门禁：`make verify`。它依次执行 `fmt`、`vet`、`staticcheck`、`test`、`race`、`build`（`Makefile:34`），与 `ci` job `go` 的 step “Verify”（`.github/workflows/ci.yml:27`）一致；构建产物为 `/tmp/meshmux` 与 `/tmp/meshmux-web`（`Makefile:12,59-60`）。staticcheck 版本固定在 `Makefile:17`，首次运行需要下载模块。
- 单包与快速回路：`go test ./...`；只跑一个包时用 `go test ./internal/install`、`go test ./internal/node`，加 `-run` 限定用例。竞态检测用 `go test -race ./...`。
- 启用 opt-in 测试：第 2 节的变量未设置时相关测试会 `t.Skip`，因此 `go test ./...` 天然只跑 L1。示例：

  ~~~sh
  MESHMUX_REALITY_CHECK_BINARY=/abs/path/to/pinned/sing-box \
    go test ./internal/node -run '^TestRealityNativeCheck$' -v
  ~~~

  需要真实客户端二进制的订阅导入检查，同时设置 `MESHMUX_SINGBOX_TEST_BINARY` 与 `MESHMUX_MIHOMO_TEST_BINARY`。
- L2/L3（Debian 13 容器、一次性 QEMU VM、真实 systemd/nftables）：使用 `scripts/ci-*.sh`，所需环境与证据级别见 [CI_HUB_VALIDATION](CI_HUB_VALIDATION.zh-CN.md)；这些脚本只允许操作隔离 fixture/VM，禁止指向现网。

## 6. 维护约定

- 新增、删除或改名 `MESHMUX_*` 变量时，在同一个 PR 更新本表，并保留“读取点”与“设置方”两列的证据。
- 表中行号会漂移；合并冲突时以 `grep -rn 'os.Getenv' --include='*_test.go'` 和脚本中的赋值行为准重新定位。
- 若某变量从测试提升为运行时配置，必须先写入架构/安全文档并更新本节结论，不能只改表。
