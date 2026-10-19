# Hub 安装器 CI 验证规范（Issue #5）

MeshMux 优先继承 `my-sub` 的稳定经验及上游组件自校验能力，不为测试引入 Ansible/Molecule 或持续在线 VPS。开发期禁止现网执行。CI 只验证代码真实覆盖的阶段，L1/L2 通过都不代表真实宿主机安装成功。

三层门禁的分工与证据强度：

- **L1（Go 测试 + 故障注入）**：验证纯逻辑、flag/配置边界、受控命令调用、文件事务、幂等和回滚状态，速度最快、覆盖分支最广，但不证明真实 systemd、内核、nftables 或网络行为。
- **L2（Debian 13 容器组件自检）**：在官方发行容器内运行固定版本 Caddy/Headscale 的配置校验和 systemd unit 语法检查，证明组件配置可被官方工具接受，但不是完整系统安装。
- **L3（QEMU 真实 systemd 全系统）**：在可销毁的 Debian 13 VM 中执行实际 install、repair、重启和 Fail2ban/nftables 操作，是 Issue #5 的 C 级证据；必须引用明确成功运行。

## L1：每次提交（现有 ci.yml）

- Go gofmt、vet、test、race、build、Web 浏览器回归。
- 预检：Debian 13、架构/root、真实 SSH 和 socket activation、监听冲突、禁用 IPv6 的主机、DNS/时间/出口检查。
- 制品：锁定 SHA、拒绝篡改或截断、幂等缓存。测试不修改 `/etc`、`/var/lib` 和第三方规则。
- PR B 增加可注入受控命令、文件系统和宿主机探针的 Go 安装事务测试；模拟每个关键阶段失败、重试、恢复及文件归属错误。不要验证 shell 字符串代替验证最终状态。

## L2：安装器相关 PR（hub-components.yml）

单独运行官方 Debian 13 容器，不需在 CI 主机安装第三方服务。
- amd64、arm64 使用 GitHub Actions 对应原生 Linux runner，构建 Go fixture 与 Web。
- 启动 `debian:13` 容器，从 GitHub 固定发行 URL 下载 Caddy **2.11.7** 与 Headscale **0.29.5**，按代码锁定的同一 SHA-256 校验。
- 从实际 `CandidateFiles` 生成候选配置；隔离 Headscale 的 SQLite、Noise/DERP 私钥、Unix Socket 到容器临时路径。
- 官方 `caddy validate`、`headscale configtest`、`systemd-analyze verify` 和 `fail2ban-client -t`。
- 任一步失败则 CI 失败；无条件保留 root 或 apt 日志并非必须，失效时上传脱敏定位信息即可。
- 这是组件 **配置校验**，**不是**真正的宿主机/systemd/公网验收。没有运行 Headscale 控制连接或 DERP/STUN。

## L3：安装器相关 PR 与发布候选

PR B 实现真实 `check → stage → validate → apply → readback` 后，`hub-vm` 在 PR 触及安装器路径时自动运行，也可在 `verify/issue5-hub-vm-*` 分支 push 或通过 `workflow_dispatch` 的 `ref` 输入手动验证指定分支/标签。Debian 13 QEMU 全系统 VM 执行：
1. 首次安装，检查账户、权限、服务 active/boot-enabled、本机 HTTP 健康与传输层 TLS 就绪。
2. 幂等再次执行，已有 SQLite、Noise/DERP 私钥及管理员身份不变。
3. 重启 VM 后服务可恢复，状态、文件和版本正确。
4. 至少模拟一次服务启动失败并恢复，记录 operation_id、错误码与最终状态；回归覆盖健康探针 303 语义、回滚后 `ManagedFiles` 与磁盘一致、apt 查询优先，以及 Web jail 默认禁用/`--direct-caddy` 启用和 RFC3339Nano 日期过滤。

优先使用 GitHub 托管 Runner；先探测 `/dev/kvm` 是否可用，不能默认具备硬件加速。无 KVM 时使用可接受时长的 TCG 软件模拟或临时隔离 VM。**不得使用纯 Docker 结果冒充完整系统验收。**

`pull_request` 触发的 workflow 不获得仓库 secrets；当前 `permissions: contents: read` 保持不变，L3 只使用公开固定镜像、官方组件和隔离测试证书，不依赖发布凭据。

## 外部条件与发布门槛

Cloudflare 灰云 DNS、真实 ACME TLS、UDP/3478、Headscale 特殊控制协议、内置 DERP、云安全组和 NAT 受外部条件影响，只有真实完成时才能标记 pass，否则是 `pending`，不能以配置校验代替。

在 `v1.0.0` 明确声明支持的架构必须完成相应宿主机验证；交叉编译/容器中的二进制校验不等于系统安装验证。不要将未通过的关键场景消失在总体 CI 绿色里。

## my-sub 的可复用设计证据

- `my_sub/predeploy.py` 与 `tests/test_predeploy.py`：引导阶段独立、缺少初始工具时从 /proc/net 探查端口，IPv4/IPv6/UDP 区分。
- `my_sub/hub_stage.py` 与 `tests/test_hub_stage.py`：真实 Headscale 在临时 SQLite/密钥路径执行配置自检。
- `my_sub/hub_activate.py` 与 `tests/test_hub_activate.py`：systemd Fake 状态、读回、失败后回滚。
- `install.sh` 与 `tests/test_install_swap.py`：被中断的代码替换和备份恢复。
- `my_sub/security.py`：验证 Fail2ban 前不启动/重启，避免误封 SSH。MeshMux 须进一步识别真实 SSH 非 22 端口。

借鉴测试思想，不从私有仓库复制代码；`my-sub` 的 Python 安装器和 MeshMux Go 安装器相互独立。

## PR B CI 运行入口

- **L1**：GitHub Actions `ci`（`go test ./...` / `go test -race ./...`），含 `internal/install/apply_test.go` 的随机私有目录注入、幂等性及回滚。测试进程没有操作真实 `/etc` 的权利。
- **L2**：`hub-components` 的 amd64、arm64 官方二进制校验，额外上传短期保留的 `hub-installer-<arch>` 和对应 `SHA256SUMS`，并非稳定 release。
- **L3**：`hub-vm` 工作流在触及 `internal/install/**`、`cmd/meshmux/**`、`cmd/meshmux-web/**`、`scripts/ci-hub-vm.sh` 或相关文档/workflow 的 PR 上自动触发，也支持 `verify/issue5-hub-vm-*` 分支 push 与带 `ref` 输入的手动运行；启动带 SHA-512 固定校验的 Debian 13 官方 qcow2 / systemd。`internal/install/vm_test.go` 仅在 `MESHMUX_HUB_SYSTEM_VM=1` 时激活；虚拟机才执行安装器、故障修复与重启、真实 Fail2ban nftables ban/unban。实验性的内部签发证书只用于隔离 CI；正式 CLI 不能启用。

QEMU 若没有 `/dev/kvm` 则改用 TCG 软件模拟；有条件时验证速度更快。**L3 必须有明确成功运行链接，不能以脚本存在或启动 QEMU 代替成功。**
