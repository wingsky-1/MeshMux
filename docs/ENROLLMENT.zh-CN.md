# 纳管、安装与状态收敛时序

## 安装原则

Hub 与目标节点面向用户的 CLI 只有 `meshmux install`；Agent 长期运行由 systemd 维护。用户在 Web 先创建待纳管节点，核验当前同源 CLI 的 SHA-256，再复制不含配对码的安装命令。首次安装时，安装器先完成本地配置校验和真实 preflight，展示 plan，取得精确确认后从 stdin 读取 Web 提供的 43 字符一次性配对码（不要把配对码放入 flag、argv、Shell 历史、URL、JSON 或日志）。后续日常操作从 Web 发起。

Issue #6 PR-A 冻结 `meshmux-agent/v1`：Web 签发一次性 15 分钟 JSON-body 配对码，Agent 经出站 HTTPS 换取节点专属、可撤销 Bearer 身份；任务固定为 `config.check` / `config.stage` / `config.apply` / `config.readback` / `health.status` / `node.status`，`upgrade.*` 与 `rollback.*` 预留给 #11 且当前拒绝。PR-A 已完成本地评审/L1 验收并本地 ff 合入 `adb7558`，远端 `main` 仍为 `17baaa1`；PR-A 无新的远端 CI 结论。

PR-B 的宿主机安装、sing-box 控制、Out nftables ACL、Web 固定重新校验/身份重签与离线展示已写入当前工作树，但尚待全仓及隔离 Debian 13 验收。配置任务参数只允许 `revision`，候选配置必须经受认证的专用候选配置通道或授权封装传输，不得复用公开订阅通道。

下图描述当前实现的计划行为，不是验收通过声明。公网可达、真实协议握手和客户端可用仍为 pending。

~~~mermaid
sequenceDiagram
  autonumber
  actor User as Administrator
  participant Web as Hub Web
  participant DB as Hub SQLite
  participant Host as Clean Line/Out host
  participant Agent as Node Agent
  participant Core as sing-box
  User->>Web: Create node: role/name/ports
  Web->>DB: Create pending enrollment + short-lived code
  Web-->>User: Show version-pinned install instruction
  User->>Host: Execute install once
  Host->>Host: Check Debian version, arch, SSH, DNS, port, firewall
  alt Preflight blocked
    Host-->>User: Structured error + safe remediation
  else Preflight passed
  Host->>Host: Verify fixed checksums, stage files and validate units
    Host->>Web: Pair with stdin one-time code and trusted server identity
    Web->>DB: Consume pairing code, bind Node ID
    Web-->>Agent: Issue node-scoped credential + desired revision
    Agent->>Web: Poll/stream bounded task
    Web-->>Agent: Apply validated desired config
    Agent->>Core: sing-box check candidate
    alt Candidate rejected
      Agent-->>Web: Failure code / no activation
    else Candidate valid
      Agent->>Core: Atomic local config swap + controlled restart
      Agent->>Web: Report strict local readback
      Web->>DB: Native observed revision/hash + recent heartbeat
      Web-->>User: Local evidence only; external checks remain pending
    end
  end
~~~

## Node 状态机

Web 节点记录从 `pending` 开始；配对事务消费一次性码并签发节点身份后变为 `paired`，心跳更新最近联系时间。配置链使用固定 `config.check → config.stage → config.apply → config.readback`，任务结果可为 `healthy`、`partial`、`failed` 或 `rolled_back`；Node 页面只把最新 desired revision 与严格本机 readback 一致标为“本机服务已确认”，历史成功不会覆盖当前失败或排队状态。

节点没有 heartbeat、仍为 `pending`，或最近 heartbeat 超过 2 分钟，Web 显示离线且不向其投递会改动节点状态的任务。离线不会触发停线操作。安装/apply 失败返回 `operation_id`、`stage`、`status`、稳定 `error_code` 与 recovery；`partial`/`failed` 以非零退出，plan 成功不代表安装成功。

Web 当前提供固定“重新校验 / 应用”入口，在单个事务中生成不可变候选 revision 和固定四任务链。身份重签会撤销旧节点身份、替换待用配对码、终止未完成的旧任务并回到 `pending`，但不停止节点服务或删除候选/配置数据；若旧身份仍可用于 repair，则不应无谓重签。没有通用节点管理命令或任意 task 编辑器。

## Out 与 Line 的授权顺序

- Out 无法作为普通公网客户端线路；默认 VLESS 白名单为空/拒绝。
- 新 Line 通过 Hub 身份、配置和公网来源校验后，Hub 才向相关 Out 更新授权来源，再发布引用该 Out 的服务端策略。
- 没有 Out 时绝不要求执行 ACL 协调。
- 新增 Line 对已有订阅的自动扩展必须先通过远端配置校验、入站可达、关联 Out ACL 确认，再原子发布新订阅修订。

当前实现与上述目标仍有差距：VLESS 候选的 `users` 为空，没有 TLS/REALITY、用户、客户端凭据或订阅；#7 未实现。当前 Out nft 渲染为 `policy accept` 并 drop 目标 VLESS TCP/UDP 端口，尚未满足“空授权时默认拒绝、仅目标端口可用”的验收语义。#8、#9 与 #11 不在本轮范围。

## 安装失败和升级失败

不能自动重置 Headscale 数据库、Docker/NAS Tailscale 身份或覆盖非本项目的 nftables 规则。安装器具有 `--plan` 观察阶段、受管文件快照与 operation journal；可在覆盖前失败时恢复已记录文件，但回滚本身可能失败，因此结果必须显式报告 `rolled_back` 或 `partial`。runtime apply 仅在已有 LKG 时可尝试恢复并严格 readback；LKG 不可用或恢复失败时不得宣称成功。

当前实现只交付 Node 首装与 repair 身份复用，不实现升级。升级将目标 Release tag、SHA256、旧版本配置、任务阶段持久保存，属于 #11，需独立验收。
