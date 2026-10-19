# 纳管、安装与状态收敛时序

## 安装原则

以下是 v1.0.0 的目标安装流程；PR-A 当前不提供可执行节点安装。目标态下，Hub 与目标节点面向用户的 CLI 只有 install；Agent 长期运行由 systemd 维护。用户在 Web 先创建待纳管节点，复制**一条经过版本固定的安装命令**，目标机在首次运行时输入 Web 提供的短期一次性配对码（不要把配对码放入进程参数、Shell 历史或安装 URL）。后续配置、日志、升级、回退、停用从 Web 操作。

Issue #6 PR-A 设计冻结 `meshmux-agent/v1`：Web 签发一次性 15 分钟 JSON-body 配对码，Agent 经出站 HTTPS 换取节点专属可撤销 Bearer 身份；任务固定为 `config.check` / `config.stage` / `config.apply` / `config.readback` / `health.status` / `node.status`，`upgrade.*` 与 `rollback.*` 预留给 #11 且当前拒绝。PR-A 基础实现已完成本地评审/L1 验收，可进入主控授权的本地提交与 ff merge 流程，当前没有新的远端 CI 结论；宿主机安装与 apply、sing-box 控制和 Out nftables ACL 属于尚未实现的 PR-B。配置任务参数只允许 `revision`，候选配置必须经受认证的专用候选配置通道或授权封装传输，不得复用公开订阅通道。首次密钥发行后须轮换到节点专属不可复用凭据，支持撤销和过期。

下图描述 v1.0.0 目标态，不代表 PR-A 已实现宿主机安装、服务健康或配置应用。

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
    Host->>Host: Verify distribution checksums and install units
    Host->>Agent: Start outbound HTTPS agent
    Agent->>Web: Pair with one-time code and trusted server identity
    Web->>DB: Consume pairing code, bind Node ID
    Web-->>Agent: Issue node-scoped credential + desired revision
    Agent->>Web: Poll/stream bounded task
    Web-->>Agent: Apply validated desired config
    Agent->>Core: sing-box check candidate
    alt Candidate rejected
      Agent-->>Web: Failure code / no activation
    else Candidate valid
      Agent->>Core: Atomic local config swap + controlled restart
      Agent->>Web: Read back runtime status and version
      Web->>Web: External port/handshake probe and Out ACL checks
      alt External probe fails
        Web->>DB: pending-verification (not healthy)
      else Verification succeeds
        Web->>DB: ready + verified version
        Web-->>User: Enrollment complete
      end
    end
  end
~~~

## Node 状态机

pending → installing → paired → staging → verifying → ready。可由 installing、staging、verifying 转入 failed；运行中远端失联进入 degraded。失败事件包含 stage、error_code、operation_id、suggested_action，不把 partially installed 伪装成成功。

## Out 与 Line 的授权顺序

- Out 无法作为普通公网客户端线路；默认 VLESS 白名单为空/拒绝。
- 新 Line 通过 Hub 身份、配置和公网来源校验后，Hub 才向相关 Out 更新授权来源，再发布引用该 Out 的服务端策略。
- 没有 Out 时绝不要求执行 ACL 协调。
- 新增 Line 对已有订阅的自动扩展必须先通过远端配置校验、入站可达、关联 Out ACL 确认，再原子发布新订阅修订。

## 安装失败和升级失败

不能自动重置 Headscale 数据库、Docker/NAS Tailscale 身份或覆盖非本项目的 nftables 规则。安装器具有 dry-run/preflight 观察阶段以及前滚/回滚 journal。升级将目标 Release tag、SHA256、旧版本配置、任务阶段持久保存；后台恢复继续或请求人工干预，不能依赖浏览器始终在线。
