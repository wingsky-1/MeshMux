# ADR-0002：节点通过 outbound Agent 纳管

状态：Accepted (transport authentication details unresolved)。

Hub 在 Web 中创建 pending 节点/短期配对码；管理员在目标 Debian13 主机仅运行一次版本固定的 install。Agent 以可信 TLS 身份主动连回 Hub，完成短期一次性配对，领取节点独立身份，持续拉取期望配置/升级任务并返回精确状态。

## 权限范围

Agent 仅具备明确允许的校验、配置切换、服务启停、健康采集、升级和 rollback 操作；无交互 Shell、任意路径执行、任意远端下载或不受约束的 URL。Out 来源 ACL 默认拒绝，由纳管 Line 身份和公网出口探测结果控制。

## 风险与边界

与旧 SSH forced-command 相比减少了管理入站，但增加 Agent 首次身份、凭据轮换、证书与重连安全问题。必须在 PR2 之前完成协议和威胁建模，模拟冒领节点、重放一次性码、过期码、MITM、Hub 失联及任务重复提交。Agent 的长时间离线不能让已发布的原生代理无故停止。
