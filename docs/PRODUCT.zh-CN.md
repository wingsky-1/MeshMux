# MeshMux：产品定位与范围

状态：v0.1 设计基线；实现前的契约，不代表当前功能可用。

## 使命

让用户通过一个 Web 控制台管理自建代理线路、Headscale 私有组网、按策略指定的可选 Out 出口，最终能在手机上用一个 sing-box VPN 配置同时访问代理网络与家庭 Tailnet。

## 核心差异

1. **代理与组网统一编排但身份独立**：订阅用户、代理凭据和 Mesh 设备各自有生命周期。
2. **Out 从来不是安装前提**：一体机 Hub+Line、Hub+多 Line、Hub+Line+Out 均是正式部署模式。
3. **客户端 + 服务端双层策略**：SSID / LAN / Tailnet / CN / global 由客户端解释；Line 服务端按域名和规则集选 Line 直出或 Out 双跳。
4. **Web-first 操作**：安装目标机只执行一次安装器，之后管理、发布、诊断、升级、退役在 Web 中完成。
5. **可靠性优于复杂度**：可重现安装、明确阶段、失败不假成功、有版本和配置回退。

## 明确的对象

- Hub：唯一 Web 管理、数据与编排节点；可选兼任一个 Line。
- Line（原 Edge）：面向客户端的 sing-box 代理入口，可以有多个。
- Out：可选私有出口节点，可被 Line 按策略使用；默认不是公网代理入口。
- Agent：Hub/Line/Out 宿主机上的受限服务，主动与 Hub 建立 HTTPS 管理通道。
- Subscriber：可以获取标准代理订阅的用户。
- Mesh Device：独立的 Headscale/Tailscale 身份，可能关联 Subscriber，也可以只有 Mesh。
- Subnet Router：通告和经 Headscale 批准特定子网的 Mesh Device（NAS/服务器）。
- Route Policy：独立的客户端或服务端分流规则与明确兜底。

## 不做

不重写 WireGuard、Headscale、sing-box；不制作通用服务器面板、任意 root Shell、远程交互终端、Kubernetes、RBAC/多管理员、强制 Cloudflare Zero Trust、收款系统。第一版不追求第三方组件任意版本的一键升级、自动支持所有 Linux 发行版和严格实时的每用户配额。

## 隐私与公开边界

公开仓库只存架构、通用实现、虚构的域名/IP 和脱敏测试 fixtures；不得复制个人 VPS 地址、家庭内网拓扑细节、真实订阅 Token、Agent 注册码、Headscale 私钥、访问凭据或私有仓库内部状态。旧系统仅用作行为参照，不在公共源码中移植私有部署数据。

## 交付判据

代码完成、自动化/Mock 通过、隔离三节点真实联调通过、现网迁移验收是**四种不同证据**。未获得真实验收不能宣称生产可用。
