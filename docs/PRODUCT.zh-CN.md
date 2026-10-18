# MeshMux：产品定位与范围

状态：**目标首发 v1.0.0，尚未实现**。开发按 Issue/PR 小步交付，正式可安装且完成验收时才发行 v1.0.0。

## 使命

让用户通过一个 Web 控制台管理自建代理线路、Headscale 私有组网、按策略指定的可选 Out 出口，最终能在手机上用一个 sing-box VPN 配置同时访问代理网络与家庭 Tailnet。

## 核心差异

1. **代理与组网统一编排但身份独立**：订阅用户、代理凭据和 Mesh 设备各自有生命周期。
2. **Out 从来不是安装前提**：一体机 Hub+Line、Hub+多 Line、Hub+Line+Out 均是正式部署模式。
3. **客户端 + 服务端双层策略**：SSID / LAN / Tailnet / CN / global 由客户端解释；Line 服务端按域名和规则集选 Line 直出或 Out 双跳。
4. **Web-first 操作**：首次在宿主机运行 install，之后纳管、订阅、Mesh 与分流都通过 Web；升级暂由明确可重复的受控修复/安装路径承担，全节点 Web 升级留待后续。
5. **安全且克制**：复用成熟技术；保留认证、Fail2ban、最小权限、清晰日志、校验与失败回退，不过度架构或重复构建底层协议。

## 核心业务对象

- Hub：唯一 Web 管理与编排节点，可选兼任一个 Line。
- Line（原 Edge）：面向客户端的 sing-box 代理入口，可以有多个。
- Out：可选私有出口节点，可被 Line 按策略使用；默认不是公网代理入口。
- Agent：Hub/Line/Out 宿主机上的受限服务，主动与 Hub 建立 HTTPS 管理通道。
- Subscriber：可以获取标准代理订阅的用户。
- Mesh Device：独立的 Headscale/Tailscale 身份，可能关联 Subscriber，也可以只有 Mesh。
- Subnet Router：通告和经 Headscale 批准特定子网的 Mesh Device（NAS/服务器）。
- Route Policy：独立的客户端或服务端分流规则与明确兜底。

## 首版不做

不重写 WireGuard、Headscale、sing-box；不制作通用服务器面板、任意 root Shell、远程交互终端、Kubernetes、RBAC/多管理员、Cloudflare Zero Trust、收款系统。v1.0.0 不阻塞于全节点 Web 升级、复杂流量配额、多 Out 故障切换、第三方组件跨版本升级或自动适配全部 Linux 发行版。

## 公开仓库边界

仅存通用实现、虚构的测试域名/IP、脱敏 fixtures；不得提交个人 VPS、真实订阅 Token、Agent 注册码、Headscale 私钥或私有仓库运行状态。旧系统仅作行为与问题复现参考，不能复制个人环境秘密。

## 交付判据

代码完成、单元/CI 通过、隔离三节点真实联调、现网迁移验收是四种不同证据。没有真实验收不能宣称可安装或生产可用。详细条件见 [ACCEPTANCE](ACCEPTANCE.zh-CN.md)。
