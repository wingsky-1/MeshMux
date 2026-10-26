# 客户端能力说明（订阅导入侧）

本文件只描述 MeshMux 生成的**标准桌面订阅配置**的目标能力与当前证据边界，不承诺移动端形态。

## 目标客户端与固定版本

| 客户端 | 固定版本 | 用途 |
| --- | --- | --- |
| sing-box | 1.14.3 | 生成并校验 sing-box 格式订阅 |
| Mihomo | 1.19.32 | 生成并校验 Mihomo（Clash.Meta）格式订阅 |

上游官方发行包在 CI 校验中使用，仅用于测试；两者均为 GPL-3.0，**不进入 MeshMux 服务端发行包**，服务端不随包分发客户端二进制。

## 传输与协议能力

- 传输：**TCP**。
- 流控：**Vision**。
- TLS 握手：**REALITY**（X25519 密钥对 + 16 位十六进制 short id，服务端名与握手目标分离）。
- 客户端凭据：每条 Line 上每个订阅用户一个独立的 VLESS UUID；订阅导出与撤销均按 Line + 用户粒度。

## 订阅内可配置项

- **线路选择**：订阅内可包含多条 Line，客户端可按选定线路使用；新增或移除 Line 后重新获取订阅即生效。
- **本地代理入口**：客户端本地 mixed 监听端口为 **1080**（HTTP/SOCKS 合用）。
- **配置分级**：CN / 国际 / DNS 规则由服务端侧策略定义并下发，客户端按订阅内容执行；Tailnet 规则只出现在 proxy+mesh 设备配置中，标准订阅不含 Tailnet/Mesh 规则。

## 标准订阅与设备配置的边界

- **标准订阅仍不提供 Mesh（Headscale）入网能力**：普通 sing-box / Mihomo 订阅不含 Tailscale Endpoint、`auth_key` 或 Mesh 路由；Mesh-only 设备仍走标准 Tailscale 客户端注册 Headscale，与代理订阅无关。
- **proxy+mesh 设备配置是单独的一次性文档**：仅待注册的 `proxy_mesh` 设备可在 `/mesh` 生成，合并代理出站与一个 Tailscale Endpoint；它不属于标准订阅，也不提供持续下载 URL。配置在本响应中只显示一次，不写入数据库或日志。用途决定文档：`mesh_only` 与 `subnet_router` 不渲染该文档，继续使用现成 Tailscale 客户端（子网路由设备在入网命令里带上已声明前缀）。
- **不提供 TUN 模式**配置：设备配置不包含 `tun` inbound、`auto_route` 或本地回环代理。
- **不接受对端子网路由（`accept_routes:false`，有意固定）**：设备配置没有 TUN，唯一的 Tailscale 路由规则只匹配 Tailnet CGNAT 前缀（`100.64.0.0/10`、`fd7a:115c:a1e0::/48`），因此即使接受了别的节点通告的 LAN 前缀也没有出口路径，只会让客户端以为自己能到达。远程家庭网段策略属 #10；在那之前本文件不声称代理+Mesh 设备可访问对端子网，`subnet_router` 侧的 LAN 可达由现成 Tailscale 客户端（其自身 `--accept-routes`）与 Tailscale 路由能力决定。
- **不含 SSID 与远程家庭网段策略**：SSID 分流、远程家庭网段和真机跨网可用性属 #10 及后续 C 级验收；本文件不声称 iOS/Android 真机已通过。
  - 10b-1 已实现策略后端：客户端默认顺序为 Tailnet/远端家庭网段→Tailscale、CN→直连、例外→直连、其余→所选 Line 兜底；SSID 仅作为 sing-box 1.14.3 的 `wifi_ssid` 表达（Mihomo 1.19.32 无 SSID 规则类型，生成时返回 `RENDER_UNSUPPORTED`，不下发猜测字段）。策略持久化已由 `route_policies` 完成；Task 6 起客户端层停写（只保留既有 revision 的只读预览），客户端分流改由规则库写入订阅（六种匹配器，SSID 暂不上架），真机验证仍属 #10/#12。
- **AI 双跳不改变客户端形态**：AI 域名选路由服务端与规则集决定；Out 不可用时服务端拒绝发布相关策略，而不是让客户端自行回退。

## 证据边界

- CI 中执行的是**配置校验**：由固定版本的 sing-box / Mihomo 官方二进制解析并检查生成的订阅配置是否合法、可被加载。
- 配置校验通过**不等于**真实协议握手成功，也**不等于**公网可达或用户端可用；真实握手、跨网可达性与真机可用性验证**仍待完成**（见 `docs/ACCEPTANCE.zh-CN.md`）。

## 凭据生命周期提示

- 客户端本地已缓存的 VLESS UUID 在服务端撤销之前**仍然有效**；订阅地址本地缓存同理。
- 撤销（删除用户、删除 Line 或轮换 Token）只影响后续获取；用户需重新获取订阅或删除本地缓存条目才能停止使用旧凭据。
- 订阅 Token 与 VLESS 凭据是两类独立对象：Token 轮换/撤销与 per-Line 凭据删除互不替代。
