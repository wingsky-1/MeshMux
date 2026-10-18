# ADR-0001：直接管理原生 sing-box 1.14.3

状态：**Accepted as initial direction; runtime API details pending validation**。

## 决策

不把 s-ui、2S-UI 或 Sub-Store 作为必须依赖；Hub 编译器生成受审计的 sing-box JSON，各节点 Agent 本地 check / apply / readback。标准订阅由 Hub 生成 sing-box 与 Mihomo，Mesh 设备由单独生成器扩展 Tailscale Endpoint。

## 理由

产品差异在多 Line 聚合、可选 Out 双跳、Headscale Mesh 和统一 Web 设备生命周期，而不是再实现一个现成面板的管理 UI。直接纳管内核降低中间数据库、动态版本和管理端口依赖。

## 风险/验证

用户级动态启停、准确流量统计、无中断重载和 sing-box API 的所有调用均须在固定 1.14.3 版本上验证，绝不将最新版 API 文档当作兼容证明。Mihomo 不生成 Tailscale Endpoint。首版允许受控重启，必须回退旧配置。禁用或删除用户要验证 UUID 精确匹配与生效状态。
