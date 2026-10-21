// Package mesh is a placeholder for the post-v1.0.0 Headscale mesh device and
// subnet-router domain: device registration state, one-time enrollment keys,
// route approvals and mesh-only client configuration.
//
// 占位：post-v1.0.0 演进方向，当前无实现、无外部引用。
//
// 职责：表达 MeshDevice（用途、平台、Headscale Node ID、路由批准与在线证据）
// 的领域模型与生命周期规则。
//
// 边界：与 node 包不同——node 是 Line 主机上的 sing-box 运行时、固定目录布局
// 与 Agent 数据契约；mesh 描述的是 Headscale 侧的设备身份与入网状态，不定义
// 第二个 Line 或 Agent 模型，也不执行 Agent 动作。
//
// This package must stay free of I/O and of imports from internal/web so the
// domain remains testable without Hub state. See ADR-0007 for the boundary.
package mesh
