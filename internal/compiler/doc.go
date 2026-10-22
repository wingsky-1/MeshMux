// Package compiler turns Hub-side routing intent into deterministic documents.
//
// 10a implements the format-independent policy model (policy.go), the Geo and
// remote ruleset version lock (ruleset.go) and the sing-box 1.14.3 / Mihomo
// generators (render.go). Route owns connectivity and admission decisions;
// subscription owns subscriber documents and the existing client exports. This
// package only assembles, orders and hashes the intent that route has already
// admitted.
//
// 边界：与候选渲染不同——node.CompileCandidate 已负责把 meshmux-node/v2 候选
// 规范化为节点本地配置，属于节点侧既有能力；compiler 面向 Hub 侧完整文档
// 组装，不复刻候选 schema，不承担传输、落盘或 apply，也不写 Mesh、订阅或
// 凭据数据。MeshConfigModel 只读消费，reconcile 不会猜测缺失的设备或节点。
//
// See ADR-0007 for the original placeholder scope and the 10a revision.
package compiler
