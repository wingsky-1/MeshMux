// Package compiler is a placeholder for the post-v1.0.0 configuration compiler:
// assembling a complete, audited sing-box or Mihomo document from Line,
// Subscriber, Credential and route intent, then handing it to the existing
// validate -> stage -> apply -> readback path.
//
// 占位：post-v1.0.0 演进方向，当前无实现、无外部引用。
//
// 职责：单一来源地把领域输入编译为确定性配置文档，使同一输入永远得到可比较
// 的字节输出与配置哈希。
//
// 边界：与候选渲染不同——node.CompileCandidate 已负责把 meshmux-node/v2 候选
// 规范化为节点本地配置，属于节点侧既有能力；compiler 面向 Hub 侧完整文档
// 组装，不复刻候选 schema，不承担传输、落盘或 apply。
//
// See ADR-0007; it introduces no implementation.
package compiler
