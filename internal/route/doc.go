// Package route is a placeholder for the post-v1.0.0 routing-decision domain:
// per-Line inbound selection, optional Out chaining, direct-only zero-Out Lines
// and the ACL rules that decide which user may egress through which Out.
//
// 占位：post-v1.0.0 演进方向，当前无实现、无外部引用。
//
// 职责：把"用户 / Line / Out"的组合解析为一组受审计的路由意图，供编译器消费。
//
// 边界：与订阅分流不同——订阅分流负责把同一份用户集合渲染为不同客户端所需的
// sing-box 与 Mihomo 文档，属于渲染层的表达选择；route 只描述连通性与准入，
// 不渲染配置，不读写订阅 Token，也不定义 Out 的安装或升级流程。
//
// See ADR-0007 for the placeholder scope and the excluded cross-source ACL work.
package route
