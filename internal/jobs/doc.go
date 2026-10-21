// Package jobs is a placeholder for the post-v1.0.0 long-running work domain:
// multi-Line convergence, per-node staged apply with readback, revocation
// fan-out and upgrade runs that outlive a single HTTP request.
//
// 占位：post-v1.0.0 演进方向，当前无实现、无外部引用。
//
// 职责：描述任务修订、阶段状态（pending / partial / failed）、operation_id
// 与可重试语义，使一次跨节点操作可被追踪和恢复。
//
// 边界：与现有轮询不同——当前 Web 层在请求内直接调用节点并靠短轮询读取状态，
// 不引入执行器、队列或新进程；jobs 若被采纳，只是把已明确的阶段与错误码固化
// 为持久记录，不改变 Agent allowlist，也不允许任意 shell 或外部 URL。
//
// See ADR-0007; v1.0.0 deliberately ships without a generic task engine.
package jobs
