// Package jobs is the task domain of v1.0.0 issue #11b: the persisted
// lifecycle of one task revision and the release it converges a node to.
//
// 职责：任务阶段机（pending / applying / verifying / healthy / partial /
// failed / rolled_back）、转换规则、operation_id 与修订/重试语义，以及目标
// 发行引用（版本、manifest 摘要、policy_schema 快照、candidate revision）。
// 这些类型只供调用方判断“这条记录是否还能前进、是否需要新修订重试”。
//
// 边界：本包不执行 I/O，不建表、不排队、不启动进程，也不 import
// internal/web 或 internal/install；持久化在 internal/web 的既有 agent_tasks
// 列上完成，拉取仍由 Agent 轮询既有任务链。不扩展 Agent allowlist，不支持
// 任意 shell、路径或外部 URL；升级的执行器、apply 与回滚属 #11c 系。
//
// See ADR-0007 (修订记录 PR-11b); v1.0.0 deliberately ships without a generic
// task engine, queue or daemon.
package jobs
