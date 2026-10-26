// Package jobs is the release-target domain of v1.0.0 issue #11b: the release
// a task record converges a node to and the operation id it carries.
//
// 职责：目标发行引用（SemVer 版本、manifest SHA-256、`policy_schema` 快照、
// candidate revision）与 `operation_id` 形状校验。升级任务的状态、修订与拉取
// 复用 internal/web 的既有 agent_tasks 列和固定四任务链，不在本包复制第二套
// 阶段机。
//
// 边界：本包不执行 I/O，不建表、不排队、不启动进程，也不 import
// internal/web 或 internal/install；升级的执行器、apply 与回滚属 #11c 系。
// 不扩展 Agent allowlist，不支持任意 shell、路径或外部 URL。
//
// See ADR-0007 (修订记录 PR-11b 与 2026-10-26 Task 6); v1.0.0 deliberately
// ships without a generic task engine, queue or daemon.
package jobs
