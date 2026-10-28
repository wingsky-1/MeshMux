// Package agent executes the frozen node task set against one installed Agent
// host and reports the result to the Hub.
//
// The implementation is organised in two file groups, both in this package:
//
//   - Runtime core: runtime.go (construction and lifecycle), runtime_state.go
//     (persisted state, bootstrap and journal schema), runtime_task.go (task
//     validation, idempotency and result helpers), runtime_loop.go (poll loop,
//     journal-recovery retry and outbox replay), runtime_apply.go
//     (check/stage/apply), runtime_readback.go (readback evidence),
//     runtime_codes.go (stable error codes), command.go, files.go,
//     process_linux.go, publish_check.go and aliases.go.
//   - Upgrade handoff: runtime_handoff.go (marker, claim and updater-result
//     records), runtime_handoff_stage.go (a stamped stage row starts the
//     updater), runtime_handoff_gate.go (apply/readback gate, reconciliation
//     and failure receipts) and runtime_handoff_finalize.go (accepted-readback
//     finalize, rollback confirmation and revert records).
//
// The two groups share one Runtime and one package: the split is file-level
// only, so the exported API and the root facade forwarding in
// internal/core/node stay unchanged.
package agent
