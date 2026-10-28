// Package node installs an Edge or Out Node: the MeshMux Agent, sing-box, the
// Agent config, the systemd units and the Out default-deny ACL.
//
// It owns the Node-only preflight (Agent identity, pairing, readback), the
// candidate and identity staging, the Fail2ban jail and the Node ledger
// layouts. The shared engine (ledger, artifacts, lock, journal, file apply
// primitives, host probes) comes from install/core, and the durable upgrade
// snapshot written after a successful install comes from install/snapshot.
// This package never imports the Hub channel.
//
// The MeshMux node domain package (internal/core/node) is imported as
// corenode here because this package is itself named node.
//
// The sources are grouped by phase: apply orchestration (node_apply.go,
// node_apply_files.go, node_apply_verify.go, node_stage.go, node_candidate.go,
// node_identity.go, node_recorded.go, node_claim.go, node_converge.go,
// node_render.go, node_fail2ban.go), verify tail (node_verify_tail.go,
// node_verify_dataplane.go, node_verify_fail2ban.go) and plan
// (node_plan.go, node_preflight.go), with node_encoding.go shared.
//
// InstallNode is the only Node host-mutation entry the CLI calls. A fresh
// install may need a one-time pairing code; a repair reuses the recorded
// identity, and the non-interactive handoff reads it from the ledger.
package node
