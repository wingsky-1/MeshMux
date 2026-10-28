// Package node is the stable facade of the Line/Out node domain. The
// implementation is split into four subpackages so each boundary is explicit:
//
//   - spec is the pure, deterministic domain: the host layout, the frozen
//     meshmux-node/v1 candidate document with its optional users, reality,
//     route and out blocks, the Out egress shapes, and the pinned kernel
//     release. It never performs I/O.
//   - render compiles one validated candidate into the exact sing-box bytes
//     (and the retired Out guard table). It is pure and deterministic.
//   - agent is the host runtime: it owns the private directories, writes
//     managed files atomically, runs the pinned subprocesses through a fixed
//     argv, holds the shared runtime lock and reads the live data plane back.
//   - client is the authenticated outbound Hub client used by the Agent.
//
// This package re-exports the public types, constants and functions of those
// subpackages, so callers keep importing internal/core/node while the
// implementation stays navigable. A new egress tag or wire grammar value
// belongs in internal/core/node/protocol (and must not change an existing
// document's bytes); a new command must be added to the allowlist in protocol
// before it can be run.
package node
