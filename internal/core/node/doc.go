// Package node is the Line/Out node domain: the fixed host layout, the frozen
// candidate contract and the runtime that applies it.
//
// Boundary (2026-10-26 core split): this package is the node half of the pure
// domain layer plus the Agent runtime that executes it. It never imports a
// Hub-side domain — no policy, no subscription, no web. Its one internal
// dependency is the wire contract internal/node/protocol, which also owns the
// values every document producer must share (egress tags, the VLESS flow, the
// selector and Tailscale endpoint tags, the rule-set format, and the identity,
// digest, token and release-version grammars).
//
// The pure half is deliberately small and deterministic:
//   - CompileCandidate / CompileCandidateWithRoute and CompileACL turn a
//     validated candidate into exact bytes;
//   - Candidate.Validate, CandidateDocument.Validate, ValidateFor, ParseACLAllowed
//     and the ACL source predicates are shape checks with stable refusal codes;
//   - ParseHTTPProxyURL, ValidateOutLinkKey and NewOutLinkKey describe the Out
//     egress.
//
// Everything else is the runtime: it owns the host directories, writes managed
// files atomically, runs the pinned subprocesses through a fixed argv, holds the
// shared runtime lock and reads the live data plane back. The runtime performs
// I/O; the pure half never does.
//
// Extension points are additive: a new egress tag or wire grammar value belongs
// in internal/node/protocol (and must not change an existing document's bytes),
// a new candidate schema is a new reader beside the frozen ones, and a new
// command must be added to the allowlist in protocol before it can be run.
package node
