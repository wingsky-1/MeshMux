// Package policy is the persistence boundary of route policies, the rule library
// and the gated publication.
//
// The layer model is unchanged: the server layer is writable and drives the Line
// candidate; the client layer is read-only, kept as a gated preview of its legacy
// revision because the standard subscription export never consumed it.
//
// # Dependency direction
//
// This package sits above node: it reads the Line list, the per-Line egress facts
// and the candidate builder to assemble and publish, and node never reads a
// policy row back. The route a Line must publish is derived here
// (LineServerRouteTx) from the active server revision plus the current Out facts,
// so the two implicit publishers (subscriber synchronization and upgrade
// approval) reach it through this package instead of through node.
//
// # Publication order
//
// One order, no shortcut:
//
//	active revision -> Validate -> ResolveServerPolicy (fail-closed Out)
//	-> RuleSetPins.Validate -> RenderServerRoute / RenderSingBox / RenderMihomo
//	-> kernel gate -> candidate publication
//
// Nothing here executes a shell: both kernels are reached through the fixed
// verifier wrapper of common/publish_verifier.go, which runs one argv without a
// shell.
package policy
