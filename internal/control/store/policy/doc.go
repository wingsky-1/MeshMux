// Package policy is the persistence boundary of route policies, the rule library
// and the gated publication.
//
// The layer model is unchanged: the server layer is writable and the client
// layer is read-only. Neither layer delivers routing rules to an Agent any more:
// the server publishes proxy ports and credentials only, and every split rule
// lives in the client document a subscriber downloads (iron rule ① of the
// client-chain design).
//
// # Dependency direction
//
// This package sits above node and reads the Line list only for the projections
// a page needs; node never reads a policy row back.
//
// # Publication order
//
// One order, no shortcut:
//
//	active revision -> Validate -> RenderSingBox / RenderMihomo (preview)
//	-> kernel gate -> receipt
//
// Nothing here executes a shell: both kernels are reached through the fixed
// verifier wrapper of common/publish_verifier.go, which runs one argv without a
// shell.
package policy
