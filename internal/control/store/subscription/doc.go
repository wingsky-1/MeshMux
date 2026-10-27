// Package subscription is the persistence boundary of subscribers, their
// credentials and the subscription workspace.
//
// # Dependency direction
//
// This is the top of the store's data order: it reads Lines, candidates, egress
// facts and policy revisions from the domains below it, and none of them imports
// it. The two facts it supplies upwards — the convergence view and the delete
// finalization — satisfy the Subscribers port the node domain declares, wired by
// the root assembly.
//
// # Subscription aggregation (ADR-0008)
//
// The four reference edge tables (subscription_lines/outs/rules/networks) plus
// subscription_snapshots are the subscription's side of every reference. The flow
// is one order and every step is a public function:
//
//	spec           SelectionSpec.Normalize — the input boundary
//	refs           reference validation: existence, egress role whitelist,
//	               same-Line Out agreement
//	inputs         the one composer-input builder (draft and download share it)
//	compose        draft -> preview -> approve -> save, and the read-back
//	selection      persistence only: edge tables, snapshot row, used-by
//	artifact       download: re-derive the stored selection, compare the digest
//	impact         read-only impact preview (reserved extension)
//	batch          per-subscriber batch re-approval, partial success
//
// The invariants that must not regress: a preview or a blocked save writes
// nothing at all; only an approved digest is stored and the snapshot never stores
// a rendered byte; the download re-composes and compares; same-Line subscriptions
// must agree on the Out; the convergence gate runs before an approved artifact is
// served.
package subscription
