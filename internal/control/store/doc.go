// Package store is the persistence layer of the Hub control plane: the SQLite
// store, schema migrations, session/authentication records, node, mesh,
// subscriber, subscription, route-policy, Out-sync and upgrade-task state, plus
// the publish-gate inputs that validate assembled candidates.
//
// # Orchestration, not assembly
//
// The control plane is split by responsibility, and this package is the
// orchestration layer only:
//
//	read    (SQL in one transaction) -> call a pure core function -> persist ->
//	enqueue a task -> record a stable code
//
// Byte assembly does not happen here. Client documents for the publish gate live
// in the child package clientdoc; routing fragments, rule-set pins and selection
// identity live in internal/core/policy and internal/core/subscription. store
// calls them and persists the outcome.
//
// # Subscription aggregation (ADR-0008)
//
// The four reference edge tables (subscription_lines/outs/rules/networks) plus
// subscription_snapshots are the subscription's side of every reference. The
// flow is one order, and every step is a separate public function so a caller can
// stop earlier:
//
//	store_subscription_spec.go     SelectionSpec.Normalize — the input boundary
//	                               (shape, dedupe, canonical identities)
//	store_subscription_refs.go     reference validation: existence, egress role
//	                               whitelist, same-Line Out agreement
//	store_subscription_inputs.go   the one composer-input builder (draft and
//	                               download share it, so the digest means something)
//	store_subscription_compose.go  draft -> preview -> approve -> save, and the
//	                               selection-snapshot read-back
//	store_subscription_selection.go persistence only: the edge tables, the
//	                               snapshot row and the used-by projections
//	store_subscription_artifact.go download: re-derive from the stored selection
//	                               and compare the approved digest
//	store_subscription_impact.go   read-only impact preview (reserved extension)
//	store_subscription_batch.go    per-subscriber batch re-approval, partial
//	                               success (reserved extension)
//
// The invariants that must not regress: a preview or a blocked save writes
// nothing at all; only an approved digest is stored, and the snapshot never
// stores a rendered byte; the download re-composes and compares; same-Line
// subscriptions must agree on the Out; the convergence gate runs before an
// approved artifact is served.
//
// proxy_credentials keeps its role as the materialized VLESS identity.
//
// # Out authorization (ADR-0008 §3, Ruling R10)
//
// The Out allowlist is node membership — every Line that holds a current pairing
// identity — never a stored binding and never a subscription.
// store_out_sync.go owns the derivation (outAuthorizationTx), the
// publication/readback chain and the publish gate;
// store_out_authorization_view.go owns the read-only projection;
// store_out_lifecycle.go owns the delete (Ruling R9: delete is total);
// store_out_migration.go owns the schema legs (5 created out_bindings, 14 dropped
// it, 15 narrowed the candidate immutability trigger so a node can be deleted).
// There is no second authorization source.
//
// # Dependency direction (compiler-enforced)
//
// store imports no Hub web package. Shared record types (Node, RoutePolicy,
// MeshDeviceRecord, OutAuthorizationPreview, subscriber snapshots, upgrade
// targets) and their stable error codes are defined here and consumed by handler
// and view. store never imports handler, view or web.
//
// # Single source of shared literals
//
// Repeated values are defined once and referenced, never re-typed at a call
// site:
//
//	store_codes.go           stable codes this package owns or mirrors
//	store_limits.go          the bounds this package enforces
//	store_roles.go           node roles and gate kernel names
//	store_status.go          task/node status names and the terminal predicate
//	store_sentinels.go       the missing/corrupt refusals of every read path
//	store_write_errors.go    write refusals several writers emit
//	store_identity_errors.go canonical identity refusals
//	store_transport.go       session/auth lifetimes, offline window, DSN pragmas
//
// A value a lower layer already exports is referenced from that layer; a value
// this package must also emit while its owner keeps it unexported is declared
// here once as an explicit mirror naming the owner.
//
// # Policy layers
//
// route_policies keeps its immutable server revision chain and its append-only
// events. The client layer is read-only — create, revise, activate and revoke
// are refused with POLICY_LAYER_RETIRED — because the standard subscription
// export never consumed it; existing revisions remain readable and are rendered
// only as a gated preview. Payloads carry default/rules/note; the retired
// top-level exceptions/ssids keys are refused with POLICY_PAYLOAD_RETIRED, and
// schema 17 rewrites stored payloads that predate the retirement.
package store
