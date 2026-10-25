// Package store is the persistence layer of the Hub control plane: the SQLite
// store, schema migrations, session/authentication records, node, mesh,
// subscriber, subscription, route-policy, Out-sync and upgrade-task state,
// plus the publish-gate inputs that validate assembled candidates.
//
// Subscription aggregation (Task 4, ADR-0008): the four reference edge tables
// (subscription_lines/outs/rules/networks) plus subscription_snapshots are the
// subscription's side of every reference. store_subscription_selection.go owns
// the tables and the strict save; store_subscription_compose.go owns the draft,
// the pure composer call, the kernel gate and the approved artifact digest;
// store_subscription_artifact.go owns the download's re-derive-and-compare
// path. proxy_credentials keeps its role as the materialized VLESS identity.
//
// Out authorization (Task 5, ADR-0008 §3, Ruling R10): the Out allowlist is node
// membership — every Line that holds a current pairing identity — never a stored
// binding and never a subscription. store_out_sync.go owns the derivation
// (outAuthorizationTx), the publication/readback chain and the publish gate;
// store_out_authorization_view.go owns the read-only projection;
// store_out_lifecycle.go owns the delete (Ruling R9: delete is total);
// store_out_migration.go owns the schema legs (5 created out_bindings, 14 dropped it,
// 15 narrowed the candidate immutability trigger so a node can be deleted). There is
// no second authorization source.
//
// Dependency direction (compiler-enforced): store imports no Hub web package.
// Shared record types (Node, RoutePolicy, MeshDeviceRecord, OutAuthorizationPreview,
// subscriber snapshots, upgrade targets) and their stable error codes are defined
// here and consumed by handler and view. store never imports handler, view or web.
//
// Policy layers (Task 6): route_policies keeps its immutable server revision
// chain and its append-only events. The client layer is read-only — create,
// revise, activate and revoke are refused with POLICY_LAYER_RETIRED — because the
// standard subscription export never consumed it; existing revisions remain
// readable and are rendered only as a gated preview. Payloads carry
// default/rules/note; the retired top-level exceptions/ssids keys are refused
// with POLICY_PAYLOAD_RETIRED, and schema 17 rewrites stored payloads that
// predate the retirement.
package store
