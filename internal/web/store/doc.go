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
// Dependency direction (compiler-enforced): store imports no Hub web package.
// Shared record types (Node, RoutePolicy, MeshDeviceRecord, OutBinding,
// subscriber snapshots, upgrade targets) and their stable error codes are
// defined here and consumed by handler and view. store never imports handler,
// view or web.
package store
