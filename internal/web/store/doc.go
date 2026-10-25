// Package store is the persistence layer of the Hub control plane: the SQLite
// store, schema migrations, session/authentication records, node, mesh,
// subscriber, subscription, route-policy, Out-sync and upgrade-task state,
// plus the publish-gate inputs that validate assembled candidates.
//
// Dependency direction (compiler-enforced): store imports no Hub web package.
// Shared record types (Node, RoutePolicy, MeshDeviceRecord, OutBinding,
// subscriber snapshots, upgrade targets) and their stable error codes are
// defined here and consumed by handler and view. store never imports handler,
// view or web.
package store
