// Package store is the persistence layer of the Hub control plane.
//
// The package is the assembly point of seven domain packages. Each one owns its
// tables, its schema legs and its rules; this package owns the SQLite
// connection, the data directory, the process lock, the migration chain, the
// single-administrator session/auth state and the wiring that joins the domains.
//
// # The domains
//
//	common        stable codes, sentinel refusals, role/status/limit vocabulary,
//	              transport lifetimes, Argon2id/token helpers, the kernel gate
//	candidate     the immutable candidate revision and the fixed Agent task chain
//	node          nodes, Lines, the optional Out, egress facts and readback
//	mesh          Mesh devices, enrollment keys and subnet routes
//	policy        route policies, the rule library, the gated publication
//	subscription  subscribers, credentials, the selection workspace, download
//	upgrade       approved release targets and the Agent upgrade channel
//
// # Dependency order (compiler-enforced)
//
//	common, candidate
//	    ↑
//	  node
//	    ↑
//	policy
//	    ↑
//	subscription
//	    ↑
//	upgrade
//
// A domain imports only the packages below it. Two edges of the real data model
// point the other way, and both are inverted rather than imported:
//
//   - node needs the subscriber convergence view, the delete finalization, the
//     selection used-by projections and the drain. It declares them as
//     node.Subscribers and subscription satisfies the port.
//
// wire.go is the only place those two are joined, once, after the database
// opens. boundary_test.go pins the import graph, so a package that reaches
// sideways is a failing test rather than a review comment.
//
// # Orchestration, not assembly
//
// The control plane is split by responsibility, and every domain is an
// orchestration layer over its own tables:
//
//	read (SQL in one transaction) -> call a pure core function -> persist ->
//	enqueue a task -> record a stable code
//
// Byte assembly does not happen here. Client documents for the publish gate live
// in the child package clientdoc; routing fragments, rule-set pins and selection
// identity live in internal/core/policy and internal/core/subscription.
//
// # Subscription aggregation (ADR-0008)
//
// The four reference edge tables (subscription_lines/outs/rules/networks) plus
// subscription_snapshots are the subscription's side of every reference. The
// flow is one order, and every step is a separate public function:
//
//	spec           SelectionSpec.Normalize — the input boundary
//	refs           reference validation: existence, egress role whitelist
//	inputs         the one composer-input builder (draft and download share it)
//	compose        draft -> preview -> approve -> save, snapshot read-back
//	selection      persistence only: the edge tables, the snapshot row, used-by
//	artifact       download: re-derive from the stored selection and compare
//	impact         read-only impact preview (reserved extension)
//	batch          per-subscriber batch re-approval, partial success
//
// The invariants that must not regress: a preview or a blocked save writes
// nothing at all; only an approved digest is stored, and the snapshot never
// stores a rendered byte; the download re-composes and compares; the
// convergence gate runs before an approved artifact is served.
//
// # Out egress (client chain)
//
// The Out is an ordinary Shadowsocks endpoint that admits any client presenting
// its link key: there is no source allowlist, no per-Line authorization and no
// Line publish gate. A subscription selects which egress its own client document
// names, so two subscriptions on one Line may choose different Outs. The node
// domain owns the Out's own publication/readback chain; the delete path is total
// (Ruling R9), and creating, editing, pausing or deleting a subscription never
// republishes an Out.
//
// # Single source of shared literals
//
// Repeated values are defined once and referenced, never re-typed at a call
// site. Within a domain the rule is unchanged; across domains a value lives in
// common, or is exported by the domain that owns it and referenced from there.
// A value this package must also emit while its owner keeps it unexported is
// declared once as an explicit mirror naming the owner, and deleted the moment
// the owner exports it.
//
// The error-code golden (internal/cli/upgrade/codes_golden_test.go) freezes the
// VALUES of every exported Code* constant under internal/control/store, whether
// the literal lives in a domain package or in common. The package is matched by
// path as well as by name, because three of the domain package names also exist
// under internal/core.
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
