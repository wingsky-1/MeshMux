// Package clientdoc is the store's pure client-document adapter for the publish
// gate.
//
// Ownership and direction:
//   - layer: control-plane rendering leaf, directly below internal/control/store;
//   - owner: the policy render layer (internal/core/policy) emits routing
//     fragments; this package only wraps one fragment into the minimal native
//     document shape a kernel can validate. It never names an endpoint, a
//     credential or a Line;
//   - consumers: internal/control/store (publication gate only);
//   - imports: internal/core/policy, the shared subscription IR vocabulary
//     (internal/core/subscription/ir) and the standard library. Never add a
//     database, filesystem, clock or network dependency here: every function is
//     a pure byte transform, which is what lets the orchestration layer state
//     "assemble, do not write".
//
// Why a package instead of a file in store: the store is transaction
// orchestration (read, call core, persist, enqueue, audit). Byte assembly is a
// rendering concern, so it lives outside that package and the store only calls
// it. A future move into internal/core/policy is a rename of this package, not a
// rewrite of the gate.
package clientdoc
