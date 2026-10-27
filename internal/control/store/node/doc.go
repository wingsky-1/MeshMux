// Package node is the persistence boundary of nodes, Lines and the optional Out.
//
// A node row is the host identity; a Line is an edge node with stored transport
// and the VLESS users its subscribers hold; an Out is an optional managed egress
// with its own authorization and readback. All three share the immutable
// candidate chain, so they live in one domain.
//
// # Dependency direction
//
// This package is above candidate and common and below policy, subscription and
// upgrade, which read Line candidates and egress facts from here. It imports
// none of them. The subscriber facts it needs — the delete finalization, the
// selection used-by projections, the convergence view and the drain — are
// declared as the Subscribers port and injected by the root assembly. That
// inversion is what keeps node and subscription acyclic: subscription reads Line
// state, node never reads a subscriber row directly.
//
// # Evidence
//
// "The Hub published this candidate" is proven by the immutable revision and the
// task envelope. "The Agent applied it" is proven only by a healthy readback of
// that revision with the same compiled digest. "This address really is the
// Line's egress on the wire" is not proven by any readback, which is why the
// allowlist derivation refuses anything that is not a literal IP.
package node
