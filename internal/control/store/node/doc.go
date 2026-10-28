// Package node is the persistence boundary of nodes, Lines and the optional Out.
//
// A node row is the host identity; a Line is an edge node with stored transport
// and the VLESS users its subscribers hold; an Out is an optional Shadowsocks
// egress that admits clients by its link key. All three share the immutable
// candidate chain, so they live in one domain.
//
// # Layers
//
// This package holds the node identity work: creation, pairing, heartbeat, the
// task delivery window, the result/readback state machine and the external HTTP
// proxy. The Line and Out halves live in the two layers below it:
//
//   - node/line owns the stored Line transport, the candidate snapshot (which an
//     Out also renders as its baseline or link-key document) and the Line-side
//     egress facts;
//   - node/out owns the Out dial body and link key, the Out's own chain, the
//     projections the Web layer consumes and the Out lifecycle.
//
// The layers are acyclic: line is the bottom, out is built on line, and this
// package is the meeting point. Every declaration this package re-exports is an
// alias or a one-line forwarder, so the assembled store's API stays exactly what
// it was before the split. node/out reaches the Line only through line's exported
// transaction-scoped helpers; line never imports out.
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
// that revision with the same compiled digest. "A client really reached the Out"
// is not proven by any readback: the Out admits by link key, and the download is
// where a subscriber chooses that hop.
package node
