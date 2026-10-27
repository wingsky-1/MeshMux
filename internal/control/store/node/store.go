package node

// Nodes, Lines and the optional Out.
//
// A node row is the host identity; a Line is an edge node with stored transport
// and the VLESS users its subscribers hold; an Out is an optional managed egress
// with its own authorization and readback. All three share the immutable
// candidate chain, so they live in one domain.
//
// Dependency direction. This package is above candidate and common and below
// policy, subscription and upgrade, which read Line candidates and egress facts
// from here. It imports none of them. The facts it needs from the subscriber
// domain — the convergence view, the delete finalization, the selection used-by
// projections and the drain — are declared here as the Subscribers port and
// injected by the root assembly. That inversion is what keeps node and
// subscription acyclic: subscription reads Line state, node never reads a
// subscriber row directly.

import (
	"database/sql"

	"github.com/wingsky-1/MeshMux/internal/control/store/candidate"
)

// Store is the node persistence handle. The root store embeds one around the
// same connection.
type Store struct {
	DB *sql.DB

	// Candidates is the shared candidate/task leaf: the Line snapshot, the
	// publication and the convergence reads all go through it.
	Candidates *candidate.Store

	// Subscribers is the subscriber-domain port. The root assembly wires the
	// subscription handle into it; a test may supply a fixture.
	Subscribers Subscribers
}
