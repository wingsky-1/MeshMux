package policy

// Route policies, the rule library and the gated publication.
//
// The layer model is unchanged: the server layer is writable and drives the
// Line candidate; the client layer is read-only, kept as a gated preview of its
// legacy revision because the standard subscription export never consumed it.
//
// This package sits above node: it reads the Line list, the per-Line egress
// facts and the candidate builder to assemble and publish, and node never reads
// a policy row back. The route a Line must publish is derived here
// (LineServerRouteTx) from the active server revision plus the current Out
// facts, so the two implicit publishers (subscriber synchronization and upgrade
// approval) reach it through this package instead of through node.

import (
	"database/sql"

	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"
)

// Store is the policy persistence handle. The root store embeds one around the
// same connection.
type Store struct {
	DB *sql.DB

	// Nodes is the node-domain read surface a publication needs. node is the
	// lower layer, so this is a plain field rather than an inverted port.
	Nodes *storenode.Store
}
