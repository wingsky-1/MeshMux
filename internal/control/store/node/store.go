package node

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
