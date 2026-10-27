package subscription

import (
	"database/sql"

	"github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"
	storepolicy "github.com/wingsky-1/MeshMux/internal/control/store/policy"
)

// Store is the subscription persistence handle. The root store embeds one
// around the same connection.
type Store struct {
	DB *sql.DB

	// Nodes supplies the Line snapshot, the route and the egress facts a
	// subscription publishes against.
	Nodes *storenode.Store
	// Candidates is the shared candidate/task leaf.
	Candidates *candidate.Store
	// Policies supplies the active policy revision the desired Line route is
	// derived from.
	Policies *storepolicy.Store
}
