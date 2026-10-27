package upgrade

import (
	"database/sql"

	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"
	storepolicy "github.com/wingsky-1/MeshMux/internal/control/store/policy"
)

// Store is the upgrade persistence handle. The root store embeds one.
type Store struct {
	DB *sql.DB

	// Nodes supplies the Line snapshot and the candidate revision.
	Nodes *storenode.Store
	// Policies supplies the route a node must publish.
	Policies *storepolicy.Store
}
