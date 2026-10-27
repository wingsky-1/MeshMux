package upgrade

// The Hub's upgrade targets and the Agent upgrade channel.
//
// An approved release is a stamped row per node plus the four-task chain that
// applies it. The chain is the same publication path every other change uses,
// so this package reads the Line snapshot, the derived route and the candidate
// revision from the node and policy domains; neither of them imports it.

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
