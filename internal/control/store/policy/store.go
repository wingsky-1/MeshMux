package policy

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
