package subscription

import (
	"database/sql"

	"github.com/wingsky-1/MeshMux/internal/control/store/candidate"
)

// Store is the subscription persistence handle. The root store embeds one
// around the same connection.
type Store struct {
	DB *sql.DB

	// Candidates is the shared candidate/task leaf.
	Candidates *candidate.Store
}
