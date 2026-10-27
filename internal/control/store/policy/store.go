package policy

import (
	"database/sql"
)

// Store is the policy persistence handle. The root store embeds one around the
// same connection.
//
// It holds no node handle: a publication no longer builds a Line candidate, so
// this package reads policy rows only.
type Store struct {
	DB *sql.DB
}
