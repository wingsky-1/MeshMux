package upgrade

import (
	"database/sql"
)

// Store is the upgrade persistence handle. The root store embeds one.
//
// It holds no node handle any more: an approval republishes the Line candidate
// the node domain already builds, so this package reads upgrade rows only.
type Store struct {
	DB *sql.DB
}
