package node

import (
	"database/sql"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// LineTrackedTx reports whether a node can carry proxy credentials.
// An Out node is never a subscriber Line, and an Edge node without stored Line
// settings has no transport to publish.
func LineTrackedTx(tx *sql.Tx, nodeID string) (bool, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(coredomain.RoleEdge) {
		return false, nil
	}
	var settings int
	if err := tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, nodeID).Scan(&settings); err != nil {
		return false, errors.New(common.CodeDatabaseUnavailable)
	}
	return settings > 0, nil
}
