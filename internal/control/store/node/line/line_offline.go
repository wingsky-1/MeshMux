package line

// The offline window of one node.
//
// Every projection that asks "is this host currently reporting?" reads the same
// two columns and the same window, so the answer is declared once. It lives at
// this layer because both the node root and the Out drain ask it before handing
// out a task.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

// NodeOfflineTx reports whether a node is currently outside the delivery window
// used by the job endpoints.
func NodeOfflineTx(tx *sql.Tx, nodeID string, now time.Time) (bool, error) {
	var status string
	var lastHeartbeat int64
	err := tx.QueryRow(`SELECT status, last_heartbeat FROM nodes WHERE id=?`, nodeID).Scan(&status, &lastHeartbeat)
	if errors.Is(err, sql.ErrNoRows) {
		return true, common.ErrNodeNotFound
	}
	if err != nil {
		return true, errors.New(common.CodeDatabaseUnavailable)
	}
	if status == common.NodeStatusPending || lastHeartbeat == 0 {
		return true, nil
	}
	return now.Sub(time.Unix(lastHeartbeat, 0)) > common.OfflineAfter, nil
}
