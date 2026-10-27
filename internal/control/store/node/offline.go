package node

// The offline window of one node.
//
// Every projection that asks "is this host currently reporting?" reads the same
// two columns and the same window, so the answer is declared once. It lives in
// the node domain because the row is a node row; the subscriber and Out
// projections call it instead of spelling the query again.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

// SubscriberLineNodeOfflineTx reports whether a node is currently outside the
// delivery window used by the task endpoints.
func SubscriberLineNodeOfflineTx(tx *sql.Tx, nodeID string, now time.Time) (bool, error) {
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
