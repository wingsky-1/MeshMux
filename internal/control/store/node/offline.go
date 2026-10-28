package node

// The offline window of one node.
//
// Every projection that asks "is this host currently reporting?" reads the same
// two columns and the same window, so the answer is declared once, in the line
// layer below this package. The subscriber and Out projections call this
// forwarder instead of spelling the query again.

import (
	"database/sql"
	"time"

	storeline "github.com/wingsky-1/MeshMux/internal/control/store/node/line"
)

// SubscriberLineNodeOfflineTx reports whether a node is currently outside the
// delivery window used by the task endpoints.
func SubscriberLineNodeOfflineTx(tx *sql.Tx, nodeID string, now time.Time) (bool, error) {
	return storeline.NodeOfflineTx(tx, nodeID, now)
}
