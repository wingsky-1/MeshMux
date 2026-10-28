package out

// The subscriber-domain port of the Out layer.
//
// The port is deliberately narrow: an Out delete, a used-by projection and the
// Line readback are the only subscriber facts this layer calls. The node root
// holds the wider port and injects its handle here; because Go interfaces are
// structural, the passing of that handle is the compile-time proof that the two
// declarations still agree.
//
// The port is transaction-scoped where the caller owns the transaction, so an
// Out result and the subscriber state it reads commit together.

import (
	"database/sql"
	"time"
)

// Subscribers is the subscriber-owned surface this domain calls.
type Subscribers interface {
	// OutUsedByTx names the subscribers that select one egress.
	OutUsedByTx(tx *sql.Tx, outID string) ([]string, error)
	// SelectionUsedByTx runs one used-by projection over an edge table.
	SelectionUsedByTx(tx *sql.Tx, query, id string) ([]string, error)
	// LineSyncViewTx is the convergence view of one Line.
	LineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error)
	// DrainNode republishes one Line's persisted intent in its own transaction.
	DrainNode(nodeID string, now time.Time)
	// OutReferencedCode is the refusal code for an egress a subscription still
	// selects.
	OutReferencedCode() string
}
