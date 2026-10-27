package node

// The subscriber-domain port.
//
// Two domains are mutually dependent in the data model — a Line publishes the
// users its subscribers hold, and a subscriber's convergence is decided by the
// Line's candidate chain — so one direction has to be an interface. node is the
// lower layer: subscription imports node for the Line snapshot, the route and
// the egress facts, and node declares here the subscriber facts it needs.
//
// The port is deliberately transaction-scoped: the caller owns the transaction,
// so a node result and the subscriber state it changes commit together.

import (
	"database/sql"
	"time"
)

// Subscribers is the subscriber-owned surface this domain calls. The
// subscription handle satisfies it; the root assembly wires the two together.
type Subscribers interface {
	// FinalizeDeletingTx moves a deleting subscriber to deleted once every
	// affected Line confirmed the snapshot without its UUIDs.
	FinalizeDeletingTx(tx *sql.Tx, nodeID string, now time.Time) error
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
