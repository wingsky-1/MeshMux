package store

// The candidate/task surface, re-exported from the candidate leaf.
//
// A candidate revision and the fixed Agent task chain that publishes it are one
// artifact, so the reads and writes of both live together in
// internal/control/store/candidate. The names below are the public ones the
// HTTP and CLI layers already use.

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// CandidateSHA256 is the compiled digest of one candidate document.
func CandidateSHA256(document []byte) (string, error) { return candidate.SHA256(document) }

// InsertCandidateTx stores one immutable candidate revision.
func InsertCandidateTx(tx *sql.Tx, document node.Candidate, now int64) error {
	return candidate.InsertTx(tx, document, now)
}

// NextCandidateRevisionTx returns the next immutable revision of one node.
func NextCandidateRevisionTx(tx *sql.Tx, nodeID string) (int64, error) {
	return candidate.NextCandidateRevisionTx(tx, nodeID)
}

// NewFixedTask builds one task envelope of the fixed publication chain.
func NewFixedTask(nodeID, kind string, params json.RawMessage, revision int64) (protocol.Task, error) {
	return candidate.NewFixedTask(nodeID, kind, params, revision)
}

// SeedInitialTasksTx enqueues the fixed reconcile chain of a freshly paired node.
func SeedInitialTasksTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return candidate.SeedInitialTasksTx(tx, nodeID, now, outAuthorizationTx)
}
