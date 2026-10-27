package candidate

// The shared candidate and Agent-task store.
//
// A candidate revision and the four-task chain that publishes it are one
// artifact: the immutable row, the idempotent task envelope and the per-node
// monotonic revisions are written together or not at all. Four domains
// (node, policy, subscription, upgrade) need that pair, and none of them owns
// it, so it lives here — the second leaf of the split, beside common.
//
// The Out authorization a candidate chain carries is the one fact this package
// cannot derive: the Out domain owns it. It is injected (see Store.OutAllowlist)
// rather than imported, so candidate stays below every domain that publishes.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// Store is the candidate/task handle. The root store embeds one and wires the
// Out authorization derivation; a domain that only reads candidates may build
// one with a nil OutAllowlist.
type Store struct {
	DB *sql.DB

	// OutAllowlist derives the source authorization of one Out inside the
	// caller's transaction. Publishing an Out chain without it would enqueue a
	// task whose guard the Hub cannot prove, so a nil value is a refusal.
	OutAllowlist func(tx *sql.Tx, outID string) ([]string, error)
}

// enqueueTaskAt persists a validated task with exact-envelope idempotency and a
// per-node monotonic revision. An identical re-enqueue is a success (nil); the
// same operation_id or idempotency_key with different content is a conflict;
// a revision that would rewind the node chain is stale. Reserved
// upgrade/rollback kinds never reach storage because protocol.ValidateTask
// rejects them first.
//
// Every request path threads the handler clock through EnqueueTaskAt, so one
// request has one timestamp.
func (s *Store) EnqueueTaskAt(task protocol.Task, now time.Time) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if err = EnqueueTx(tx, task, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	return nil
}

// NormalizeParams renders the params envelope a task row stores. An absent
// envelope is the empty JSON object, never an empty string: the Agent parses
// the column as JSON.
func NormalizeParams(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

// EnqueueTx is the sole task insertion path. It never begins or commits a
// transaction, so candidate publication and pairing can include tasks without
// nesting transactions on the MaxOpenConns(1) SQLite pool. The caller-supplied
// clock is shared with the candidate inserted in the same transaction, so one
// publication has one consistent timestamp.
func EnqueueTx(tx *sql.Tx, task protocol.Task, now time.Time) error {
	if err := protocol.ValidateTask(task); err != nil {
		return err
	}
	params := NormalizeParams(task.Params)
	res, err := LookupTask(tx, "operation_id=?", task.OperationID, task, params)
	if err != nil {
		return err
	}
	if res == lookupExact {
		return nil
	}
	if res == lookupConflict {
		return errors.New("IDEMPOTENCY_CONFLICT: operation_id already recorded with different content")
	}
	res, err = LookupTask(tx, "idempotency_key=?", task.IdempotencyKey, task, params)
	if err != nil {
		return err
	}
	if res == lookupExact {
		return nil
	}
	if res == lookupConflict {
		return errors.New("IDEMPOTENCY_CONFLICT: idempotency_key already recorded with different content")
	}
	var maxRev sql.NullInt64
	if err = tx.QueryRow(`SELECT MAX(revision) FROM agent_tasks WHERE node_id=?`, task.NodeID).Scan(&maxRev); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if maxRev.Valid && task.Revision <= maxRev.Int64 {
		return errors.New("REVISION_STALE: revision must increase monotonically")
	}
	stamp := now.Unix()
	if _, err = tx.Exec(`INSERT INTO agent_tasks(operation_id, node_id, kind, revision, idempotency_key, status, params, created_at, updated_at) VALUES(?,?,?,?,?,'pending',?,?,?)`, task.OperationID, task.NodeID, task.Kind, task.Revision, task.IdempotencyKey, params, stamp, stamp); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	return nil
}

type lookupKind int

const (
	lookupNone lookupKind = iota
	lookupExact
	lookupConflict
)

// LookupTask classifies an existing row matched by whereArg against the
// incoming envelope. The full stored envelope is compared so an idempotent
// replay is only accepted when every field matches exactly.
func LookupTask(tx *sql.Tx, where string, arg any, task protocol.Task, params string) (lookupKind, error) {
	var (
		opID, nodeID, kind, idem, storedParams string
		revision                               int64
	)
	err := tx.QueryRow(`SELECT operation_id, node_id, kind, revision, idempotency_key, params FROM agent_tasks WHERE `+where, arg).Scan(&opID, &nodeID, &kind, &revision, &idem, &storedParams)
	if errors.Is(err, sql.ErrNoRows) {
		return lookupNone, nil
	}
	if err != nil {
		return lookupNone, errors.New(common.CodeDatabaseUnavailable)
	}
	if opID == task.OperationID && nodeID == task.NodeID && kind == task.Kind && revision == task.Revision && idem == task.IdempotencyKey && storedParams == params {
		return lookupExact, nil
	}
	return lookupConflict, nil
}
