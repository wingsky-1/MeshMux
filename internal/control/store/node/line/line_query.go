package line

// The bounded identifier projections of the node domain.
//
// Both node layers ask the same shape of question ("which ids does this query
// name?") and both must close the rows before the single-connection pool is used
// again. The helper sits at the bottom so the Out layer does not carry a second
// copy that could drift.

import (
	"database/sql"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

// QueryIDsTx runs one bounded identifier query inside the caller's transaction.
func QueryIDsTx(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return scanIDRows(rows)
}

// QueryIDs runs one bounded identifier query on its own statement, so no
// transaction is held open while another begins on the single-connection pool.
func QueryIDs(db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return scanIDRows(rows)
}

// scanIDRows drains one single-column identifier result set, closing it before
// the caller opens another statement or transaction on the single-connection
// pool. Every failure maps to the same stable code so callers never leak driver
// detail.
func scanIDRows(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}
