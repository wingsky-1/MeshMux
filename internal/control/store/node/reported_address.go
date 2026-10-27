package node

// Agent-reported egress address support.
//
// The address is observation only: it never authenticates a node and never
// grants access. The Hub keeps the last report per node and fills an operator
// field only while that field is still "reported". A manually entered value is
// stored with source "manual" and is never overwritten by a later report.
//
// The three columns are additive so an older binary keeps reading the same
// database: a database at the current user_version is upgraded in place by
// EnsureReportedAddressColumns on every open, and no schema number moves.

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

const (
	// AddressSourceManual is an operator-entered dial or client-facing address.
	AddressSourceManual = "manual"
	// AddressSourceReported is an address the Hub filled from the node's own
	// egress report.
	AddressSourceReported = "reported"
)

// EnsureReportedAddressColumns adds the reported-address columns to databases
// created before this feature. Each ALTER is idempotent and changes no existing
// value: an existing Out/Line is therefore still a manual address.
func EnsureReportedAddressColumns(db *sql.DB) error {
	additions := []struct {
		table      string
		column     string
		definition string
	}{
		{"nodes", "observed_ipv4", "TEXT NOT NULL DEFAULT ''"},
		{"line_settings", "server_source", "TEXT NOT NULL DEFAULT 'manual'"},
		{"out_settings", "server_source", "TEXT NOT NULL DEFAULT 'manual'"},
	}
	for _, addition := range additions {
		var present int
		query := "SELECT count(*) FROM pragma_table_info('" + addition.table + "') WHERE name='" + addition.column + "'"
		if err := db.QueryRow(query).Scan(&present); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: reported address column %s.%s: %w", addition.table, addition.column, err)
		}
		if present != 0 {
			continue
		}
		if _, err := db.Exec("ALTER TABLE " + addition.table + " ADD COLUMN " + addition.column + " " + addition.definition); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: reported address column %s.%s: %w", addition.table, addition.column, err)
		}
	}
	return nil
}

// applyReportedIPv4Tx records one node's reported egress address and refreshes
// the defaulted addresses that belong to it. An empty report is ignored, which
// keeps an older Agent's heartbeat from erasing the last observation. A manual
// address is never touched.
func applyReportedIPv4Tx(tx *sql.Tx, nodeID, reportedIPv4 string, now time.Time) error {
	if reportedIPv4 == "" {
		return nil
	}
	if !protocol.ValidIPv4(reportedIPv4) {
		return errors.New("REPORTED_IPV4_INVALID: the reported address is not one canonical IPv4 literal")
	}
	var previous string
	err := tx.QueryRow(`SELECT observed_ipv4 FROM nodes WHERE id=?`, nodeID).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		return common.ErrNodeNotFound
	}
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if previous == reportedIPv4 {
		return nil
	}
	stamp := now.Unix()
	if _, err := tx.Exec(`UPDATE nodes SET observed_ipv4=?, updated_at=? WHERE id=?`, reportedIPv4, stamp, nodeID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	// Only a field the operator never filled follows a new report. The
	// materialized value is what every existing reader (candidate rendering,
	// subscription download, Out allowlist) already consumes, so a report
	// change converges through the same path as a manual edit.
	if _, err := tx.Exec(`UPDATE line_settings SET server=?, updated_at=? WHERE node_id=? AND server_source=?`,
		reportedIPv4, stamp, nodeID, AddressSourceReported); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if _, err := tx.Exec(`UPDATE out_settings SET server=?, updated_at=? WHERE node_id=? AND server_source=?`,
		reportedIPv4, stamp, nodeID, AddressSourceReported); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	return nil
}
