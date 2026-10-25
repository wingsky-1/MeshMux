package store

import (
	"database/sql"
	"time"

	"github.com/wingsky-1/MeshMux/internal/policy"
)

// Rule library persistence for the subscription aggregation rebuild (Task 3,
// ADR-0008 §5): the policy_rules table with immutable (stable_key, version)
// rows plus the versioned preset seed bundle.
//
// `route_policies` (schema 8, server layer) is untouched: this table is the
// new library Task 4 pins by rule_revision_id = (stable_key, version). It does
// not double-write the old table.

// migrateSchema12 adds the rule library and seeds preset bundle v1. It is
// purely additive: one new table and seed rows, no existing table, row or
// index changes, so a rollback only needs to drop the table and set
// user_version back. Both the DDL and the seed are idempotent, so a replayed
// migration cannot fail on its own earlier write.
//
// Version note: schema 11 belongs to 11d (not merged on this branch), so this
// migration also accepts a database at 11 — the rule table is orthogonal to
// whatever 11d adds, and applying it on top of 11 is the same additive step.
// A future 11d merge inserts its own 10→11 leg ahead of this one.
func migrateSchema12(tx *sql.Tx) error {
	if _, err := tx.Exec(policy.SchemaDDL() + "\nPRAGMA user_version=12;\n"); err != nil {
		return err
	}
	return policy.SeedPresetsTx(tx, time.Now().Unix())
}
