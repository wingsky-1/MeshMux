package policy

import (
	"database/sql"
	"time"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/policy"
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
// Atomicity (C3): the version bump is the LAST statement, after the seed. If
// the seed fails the whole transaction rolls back and user_version keeps its
// old value, so the next open retries the full leg instead of skipping a
// half-seeded library.
//
// Version note: schema 11 was reserved for 11d. 11d merged with no mirror
// table and no schema bump (D3: the operation journal is authoritative), so
// no leg runs at 11: a database already at 11 keeps the rule table this leg
// adds on top, and the 11d tables never exist to backfill.
// MigrateSchema12 creates the rule library and seeds its presets.
func MigrateSchema12(tx *sql.Tx) error {
	if _, err := tx.Exec(coredomain.SchemaDDL()); err != nil {
		return err
	}
	if err := coredomain.SeedPresetsTx(tx, time.Now().Unix()); err != nil {
		return err
	}
	_, err := tx.Exec(`PRAGMA user_version=12`)
	return err
}
