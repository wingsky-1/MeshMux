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
// Atomicity (C3): the version bump is the LAST statement, after the seed. If
// the seed fails the whole transaction rolls back and user_version keeps its
// old value, so the next open retries the full leg instead of skipping a
// half-seeded library.
//
// Version note: schema 11 belongs to 11d (not merged on this branch), so this
// migration also accepts a database at 11 — the rule table is orthogonal to
// whatever 11d adds, and applying it on top of 11 is the same additive step.
// A future 11d merge inserts its own 10→11 leg ahead of this one; the reserved
// leg backfill below (ensureSchema11Mirror) keeps a database that jumped to
// 12 from missing the 11d table forever.
func migrateSchema12(tx *sql.Tx) error {
	if _, err := tx.Exec(policy.SchemaDDL()); err != nil {
		return err
	}
	if err := policy.SeedPresetsTx(tx, time.Now().Unix()); err != nil {
		return err
	}
	_, err := tx.Exec(`PRAGMA user_version=12`)
	return err
}

// ensureSchema11Mirror backfills the 11d-reserved leg for databases that
// already moved past 11 (C2). A database that jumped 10→12 on this branch
// would otherwise never run 11d's 10→11 leg once it merges, losing the
// 11d table permanently. This step runs on every open after the version
// chain and is idempotent (CREATE TABLE IF NOT EXISTS), so it is a no-op
// once 11d owns the leg.
//
// Ownership: the table shape below is the 11d plan's documented §5.5 mirror
// (operation journal mirror); 11d owns the authoritative DDL and reconciles
// or replaces this backfill at merge. Heads-up: 11d r6 (owner D3, still under
// review) proposes dropping this mirror table entirely and staying at schema
// 10 — if that lands, this backfill leaves an unread, harmless table and 11d
// removes it at merge; nothing in this binary reads it either way.
func ensureSchema11Mirror(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS hub_upgrade_operations(
  operation_id TEXT PRIMARY KEY, target_version TEXT NOT NULL, from_version TEXT NOT NULL,
  state TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
  manifest_sha256 TEXT NOT NULL, package_sha256 TEXT NOT NULL, db_schema INTEGER NOT NULL,
  backup_generation INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
)`)
	return err
}
