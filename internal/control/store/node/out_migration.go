package node

// The Out authorization schema legs of the subscription-aggregation rebuild.
//
// Two versions touch the old binding relation:
//
//	schema 5  created out_bindings (one Out bound to one Line, with an
//	          "enabled" flag) — PR #8, kept verbatim so a version-4 database
//	          can still climb the chain it was written against.
//	schema 14 drops out_bindings and its index (Task 5, ADR-0008 §3).
//	schema 15 narrows the candidate immutability trigger so an Out (or Line)
//	          can actually be deleted (Ruling R9).
//
// Both legs run inside the single Migrate transaction, so a database that starts
// at 4 never observes a state in which the binding table is the only
// authorization source: the version that drops the table is the version whose code
// derives the allowlist without it. That is what makes the switch atomic instead of a
// two-release migration with an authorization window.
//
// The drop is irreversible by design and is declared as such for the 11d gate. No
// operator-entered data is lost: the binding row only ever mirrored a relation the Hub
// now owns outright, and the authorization is node membership (Ruling R10) — every
// enrolled Line is accepted by every enrolled Out, with no per-relation record needed.

import (
	"database/sql"
)

// migrateSchema5 adds the Out binding table. It is the historical PR #8 leg.
//
// It is deliberately kept even though Task 5 drops the table again: the schema
// version is monotonic, so a database that reports 4 has to pass through 5 to
// reach the current version, and a leg that silently changed meaning would make
// the chain untrustworthy for every later leg. A fresh database runs it and the
// drop in the same transaction, which costs one empty table creation.
// MigrateSchema5 creates the Out binding table.
func MigrateSchema5(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE out_bindings (
  out_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  line_id TEXT REFERENCES nodes(id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  updated_at INTEGER NOT NULL,
  CHECK(enabled=0 OR line_id IS NOT NULL)
);
CREATE INDEX out_bindings_line ON out_bindings(line_id);
PRAGMA user_version=5;
`); err != nil {
		return err
	}
	return nil
}

// migrateSchema14 drops the Out binding table and its index.
//
// It is the only destructive migration of the aggregation rebuild and it is
// irreversible: from this version on the authorization is node membership (Ruling R10),
// which needs no table at all. Dropping the table together with the code that read it is
// what makes the switch atomic — an older binary refuses the newer file
// (SCHEMA_TOO_NEW) instead of reading a table that no longer exists, and a newer binary
// never looks at a table it does not read.
//
// The DDL is idempotent so a replay (a fixture that starts from a pre-14 file whose
// table was already dropped by hand) cannot fail on its own earlier write.
// MigrateSchema14 drops the Out binding table: membership is the authorization.
func MigrateSchema14(tx *sql.Tx) error {
	if _, err := tx.Exec(`
DROP INDEX IF EXISTS out_bindings_line;
DROP TABLE IF EXISTS out_bindings;
PRAGMA user_version=14;
`); err != nil {
		return err
	}
	return nil
}

// migrateSchema15 lets a node row be deleted.
//
// Schema 3 installed an unconditional BEFORE DELETE trigger on node_candidates, so a
// candidate row can never be rewritten or removed. That is right for a line of
// history, but it also makes "delete the node" impossible: the ON DELETE CASCADE
// fires the trigger for every candidate of the node and the whole statement aborts
// with CANDIDATE_IMMUTABLE.
//
// The narrowed trigger keeps the immutability guarantee for every reachable row and
// only stands aside for the cascade: it aborts while the owning node still exists, and
// a cascade from the parent delete runs after the parent row is gone. A direct
// `DELETE FROM node_candidates` for a live node is still refused, and an UPDATE is
// still refused unconditionally.
//
// ORDERING ASSUMPTION: the WHEN clause relies on SQLite removing the parent row before
// it runs the ON DELETE CASCADE children. That is what SQLite does (the parent DELETE
// is applied, then the FK action fires per child), and it was verified against this
// exact schema with an isolated probe: a direct child DELETE aborts with
// CANDIDATE_IMMUTABLE while `DELETE FROM nodes` succeeds and leaves no candidate rows.
// If a future SQLite version ever ran cascade children first, this trigger would abort
// the parent delete again — the delete path's own test (Ruling R9) is what would catch
// it, not a silent data loss.
// MigrateSchema15 narrows the candidate immutability trigger.
func MigrateSchema15(tx *sql.Tx) error {
	if _, err := tx.Exec(`
DROP TRIGGER IF EXISTS node_candidates_immutable_delete;
CREATE TRIGGER node_candidates_immutable_delete BEFORE DELETE ON node_candidates
WHEN EXISTS (SELECT 1 FROM nodes WHERE id = OLD.node_id)
BEGIN
  SELECT RAISE(ABORT, 'CANDIDATE_IMMUTABLE');
END;
PRAGMA user_version=15;
`); err != nil {
		return err
	}
	return nil
}
