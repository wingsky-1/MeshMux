package store

// Schema 17: retire the two no-op client intent fields.
//
// The legacy client layer payload carried top-level `exceptions` and `ssids`.
// After the rule library landed (Task 3/4) neither field reached a rendered
// document: the publication path built policy.ClientPolicy from `default`
// and `rules` only, so a stored exceptions/ssids value looked applied while no
// byte changed. Task 6 refuses those keys on every write (and on every read
// that bypasses the write path) and this leg removes them from rows written by
// an older release.
//
// The rewrite is deliberately minimal:
//
//   - only rows that still contain one of the retired keys are touched, so an
//     already-clean database keeps every payload byte-for-byte;
//   - `default`, `rules` and `note` are preserved; the retired keys carried no
//     consumer-visible behaviour, so no routing decision changes;
//   - revision numbers, statuses, timestamps and audit events are untouched:
//     this is a payload-shape migration, not a new revision;
//   - a payload that is not a JSON object is left alone. It was already
//     unusable (`POLICY_CORRUPT` on read), and replacing it would destroy
//     evidence.
//
// Irreversible by design: the old keys cannot be reconstructed, but they were
// never authoritative. A downgrade needs the pre-upgrade database backup, the
// same rule every other schema in this chain follows.

import (
	"encoding/json"
	"fmt"
)

// migrateSchema17 strips the retired exceptions/ssids keys from every stored
// route policy payload. It runs after the schema 16 rebuild and before the
// first read of a policy row.
func migrateSchema17(s *Store) error {
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version == DatabaseSchemaVersion {
		return nil
	}
	if version != 16 {
		return fmt.Errorf("schema 17 requires the schema 16 database, found %d", version)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, revision, payload FROM route_policies`)
	if err != nil {
		return err
	}
	type rewrite struct {
		id       string
		revision int64
		payload  []byte
	}
	var pending []rewrite
	for rows.Next() {
		var id, payload string
		var revision int64
		if err := rows.Scan(&id, &revision, &payload); err != nil {
			rows.Close()
			return err
		}
		cleaned, changed, err := stripRetiredPolicyFields([]byte(payload))
		if err != nil {
			rows.Close()
			return err
		}
		if changed {
			pending = append(pending, rewrite{id: id, revision: revision, payload: cleaned})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// Updates run after the cursor is closed: the store has one connection, so
	// writing while a SELECT is still open would wait on itself.
	for _, row := range pending {
		if _, err := tx.Exec(`UPDATE route_policies SET payload=? WHERE id=? AND revision=?`,
			string(row.payload), row.id, row.revision); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`PRAGMA user_version=17`); err != nil {
		return err
	}
	return tx.Commit()
}

// stripRetiredPolicyFields removes the retired keys from one payload object.
// changed is false when the row is already clean or is not an object at all.
func stripRetiredPolicyFields(payload []byte) ([]byte, bool, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return payload, false, nil
	}
	changed := false
	for _, key := range retiredPolicyFields {
		if _, present := object[key]; present {
			delete(object, key)
			changed = true
		}
	}
	if !changed {
		return payload, false, nil
	}
	cleaned, err := json.Marshal(object)
	if err != nil {
		return nil, false, fmt.Errorf("ROUTE_POLICY_PAYLOAD_REWRITE_FAILED: %w", err)
	}
	return cleaned, true, nil
}
