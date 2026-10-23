package web

// Persistence of #11b upgrade task records. The record is not a new table: the
// existing agent_tasks row that carries the fixed chain gains the target release
// columns, so the same polling pull and revision space stay authoritative.
// #11b has no executor and no HTTP write path; stampUpgradeTarget is the seam
// #11c-1 calls when it enqueues an upgrade chain. Upgrade kinds are still
// rejected by protocol.ValidateTask, so no upgrade.* row can be dispatched.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/jobs"
	"github.com/wingsky-1/MeshMux/internal/protocol"
)

// migrateSchema9 adds the target release snapshot to existing task rows. It is
// purely additive and defaults every existing row to "no target record". Fixtures
// that replay an older user_version already carry these columns, so only missing
// ones are added instead of failing on a duplicate column.
func migrateSchema9(tx *sql.Tx) error {
	for _, column := range []struct{ name, ddl string }{
		{"target_version", "target_version TEXT NOT NULL DEFAULT ''"},
		{"target_manifest_sha256", "target_manifest_sha256 TEXT NOT NULL DEFAULT ''"},
		{"policy_schema", "policy_schema INTEGER NOT NULL DEFAULT 0"},
		{"target_revision", "target_revision INTEGER NOT NULL DEFAULT 0"},
	} {
		var found int
		if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('agent_tasks') WHERE name=?`, column.name).Scan(&found); err != nil {
			return err
		}
		if found == 0 {
			if _, err := tx.Exec(`ALTER TABLE agent_tasks ADD COLUMN ` + column.ddl); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(`PRAGMA user_version=9`)
	return err
}

// stampUpgradeTarget attaches one release record to a pending config.stage row,
// the row /tasks reads as the formal staged evidence. The target is validated in
// the jobs domain before storage; the caller supplies no shell, path or URL, and
// re-stamping is allowed only before any result exists.
func (s *store) stampUpgradeTarget(operationID string, target jobs.Target, now time.Time) error {
	if err := jobs.ValidateOperationID(operationID); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE agent_tasks
 SET target_version=?, target_manifest_sha256=?, policy_schema=?, target_revision=?, updated_at=?
 WHERE operation_id=? AND kind=? AND status='pending'`,
		target.Version, target.ManifestSHA256, target.PolicySchema, target.CandidateRevision, now.Unix(), operationID, protocol.KindConfigStage)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if changed != 1 {
		return errors.New("STAGE_TASK_NOT_PENDING: only a pending config.stage task can take an upgrade target")
	}
	return nil
}
