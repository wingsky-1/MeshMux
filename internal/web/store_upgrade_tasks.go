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

// stampUpgradeTargetTx attaches one release record to a pending config.stage row,
// the row /tasks reads as the formal staged evidence. The target is validated in
// the jobs domain before storage; the caller supplies no shell, path or URL, and
// re-stamping is allowed only before any result exists.
//
// It runs inside the caller's transaction because the approval path enqueues the
// chain and stamps its stage row together: the first Agent poll can never see a
// pending row without its target. There is deliberately no non-transactional
// twin, so no future caller can split the two writes.
func stampUpgradeTargetTx(tx *sql.Tx, operationID string, target jobs.Target, now time.Time) error {
	if err := jobs.ValidateOperationID(operationID); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE agent_tasks
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

// ApprovedTarget is the newest release record one node carries (#11b). Status
// is the stage row's phase, so an approval still in flight is distinguishable
// from one the node has read back; neither proves the target is installed.
type ApprovedTarget struct {
	Version        string
	ManifestSHA256 string
	PolicySchema   int
	Revision       int64
	OperationID    string
	Status         string
}

// approvedTargets returns the newest stamped record per node. Rows are read in
// descending revision order and the first row of a node wins, so an older
// approval can never shadow a newer one.
func (s *store) approvedTargets() (map[string]ApprovedTarget, error) {
	rows, err := s.db.Query(`SELECT node_id, target_version, target_manifest_sha256,
 policy_schema, target_revision, operation_id, status FROM agent_tasks
 WHERE target_version<>'' ORDER BY node_id ASC, revision DESC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := make(map[string]ApprovedTarget)
	for rows.Next() {
		var nodeID string
		var target ApprovedTarget
		if err := rows.Scan(&nodeID, &target.Version, &target.ManifestSHA256,
			&target.PolicySchema, &target.Revision, &target.OperationID, &target.Status); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		if _, seen := out[nodeID]; !seen {
			out[nodeID] = target
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// stampedStageTarget reads the persisted target of one stage row regardless of
// its status. The Agent polls the row after the Hub may already have moved it
// on, so a pending-only read would lose the stamp; an unstamped row is simply
// not an upgrade.
func (s *store) stampedStageTarget(nodeID, operationID string) (jobs.Target, bool, error) {
	var target jobs.Target
	var version, manifest string
	var policySchema int64
	err := s.db.QueryRow(`SELECT target_version, target_manifest_sha256, policy_schema, target_revision
 FROM agent_tasks WHERE operation_id=? AND node_id=? AND kind=?`,
		operationID, nodeID, protocol.KindConfigStage).Scan(&version, &manifest, &policySchema, &target.CandidateRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.Target{}, false, nil
	}
	if err != nil {
		return jobs.Target{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	if version == "" {
		return jobs.Target{}, false, nil
	}
	target.Version, target.ManifestSHA256, target.PolicySchema = version, manifest, int(policySchema)
	if err := target.Validate(); err != nil {
		return jobs.Target{}, false, errors.New("UPGRADE_RECORD_CORRUPT: the persisted upgrade target is not actionable")
	}
	return target, true, nil
}
