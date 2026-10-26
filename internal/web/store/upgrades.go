package store

// Read-only upgrade view for issue #11a (GET /tasks): the release manifest of
// this Hub build and, per node, the observed active readback next to the staged
// target. #11b persists that target on the existing agent_tasks row (version,
// manifest digest, policy schema and candidate revision); the pre-existing
// derivation from a healthy config.stage task stays as the labelled fallback for
// nodes without a record. There is still no apply, rollback, retry or enqueue
// path; those belong to #11c-11e, so the page offers no control that cannot act.

import (
	"encoding/json"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// StagedReadback is the newest staged evidence of one node. A formal upgrade
// record (#11b) supplies the target release; without one the row is derived
// from the newest healthy config.stage task and marked Derived. Neither proves
// apply, public reachability or a live handshake.
type StagedReadback struct {
	Revision       int64
	ConfigSHA256   string
	OperationID    string
	TargetVersion  string
	ManifestSHA256 string
	PolicySchema   int
	Derived        bool
}

// stagedReadbacks returns the newest healthy stage per node. A row carrying a
// persisted upgrade target is the formal record; an empty target falls back to
// the #11a derivation and is labelled. An undecodable row is an error, never a
// guessed revision.
func (s *Store) StagedReadbacks() (map[string]StagedReadback, error) {
	rows, err := s.DB.Query(`SELECT t.node_id, t.operation_id, t.params, t.target_version,
 t.target_manifest_sha256, t.policy_schema, t.target_revision FROM agent_tasks t
WHERE t.kind=? AND t.status='healthy' AND t.revision=(SELECT MAX(x.revision) FROM agent_tasks x
 WHERE x.node_id=t.node_id AND x.kind=? AND x.status='healthy')`, protocol.KindConfigStage, protocol.KindConfigStage)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	type pending struct {
		nodeID string
		staged StagedReadback
	}
	var found []pending
	for rows.Next() {
		var row pending
		var params, targetVersion, manifest string
		var policySchema, targetRevision int64
		if err := rows.Scan(&row.nodeID, &row.staged.OperationID, &params, &targetVersion,
			&manifest, &policySchema, &targetRevision); err != nil {
			rows.Close()
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		var revision struct {
			Revision int64 `json:"revision"`
		}
		if err := json.Unmarshal([]byte(params), &revision); err != nil || revision.Revision < 1 {
			rows.Close()
			return nil, errors.New("STAGED_READBACK_CORRUPT: the stage task has no candidate revision")
		}
		row.staged.Revision = revision.Revision
		if targetVersion == "" {
			// No formal record: keep the pre-#11b derivation and label it.
			if manifest != "" || policySchema != 0 || targetRevision != 0 {
				rows.Close()
				return nil, errors.New("UPGRADE_RECORD_CORRUPT: the upgrade target is incomplete")
			}
			row.staged.Derived = true
		} else {
			target := upgrade.Target{Version: targetVersion, ManifestSHA256: manifest,
				PolicySchema: int(policySchema), CandidateRevision: targetRevision}
			if err := target.Validate(); err != nil || targetRevision != revision.Revision {
				rows.Close()
				return nil, errUpgradeRecordCorrupt
			}
			row.staged.TargetVersion = targetVersion
			row.staged.ManifestSHA256 = manifest
			row.staged.PolicySchema = int(policySchema)
		}
		found = append(found, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	// The store holds one connection: the candidate digest is read only after
	// the task rows are drained and closed.
	if err := rows.Close(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	out := make(map[string]StagedReadback, len(found))
	for _, row := range found {
		staged := row.staged
		if err := s.DB.QueryRow(`SELECT config_sha256 FROM node_candidates WHERE node_id=? AND revision=?`,
			row.nodeID, staged.Revision).Scan(&staged.ConfigSHA256); err != nil {
			return nil, errors.New("STAGED_READBACK_CORRUPT: the staged candidate revision is missing")
		}
		out[row.nodeID] = staged
	}
	return out, nil
}
