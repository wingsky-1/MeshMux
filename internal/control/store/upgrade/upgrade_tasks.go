package upgrade

// Persistence of #11b upgrade task records. The record is not a new table: the
// existing agent_tasks row that carries the fixed chain gains the target release
// columns, so the same polling pull and revision space stay authoritative.
// #11c-1 added the HTTP write path (POST /tasks/approve) and agent read
// (GET /api/agent/upgrade-target/{operation_id}); both funnel through
// StampUpgradeTargetTx, which an approval calls in the same transaction as the
// chain it stamps. Upgrade kinds are still rejected by protocol.ValidateTask, so
// no upgrade.* row can be dispatched.

import (
	"database/sql"
	"errors"
	"time"

	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"

	storecandidate "github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// purely additive and defaults every existing row to "no target record". Fixtures
// that replay an older user_version already carry these columns, so only missing
// ones are added instead of failing on a duplicate column.
// MigrateSchema9 adds the target release snapshot to existing task rows.
func MigrateSchema9(tx *sql.Tx) error {
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

// StampUpgradeTargetTx attaches one release record to a pending config.stage row,
// the row /tasks reads as the formal staged evidence. The target is validated in
// the jobs domain before storage; the caller supplies no shell, path or URL, and
// re-stamping is allowed only before any result exists.
//
// It runs inside the caller's transaction because the approval path enqueues the
// chain and stamps its stage row together: the first Agent poll can never see a
// pending row without its target. There is deliberately no non-transactional
// twin, so no future caller can split the two writes.
func StampUpgradeTargetTx(tx *sql.Tx, operationID string, target coredomain.Target, now time.Time) error {
	if err := coredomain.ValidateOperationID(operationID); err != nil {
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
		return errors.New(common.CodeDatabaseUnavailable)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
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
func (s *Store) ApprovedTargets() (map[string]ApprovedTarget, error) {
	rows, err := s.DB.Query(`SELECT node_id, target_version, target_manifest_sha256,
 policy_schema, target_revision, operation_id, status FROM agent_tasks
 WHERE target_version<>'' ORDER BY node_id ASC, revision DESC`)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := make(map[string]ApprovedTarget)
	for rows.Next() {
		var nodeID string
		var target ApprovedTarget
		if err := rows.Scan(&nodeID, &target.Version, &target.ManifestSHA256,
			&target.PolicySchema, &target.Revision, &target.OperationID, &target.Status); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		if _, seen := out[nodeID]; !seen {
			out[nodeID] = target
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}

// stampedStageTarget reads the persisted target of one stage row regardless of
// its status. The Agent polls the row after the Hub may already have moved it
// on, so a pending-only read would lose the stamp; an unstamped row is simply
// not an upgrade.
func (s *Store) StampedStageTarget(nodeID, operationID string) (coredomain.Target, bool, error) {
	var target coredomain.Target
	var version, manifest string
	var policySchema int64
	err := s.DB.QueryRow(`SELECT target_version, target_manifest_sha256, policy_schema, target_revision
 FROM agent_tasks WHERE operation_id=? AND node_id=? AND kind=?`,
		operationID, nodeID, protocol.KindConfigStage).Scan(&version, &manifest, &policySchema, &target.CandidateRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.Target{}, false, nil
	}
	if err != nil {
		return coredomain.Target{}, false, errors.New(common.CodeDatabaseUnavailable)
	}
	if version == "" {
		return coredomain.Target{}, false, nil
	}
	target.Version, target.ManifestSHA256, target.PolicySchema = version, manifest, int(policySchema)
	if err := target.Validate(); err != nil {
		return coredomain.Target{}, false, common.ErrUpgradeRecordCorrupt
	}
	return target, true, nil
}

// ApprovedUpgrade is one stored approval.
type ApprovedUpgrade struct {
	coredomain.Target
	StageOperationID string
	Tasks            []string
}

// approveUpgrade is the single write path of an approval. Everything happens in
// one transaction: the new candidate revision, the fixed chain and the stamp.
func (s *Store) ApproveUpgrade(nodeID string, manifest coredomain.Manifest, manifestSHA string, now time.Time) (ApprovedUpgrade, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return ApprovedUpgrade{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var observed string
	if err = tx.QueryRow(`SELECT observed_agent_version FROM nodes WHERE id=?`, nodeID).Scan(&observed); errors.Is(err, sql.ErrNoRows) {
		return ApprovedUpgrade{}, common.ErrNodeNotFound
	} else if err != nil {
		return ApprovedUpgrade{}, errors.New(common.CodeDatabaseUnavailable)
	}
	// Without a read-back version the Hub cannot prove which candidate schema
	// this node consumes, so it refuses instead of guessing. This is the same
	// rule the page applies by not offering the control.
	if observed == "" {
		return ApprovedUpgrade{}, errors.New("UPGRADE_AGENT_UNOBSERVED: the node has no read-back Agent version")
	}
	// Single flight: an unfinished chain owns the node, so a second approval
	// would replace work in progress. Checked inside the write transaction.
	var unfinished int
	if err = tx.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying')`,
		nodeID).Scan(&unfinished); err != nil {
		return ApprovedUpgrade{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if unfinished != 0 {
		return ApprovedUpgrade{}, errors.New("TASKS_IN_PROGRESS: the node has an unfinished task chain")
	}
	// Adjacency: the ordered history is the approved 11b chain (ruling U5), and
	// the current version is the node's own read-back — never
	// node.CurrentAgentVersion, which would never match a real release history.
	//
	// The Hub can only pin its own build, so at most one target is offerable at
	// a time; the rules below still matter because they refuse a chain that
	// disagrees with the read-back and they refuse a skip as soon as the history
	// names more than one release.
	history, err := ApprovedReleaseChainTx(tx, nodeID)
	if err != nil {
		return ApprovedUpgrade{}, err
	}
	if manifest.Version == observed {
		// A node already on the running build. 11d lifts the *newer* target
		// refusal; it does not change this branch.
		return ApprovedUpgrade{}, errors.New("UPGRADE_ALREADY_CURRENT: the node already runs the approved release")
	}
	if len(history) > 0 {
		current := history[len(history)-1]
		switch {
		case current == manifest.Version:
			// Retrying a release whose chain failed: the previous chain is
			// terminal (TASKS_IN_PROGRESS already cleared it), so a new attempt
			// is allowed and stays auditable as its own revision.
		case current != observed:
			return ApprovedUpgrade{}, errors.New(CodeUpgradeNotAdjacent +
				": the node reports a version the approved chain never named")
		default:
			chain := append(append([]string(nil), history...), manifest.Version)
			if err := coredomain.AdjacentRelease(chain, current, manifest.Version); err != nil {
				return ApprovedUpgrade{}, err
			}
		}
	}
	revision, err := storecandidate.NextCandidateRevisionTx(tx, nodeID)
	if err != nil {
		return ApprovedUpgrade{}, err
	}
	candidate, err := storenode.BuildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return ApprovedUpgrade{}, err
	}
	// An approval must not silently drop the route the live policy resolves for
	// this node, and it must not resurrect one the policy no longer justifies:
	// the route is re-derived from the active server revision and the current
	// Out facts, exactly like a policy publication. An Out that was unbound,
	// deleted or went offline therefore invalidates the old route instead of
	// being republished by an upgrade, and a policy that selects it fails closed
	// here with the policy package's own code.
	serverRoute, err := s.Policies.LineServerRouteTx(tx, nodeID, now)
	if err != nil {
		return ApprovedUpgrade{}, err
	}
	candidate.Route = serverRoute
	if err := MixedVersionGate(candidate, observed); err != nil {
		return ApprovedUpgrade{}, err
	}
	var tasks []protocol.Task
	if candidate.Role == node.RoleOut {
		allowed, authErr := storenode.OutAuthorizationTx(tx, nodeID)
		if authErr != nil {
			return ApprovedUpgrade{}, authErr
		}
		tasks, err = storecandidate.PublishOutTx(tx, nodeID, candidate, now, allowed)
	} else {
		tasks, err = storecandidate.PublishTx(tx, nodeID, candidate, now)
	}
	if err != nil {
		return ApprovedUpgrade{}, err
	}
	stageOperation := ""
	for _, task := range tasks {
		if task.Kind == protocol.KindConfigStage {
			stageOperation = task.OperationID
		}
	}
	if stageOperation == "" {
		return ApprovedUpgrade{}, errors.New("UPGRADE_CHAIN_INVALID: the fixed chain has no stage step")
	}
	target := coredomain.Target{Version: manifest.Version, ManifestSHA256: manifestSHA,
		PolicySchema: manifest.PolicySchema, CandidateRevision: revision}
	// Same transaction as the enqueue: the first poll can never see an
	// unstamped pending row.
	if err := StampUpgradeTargetTx(tx, stageOperation, target, now); err != nil {
		return ApprovedUpgrade{}, err
	}
	if err := tx.Commit(); err != nil {
		return ApprovedUpgrade{}, errors.New(common.CodeDatabaseUnavailable)
	}
	out := ApprovedUpgrade{Target: target, StageOperationID: stageOperation}
	for _, task := range tasks {
		out.Tasks = append(out.Tasks, task.Kind)
	}
	return out, nil
}

// Stable approval refusals produced by the store write path. The handler maps
// them onto HTTP statuses; the codes themselves are owned here, next to the
// gate that produces them.
const (
	// CodeUpgradeNotAdjacent: the target is not the immediate successor of the
	// node's approved chain; a skipped release would make rollback an
	// unverified N-2.
	CodeUpgradeNotAdjacent = "UPGRADE_NOT_ADJACENT"
	// CodeUpgradeAgentIncompatible: the node's read-back Agent version cannot
	// consume the candidate this target would publish. The Hub refuses instead
	// of forcing a mixed-version fleet.
	CodeUpgradeAgentIncompatible = "UPGRADE_AGENT_INCOMPATIBLE"
)

// ApprovedReleaseChainTx is the transaction-scoped ordered history of the
// versions this node was approved for. Consecutive duplicates collapse, so a
// re-approval never fakes an extra release.
func ApprovedReleaseChainTx(tx *sql.Tx, nodeID string) ([]string, error) {
	rows, err := tx.Query(`SELECT target_version FROM agent_tasks
 WHERE node_id=? AND target_version<>'' ORDER BY revision ASC, updated_at ASC`, nodeID)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	var history []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		if len(history) == 0 || history[len(history)-1] != version {
			history = append(history, version)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return history, nil
}

// MixedVersionGate refuses to publish a candidate the node's read-back Agent
// version cannot consume. A v3 document (one carrying a resolved route) needs a
// node that already reports this build; an unknown version counts as unable. A
// v1/v2 document stays publishable to an older fleet, so a mixed-version fleet
// keeps proxying instead of being force-upgraded.
func MixedVersionGate(candidate node.Candidate, observed string) error {
	if len(candidate.Route) == 0 {
		return nil
	}
	if observed != node.CurrentAgentVersion() {
		return errors.New(CodeUpgradeAgentIncompatible + ": the node cannot consume a v3 candidate")
	}
	return nil
}
