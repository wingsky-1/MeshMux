package web

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wingsky-1/MeshMux/internal/agent"
	"github.com/wingsky-1/MeshMux/internal/node"
)

const initialCandidateRevision int64 = 1

type storedCandidate struct {
	Revision     int64
	Document     node.CandidateDocument
	JSON         []byte
	ConfigSHA256 string
}

func candidateSHA256(document []byte) (string, error) {
	var parsed node.CandidateDocument
	if err := json.Unmarshal(document, &parsed); err != nil {
		return "", errors.New("CANDIDATE_INVALID")
	}
	compiled, err := node.CompileCandidate(parsed.Candidate())
	if err != nil {
		return "", errors.New("CANDIDATE_RENDER_FAILED")
	}
	sum := sha256.Sum256(compiled)
	return hex.EncodeToString(sum[:]), nil
}

// migrateSchema3 is the one explicit upgrade to the candidate/readback model.
// It intentionally does not introduce a general migration framework.
func migrateSchema3(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE node_candidates (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL CHECK(revision > 0),
  candidate_json BLOB NOT NULL,
  config_sha256 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(node_id, revision)
);
CREATE INDEX node_candidates_latest ON node_candidates(node_id, revision DESC);
CREATE TRIGGER node_candidates_immutable_update BEFORE UPDATE ON node_candidates BEGIN
  SELECT RAISE(ABORT, 'CANDIDATE_IMMUTABLE');
END;
CREATE TRIGGER node_candidates_immutable_delete BEFORE DELETE ON node_candidates BEGIN
  SELECT RAISE(ABORT, 'CANDIDATE_IMMUTABLE');
END;
ALTER TABLE agent_tasks ADD COLUMN detail TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN observed_config_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_architecture TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_agent_version TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_agent_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_kernel_version TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_kernel_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN observed_out_default_deny INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN observed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN observed_task_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN observed_task_operation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN last_success_at INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version=3;
`); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id, role, vless_port, created_at FROM nodes ORDER BY created_at`)
	if err != nil {
		return err
	}
	type legacyNode struct {
		id      string
		role    string
		port    int
		created int64
	}
	var legacy []legacyNode
	for rows.Next() {
		var n legacyNode
		if err := rows.Scan(&n.id, &n.role, &n.port, &n.created); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, n)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range legacy {
		candidate := node.Candidate{
			NodeID:        n.id,
			Role:          node.Role(n.role),
			Revision:      initialCandidateRevision,
			VLESSPort:     n.port,
			KernelVersion: node.KernelVersion,
		}
		if err := insertCandidateTx(tx, candidate, n.created); err != nil {
			return err
		}
	}
	return nil
}

func insertCandidateTx(tx *sql.Tx, candidate node.Candidate, now int64) error {
	if err := candidate.Validate(); err != nil {
		return errors.New("CANDIDATE_INVALID")
	}
	document, err := json.Marshal(node.NewCandidateDocument(candidate))
	if err != nil {
		return errors.New("CANDIDATE_RENDER_FAILED")
	}
	hash, err := candidateSHA256(document)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO node_candidates(node_id, revision, candidate_json, config_sha256, created_at) VALUES(?,?,?,?,?)`,
		candidate.NodeID, candidate.Revision, document, hash, now); err != nil {
		return errors.New("CANDIDATE_CREATE_FAILED")
	}
	return nil
}

func (s *store) candidate(nodeID string, revision int64) (storedCandidate, error) {
	if revision < 1 {
		return storedCandidate{}, errors.New("REVISION_INVALID")
	}
	var c storedCandidate
	c.Revision = revision
	err := s.db.QueryRow(`SELECT candidate_json, config_sha256 FROM node_candidates WHERE node_id=? AND revision=?`, nodeID, revision).Scan(&c.JSON, &c.ConfigSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, errors.New("CANDIDATE_NOT_FOUND")
	}
	if err != nil {
		return storedCandidate{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if string(c.JSON) != string(bytes.TrimSpace(c.JSON)) || len(c.JSON) == 0 {
		return storedCandidate{}, errors.New("CANDIDATE_CORRUPT")
	}
	if err := json.Unmarshal(c.JSON, &c.Document); err != nil {
		return storedCandidate{}, errors.New("CANDIDATE_CORRUPT")
	}
	if c.Document.Revision != revision {
		return storedCandidate{}, errors.New("CANDIDATE_CORRUPT")
	}
	hash, err := candidateSHA256(c.JSON)
	if err != nil || hash != c.ConfigSHA256 {
		return storedCandidate{}, errors.New("CANDIDATE_CORRUPT")
	}
	return c, nil
}

func (s *store) latestCandidate(nodeID string) (storedCandidate, error) {
	var revision sql.NullInt64
	err := s.db.QueryRow(`SELECT MAX(revision) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision)
	if err != nil {
		return storedCandidate{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if !revision.Valid {
		return storedCandidate{}, errors.New("CANDIDATE_NOT_FOUND")
	}
	return s.candidate(nodeID, revision.Int64)
}

// publishCandidateTx stores one immutable candidate revision and the fixed
// four task chain in the caller's transaction.
//
// It is the single publication path of the control plane: the manual reconcile
// and the subscriber synchronization both use it, so one Line never carries
// two chains at the same time. The caller owns the transaction, so a failure
// rolls the candidate and the chain back together.
func publishCandidateTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time) ([]agent.Task, error) {
	if err := insertCandidateTx(tx, candidate, now.Unix()); err != nil {
		return nil, err
	}
	params, _ := json.Marshal(map[string]int64{"revision": candidate.Revision})
	taskRevision, err := taskRevisionAfter(tx, nodeID)
	if err != nil {
		return nil, err
	}
	tasks := make([]agent.Task, 0, 4)
	for _, kind := range []string{agent.KindConfigCheck, agent.KindConfigStage, agent.KindConfigApply, agent.KindConfigReadback} {
		task, err := newFixedTask(nodeID, kind, params, taskRevision)
		if err != nil {
			return nil, err
		}
		if err := enqueueTaskTx(tx, task, now); err != nil {
			return nil, err
		}
		taskRevision++
		tasks = append(tasks, task)
	}
	return tasks, nil
}

// reconcileNode publishes one immutable revision and the fixed four task chain
// in a single transaction. Callers cannot supply kinds or params.
//
// A Line with stored transport settings publishes the full snapshot, so a
// manual reconcile never erases the credentials of another subscriber. A node
// without Line settings keeps the frozen v1 baseline and the Out behavior is
// unchanged.
func (s *store) reconcileNode(nodeID string, now time.Time) (storedCandidate, []agent.Task, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return storedCandidate{}, nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	var vless int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, nodeID).Scan(&role, &vless)
	if errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, nil, errors.New("NODE_NOT_FOUND")
	}
	if err != nil {
		return storedCandidate{}, nil, errors.New("DATABASE_UNAVAILABLE")
	}
	var unfinished int
	if err = tx.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished); err != nil {
		return storedCandidate{}, nil, errors.New("DATABASE_UNAVAILABLE")
	}
	if unfinished != 0 {
		return storedCandidate{}, nil, errors.New("TASKS_IN_PROGRESS")
	}
	var revision int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return storedCandidate{}, nil, errors.New("DATABASE_UNAVAILABLE")
	}
	candidate, err := buildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return storedCandidate{}, nil, err
	}
	if candidate.Role != node.Role(role) || candidate.VLESSPort != vless {
		return storedCandidate{}, nil, errors.New("CANDIDATE_MISMATCH: candidate does not match the node")
	}
	tasks, err := publishCandidateTx(tx, nodeID, candidate, now)
	if err != nil {
		return storedCandidate{}, nil, err
	}
	if err = tx.Commit(); err != nil {
		return storedCandidate{}, nil, errors.New("DATABASE_UNAVAILABLE")
	}
	stored, err := s.candidate(nodeID, candidate.Revision)
	if err != nil {
		return storedCandidate{}, nil, fmt.Errorf("CANDIDATE_READBACK_FAILED: %w", err)
	}
	return stored, tasks, nil
}

func taskRevisionAfter(tx *sql.Tx, nodeID string) (int64, error) {
	var revision sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(revision) FROM agent_tasks WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New("DATABASE_UNAVAILABLE")
	}
	if revision.Valid {
		return revision.Int64 + 1, nil
	}
	return 1, nil
}

func newFixedTask(nodeID, kind string, params json.RawMessage, revision int64) (agent.Task, error) {
	operationID, err := agent.NewID()
	if err != nil {
		return agent.Task{}, errors.New("OPERATION_ID_FAILED")
	}
	return agent.Task{
		Schema:         agent.Schema,
		Version:        agent.Version,
		OperationID:    operationID,
		Revision:       revision,
		IdempotencyKey: operationID,
		NodeID:         nodeID,
		Kind:           kind,
		Params:         append(json.RawMessage(nil), params...),
	}, nil
}

// seedInitialTasksTx enqueues the fixed reconcile chain for the latest initial
// candidate. Pairing calls this only after identity insertion succeeds. The
// caller's clock is the same one that stamped the pairing identity.
func seedInitialTasksTx(tx *sql.Tx, nodeID string, now time.Time) error {
	candidate, err := candidateTx(tx, nodeID)
	if err != nil {
		return err
	}
	var unfinished int
	if err := tx.QueryRow(`SELECT count(*) FROM agent_tasks
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if unfinished != 0 {
		return nil
	}
	params, _ := json.Marshal(map[string]int64{"revision": candidate.Revision})
	taskRevision, err := taskRevisionAfter(tx, nodeID)
	if err != nil {
		return err
	}
	for _, kind := range []string{agent.KindConfigCheck, agent.KindConfigStage, agent.KindConfigApply, agent.KindConfigReadback} {
		task, err := newFixedTask(nodeID, kind, params, taskRevision)
		if err != nil {
			return err
		}
		if err := enqueueTaskTx(tx, task, now); err != nil {
			return err
		}
		taskRevision++
	}
	return nil
}

func candidateTx(tx *sql.Tx, nodeID string) (storedCandidate, error) {
	var c storedCandidate
	err := tx.QueryRow(`SELECT revision, candidate_json, config_sha256 FROM node_candidates WHERE node_id=? ORDER BY revision DESC LIMIT 1`, nodeID).Scan(&c.Revision, &c.JSON, &c.ConfigSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, errors.New("CANDIDATE_NOT_FOUND")
	}
	if err != nil {
		return storedCandidate{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err := json.Unmarshal(c.JSON, &c.Document); err != nil || c.Document.Revision != c.Revision {
		return storedCandidate{}, errors.New("CANDIDATE_CORRUPT")
	}
	return c, nil
}
