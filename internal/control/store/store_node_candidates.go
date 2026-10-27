package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

const initialCandidateRevision int64 = 1

type storedCandidate struct {
	Revision     int64
	Document     node.CandidateDocument
	JSON         []byte
	ConfigSHA256 string
}

func CandidateSHA256(document []byte) (string, error) {
	var parsed node.CandidateDocument
	if err := json.Unmarshal(document, &parsed); err != nil {
		return "", errors.New("CANDIDATE_INVALID")
	}
	compiled, err := node.CompileCandidate(parsed.Candidate())
	if err != nil {
		return "", common.ErrCandidateRenderFailed
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
		if err := InsertCandidateTx(tx, candidate, n.created); err != nil {
			return err
		}
	}
	return nil
}

func InsertCandidateTx(tx *sql.Tx, candidate node.Candidate, now int64) error {
	if err := candidate.Validate(); err != nil {
		return errors.New("CANDIDATE_INVALID")
	}
	document, err := json.Marshal(node.NewCandidateDocument(candidate))
	if err != nil {
		return common.ErrCandidateRenderFailed
	}
	hash, err := CandidateSHA256(document)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO node_candidates(node_id, revision, candidate_json, config_sha256, created_at) VALUES(?,?,?,?,?)`,
		candidate.NodeID, candidate.Revision, document, hash, now); err != nil {
		return errors.New("CANDIDATE_CREATE_FAILED")
	}
	return nil
}

func (s *Store) Candidate(nodeID string, revision int64) (storedCandidate, error) {
	if revision < 1 {
		return storedCandidate{}, errors.New("REVISION_INVALID")
	}
	var c storedCandidate
	c.Revision = revision
	err := s.DB.QueryRow(`SELECT candidate_json, config_sha256 FROM node_candidates WHERE node_id=? AND revision=?`, nodeID, revision).Scan(&c.JSON, &c.ConfigSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, common.ErrCandidateNotFound
	}
	if err != nil {
		return storedCandidate{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if string(c.JSON) != string(bytes.TrimSpace(c.JSON)) || len(c.JSON) == 0 {
		return storedCandidate{}, common.ErrCandidateCorrupt
	}
	if err := json.Unmarshal(c.JSON, &c.Document); err != nil {
		return storedCandidate{}, common.ErrCandidateCorrupt
	}
	if c.Document.Revision != revision {
		return storedCandidate{}, common.ErrCandidateCorrupt
	}
	hash, err := CandidateSHA256(c.JSON)
	if err != nil || hash != c.ConfigSHA256 {
		return storedCandidate{}, common.ErrCandidateCorrupt
	}
	return c, nil
}

func (s *Store) LatestCandidate(nodeID string) (storedCandidate, error) {
	var revision sql.NullInt64
	err := s.DB.QueryRow(`SELECT MAX(revision) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision)
	if err != nil {
		return storedCandidate{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if !revision.Valid {
		return storedCandidate{}, common.ErrCandidateNotFound
	}
	return s.Candidate(nodeID, revision.Int64)
}

// publishCandidateTx stores one immutable candidate revision and the fixed
// four task chain in the caller's transaction.
//
// It is the single publication path of the control plane: the manual reconcile
// and the subscriber synchronization both use it, so one Line never carries
// two chains at the same time. The caller owns the transaction, so a failure
// rolls the candidate and the chain back together.
//
// Every config task of an Out candidate carries allowed_sources, and an Out
// without an authorized source carries an explicit empty array rather than an
// omitted key. The Agent treats a missing key as "no Hub expectation" and
// degrades its readback to a shape-only check; omitting the key would therefore
// hide a missing authorization behind a healthy-looking guard. An empty array
// means "authorized for nothing", which is exactly the fail-closed state the
// Hub wants when no Line is bound.
//
// An Edge candidate never carries the key: its allowlist is meaningless there
// and the Agent renders no Out table.
func publishCandidateTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time) ([]protocol.Task, error) {
	if err := InsertCandidateTx(tx, candidate, now.Unix()); err != nil {
		return nil, err
	}
	params, err := candidateTaskParamsTx(tx, candidate)
	if err != nil {
		return nil, err
	}
	taskRevision, err := taskRevisionAfter(tx, nodeID)
	if err != nil {
		return nil, err
	}
	tasks := make([]protocol.Task, 0, 4)
	for _, kind := range protocol.PublicationKinds {
		task, err := NewFixedTask(nodeID, kind, params, taskRevision)
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

// insertCandidateWithAllowlistTx publishes one candidate whose task chain carries an
// explicitly supplied allowlist.
//
// It exists for the delete path (Ruling R9): the last chain an Out ever publishes must
// authorize NOTHING, and the ordinary publication derives the current membership — which
// still includes every Line while the node row exists. Passing the empty set is the only
// way to express "this host must end in default-deny", and it goes through the same
// four-task chain, the same params envelope and the same immutability as every other
// revision, so the Agent cannot tell the two apart.
//
// The allowlist is not derived here: a caller that cannot name the set explicitly must use
// publishCandidateTx.
func insertCandidateWithAllowlistTx(tx *sql.Tx, nodeID string, candidate node.Candidate, allowed []string, now time.Time) error {
	if err := InsertCandidateTx(tx, candidate, now.Unix()); err != nil {
		return err
	}
	if allowed == nil {
		allowed = []string{}
	}
	params, err := json.Marshal(struct {
		Revision       int64    `json:"revision"`
		AllowedSources []string `json:"allowed_sources"`
	}{Revision: candidate.Revision, AllowedSources: allowed})
	if err != nil {
		return common.ErrCandidateRenderFailed
	}
	taskRevision, err := taskRevisionAfter(tx, nodeID)
	if err != nil {
		return err
	}
	for _, kind := range protocol.PublicationKinds {
		task, err := NewFixedTask(nodeID, kind, params, taskRevision)
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

// reconcileNode publishes one immutable revision and the fixed four task chain
// in a single transaction. Callers cannot supply kinds or params.
//
// A Line with stored transport settings publishes the full snapshot, so a
// manual reconcile never erases the credentials of another subscriber. A node
// without Line settings keeps the frozen v1 baseline and the Out behavior is
// unchanged.
func (s *Store) ReconcileNode(nodeID string, now time.Time) (storedCandidate, []protocol.Task, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return storedCandidate{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	var vless int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, nodeID).Scan(&role, &vless)
	if errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, nil, common.ErrNodeNotFound
	}
	if err != nil {
		return storedCandidate{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(node.RoleHTTP) {
		// An external HTTP proxy has no Agent, candidate or readback; a
		// reconcile would have nowhere to go (Ruling R11).
		return storedCandidate{}, nil, errors.New("NODE_ROLE_INVALID: an external http proxy has no agent candidate")
	}
	var unfinished int
	if err = tx.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished); err != nil {
		return storedCandidate{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if unfinished != 0 {
		return storedCandidate{}, nil, errors.New("TASKS_IN_PROGRESS")
	}
	var revision int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return storedCandidate{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	candidate, err := BuildLineCandidateTx(tx, nodeID, revision)
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
		return storedCandidate{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	stored, err := s.Candidate(nodeID, candidate.Revision)
	if err != nil {
		return storedCandidate{}, nil, fmt.Errorf("CANDIDATE_READBACK_FAILED: %w", err)
	}
	return stored, tasks, nil
}

// candidateTaskParamsTx builds the params envelope of one candidate chain.
//
// An Out candidate always names its source authorization, including the empty
// one, because the Agent distinguishes "no expectation" (omitted) from
// "authorized for nothing" (explicit empty array). Anything that fails to derive
// the Out authorization aborts the publication: publishing a chain whose guard
// cannot be verified would report a health the Hub does not have.
func candidateTaskParamsTx(tx *sql.Tx, candidate node.Candidate) (json.RawMessage, error) {
	if candidate.Role != node.RoleOut {
		return json.Marshal(map[string]int64{"revision": candidate.Revision})
	}
	allowed, err := outAuthorizationTx(tx, candidate.NodeID)
	if err != nil {
		return nil, err
	}
	if allowed == nil {
		allowed = []string{}
	}
	return json.Marshal(struct {
		Revision       int64    `json:"revision"`
		AllowedSources []string `json:"allowed_sources"`
	}{Revision: candidate.Revision, AllowedSources: allowed})
}

// taskRevisionAfter returns the next per-node task revision.
func taskRevisionAfter(tx *sql.Tx, nodeID string) (int64, error) {
	var revision sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(revision) FROM agent_tasks WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	if revision.Valid {
		return revision.Int64 + 1, nil
	}
	return 1, nil
}

func NewFixedTask(nodeID, kind string, params json.RawMessage, revision int64) (protocol.Task, error) {
	operationID, err := protocol.NewID()
	if err != nil {
		return protocol.Task{}, errors.New("OPERATION_ID_FAILED")
	}
	return protocol.Task{
		Schema:         protocol.Schema,
		Version:        protocol.Version,
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
func SeedInitialTasksTx(tx *sql.Tx, nodeID string, now time.Time) error {
	candidate, err := candidateTx(tx, nodeID)
	if err != nil {
		return err
	}
	var unfinished int
	if err := tx.QueryRow(`SELECT count(*) FROM agent_tasks
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if unfinished != 0 {
		return nil
	}
	// The seeded chain uses the same params envelope as any later publication,
	// so an Out that was paired before its binding existed still starts with an
	// explicit empty authorization instead of an omitted key.
	params, err := candidateTaskParamsTx(tx, candidate.Document.Candidate())
	if err != nil {
		return err
	}
	taskRevision, err := taskRevisionAfter(tx, nodeID)
	if err != nil {
		return err
	}
	for _, kind := range protocol.PublicationKinds {
		task, err := NewFixedTask(nodeID, kind, params, taskRevision)
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
		return storedCandidate{}, common.ErrCandidateNotFound
	}
	if err != nil {
		return storedCandidate{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := json.Unmarshal(c.JSON, &c.Document); err != nil || c.Document.Revision != c.Revision {
		return storedCandidate{}, common.ErrCandidateCorrupt
	}
	return c, nil
}
