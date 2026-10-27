package candidate

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// InitialRevision is the revision of the baseline candidate a new node carries.
const InitialRevision int64 = 1

// Stored is one immutable candidate revision as it was persisted: the parsed
// document, its raw bytes and the digest of the compiled kernel configuration.
type Stored struct {
	Revision     int64
	Document     node.CandidateDocument
	JSON         []byte
	ConfigSHA256 string
}

// SHA256 returns the digest of the compiled kernel configuration of one
// candidate document. The document is parsed and compiled first, so the digest
// is always derived from bytes the Agent could run.
func SHA256(document []byte) (string, error) {
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

// MigrateSchema3 is the one explicit upgrade to the candidate/readback model.
func MigrateSchema3(tx *sql.Tx) error {
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
			Revision:      InitialRevision,
			VLESSPort:     n.port,
			KernelVersion: node.KernelVersion,
		}
		if err := InsertTx(tx, candidate, n.created); err != nil {
			return err
		}
	}
	return nil
}

func InsertTx(tx *sql.Tx, candidate node.Candidate, now int64) error {
	if err := candidate.Validate(); err != nil {
		return errors.New("CANDIDATE_INVALID")
	}
	document, err := json.Marshal(node.NewCandidateDocument(candidate))
	if err != nil {
		return common.ErrCandidateRenderFailed
	}
	hash, err := SHA256(document)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO node_candidates(node_id, revision, candidate_json, config_sha256, created_at) VALUES(?,?,?,?,?)`,
		candidate.NodeID, candidate.Revision, document, hash, now); err != nil {
		return errors.New("CANDIDATE_CREATE_FAILED")
	}
	return nil
}

func (s *Store) Candidate(nodeID string, revision int64) (Stored, error) {
	if revision < 1 {
		return Stored{}, errors.New("REVISION_INVALID")
	}
	var c Stored
	c.Revision = revision
	err := s.DB.QueryRow(`SELECT candidate_json, config_sha256 FROM node_candidates WHERE node_id=? AND revision=?`, nodeID, revision).Scan(&c.JSON, &c.ConfigSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return Stored{}, common.ErrCandidateNotFound
	}
	if err != nil {
		return Stored{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if string(c.JSON) != string(bytes.TrimSpace(c.JSON)) || len(c.JSON) == 0 {
		return Stored{}, common.ErrCandidateCorrupt
	}
	if err := json.Unmarshal(c.JSON, &c.Document); err != nil {
		return Stored{}, common.ErrCandidateCorrupt
	}
	if c.Document.Revision != revision {
		return Stored{}, common.ErrCandidateCorrupt
	}
	hash, err := SHA256(c.JSON)
	if err != nil || hash != c.ConfigSHA256 {
		return Stored{}, common.ErrCandidateCorrupt
	}
	return c, nil
}

func (s *Store) LatestCandidate(nodeID string) (Stored, error) {
	var revision sql.NullInt64
	err := s.DB.QueryRow(`SELECT MAX(revision) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision)
	if err != nil {
		return Stored{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if !revision.Valid {
		return Stored{}, common.ErrCandidateNotFound
	}
	return s.Candidate(nodeID, revision.Int64)
}

// PublishTx stores one immutable candidate revision and the fixed
// four task chain in the caller's transaction.
//
// It is the single publication path of the control plane and handles every
// role: the manual reconcile, the subscriber synchronization and the Out
// lifecycle all use it, so one node never carries two chains at the same time.
// The caller owns the transaction, so a failure rolls the candidate and the
// chain back together.
//
// The task envelope carries only the revision. The retired source allowlist is
// not republished: an Out admits clients by the link key its own candidate
// carries, so there is no `allowed_sources` key to send and the Agent's guard is
// no longer an authorization input.
func PublishTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time) ([]protocol.Task, error) {
	return publishChainTx(tx, nodeID, candidate, now)
}

// publishChainTx stores one immutable revision and enqueues the fixed four-task
// chain in the caller's transaction.
func publishChainTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time) ([]protocol.Task, error) {
	if err := InsertTx(tx, candidate, now.Unix()); err != nil {
		return nil, err
	}
	params, err := taskParams(candidate)
	if err != nil {
		return nil, err
	}
	taskRevision, err := TaskRevisionAfter(tx, nodeID)
	if err != nil {
		return nil, err
	}
	tasks := make([]protocol.Task, 0, 4)
	for _, kind := range protocol.PublicationKinds {
		task, err := NewFixedTask(nodeID, kind, params, taskRevision)
		if err != nil {
			return nil, err
		}
		if err := EnqueueTx(tx, task, now); err != nil {
			return nil, err
		}
		taskRevision++
		tasks = append(tasks, task)
	}
	return tasks, nil
}

// taskParams builds the params envelope of one candidate chain: the revision,
// and nothing else. The retired `allowed_sources` key is deliberately absent for
// every role; an old Agent degrades its readback to a shape-only check instead
// of comparing an authorization the Hub no longer maintains.
func taskParams(candidate node.Candidate) (json.RawMessage, error) {
	return json.Marshal(map[string]int64{"revision": candidate.Revision})
}

// NextCandidateRevisionTx returns the next immutable revision of one node.
func NextCandidateRevisionTx(tx *sql.Tx, nodeID string) (int64, error) {
	var revision int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	return revision, nil
}

// TaskRevisionAfter returns the next per-node task revision.
func TaskRevisionAfter(tx *sql.Tx, nodeID string) (int64, error) {
	var revision sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(revision) FROM agent_tasks WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	if revision.Valid {
		return revision.Int64 + 1, nil
	}
	return 1, nil
}

// NewFixedTask builds one task envelope of the fixed publication chain.
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

// SeedInitialTasksTx enqueues the fixed reconcile chain for the latest initial
// candidate. Pairing calls this only after identity insertion succeeds. The
// caller's clock is the same one that stamped the pairing identity.
//
// The chain carries the same params envelope as any later publication (the
// revision only), so a freshly paired node starts on exactly the contract the
// rest of the control plane uses.
func SeedInitialTasksTx(tx *sql.Tx, nodeID string, now time.Time) error {
	candidate, err := LatestTx(tx, nodeID)
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
	params, err := taskParams(candidate.Document.Candidate())
	if err != nil {
		return err
	}
	taskRevision, err := TaskRevisionAfter(tx, nodeID)
	if err != nil {
		return err
	}
	for _, kind := range protocol.PublicationKinds {
		task, err := NewFixedTask(nodeID, kind, params, taskRevision)
		if err != nil {
			return err
		}
		if err := EnqueueTx(tx, task, now); err != nil {
			return err
		}
		taskRevision++
	}
	return nil
}

func LatestTx(tx *sql.Tx, nodeID string) (Stored, error) {
	var c Stored
	err := tx.QueryRow(`SELECT revision, candidate_json, config_sha256 FROM node_candidates WHERE node_id=? ORDER BY revision DESC LIMIT 1`, nodeID).Scan(&c.Revision, &c.JSON, &c.ConfigSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return Stored{}, common.ErrCandidateNotFound
	}
	if err != nil {
		return Stored{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := json.Unmarshal(c.JSON, &c.Document); err != nil || c.Document.Revision != c.Revision {
		return Stored{}, common.ErrCandidateCorrupt
	}
	return c, nil
}
