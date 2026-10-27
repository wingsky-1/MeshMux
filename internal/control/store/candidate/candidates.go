package candidate

// The immutable candidate revision and the fixed Agent task chain that
// publishes it.
//
// A revision is never updated or deleted (the schema's triggers refuse both),
// and the chain that names it is enqueued in the same transaction, so a
// publication either stores both or neither. The read helpers below re-derive
// the stored digest instead of trusting the column, so a corrupted row fails
// closed.

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
func PublishTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time) ([]protocol.Task, error) {
	if candidate.Role == node.RoleOut {
		return nil, errors.New("CANDIDATE_INVALID: an out candidate must publish its source authorization")
	}
	return publishChainTx(tx, nodeID, candidate, now, nil)
}

// PublishOutTx publishes one Out candidate whose chain carries exactly the
// supplied source authorization.
//
// The allowlist is not derived here: the Out domain owns that derivation, and a
// caller that cannot name the set explicitly must not publish an Out at all.
// Publishing the empty set is how the delete path expresses "this host must end
// in default-deny"; publishing a nil set is refused, because the Agent reads an
// omitted key as "no Hub expectation".
func PublishOutTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time, allowed []string) ([]protocol.Task, error) {
	if candidate.Role != node.RoleOut {
		return nil, errors.New("CANDIDATE_INVALID: only an out candidate carries a source authorization")
	}
	if allowed == nil {
		return nil, errors.New("CANDIDATE_INVALID: an out chain must name its authorization, empty or not")
	}
	return publishChainTx(tx, nodeID, candidate, now, allowed)
}

// publishChainTx stores one immutable revision and enqueues the fixed four-task
// chain in the caller's transaction.
func publishChainTx(tx *sql.Tx, nodeID string, candidate node.Candidate, now time.Time, allowed []string) ([]protocol.Task, error) {
	if err := InsertTx(tx, candidate, now.Unix()); err != nil {
		return nil, err
	}
	params, err := taskParams(candidate, allowed)
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

// TaskParamsTx builds the params envelope of one candidate chain.
//
// An Out candidate always names its source authorization, including the empty
// one, because the Agent distinguishes "no expectation" (omitted) from
// "authorized for nothing" (explicit empty array). Anything that fails to derive
// the Out authorization aborts the publication: publishing a chain whose guard
// cannot be verified would report a health the Hub does not have.
func taskParams(candidate node.Candidate, allowed []string) (json.RawMessage, error) {
	if candidate.Role != node.RoleOut {
		return json.Marshal(map[string]int64{"revision": candidate.Revision})
	}
	return json.Marshal(struct {
		Revision       int64    `json:"revision"`
		AllowedSources []string `json:"allowed_sources"`
	}{Revision: candidate.Revision, AllowedSources: allowed})
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
// The Out authorization is derived by the caller and passed in: this package
// sits below the Out domain, so it cannot read that derivation itself.
func SeedInitialTasksTx(tx *sql.Tx, nodeID string, now time.Time, outAllowlist func(tx *sql.Tx, outID string) ([]string, error)) error {
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
	// The seeded chain uses the same params envelope as any later publication,
	// so an Out that was paired before its binding existed still starts with an
	// explicit empty authorization instead of an omitted key.
	stored := candidate.Document.Candidate()
	var allowed []string
	if stored.Role == node.RoleOut {
		if outAllowlist == nil {
			return errors.New("CANDIDATE_INVALID: no out authorization derivation is wired")
		}
		allowed, err = outAllowlist(tx, nodeID)
		if err != nil {
			return err
		}
		if allowed == nil {
			allowed = []string{}
		}
	}
	params, err := taskParams(stored, allowed)
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
