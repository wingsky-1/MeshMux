package web

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	nodedomain "github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
)

const offlineAfter = 2 * time.Minute

// Node is the Hub-visible record for a Line/Out host. The ID and role are
// immutable after creation; pairing binds them to one host identity.
type Node struct {
	ID                         string `json:"id"`
	Role                       string `json:"role"`
	DisplayName                string `json:"display_name"`
	VlessPort                  int    `json:"vless_port"`
	SSHPort                    int    `json:"ssh_port"`
	Status                     string `json:"status"`
	AgentVersion               string `json:"agent_version"`
	KernelVersion              string `json:"kernel_version"`
	LastHeartbeat              int64  `json:"last_heartbeat"`
	LastSuccess                string `json:"last_success"`
	LatestConfigRevision       int64  `json:"latest_config_revision"`
	LatestConfigSHA256         string `json:"latest_config_sha256"`
	ObservedRevision           int64  `json:"observed_config_revision"`
	ObservedConfigSHA256       string `json:"observed_config_sha256"`
	ObservedArchitecture       string `json:"observed_architecture"`
	ObservedAgentVersion       string `json:"observed_agent_version"`
	ObservedAgentSHA256        string `json:"observed_agent_sha256"`
	ObservedKernelVersion      string `json:"observed_kernel_version"`
	ObservedKernelSHA256       string `json:"observed_kernel_sha256"`
	ObservedOutDefaultDeny     bool   `json:"observed_out_default_deny"`
	ObservedAt                 int64  `json:"observed_at"`
	ObservedTaskRevision       int64  `json:"observed_task_revision"`
	ObservedTaskOperationID    string `json:"observed_task_operation_id"`
	LastTaskStatus             string `json:"last_task_status"`
	LastTaskKind               string `json:"last_task_kind"`
	LastTaskOperationID        string `json:"last_task_operation_id"`
	LastTaskErrorCode          string `json:"last_task_error_code"`
	LastTaskDetail             string `json:"last_task_detail"`
	LastTaskRevision           int64  `json:"last_task_revision"`
	LastTaskUpdatedAt          int64  `json:"last_task_updated_at"`
	LastFailureTaskKind        string `json:"last_failure_task_kind"`
	LastFailureTaskOperationID string `json:"last_failure_task_operation_id"`
	LastFailureTaskErrorCode   string `json:"last_failure_task_error_code"`
	LastFailureTaskRevision    int64  `json:"last_failure_task_revision"`
	LastFailureTaskUpdatedAt   int64  `json:"last_failure_task_updated_at"`
	LastSuccessTaskKind        string `json:"last_success_task_kind"`
	LastSuccessTaskOperationID string `json:"last_success_task_operation_id"`
	LastSuccessTaskRevision    int64  `json:"last_success_task_revision"`
	LastSuccessTaskUpdatedAt   int64  `json:"last_success_task_updated_at"`
	LastSuccessAt              int64  `json:"last_success_at"`
	Offline                    bool   `json:"offline"`
	NativeReady                bool   `json:"native_ready"`
	LocalVerified              bool   `json:"local_verified"`
	PublicReachabilityVerified bool   `json:"public_reachability_verified"`
	ProtocolVerified           bool   `json:"protocol_verified"`
	ClientVerified             bool   `json:"client_verified"`
	CreatedAt                  int64  `json:"created_at"`
	UpdatedAt                  int64  `json:"updated_at"`
}

// VlessPortString renders the port for templ without extra imports.
func (n Node) VlessPortString() string { return itoa(n.VlessPort) }

// SSHPortString renders the port for templ without extra imports.
func (n Node) SSHPortString() string { return itoa(n.SSHPort) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// nativeReady means one validated local readback matches the current immutable
// candidate while the node is currently contacting the Hub. It never asserts
// public reachability, protocol handshake or client usability, and it does not
// claim that the Agent binary digest was compared with a Hub-signed manifest.
func nativeReady(n Node) bool {
	return !n.Offline && n.LocalVerified &&
		n.LatestConfigRevision > 0 &&
		n.ObservedRevision == n.LatestConfigRevision &&
		n.ObservedConfigSHA256 != "" &&
		n.ObservedConfigSHA256 == n.LatestConfigSHA256
}

func (n Node) LastContactString() string {
	if n.LastHeartbeat == 0 {
		return "尚未联系"
	}
	return time.Unix(n.LastHeartbeat, 0).Format("2006-01-02 15:04:05")
}

func (n Node) ObservedAtString() string {
	if n.ObservedAt == 0 {
		return "尚无有效回读"
	}
	return time.Unix(n.ObservedAt, 0).Format("2006-01-02 15:04:05")
}

func (n Node) LastTaskUpdatedString() string {
	if n.LastTaskUpdatedAt == 0 {
		return "尚无任务结果"
	}
	return time.Unix(n.LastTaskUpdatedAt, 0).Format("2006-01-02 15:04:05")
}

// createNode inserts a pending node and returns the one-time pairing code.
// The plaintext code is returned once and never persisted; only its hash is
// stored. Callers must not log the code.
func (s *store) createNode(role, displayName string, vlessPort, sshPort int, now time.Time) (Node, string, error) {
	if err := protocol.ValidateNodeInputs(role, displayName, vlessPort, sshPort); err != nil {
		return Node{}, "", err
	}
	id, err := protocol.NewID()
	if err != nil {
		return Node{}, "", errors.New("NODE_ID_FAILED")
	}
	code, err := protocol.NewSecret()
	if err != nil {
		return Node{}, "", errors.New("PAIRING_CODE_FAILED")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Node{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	node := Node{ID: id, Role: role, DisplayName: strings.TrimSpace(displayName), VlessPort: vlessPort, SSHPort: sshPort, Status: "pending", CreatedAt: now.Unix(), UpdatedAt: now.Unix()}
	if _, err = tx.Exec(`INSERT INTO nodes(id, role, display_name, vless_port, ssh_port, status, agent_version, kernel_version, last_heartbeat, last_success, created_at, updated_at) VALUES(?,?,?,?,?,'pending','','',0,'',?,?)`, node.ID, node.Role, node.DisplayName, node.VlessPort, node.SSHPort, node.CreatedAt, node.UpdatedAt); err != nil {
		return Node{}, "", errors.New("NODE_CREATE_FAILED")
	}
	if _, err = tx.Exec(`INSERT INTO node_pairing(node_id, code_hash, expires, consumed) VALUES(?,?,?,0)`, node.ID, tokenHash(code), now.Add(15*time.Minute).Unix()); err != nil {
		return Node{}, "", errors.New("NODE_CREATE_FAILED")
	}
	candidate := nodedomain.Candidate{
		NodeID:        node.ID,
		Role:          nodedomain.Role(node.Role),
		Revision:      initialCandidateRevision,
		VLESSPort:     node.VlessPort,
		KernelVersion: nodedomain.KernelVersion,
	}
	if err = insertCandidateTx(tx, candidate, now.Unix()); err != nil {
		return Node{}, "", errors.New("NODE_CREATE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return Node{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	return node, code, nil
}

const nodeSelect = `
SELECT n.id, n.role, n.display_name, n.vless_port, n.ssh_port, n.status,
 n.agent_version, n.kernel_version, n.last_heartbeat, n.last_success,
 COALESCE((SELECT c.revision FROM node_candidates c WHERE c.node_id=n.id ORDER BY c.revision DESC LIMIT 1),0),
 COALESCE((SELECT c.config_sha256 FROM node_candidates c WHERE c.node_id=n.id ORDER BY c.revision DESC LIMIT 1),''),
 n.observed_revision, n.observed_config_sha256, n.observed_architecture,
 n.observed_agent_version, n.observed_agent_sha256, n.observed_kernel_version,
 n.observed_kernel_sha256, n.observed_out_default_deny, n.observed_at, n.observed_task_revision,
 n.observed_task_operation_id,
 COALESCE((SELECT t.status FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.kind FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.operation_id FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.error_code FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.detail FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.revision FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),0),
 COALESCE((SELECT t.updated_at FROM agent_tasks t WHERE t.node_id=n.id ORDER BY t.revision DESC LIMIT 1),0),
 COALESCE((SELECT t.kind FROM agent_tasks t WHERE t.node_id=n.id AND t.status IN ('partial','failed','rolled_back') ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.operation_id FROM agent_tasks t WHERE t.node_id=n.id AND t.status IN ('partial','failed','rolled_back') ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.error_code FROM agent_tasks t WHERE t.node_id=n.id AND t.status IN ('partial','failed','rolled_back') ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.revision FROM agent_tasks t WHERE t.node_id=n.id AND t.status IN ('partial','failed','rolled_back') ORDER BY t.revision DESC LIMIT 1),0),
 COALESCE((SELECT t.updated_at FROM agent_tasks t WHERE t.node_id=n.id AND t.status IN ('partial','failed','rolled_back') ORDER BY t.revision DESC LIMIT 1),0),
 COALESCE((SELECT t.kind FROM agent_tasks t WHERE t.node_id=n.id AND t.status='healthy' ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.operation_id FROM agent_tasks t WHERE t.node_id=n.id AND t.status='healthy' ORDER BY t.revision DESC LIMIT 1),''),
 COALESCE((SELECT t.revision FROM agent_tasks t WHERE t.node_id=n.id AND t.status='healthy' ORDER BY t.revision DESC LIMIT 1),0),
 COALESCE((SELECT t.updated_at FROM agent_tasks t WHERE t.node_id=n.id AND t.status='healthy' ORDER BY t.revision DESC LIMIT 1),0),
 n.last_success_at,
 n.created_at, n.updated_at
FROM nodes n`

type rowScanner interface {
	Scan(...any) error
}

// scanNodeAt evaluates the offline window against one explicit clock, so the
// Web projection and the task delivery window cannot disagree because they
// read the wall clock at different moments.
func scanNodeAt(row rowScanner, now time.Time) (Node, error) {
	var n Node
	err := row.Scan(
		&n.ID, &n.Role, &n.DisplayName, &n.VlessPort, &n.SSHPort, &n.Status,
		&n.AgentVersion, &n.KernelVersion, &n.LastHeartbeat, &n.LastSuccess,
		&n.LatestConfigRevision, &n.LatestConfigSHA256,
		&n.ObservedRevision, &n.ObservedConfigSHA256, &n.ObservedArchitecture,
		&n.ObservedAgentVersion, &n.ObservedAgentSHA256, &n.ObservedKernelVersion,
		&n.ObservedKernelSHA256, &n.ObservedOutDefaultDeny, &n.ObservedAt, &n.ObservedTaskRevision,
		&n.ObservedTaskOperationID,
		&n.LastTaskStatus, &n.LastTaskKind, &n.LastTaskOperationID,
		&n.LastTaskErrorCode, &n.LastTaskDetail, &n.LastTaskRevision, &n.LastTaskUpdatedAt,
		&n.LastFailureTaskKind, &n.LastFailureTaskOperationID, &n.LastFailureTaskErrorCode,
		&n.LastFailureTaskRevision, &n.LastFailureTaskUpdatedAt,
		&n.LastSuccessTaskKind, &n.LastSuccessTaskOperationID,
		&n.LastSuccessTaskRevision, &n.LastSuccessTaskUpdatedAt, &n.LastSuccessAt,
		&n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		return Node{}, err
	}
	n.Offline = n.Status == "pending" || n.LastHeartbeat == 0 || now.Sub(time.Unix(n.LastHeartbeat, 0)) > offlineAfter
	n.LocalVerified = n.ObservedAt > 0
	n.NativeReady = nativeReady(n)
	return n, nil
}

// listNodesAt evaluates every row's offline window against one explicit clock,
// so a list projection cannot mix two different wall-clock readings.
func (s *store) listNodesAt(now time.Time) ([]Node, error) {
	rows, err := s.db.Query(nodeSelect + ` ORDER BY n.created_at ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNodeAt(rows, now)
		if err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *store) getNodeAt(id string, now time.Time) (Node, error) {
	n, err := scanNodeAt(s.db.QueryRow(nodeSelect+` WHERE n.id=?`, id), now)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, errors.New("NODE_NOT_FOUND")
	}
	return n, err
}

// observedArchitecture reads the architecture the node last reported. An
// approval pins the manifest projection of that architecture, so an arm64 node
// behind an amd64 Hub still verifies the bytes it selects from the set. The
// value is the node's immutable runtime.GOARCH (validated on readback), so
// reading it outside the approval transaction cannot race it to another arch;
// the same-arch fallback is applied by the caller.
func (s *store) observedArchitecture(id string) (string, error) {
	var architecture string
	err := s.db.QueryRow(`SELECT observed_architecture FROM nodes WHERE id=?`, id).Scan(&architecture)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("NODE_NOT_FOUND")
	}
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	return architecture, nil
}

// consumePairing atomically exchanges a one-time code for a node-scoped
// identity. Replay, expiry and role mismatch are distinct rejections here so the
// Hub log can name the reason; the HTTP layer deliberately merges replay and
// expiry into one neutral answer so the response cannot be used to learn a
// code's history. An unknown code is a generic rejection to avoid node
// enumeration.
func (s *store) consumePairing(nodeID, role, code, agentVersion, kernelVersion string, now time.Time) (string, error) {
	if err := protocol.ValidatePairingRequest(protocol.PairingRequest{NodeID: nodeID, Role: role, PairingCode: code, AgentVersion: agentVersion, KernelVersion: kernelVersion}); err != nil {
		return "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var storedRole string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&storedRole)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("PAIRING_INVALID: pairing code rejected")
	}
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	if storedRole != role {
		return "", errors.New("ROLE_MISMATCH: node role does not match pairing record")
	}
	// Atomic single-use: consume and issue identity in one transaction so
	// token persistence failure cannot strand the one-time pairing code.
	res, err := tx.Exec(`UPDATE node_pairing SET consumed=1 WHERE node_id=? AND code_hash=? AND consumed=0 AND expires>?`, nodeID, tokenHash(code), now.Unix())
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	affected, _ := res.RowsAffected()
	if affected == 1 {
		token, err := protocol.NewSecret()
		if err != nil {
			return "", errors.New("IDENTITY_ISSUE_FAILED")
		}
		if _, err = tx.Exec(`INSERT OR REPLACE INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`, nodeID, tokenHash(token), now.Unix()); err != nil {
			return "", errors.New("IDENTITY_ISSUE_FAILED")
		}
		if _, err = tx.Exec(`UPDATE nodes SET status='paired', agent_version=?, kernel_version=?, last_heartbeat=?, updated_at=? WHERE id=?`, agentVersion, kernelVersion, now.Unix(), now.Unix(), nodeID); err != nil {
			return "", errors.New("DATABASE_UNAVAILABLE")
		}
		if err = seedInitialTasksTx(tx, nodeID, now); err != nil {
			return "", err
		}
		if err = tx.Commit(); err != nil {
			return "", errors.New("DATABASE_UNAVAILABLE")
		}
		return token, nil
	}
	// Diagnose the failure without leaking whether the node exists beyond
	// the generic invalid case already handled above.
	var expires, consumed int64
	err = tx.QueryRow(`SELECT expires, consumed FROM node_pairing WHERE node_id=?`, nodeID).Scan(&expires, &consumed)
	if err != nil {
		return "", errors.New("PAIRING_INVALID: pairing code rejected")
	}
	var hash []byte
	_ = tx.QueryRow(`SELECT code_hash FROM node_pairing WHERE node_id=?`, nodeID).Scan(&hash)
	if subtle.ConstantTimeCompare(hash, tokenHash(code)) != 1 {
		return "", errors.New("PAIRING_INVALID: pairing code rejected")
	}
	if consumed != 0 {
		return "", errors.New("PAIRING_CONSUMED: pairing code already used")
	}
	if expires <= now.Unix() {
		return "", errors.New("PAIRING_EXPIRED: pairing code expired; create a fresh pending node or reissue")
	}
	return "", errors.New("PAIRING_INVALID: pairing code rejected")
}

// authenticateAgentAt maps a Bearer identity to its node. Revoked or unknown
// tokens fail closed without revealing which nodes exist. It binds the returned
// readiness window to the request clock, so the Agent task endpoint and the Web
// projection agree.
func (s *store) authenticateAgentAt(token string, now time.Time) (Node, error) {
	if len(token) != 43 {
		return Node{}, errors.New("AGENT_UNAUTHORIZED")
	}
	n, err := scanNodeAt(s.db.QueryRow(nodeSelect+` JOIN node_identities i ON n.id=i.node_id WHERE i.token_hash=? AND i.revoked=0`, tokenHash(token)), now)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, errors.New("AGENT_UNAUTHORIZED")
	}
	return n, err
}

func (s *store) heartbeat(nodeID, agentVersion, kernelVersion string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE nodes SET status='paired', agent_version=?, kernel_version=?, last_heartbeat=?, updated_at=? WHERE id=?`, agentVersion, kernelVersion, now.Unix(), now.Unix(), nodeID)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("NODE_NOT_FOUND")
	}
	// A reconnecting Line picks up the persisted subscriber intent even if
	// the Hub crashed before the tasks of a change were enqueued. The
	// coordination is bidirectional: the Line event also lets every Out that
	// serves it authorize the Line, and an Out event republishes its allowlist
	// before the Lines it serves are drained.
	s.drainNodeCoordination(nodeID, now)
	return nil
}

// reissuePairing revokes any prior identity and replaces the outstanding code
// without changing the immutable node fields. Existing unfinished work is
// terminated explicitly because the Agent that received it can no longer
// authenticate. This does not stop services or remove candidate/config data.
func (s *store) reissuePairing(nodeID string, now time.Time) (string, error) {
	code, err := protocol.NewSecret()
	if err != nil {
		return "", errors.New("PAIRING_CODE_FAILED")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT 1 FROM nodes WHERE id=?`, nodeID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("NODE_NOT_FOUND")
	} else if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, nodeID); err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`INSERT OR REPLACE INTO node_pairing(node_id, code_hash, expires, consumed) VALUES(?,?,?,0)`,
		nodeID, tokenHash(code), now.Add(15*time.Minute).Unix()); err != nil {
		return "", errors.New("PAIRING_REISSUE_FAILED")
	}
	if _, err = tx.Exec(`UPDATE agent_tasks SET status='failed', error_code='IDENTITY_REPLACED', updated_at=?
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, now.Unix(), nodeID); err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`UPDATE nodes SET status='pending', last_heartbeat=0, updated_at=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	// A reissued identity is deliberately not a retirement: the Line is coming
	// back, and the derivation already excludes a non-current identity from
	// every allowlist on its own. Forcing a reclaim here would republish an
	// empty allowlist on every re-pair and interrupt a Line that is only
	// rotating its credential. Once the Line re-pairs, its own heartbeat or
	// poll restores the authorization at the Out (drainOutsForLine).
	return code, nil
}

// revokeIdentity revokes the current node identity without deleting candidate,
// task history or any host-side configuration. A later reissue is an explicit
// administrator action.
func (s *store) revokeIdentity(nodeID string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT 1 FROM nodes WHERE id=?`, nodeID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return errors.New("NODE_NOT_FOUND")
	} else if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, nodeID); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`UPDATE node_pairing SET consumed=1 WHERE node_id=?`, nodeID); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`UPDATE agent_tasks SET status='failed', error_code='IDENTITY_REVOKED', updated_at=?
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, now.Unix(), nodeID); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`UPDATE nodes SET status='revoked', last_heartbeat=0, updated_at=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	// Revoking a Line identity retires its egress authorization: the Hub can no
	// longer vouch for the source address, so every Out that serves the Line has
	// to be republished with the remaining sources. Revoking an Out has no such
	// consequence, so only an edge node triggers the reclaim.
	//
	// A failure here does not undo the revocation (which is already recorded and
	// is itself the security boundary): the derivation excludes a revoked Line
	// from every allowlist, so the state stays honest and the next Out or Line
	// event retries the republish.
	var role string
	if err := s.db.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role); err == nil && role == "edge" {
		s.reclaimRetiredLine(nodeID, now)
	}
	return nil
}

func normalizeParams(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

// enqueueTaskAt persists a validated task with exact-envelope idempotency and a
// per-node monotonic revision. An identical re-enqueue is a success (nil); the
// same operation_id or idempotency_key with different content is a conflict;
// a revision that would rewind the node chain is stale. Reserved
// upgrade/rollback kinds never reach storage because protocol.ValidateTask
// rejects them first.
//
// Every request path threads the handler clock through enqueueTaskAt, so one
// request has one timestamp.
func (s *store) enqueueTaskAt(task protocol.Task, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if err = enqueueTaskTx(tx, task, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

// enqueueTaskTx is the sole task insertion path. It never begins or commits a
// transaction, so candidate publication and pairing can include tasks without
// nesting transactions on the MaxOpenConns(1) SQLite pool. The caller-supplied
// clock is shared with the candidate inserted in the same transaction, so one
// publication has one consistent timestamp.
func enqueueTaskTx(tx *sql.Tx, task protocol.Task, now time.Time) error {
	if err := protocol.ValidateTask(task); err != nil {
		return err
	}
	params := normalizeParams(task.Params)
	res, err := lookupTask(tx, "operation_id=?", task.OperationID, task, params)
	if err != nil {
		return err
	}
	if res == taskLookupExact {
		return nil
	}
	if res == taskLookupConflict {
		return errors.New("IDEMPOTENCY_CONFLICT: operation_id already recorded with different content")
	}
	res, err = lookupTask(tx, "idempotency_key=?", task.IdempotencyKey, task, params)
	if err != nil {
		return err
	}
	if res == taskLookupExact {
		return nil
	}
	if res == taskLookupConflict {
		return errors.New("IDEMPOTENCY_CONFLICT: idempotency_key already recorded with different content")
	}
	var maxRev sql.NullInt64
	if err = tx.QueryRow(`SELECT MAX(revision) FROM agent_tasks WHERE node_id=?`, task.NodeID).Scan(&maxRev); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if maxRev.Valid && task.Revision <= maxRev.Int64 {
		return errors.New("REVISION_STALE: revision must increase monotonically")
	}
	stamp := now.Unix()
	if _, err = tx.Exec(`INSERT INTO agent_tasks(operation_id, node_id, kind, revision, idempotency_key, status, params, created_at, updated_at) VALUES(?,?,?,?,?,'pending',?,?,?)`, task.OperationID, task.NodeID, task.Kind, task.Revision, task.IdempotencyKey, params, stamp, stamp); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

type taskLookup int

const (
	taskLookupNone taskLookup = iota
	taskLookupExact
	taskLookupConflict
)

// lookupTask classifies an existing row matched by whereArg against the
// incoming envelope. The full stored envelope is compared so an idempotent
// replay is only accepted when every field matches exactly.
func lookupTask(tx *sql.Tx, where string, arg any, task protocol.Task, params string) (taskLookup, error) {
	var (
		opID, nodeID, kind, idem, storedParams string
		revision                               int64
	)
	err := tx.QueryRow(`SELECT operation_id, node_id, kind, revision, idempotency_key, params FROM agent_tasks WHERE `+where, arg).Scan(&opID, &nodeID, &kind, &revision, &idem, &storedParams)
	if errors.Is(err, sql.ErrNoRows) {
		return taskLookupNone, nil
	}
	if err != nil {
		return taskLookupNone, errors.New("DATABASE_UNAVAILABLE")
	}
	if opID == task.OperationID && nodeID == task.NodeID && kind == task.Kind && revision == task.Revision && idem == task.IdempotencyKey && storedParams == params {
		return taskLookupExact, nil
	}
	return taskLookupConflict, nil
}

// pendingTasksAt returns every unfinished task for one node: pending, applying
// and verifying all need to be redelivered after an Agent reconnect. Revision
// ascending preserves the original enqueue order.
func (s *store) pendingTasksAt(nodeID string, limit int, now time.Time) ([]protocol.Task, error) {
	if limit < 1 || limit > 32 {
		limit = 8
	}
	// Reconcile the persisted subscriber intent before handing out tasks, so
	// a change that happened after the last publication is not missed by this
	// poll. The drain uses its own transaction and never fails the poll. An Out
	// poll republishes its own authorization first and then releases the Lines
	// it serves; a Line poll authorizes itself at its Out first.
	s.drainNodeCoordination(nodeID, now)
	rows, err := s.db.Query(`SELECT t.operation_id, t.revision, t.idempotency_key, t.kind, t.params
 FROM agent_tasks t JOIN nodes n ON n.id=t.node_id
 WHERE t.node_id=? AND n.last_heartbeat>=? AND t.status IN ('pending','applying','verifying')
 ORDER BY t.revision ASC LIMIT ?`, nodeID, now.Add(-offlineAfter).Unix(), limit)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	var out []protocol.Task
	for rows.Next() {
		var t protocol.Task
		t.Schema, t.Version = protocol.Schema, protocol.Version
		t.NodeID = nodeID
		var kind string
		var params string
		if err := rows.Scan(&t.OperationID, &t.Revision, &t.IdempotencyKey, &kind, &params); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		t.Kind = kind
		if params == "" {
			params = "{}"
		}
		t.Params = []byte(params)
		out = append(out, t)
	}
	return out, rows.Err()
}

// reportResultAudited records an Agent result in one transaction scoped to
// nodeID+operation_id and reports whether it changed a row. A repeat of the
// same terminal status/error_code is a no-op; a different terminal rewrite is
// rejected; non-terminal states may be re-reported; the state machine never
// regresses. All timestamps of the request (task update, node success,
// observation and the follow-up drain) use one caller-supplied clock, so a
// fixed-clock request cannot be split across two wall-clock readings.
func (s *store) reportResultAudited(nodeID string, res protocol.TaskResult, now time.Time) (bool, error) {
	if err := protocol.ValidateTaskResult(res); err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var current, taskNodeID, taskKind, storedCode, storedDetail string
	var taskRevision int64
	var params string
	err = tx.QueryRow(`SELECT status, node_id, kind, revision, error_code, params, detail FROM agent_tasks WHERE operation_id=?`, res.OperationID).
		Scan(&current, &taskNodeID, &taskKind, &taskRevision, &storedCode, &params, &storedDetail)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errors.New("TASK_NOT_FOUND")
	}
	if err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	if taskNodeID != nodeID {
		return false, errors.New("TASK_NOT_FOUND")
	}
	detailToStore := res.Detail
	var readback nodedomain.Readback
	if res.Status == "healthy" && (taskKind == protocol.KindConfigApply || taskKind == protocol.KindConfigReadback) {
		var configParams struct {
			Revision *int64 `json:"revision"`
		}
		if err := json.Unmarshal([]byte(params), &configParams); err != nil ||
			configParams.Revision == nil || *configParams.Revision < 1 {
			return false, errors.New("TASK_PARAMS_INVALID")
		}
		readback, detailToStore, err = decodeReadbackDetail(res.Detail)
		if err != nil {
			return false, err
		}
		if err := validateReadbackTx(tx, nodeID, *configParams.Revision, readback); err != nil {
			return false, err
		}
	}
	if terminalTaskStatus(current) {
		if res.Status == current && res.ErrorCode == storedCode && detailToStore == storedDetail {
			return false, nil
		}
		return false, errors.New("TASK_ALREADY_FINAL")
	}
	if res.Status == current {
		if res.ErrorCode == storedCode && detailToStore == storedDetail {
			return false, nil
		}
		return false, errors.New("TASK_STATE_INVALID: task state cannot change in place")
	}
	if !allowedTransition(current, res.Status) {
		return false, errors.New("TASK_STATE_INVALID: task state cannot regress")
	}
	stamp := now.Unix()
	if _, err = tx.Exec(`UPDATE agent_tasks SET status=?, error_code=?, detail=?, updated_at=? WHERE operation_id=? AND node_id=?`,
		res.Status, res.ErrorCode, detailToStore, stamp, res.OperationID, nodeID); err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	if res.Status == "healthy" {
		lastSuccess := now.UTC().Format(time.RFC3339)
		if _, err = tx.Exec(`UPDATE nodes SET last_success=?, last_success_at=?, updated_at=? WHERE id=?`, lastSuccess, stamp, stamp, nodeID); err != nil {
			return false, errors.New("DATABASE_UNAVAILABLE")
		}
		if taskKind == protocol.KindConfigReadback {
			if _, err = tx.Exec(`UPDATE nodes SET observed_revision=?, observed_config_sha256=?,
 observed_architecture=?, observed_agent_version=?, observed_agent_sha256=?,
 observed_kernel_version=?, observed_kernel_sha256=?, observed_out_default_deny=?,
 observed_at=?, observed_task_revision=?, observed_task_operation_id=?
 WHERE id=? AND observed_task_revision<=? AND observed_revision<=?`,
				readback.ActiveRevision, readback.ConfigSHA256, readback.Architecture,
				readback.AgentVersion, readback.AgentSHA256, readback.KernelVersion,
				readback.KernelSHA256, readback.OutDefaultDeny, stamp, taskRevision, res.OperationID,
				nodeID, taskRevision, readback.ActiveRevision); err != nil {
				return false, errors.New("DATABASE_UNAVAILABLE")
			}
			// A deleting subscriber becomes deleted only once the Line proved
			// the exact desired snapshot without its historical UUIDs. The
			// check runs in this transaction, directly after the observation,
			// so the result request itself can complete the deletion. Failing
			// to finalize never rejects the recorded result: the state stays
			// "deleting" and the next drain retries.
			_ = finalizeDeletingSubscribersTx(tx, nodeID, now)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	// A finished chain may make the persisted subscriber intent publishable
	// (removal of a deleted subscriber, follow-up after a changed snapshot).
	// It is also the Out-side readback event: a confirmed Out allowlist
	// releases the Lines it serves, and a confirmed Line egress is what lets
	// the pair report healthy. The drain owns its transaction and never fails
	// the recorded result.
	s.drainNodeCoordination(nodeID, now)
	return true, nil
}

func validateReadbackTx(tx *sql.Tx, nodeID string, configRevision int64, readback nodedomain.Readback) error {
	// readback.Validate deliberately binds the Agent version and digest shape.
	// The Agent digest is claimed by the node; only the kernel digest is
	// compared with the Hub's pinned architecture manifest. No Agent binary
	// manifest is fabricated here.
	if err := readback.Validate(); err != nil {
		return errors.New("READBACK_INVALID")
	}
	if !readback.LocalActive || readback.ActiveRevision != configRevision {
		return errors.New("READBACK_MISMATCH")
	}
	release, ok := nodedomain.KernelReleaseFor(readback.Architecture)
	if !ok || readback.KernelVersion != release.Version || readback.KernelSHA256 != release.BinarySHA256 {
		return errors.New("READBACK_KERNEL_MISMATCH")
	}
	var role, candidateJSON, candidateHash string
	var vlessPort int
	err := tx.QueryRow(`SELECT n.role, n.vless_port, c.candidate_json, c.config_sha256
 FROM nodes n JOIN node_candidates c ON c.node_id=n.id AND c.revision=?
 WHERE n.id=?`, configRevision, nodeID).Scan(&role, &vlessPort, &candidateJSON, &candidateHash)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("READBACK_CANDIDATE_NOT_FOUND")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if readback.ConfigSHA256 != candidateHash {
		return errors.New("READBACK_CONFIG_MISMATCH")
	}
	var document nodedomain.CandidateDocument
	if err := json.Unmarshal([]byte(candidateJSON), &document); err != nil {
		return errors.New("READBACK_CANDIDATE_CORRUPT")
	}
	if document.NodeID != nodeID || string(document.Role) != role || document.VLESSPort != vlessPort {
		return errors.New("READBACK_ROLE_MISMATCH")
	}
	if document.Role == nodedomain.RoleOut && !readback.OutDefaultDeny {
		return errors.New("READBACK_ACL_NOT_ENFORCED")
	}
	return nil
}

// decodeReadbackDetail accepts exactly the nine Readback fields and returns a
// canonical representation. This prevents extra fields, duplicate keys, nulls
// and other loose JSON from being treated as valid local evidence.
func decodeReadbackDetail(detail string) (nodedomain.Readback, string, error) {
	if len(detail) == 0 || len(detail) >= 512 {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	dec := json.NewDecoder(strings.NewReader(detail))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
		}
		key, ok := keyToken.(string)
		if !ok {
			return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
		}
		if _, duplicate := fields[key]; duplicate {
			return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || len(raw) == 0 || string(raw) == "null" {
			return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
		}
		fields[key] = raw
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	required := []string{
		"active_revision", "agent_sha256", "agent_version", "architecture",
		"config_sha256", "kernel_sha256", "kernel_version", "local_active",
		"out_default_deny",
	}
	if len(fields) != len(required) {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
		}
	}
	var readback nodedomain.Readback
	if json.Unmarshal(fields["architecture"], &readback.Architecture) != nil ||
		json.Unmarshal(fields["agent_version"], &readback.AgentVersion) != nil ||
		json.Unmarshal(fields["agent_sha256"], &readback.AgentSHA256) != nil ||
		json.Unmarshal(fields["kernel_version"], &readback.KernelVersion) != nil ||
		json.Unmarshal(fields["kernel_sha256"], &readback.KernelSHA256) != nil ||
		json.Unmarshal(fields["active_revision"], &readback.ActiveRevision) != nil ||
		json.Unmarshal(fields["config_sha256"], &readback.ConfigSHA256) != nil ||
		json.Unmarshal(fields["local_active"], &readback.LocalActive) != nil ||
		json.Unmarshal(fields["out_default_deny"], &readback.OutDefaultDeny) != nil {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	canonical, err := json.Marshal(readback)
	if err != nil || len(canonical) >= 512 {
		return nodedomain.Readback{}, "", errors.New("READBACK_INVALID")
	}
	return readback, string(canonical), nil
}

// allowedTransition is the frozen Agent result state machine. pending may jump
// straight to healthy to keep the read-only status tasks usable; applying and
// verifying may only move forward. rollback requires an applied task.
func allowedTransition(current, next string) bool {
	switch current {
	case "pending":
		switch next {
		case "applying", "verifying", "healthy", "partial", "failed":
			return true
		}
	case "applying":
		switch next {
		case "applying", "verifying", "healthy", "partial", "failed", "rolled_back":
			return true
		}
	case "verifying":
		return next == "verifying" || terminalTaskStatus(next)
	}
	return false
}

func terminalTaskStatus(status string) bool {
	switch status {
	case "healthy", "partial", "failed", "rolled_back":
		return true
	default:
		return false
	}
}
