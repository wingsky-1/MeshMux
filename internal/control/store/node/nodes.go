package node

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	candidatepkg "github.com/wingsky-1/MeshMux/internal/control/store/candidate"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

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
func (n Node) VlessPortString() string { return common.Itoa(n.VlessPort) }

// SSHPortString renders the port for templ without extra imports.
func (n Node) SSHPortString() string { return common.Itoa(n.SSHPort) }

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
func (s *Store) CreateNode(role, displayName string, vlessPort, sshPort int, now time.Time) (Node, string, error) {
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
	tx, err := s.DB.Begin()
	if err != nil {
		return Node{}, "", errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	node := Node{ID: id, Role: role, DisplayName: strings.TrimSpace(displayName), VlessPort: vlessPort, SSHPort: sshPort, Status: common.NodeStatusPending, CreatedAt: now.Unix(), UpdatedAt: now.Unix()}
	if _, err = tx.Exec(`INSERT INTO nodes(id, role, display_name, vless_port, ssh_port, status, agent_version, kernel_version, last_heartbeat, last_success, created_at, updated_at) VALUES(?,?,?,?,?,'pending','','',0,'',?,?)`, node.ID, node.Role, node.DisplayName, node.VlessPort, node.SSHPort, node.CreatedAt, node.UpdatedAt); err != nil {
		return Node{}, "", common.ErrNodeCreateFailed
	}
	if _, err = tx.Exec(`INSERT INTO node_pairing(node_id, code_hash, expires, consumed) VALUES(?,?,?,0)`, node.ID, common.TokenHash(code), now.Add(15*time.Minute).Unix()); err != nil {
		return Node{}, "", common.ErrNodeCreateFailed
	}
	candidate := coredomain.Candidate{
		NodeID:        node.ID,
		Role:          coredomain.Role(role),
		Revision:      candidatepkg.InitialRevision,
		VLESSPort:     node.VlessPort,
		KernelVersion: coredomain.KernelVersion,
	}
	if err = candidatepkg.InsertTx(tx, candidate, now.Unix()); err != nil {
		return Node{}, "", common.ErrNodeCreateFailed
	}
	if err = tx.Commit(); err != nil {
		return Node{}, "", errors.New(common.CodeDatabaseUnavailable)
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

// scanNodeAt evaluates the offline window against one explicit clock, so the
// Web projection and the task delivery window cannot disagree because they
// read the wall clock at different moments.
func scanNodeAt(row common.RowScanner, now time.Time) (Node, error) {
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
	// An external HTTP proxy (Ruling R11) is not a managed host: it has no
	// Agent and no heartbeat, so it is never "offline". Its status is the
	// constant "external" written at create time.
	if n.Role == string(coredomain.RoleHTTP) {
		n.Status = "external"
		n.Offline = false
		n.LocalVerified = false
		return n, nil
	}
	n.Offline = n.Status == common.NodeStatusPending || n.LastHeartbeat == 0 || now.Sub(time.Unix(n.LastHeartbeat, 0)) > common.OfflineAfter
	n.LocalVerified = n.ObservedAt > 0
	n.NativeReady = nativeReady(n)
	return n, nil
}

// listNodesAt evaluates every row's offline window against one explicit clock,
// so a list projection cannot mix two different wall-clock readings.
func (s *Store) ListNodesAt(now time.Time) ([]Node, error) {
	rows, err := s.DB.Query(nodeSelect + ` ORDER BY n.created_at ASC`)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNodeAt(rows, now)
		if err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNodeAt(id string, now time.Time) (Node, error) {
	n, err := scanNodeAt(s.DB.QueryRow(nodeSelect+` WHERE n.id=?`, id), now)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, common.ErrNodeNotFound
	}
	return n, err
}

// observedArchitecture reads the architecture the node last reported. An
// approval pins the manifest projection of that architecture, so an arm64 node
// behind an amd64 Hub still verifies the bytes it selects from the set. The
// value is the node's immutable runtime.GOARCH (validated on readback), so
// reading it outside the approval transaction cannot race it to another arch;
// the same-arch fallback is applied by the caller.
func (s *Store) ObservedArchitecture(id string) (string, error) {
	var architecture string
	err := s.DB.QueryRow(`SELECT observed_architecture FROM nodes WHERE id=?`, id).Scan(&architecture)
	if errors.Is(err, sql.ErrNoRows) {
		return "", common.ErrNodeNotFound
	}
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	return architecture, nil
}

// consumePairing atomically exchanges a one-time code for a node-scoped
// identity. Replay, expiry and role mismatch are distinct rejections here so the
// Hub log can name the reason; the HTTP layer deliberately merges replay and
// expiry into one neutral answer so the response cannot be used to learn a
// code's history. An unknown code is a generic rejection to avoid node
// enumeration.
func (s *Store) ConsumePairing(nodeID, role, code, agentVersion, kernelVersion string, now time.Time) (string, error) {
	if err := protocol.ValidatePairingRequest(protocol.PairingRequest{NodeID: nodeID, Role: role, PairingCode: code, AgentVersion: agentVersion, KernelVersion: kernelVersion}); err != nil {
		return "", err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var storedRole string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&storedRole)
	if errors.Is(err, sql.ErrNoRows) {
		return "", common.ErrPairingInvalid
	}
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	if storedRole != role {
		return "", errors.New("ROLE_MISMATCH: node role does not match pairing record")
	}
	// Atomic single-use: consume and issue identity in one transaction so
	// token persistence failure cannot strand the one-time pairing code.
	res, err := tx.Exec(`UPDATE node_pairing SET consumed=1 WHERE node_id=? AND code_hash=? AND consumed=0 AND expires>?`, nodeID, common.TokenHash(code), now.Unix())
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	affected, _ := res.RowsAffected()
	if affected == 1 {
		token, err := protocol.NewSecret()
		if err != nil {
			return "", errors.New("IDENTITY_ISSUE_FAILED")
		}
		if _, err = tx.Exec(`INSERT OR REPLACE INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`, nodeID, common.TokenHash(token), now.Unix()); err != nil {
			return "", errors.New("IDENTITY_ISSUE_FAILED")
		}
		if _, err = tx.Exec(`UPDATE nodes SET status='paired', agent_version=?, kernel_version=?, last_heartbeat=?, updated_at=? WHERE id=?`, agentVersion, kernelVersion, now.Unix(), now.Unix(), nodeID); err != nil {
			return "", errors.New(common.CodeDatabaseUnavailable)
		}
		if err = candidatepkg.SeedInitialTasksTx(tx, nodeID, now); err != nil {
			return "", err
		}
		if err = tx.Commit(); err != nil {
			return "", errors.New(common.CodeDatabaseUnavailable)
		}
		// Pairing reconciles the Out pool after the commit: an Out that just
		// enrolled or rotated its identity republishes its own link-key chain.
		// A Line never changes what any Out publishes, so this is a bounded
		// no-op for a Line.
		//
		// It runs after the commit and never fails the pairing: the issued
		// identity is durable, and the next Out event completes a deferred
		// publication.
		s.RepublishOutAuthorizations(now)
		return token, nil
	}
	// Diagnose the failure without leaking whether the node exists beyond
	// the generic invalid case already handled above.
	var expires, consumed int64
	err = tx.QueryRow(`SELECT expires, consumed FROM node_pairing WHERE node_id=?`, nodeID).Scan(&expires, &consumed)
	if err != nil {
		return "", common.ErrPairingInvalid
	}
	var hash []byte
	_ = tx.QueryRow(`SELECT code_hash FROM node_pairing WHERE node_id=?`, nodeID).Scan(&hash)
	if subtle.ConstantTimeCompare(hash, common.TokenHash(code)) != 1 {
		return "", common.ErrPairingInvalid
	}
	if consumed != 0 {
		return "", errors.New("PAIRING_CONSUMED: pairing code already used")
	}
	if expires <= now.Unix() {
		return "", errors.New("PAIRING_EXPIRED: pairing code expired; create a fresh pending node or reissue")
	}
	return "", common.ErrPairingInvalid
}

// authenticateAgentAt maps a Bearer identity to its node. Revoked or unknown
// tokens fail closed without revealing which nodes exist. It binds the returned
// readiness window to the request clock, so the Agent task endpoint and the Web
// projection agree.
func (s *Store) AuthenticateAgentAt(token string, now time.Time) (Node, error) {
	if len(token) != 43 {
		return Node{}, errors.New("AGENT_UNAUTHORIZED")
	}
	n, err := scanNodeAt(s.DB.QueryRow(nodeSelect+` JOIN node_identities i ON n.id=i.node_id WHERE i.token_hash=? AND i.revoked=0`, common.TokenHash(token)), now)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, errors.New("AGENT_UNAUTHORIZED")
	}
	return n, err
}

func (s *Store) Heartbeat(nodeID, agentVersion, kernelVersion string, now time.Time) error {
	res, err := s.DB.Exec(`UPDATE nodes SET status='paired', agent_version=?, kernel_version=?, last_heartbeat=?, updated_at=? WHERE id=?`, agentVersion, kernelVersion, now.Unix(), now.Unix(), nodeID)
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return common.ErrNodeNotFound
	}
	// A reconnecting Line picks up the persisted subscriber intent even if the
	// Hub crashed before the tasks of a change were enqueued. An Out event
	// republishes that Out's own link-key chain; a Line event republishes the
	// Line. Neither waits for the other.
	s.drainNodeCoordination(nodeID, now)
	return nil
}

// reissuePairing revokes any prior identity and replaces the outstanding code
// without changing the immutable node fields. Existing unfinished work is
// terminated explicitly because the Agent that received it can no longer
// authenticate. This does not stop services or remove candidate/config data.
func (s *Store) ReissuePairing(nodeID string, now time.Time) (string, error) {
	code, err := protocol.NewSecret()
	if err != nil {
		return "", errors.New("PAIRING_CODE_FAILED")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var exists int
	var role string
	if err = tx.QueryRow(`SELECT 1, role FROM nodes WHERE id=?`, nodeID).Scan(&exists, &role); errors.Is(err, sql.ErrNoRows) {
		return "", common.ErrNodeNotFound
	} else if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(common.NodeRoleHTTP) {
		// An external HTTP proxy has no Agent identity to reissue. Deleting and
		// recreating the proxy is the only rotation it supports.
		return "", errors.New("NODE_ROLE_INVALID: an external http proxy has no agent identity")
	}
	if _, err = tx.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, nodeID); err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	if _, err = tx.Exec(`INSERT OR REPLACE INTO node_pairing(node_id, code_hash, expires, consumed) VALUES(?,?,?,0)`,
		nodeID, common.TokenHash(code), now.Add(15*time.Minute).Unix()); err != nil {
		return "", errors.New("PAIRING_REISSUE_FAILED")
	}
	if _, err = tx.Exec(`UPDATE agent_tasks SET status='failed', error_code='IDENTITY_REPLACED', updated_at=?
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, now.Unix(), nodeID); err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	if _, err = tx.Exec(`UPDATE nodes SET status='pending', last_heartbeat=0, updated_at=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	// A reissued identity is deliberately not a retirement: the Line is coming
	// back, and no Out authorization depends on it any more. Once the Line
	// re-pairs, its own heartbeat or poll republishes its snapshot
	// (DrainOutsForLine is a bounded no-op for a Line event).
	return code, nil
}

// revokeIdentity revokes the current node identity without deleting candidate,
// task history or any host-side configuration. A later reissue is an explicit
// administrator action.
func (s *Store) RevokeIdentity(nodeID string, now time.Time) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var exists int
	var role string
	if err = tx.QueryRow(`SELECT 1, role FROM nodes WHERE id=?`, nodeID).Scan(&exists, &role); errors.Is(err, sql.ErrNoRows) {
		return common.ErrNodeNotFound
	} else if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(common.NodeRoleHTTP) {
		return errors.New("NODE_ROLE_INVALID: an external http proxy has no agent identity")
	}
	if _, err = tx.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, nodeID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if _, err = tx.Exec(`UPDATE node_pairing SET consumed=1 WHERE node_id=?`, nodeID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if _, err = tx.Exec(`UPDATE agent_tasks SET status='failed', error_code='IDENTITY_REVOKED', updated_at=?
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, now.Unix(), nodeID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if _, err = tx.Exec(`UPDATE nodes SET status='revoked', last_heartbeat=0, updated_at=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if err = tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	// A revoked identity changes only that node's own publication. An Out
	// republishes its link-key chain when it can no longer be reached; a Line
	// republishes its listener and user set. No source authorization is derived
	// any more, so no allowlist has to converge.
	//
	// A failure here does not undo the revocation (which is already recorded and
	// is itself the security boundary): the next Out or Line event retries the
	// republish.
	s.RepublishOutAuthorizations(now)
	return nil
}

// reconcileNode publishes one immutable revision and the fixed four task chain
// in a single transaction. Callers cannot supply kinds or params.
//
// A Line with stored transport settings publishes the full snapshot, so a
// manual reconcile never erases the credentials of another subscriber. A node
// without Line settings keeps the frozen v1 baseline and the Out behavior is
// unchanged.
func (s *Store) ReconcileNode(nodeID string, now time.Time) (candidatepkg.Stored, []protocol.Task, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return candidatepkg.Stored{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	var vless int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, nodeID).Scan(&role, &vless)
	if errors.Is(err, sql.ErrNoRows) {
		return candidatepkg.Stored{}, nil, common.ErrNodeNotFound
	}
	if err != nil {
		return candidatepkg.Stored{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(coredomain.RoleHTTP) {
		// An external HTTP proxy has no Agent, candidate or readback; a
		// reconcile would have nowhere to go (Ruling R11).
		return candidatepkg.Stored{}, nil, errors.New("NODE_ROLE_INVALID: an external http proxy has no agent candidate")
	}
	var unfinished int
	if err = tx.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished); err != nil {
		return candidatepkg.Stored{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if unfinished != 0 {
		return candidatepkg.Stored{}, nil, errors.New("TASKS_IN_PROGRESS")
	}
	var revision int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return candidatepkg.Stored{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	candidate, err := BuildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return candidatepkg.Stored{}, nil, err
	}
	if candidate.Role != coredomain.Role(role) || candidate.VLESSPort != vless {
		return candidatepkg.Stored{}, nil, errors.New("CANDIDATE_MISMATCH: candidate does not match the node")
	}
	// One publication path for every role: the task envelope carries the
	// revision only, and an Out's admission lives in the link key its own
	// candidate carries.
	tasks, err := candidatepkg.PublishTx(tx, nodeID, candidate, now)
	if err != nil {
		return candidatepkg.Stored{}, nil, err
	}
	if err = tx.Commit(); err != nil {
		return candidatepkg.Stored{}, nil, errors.New(common.CodeDatabaseUnavailable)
	}
	stored, err := s.Candidates.Candidate(nodeID, candidate.Revision)
	if err != nil {
		return candidatepkg.Stored{}, nil, fmt.Errorf("CANDIDATE_READBACK_FAILED: %w", err)
	}
	return stored, tasks, nil
}

// pendingTasksAt returns every unfinished task for one node: pending, applying
// and verifying all need to be redelivered after an Agent reconnect. Revision
// ascending preserves the original enqueue order.
func (s *Store) PendingTasksAt(nodeID string, limit int, now time.Time) ([]protocol.Task, error) {
	if limit < 1 || limit > 32 {
		limit = 8
	}
	// Reconcile the persisted subscriber intent before handing out tasks, so
	// a change that happened after the last publication is not missed by this
	// poll. The drain uses its own transaction and never fails the poll. An Out
	// poll republishes its own authorization first and then releases the Lines
	// it serves; a Line poll authorizes itself at its Out first.
	s.drainNodeCoordination(nodeID, now)
	rows, err := s.DB.Query(`SELECT t.operation_id, t.revision, t.idempotency_key, t.kind, t.params
 FROM agent_tasks t JOIN nodes n ON n.id=t.node_id
 WHERE t.node_id=? AND n.last_heartbeat>=? AND t.status IN ('pending','applying','verifying')
 ORDER BY t.revision ASC LIMIT ?`, nodeID, now.Add(-common.OfflineAfter).Unix(), limit)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
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
			return nil, errors.New(common.CodeDatabaseUnavailable)
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
func (s *Store) ReportResultAudited(nodeID string, res protocol.TaskResult, now time.Time) (bool, error) {
	if err := protocol.ValidateTaskResult(res); err != nil {
		return false, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return false, errors.New(common.CodeDatabaseUnavailable)
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
		return false, errors.New(common.CodeDatabaseUnavailable)
	}
	if taskNodeID != nodeID {
		return false, errors.New("TASK_NOT_FOUND")
	}
	detailToStore := res.Detail
	var readback coredomain.Readback
	if res.Status == common.TaskStatusHealthy && (taskKind == protocol.KindConfigApply || taskKind == protocol.KindConfigReadback) {
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
	if common.TaskStatusTerminal(current) {
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
		return false, errors.New(common.CodeDatabaseUnavailable)
	}
	if res.Status == common.TaskStatusHealthy {
		lastSuccess := now.UTC().Format(time.RFC3339)
		if _, err = tx.Exec(`UPDATE nodes SET last_success=?, last_success_at=?, updated_at=? WHERE id=?`, lastSuccess, stamp, stamp, nodeID); err != nil {
			return false, errors.New(common.CodeDatabaseUnavailable)
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
				return false, errors.New(common.CodeDatabaseUnavailable)
			}
			// A deleting subscriber becomes deleted only once the Line proved
			// the exact desired snapshot without its historical UUIDs. The
			// check runs in this transaction, directly after the observation,
			// so the result request itself can complete the deletion. Failing
			// to finalize never rejects the recorded result: the state stays
			// "deleting" and the next drain retries.
			_ = s.Subscribers.FinalizeDeletingTx(tx, nodeID, now)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, errors.New(common.CodeDatabaseUnavailable)
	}
	// A finished chain may make the persisted subscriber intent publishable
	// (removal of a deleted subscriber, follow-up after a changed snapshot).
	// It is also the Out-side readback event: a confirmed Out revision is what
	// lets that Out report healthy. The drain owns its transaction and never
	// fails the recorded result.
	s.drainNodeCoordination(nodeID, now)
	return true, nil
}

func validateReadbackTx(tx *sql.Tx, nodeID string, configRevision int64, readback coredomain.Readback) error {
	// readback.Validate deliberately binds the Agent version and digest shape.
	// The Agent digest is claimed by the node; only the kernel digest is
	// compared with the Hub's pinned architecture manifest. No Agent binary
	// manifest is fabricated here.
	if err := readback.Validate(); err != nil {
		return common.ErrReadbackInvalid
	}
	if !readback.LocalActive || readback.ActiveRevision != configRevision {
		return errors.New("READBACK_MISMATCH")
	}
	release, ok := coredomain.KernelReleaseFor(readback.Architecture)
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
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if readback.ConfigSHA256 != candidateHash {
		return errors.New("READBACK_CONFIG_MISMATCH")
	}
	var document coredomain.CandidateDocument
	if err := json.Unmarshal([]byte(candidateJSON), &document); err != nil {
		return errors.New("READBACK_CANDIDATE_CORRUPT")
	}
	if document.NodeID != nodeID || string(document.Role) != role || document.VLESSPort != vlessPort {
		return errors.New("READBACK_ROLE_MISMATCH")
	}
	// `observed_out_default_deny` is still recorded and reported, but it is no
	// longer an admission gate: the `inet meshmux_out` table is retired, so an
	// Out's reachability is proven by its link-key listener and readback, not by
	// a source allowlist.
	return nil
}

// decodeReadbackDetail accepts exactly the nine Readback fields and returns a
// canonical representation. This prevents extra fields, duplicate keys, nulls
// and other loose JSON from being treated as valid local evidence.
func decodeReadbackDetail(detail string) (coredomain.Readback, string, error) {
	if len(detail) == 0 || len(detail) >= 512 {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	dec := json.NewDecoder(strings.NewReader(detail))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return coredomain.Readback{}, "", common.ErrReadbackInvalid
		}
		key, ok := keyToken.(string)
		if !ok {
			return coredomain.Readback{}, "", common.ErrReadbackInvalid
		}
		if _, duplicate := fields[key]; duplicate {
			return coredomain.Readback{}, "", common.ErrReadbackInvalid
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || len(raw) == 0 || string(raw) == "null" {
			return coredomain.Readback{}, "", common.ErrReadbackInvalid
		}
		fields[key] = raw
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	required := []string{
		"active_revision", "agent_sha256", "agent_version", "architecture",
		"config_sha256", "kernel_sha256", "kernel_version", "local_active",
		"out_default_deny",
	}
	if len(fields) != len(required) {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return coredomain.Readback{}, "", common.ErrReadbackInvalid
		}
	}
	var readback coredomain.Readback
	if json.Unmarshal(fields["architecture"], &readback.Architecture) != nil ||
		json.Unmarshal(fields["agent_version"], &readback.AgentVersion) != nil ||
		json.Unmarshal(fields["agent_sha256"], &readback.AgentSHA256) != nil ||
		json.Unmarshal(fields["kernel_version"], &readback.KernelVersion) != nil ||
		json.Unmarshal(fields["kernel_sha256"], &readback.KernelSHA256) != nil ||
		json.Unmarshal(fields["active_revision"], &readback.ActiveRevision) != nil ||
		json.Unmarshal(fields["config_sha256"], &readback.ConfigSHA256) != nil ||
		json.Unmarshal(fields["local_active"], &readback.LocalActive) != nil ||
		json.Unmarshal(fields["out_default_deny"], &readback.OutDefaultDeny) != nil {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	canonical, err := json.Marshal(readback)
	if err != nil || len(canonical) >= 512 {
		return coredomain.Readback{}, "", common.ErrReadbackInvalid
	}
	return readback, string(canonical), nil
}

// allowedTransition is the frozen Agent result state machine. pending may jump
// straight to healthy to keep the read-only status tasks usable; applying and
// verifying may only move forward. rollback requires an applied task.
func allowedTransition(current, next string) bool {
	switch current {
	case common.TaskStatusPending:
		switch next {
		case common.TaskStatusApplying, common.TaskStatusVerifying, common.TaskStatusHealthy, common.TaskStatusPartial, common.TaskStatusFailed:
			return true
		}
	case common.TaskStatusApplying:
		switch next {
		case common.TaskStatusApplying, common.TaskStatusVerifying, common.TaskStatusHealthy, common.TaskStatusPartial, common.TaskStatusFailed, common.TaskStatusRolledBack:
			return true
		}
	case common.TaskStatusVerifying:
		return next == common.TaskStatusVerifying || common.TaskStatusTerminal(next)
	}
	return false
}
