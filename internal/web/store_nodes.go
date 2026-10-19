package web

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/agent"
)

// Node is the Hub-visible record for a Line/Out host. The ID and role are
// immutable after creation; pairing binds them to one host identity.
type Node struct {
	ID            string `json:"id"`
	Role          string `json:"role"`
	DisplayName   string `json:"display_name"`
	VlessPort     int    `json:"vless_port"`
	SSHPort       int    `json:"ssh_port"`
	Status        string `json:"status"`
	AgentVersion  string `json:"agent_version"`
	KernelVersion string `json:"kernel_version"`
	LastHeartbeat int64  `json:"last_heartbeat"`
	LastSuccess   string `json:"last_success"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
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

// createNode inserts a pending node and returns the one-time pairing code.
// The plaintext code is returned once and never persisted; only its hash is
// stored. Callers must not log the code.
func (s *store) createNode(role, displayName string, vlessPort, sshPort int, now time.Time) (Node, string, error) {
	if err := agent.ValidateNodeInputs(role, displayName, vlessPort, sshPort); err != nil {
		return Node{}, "", err
	}
	id, err := agent.NewID()
	if err != nil {
		return Node{}, "", errors.New("NODE_ID_FAILED")
	}
	code, err := agent.NewSecret()
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
	if err = tx.Commit(); err != nil {
		return Node{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	return node, code, nil
}

func (s *store) listNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT id, role, display_name, vless_port, ssh_port, status, agent_version, kernel_version, last_heartbeat, last_success, created_at, updated_at FROM nodes ORDER BY created_at ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Role, &n.DisplayName, &n.VlessPort, &n.SSHPort, &n.Status, &n.AgentVersion, &n.KernelVersion, &n.LastHeartbeat, &n.LastSuccess, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *store) getNode(id string) (Node, error) {
	var n Node
	err := s.db.QueryRow(`SELECT id, role, display_name, vless_port, ssh_port, status, agent_version, kernel_version, last_heartbeat, last_success, created_at, updated_at FROM nodes WHERE id=?`, id).Scan(&n.ID, &n.Role, &n.DisplayName, &n.VlessPort, &n.SSHPort, &n.Status, &n.AgentVersion, &n.KernelVersion, &n.LastHeartbeat, &n.LastSuccess, &n.CreatedAt, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, errors.New("NODE_NOT_FOUND")
	}
	return n, err
}

// consumePairing atomically exchanges a one-time code for a node-scoped
// identity. Replay, expiry and role mismatch are distinct rejections; an
// unknown code is a generic rejection to avoid node enumeration.
func (s *store) consumePairing(nodeID, role, code, agentVersion, kernelVersion string, now time.Time) (string, error) {
	if err := agent.ValidatePairingRequest(agent.PairingRequest{NodeID: nodeID, Role: role, PairingCode: code, AgentVersion: agentVersion, KernelVersion: kernelVersion}); err != nil {
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
		token, err := agent.NewSecret()
		if err != nil {
			return "", errors.New("IDENTITY_ISSUE_FAILED")
		}
		if _, err = tx.Exec(`INSERT OR REPLACE INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`, nodeID, tokenHash(token), now.Unix()); err != nil {
			return "", errors.New("IDENTITY_ISSUE_FAILED")
		}
		if _, err = tx.Exec(`UPDATE nodes SET status='paired', agent_version=?, kernel_version=?, last_heartbeat=?, updated_at=? WHERE id=?`, agentVersion, kernelVersion, now.Unix(), now.Unix(), nodeID); err != nil {
			return "", errors.New("DATABASE_UNAVAILABLE")
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

// authenticateAgent maps a Bearer identity to its node. Revoked or unknown
// tokens fail closed without revealing which nodes exist.
func (s *store) authenticateAgent(token string) (Node, error) {
	if len(token) != 43 {
		return Node{}, errors.New("AGENT_UNAUTHORIZED")
	}
	var n Node
	err := s.db.QueryRow(`SELECT n.id, n.role, n.display_name, n.vless_port, n.ssh_port, n.status, n.agent_version, n.kernel_version, n.last_heartbeat, n.last_success, n.created_at, n.updated_at FROM nodes n JOIN node_identities i ON n.id=i.node_id WHERE i.token_hash=? AND i.revoked=0`, tokenHash(token)).Scan(&n.ID, &n.Role, &n.DisplayName, &n.VlessPort, &n.SSHPort, &n.Status, &n.AgentVersion, &n.KernelVersion, &n.LastHeartbeat, &n.LastSuccess, &n.CreatedAt, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, errors.New("AGENT_UNAUTHORIZED")
	}
	return n, err
}

func (s *store) heartbeat(nodeID, agentVersion, kernelVersion string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE nodes SET agent_version=?, kernel_version=?, last_heartbeat=?, updated_at=? WHERE id=?`, agentVersion, kernelVersion, now.Unix(), now.Unix(), nodeID)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("NODE_NOT_FOUND")
	}
	return nil
}

func normalizeParams(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

// enqueueTask persists a validated task with exact-envelope idempotency and a
// per-node monotonic revision. An identical re-enqueue is a success (nil); the
// same operation_id or idempotency_key with different content is a conflict;
// a revision that would rewind the node chain is stale. Reserved
// upgrade/rollback kinds never reach storage because agent.ValidateTask
// rejects them first.
func (s *store) enqueueTask(task agent.Task) error {
	if err := agent.ValidateTask(task); err != nil {
		return err
	}
	params := normalizeParams(task.Params)
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	res, err := s.lookupTask(tx, "operation_id=?", task.OperationID, task, params)
	if err != nil {
		return err
	}
	if res == taskLookupExact {
		return nil
	}
	if res == taskLookupConflict {
		return errors.New("IDEMPOTENCY_CONFLICT: operation_id already recorded with different content")
	}
	res, err = s.lookupTask(tx, "idempotency_key=?", task.IdempotencyKey, task, params)
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
	now := time.Now().Unix()
	if _, err = tx.Exec(`INSERT INTO agent_tasks(operation_id, node_id, kind, revision, idempotency_key, status, params, created_at, updated_at) VALUES(?,?,?,?,?,'pending',?,?,?)`, task.OperationID, task.NodeID, task.Kind, task.Revision, task.IdempotencyKey, params, now, now); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err := tx.Commit(); err != nil {
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
func (s *store) lookupTask(tx *sql.Tx, where string, arg any, task agent.Task, params string) (taskLookup, error) {
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

// pendingTasks returns every unfinished task for one node: pending, applying
// and verifying all need to be redelivered after an Agent reconnect. Revision
// ascending preserves the original enqueue order.
func (s *store) pendingTasks(nodeID string, limit int) ([]agent.Task, error) {
	if limit < 1 || limit > 32 {
		limit = 8
	}
	rows, err := s.db.Query(`SELECT operation_id, revision, idempotency_key, kind, params FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying') ORDER BY revision ASC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	var out []agent.Task
	for rows.Next() {
		var t agent.Task
		t.Schema, t.Version = agent.Schema, agent.Version
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

// reportResult records an Agent result in one transaction scoped to
// nodeID+operation_id. A repeat of the same terminal status/error_code is a
// no-op; a different terminal rewrite is rejected; non-terminal states may be
// re-reported; the state machine never regresses.
func (s *store) reportResult(nodeID string, res agent.TaskResult) error {
	if err := agent.ValidateTaskResult(res); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var current, taskNodeID, storedCode string
	err = tx.QueryRow(`SELECT status, node_id, error_code FROM agent_tasks WHERE operation_id=?`, res.OperationID).Scan(&current, &taskNodeID, &storedCode)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("TASK_NOT_FOUND")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if taskNodeID != nodeID {
		return errors.New("TASK_NOT_FOUND")
	}
	if terminalTaskStatus(current) {
		if res.Status == current && res.ErrorCode == storedCode {
			return nil
		}
		return errors.New("TASK_ALREADY_FINAL")
	}
	if res.Status == current {
		if res.ErrorCode == storedCode {
			return nil
		}
		return errors.New("TASK_STATE_INVALID: task state cannot change in place")
	}
	if !allowedTransition(current, res.Status) {
		return errors.New("TASK_STATE_INVALID: task state cannot regress")
	}
	now := time.Now().Unix()
	if _, err = tx.Exec(`UPDATE agent_tasks SET status=?, error_code=?, updated_at=? WHERE operation_id=? AND node_id=?`, res.Status, res.ErrorCode, now, res.OperationID, nodeID); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if res.Status == "healthy" {
		lastSuccess := time.Unix(now, 0).UTC().Format(time.RFC3339)
		if _, err = tx.Exec(`UPDATE nodes SET last_success=?, updated_at=? WHERE id=?`, lastSuccess, now, nodeID); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
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
