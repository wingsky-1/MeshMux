package candidate

// The convergence reads of one Line.
//
// A Line is converged when the candidate the Hub published is the one the Agent
// proved: the same revision, the same compiled digest and a complete healthy
// four-task chain for that revision. All four facts live in the tables this
// package owns (node_candidates, agent_tasks) plus the node's observed columns,
// so the reads belong here rather than in either domain that asks for them.
//
// The subscriber domain and the Out domain both evaluate convergence, and
// neither may import the other; putting the reads in this leaf is what lets both
// ask the same question without a second implementation.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// ChainKinds is the fixed publication chain of one candidate
// revision. Every revision is published as exactly these four tasks in this
// order.
var ChainKinds = protocol.PublicationKinds

// chainTask is the latest row of one kind within one candidate
// revision chain.
type chainTask struct {
	Revision  int64
	Status    string
	ErrorCode string
}

// ChainTasksTx returns the latest row of every fixed-chain kind that
// belongs to exactly one candidate revision.
//
// Re-pairing may append a replacement chain for the same candidate revision
// after the previous one was terminated as IDENTITY_REPLACED. Only the latest
// row of each kind is authoritative, so an older terminated chain is never
// mistaken for the current one. Old chains are read-only here; this function
// never cancels, rewrites or reorders delivered work.
func ChainTasksTx(tx *sql.Tx, nodeID string, revision int64) (map[string]chainTask, error) {
	rows, err := tx.Query(`SELECT kind, revision, status, error_code, params FROM agent_tasks
 WHERE node_id=? AND kind IN (?,?,?,?) ORDER BY revision DESC`,
		nodeID, protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := map[string]chainTask{}
	for rows.Next() {
		var kind, status, code, raw string
		var taskRevision int64
		if err := rows.Scan(&kind, &taskRevision, &status, &code, &raw); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		if _, seen := out[kind]; seen {
			continue
		}
		var params struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal([]byte(raw), &params) != nil || params.Revision != revision {
			continue
		}
		out[kind] = chainTask{Revision: taskRevision, Status: status, ErrorCode: code}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}

// LineChainHealthyTx reports whether the complete latest chain of
// exactly one candidate revision is healthy: check, stage, apply and readback
// must all be present, healthy and in publication order. A healthy readback
// alone never proves convergence when an earlier step of the same revision
// failed.
func LineChainHealthyTx(tx *sql.Tx, nodeID string, revision int64) (bool, error) {
	tasks, err := ChainTasksTx(tx, nodeID, revision)
	if err != nil {
		return false, err
	}
	if len(tasks) != len(ChainKinds) {
		return false, nil
	}
	for index, kind := range ChainKinds {
		task, ok := tasks[kind]
		if !ok || task.Status != common.TaskStatusHealthy {
			return false, nil
		}
		if index > 0 {
			previous := tasks[ChainKinds[index-1]]
			if task.Revision <= previous.Revision {
				return false, nil
			}
		}
	}
	return true, nil
}

// lineLatestChainTx returns the latest fixed chain of one Line. The
// revision is read from the newest config task, so a stale failed chain of an
// older candidate revision never decides the state of a newer publication.
func lineLatestChainTx(tx *sql.Tx, nodeID string) (map[string]chainTask, bool, error) {
	var raw string
	err := tx.QueryRow(`SELECT params FROM agent_tasks
 WHERE node_id=? AND kind IN (?,?,?,?) ORDER BY revision DESC LIMIT 1`,
		nodeID, protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New(common.CodeDatabaseUnavailable)
	}
	var params struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal([]byte(raw), &params) != nil || params.Revision < 1 {
		return nil, false, nil
	}
	tasks, err := ChainTasksTx(tx, nodeID, params.Revision)
	if err != nil {
		return nil, false, err
	}
	return tasks, len(tasks) > 0, nil
}

// LineReadbackConfirmedTx reports whether the node itself proved
// exactly the published candidate: same revision, same compiled digest and a
// complete healthy chain for that revision.
func LineReadbackConfirmedTx(tx *sql.Tx, nodeID string, revision int64, digest string) (bool, error) {
	var observedRevision int64
	var observedDigest string
	var observedAt int64
	err := tx.QueryRow(`SELECT observed_revision, observed_config_sha256, observed_at FROM nodes WHERE id=?`, nodeID).
		Scan(&observedRevision, &observedDigest, &observedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New(common.CodeDatabaseUnavailable)
	}
	if observedAt <= 0 || observedRevision != revision || observedDigest == "" || observedDigest != digest {
		return false, nil
	}
	return LineChainHealthyTx(tx, nodeID, revision)
}

// LineUnfinishedTasksTx counts the fixed chain that is still in
// flight for one Line.
func LineUnfinishedTasksTx(tx *sql.Tx, nodeID string) (int, error) {
	var unfinished int
	err := tx.QueryRow(`SELECT count(*) FROM agent_tasks
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished)
	if err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	return unfinished, nil
}

// LineLatestTaskTx reports the decisive status of the newest fixed
// chain, preferring the earliest step that did not end healthy. The boolean is
// true only when that step is terminal without success. A per-revision chain
// failure can therefore never be hidden behind a later healthy readback of the
// same revision, and an older failed chain never decides a newer revision.
func LineLatestTaskTx(tx *sql.Tx, nodeID string) (status, code string, terminalFailure bool, err error) {
	tasks, found, err := lineLatestChainTx(tx, nodeID)
	if err != nil {
		return "", "", false, err
	}
	if found {
		for _, kind := range ChainKinds {
			task, ok := tasks[kind]
			if !ok {
				continue
			}
			switch task.Status {
			case common.TaskStatusHealthy:
				continue
			case common.TaskStatusPartial, common.TaskStatusFailed, common.TaskStatusRolledBack:
				return task.Status, common.SanitizeSyncCode(task.ErrorCode), true, nil
			default:
				return task.Status, "", false, nil
			}
		}
		return common.SubscriberSyncHealthy, "", false, nil
	}
	scanErr := tx.QueryRow(`SELECT status, error_code FROM agent_tasks
 WHERE node_id=? ORDER BY revision DESC LIMIT 1`, nodeID).Scan(&status, &code)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if scanErr != nil {
		return "", "", false, errors.New(common.CodeDatabaseUnavailable)
	}
	switch status {
	case common.TaskStatusPartial, common.TaskStatusFailed, common.TaskStatusRolledBack:
		return status, common.SanitizeSyncCode(code), true, nil
	default:
		return status, "", false, nil
	}
}

// CompiledHash returns the SHA-256 of the compiled sing-box bytes.
// For a configured Line the compiled document does not depend on the revision:
// its inbound tag is derived from the node identity.
func CompiledHash(candidate node.Candidate) (string, error) {
	compiled, err := node.CompileCandidate(candidate)
	if err != nil {
		return "", common.ErrCandidateRenderFailed
	}
	sum := sha256.Sum256(compiled)
	return hex.EncodeToString(sum[:]), nil
}

// LatestPublishedTx reads the latest immutable candidate of a Line.
// The stored digest is re-derived from the document, so a corrupted row fails
// closed instead of being compared as if it were trustworthy.
func LatestPublishedTx(tx *sql.Tx, nodeID string) (revision int64, digest string, users []node.VLESSUser, found bool, err error) {
	var document []byte
	var storedDigest string
	scanErr := tx.QueryRow(`SELECT revision, candidate_json, config_sha256 FROM node_candidates
 WHERE node_id=? ORDER BY revision DESC LIMIT 1`, nodeID).Scan(&revision, &document, &storedDigest)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return 0, "", nil, false, nil
	}
	if scanErr != nil {
		return 0, "", nil, false, errors.New(common.CodeDatabaseUnavailable)
	}
	digest, err = SHA256(document)
	if err != nil {
		return 0, "", nil, false, common.ErrCandidateCorrupt
	}
	if digest != storedDigest {
		return 0, "", nil, false, common.ErrCandidateCorrupt
	}
	var parsed node.CandidateDocument
	if err := json.Unmarshal(document, &parsed); err != nil || parsed.Revision != revision {
		return 0, "", nil, false, common.ErrCandidateCorrupt
	}
	return revision, digest, parsed.Users, true, nil
}

// SameUserSnapshot compares two user arrays by credential identity and UUID.
func SameUserSnapshot(left, right []node.VLESSUser) bool {
	if len(left) != len(right) {
		return false
	}
	byCredential := make(map[string]string, len(left))
	for _, user := range left {
		byCredential[user.CredentialID] = user.UUID
	}
	for _, user := range right {
		uuid, ok := byCredential[user.CredentialID]
		if !ok || uuid != user.UUID {
			return false
		}
	}
	return true
}
