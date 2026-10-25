package store

// Subscriber synchronization reconciles the durable subscriber/credential
// state with the Lines that serve the VLESS credentials.
//
// There is no second source of truth: the desired snapshot of a Line is always
// derived from the subscriber table, the credential table and the stored Line
// transport. No generation table and no sync-state table exist. The immutable
// candidate revisions and the fixed Agent task chain stay the only publication
// and confirmation records.
//
// A subscriber change therefore survives a crash before any task is enqueued:
// the next Agent poll, heartbeat or result drains the Line again from the
// persisted intent.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The subscriber-level synchronization summary.
const (
	SubscriberSyncHealthy = "healthy"
	SubscriberSyncPending = "pending"
	SubscriberSyncPartial = "partial"
)

// SyncErrorCodePattern bounds a sanitized status code. Anything else is
// replaced by a generic code, so an internal message can never reach the UI.
var SyncErrorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// sanitizeSubscriberSyncCode keeps only the stable code part of an error.
func SanitizeSubscriberSyncCode(raw string) string {
	code := strings.TrimSpace(raw)
	if index := strings.Index(code, ":"); index > 0 {
		code = strings.TrimSpace(code[:index])
	}
	if !SyncErrorCodePattern.MatchString(code) {
		return "SYNC_FAILED"
	}
	return code
}

// subscriberHistoricalLineIDsTx returns every Line that ever carried a
// credential of the subscriber. A dropped Line still has to remove the
// historical UUID from its snapshot, so it is included.
func subscriberHistoricalLineIDsTx(tx *sql.Tx, subscriberID string) ([]string, error) {
	rows, err := tx.Query(`SELECT DISTINCT node_id FROM proxy_credentials WHERE subscriber_id=? ORDER BY node_id`, subscriberID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return ids, nil
}

// SubscriberLineNodeOfflineTx reports whether a Line is currently outside the
// delivery window used by the task endpoints.
func SubscriberLineNodeOfflineTx(tx *sql.Tx, nodeID string, now time.Time) (bool, error) {
	var status string
	var lastHeartbeat int64
	err := tx.QueryRow(`SELECT status, last_heartbeat FROM nodes WHERE id=?`, nodeID).Scan(&status, &lastHeartbeat)
	if errors.Is(err, sql.ErrNoRows) {
		return true, errors.New("NODE_NOT_FOUND")
	}
	if err != nil {
		return true, errors.New("DATABASE_UNAVAILABLE")
	}
	if status == "pending" || lastHeartbeat == 0 {
		return true, nil
	}
	return now.Sub(time.Unix(lastHeartbeat, 0)) > OfflineAfter, nil
}

// lineSyncCandidateTx builds the complete desired candidate of one Line.
//
// Only an Edge node with stored Line settings is a credential-carrying Line.
// The builder returns the full active user set, so publishing it can never
// remove the credentials of another subscriber.
//
// The route is derived from the live intent, never copied from the previous
// candidate: a Line keeps the server policy that is active now, and an Out that
// was unbound, deleted or went offline invalidates the old route instead of
// being republished from a stale copy (see lineServerRouteTx). A credential
// change therefore cannot keep a route alive that the current policy and Out
// facts no longer justify.
func lineSyncCandidateTx(tx *sql.Tx, nodeID string, revision int64, now time.Time) (node.Candidate, error) {
	candidate, err := BuildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return node.Candidate{}, err
	}
	if candidate.Role != node.RoleEdge || candidate.Reality == nil {
		return node.Candidate{}, errors.New("LINE_NOT_CONFIGURED: line transport is not configured")
	}
	route, err := LineServerRouteTx(tx, nodeID, now)
	if err != nil {
		return node.Candidate{}, err
	}
	candidate.Route = route
	return candidate, nil
}

// compiledCandidateHash returns the SHA-256 of the compiled sing-box bytes.
// For a configured Line the compiled document does not depend on the revision:
// its inbound tag is derived from the node identity.
func compiledCandidateHash(candidate node.Candidate) (string, error) {
	compiled, err := node.CompileCandidate(candidate)
	if err != nil {
		return "", errors.New("CANDIDATE_RENDER_FAILED")
	}
	sum := sha256.Sum256(compiled)
	return hex.EncodeToString(sum[:]), nil
}

// LatestPublishedCandidateTx reads the latest immutable candidate of a Line.
// The stored digest is re-derived from the document, so a corrupted row fails
// closed instead of being compared as if it were trustworthy.
func LatestPublishedCandidateTx(tx *sql.Tx, nodeID string) (revision int64, digest string, users []node.VLESSUser, found bool, err error) {
	var document []byte
	var storedDigest string
	scanErr := tx.QueryRow(`SELECT revision, candidate_json, config_sha256 FROM node_candidates
 WHERE node_id=? ORDER BY revision DESC LIMIT 1`, nodeID).Scan(&revision, &document, &storedDigest)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return 0, "", nil, false, nil
	}
	if scanErr != nil {
		return 0, "", nil, false, errors.New("DATABASE_UNAVAILABLE")
	}
	digest, err = CandidateSHA256(document)
	if err != nil {
		return 0, "", nil, false, errors.New("CANDIDATE_CORRUPT")
	}
	if digest != storedDigest {
		return 0, "", nil, false, errors.New("CANDIDATE_CORRUPT")
	}
	var parsed node.CandidateDocument
	if err := json.Unmarshal(document, &parsed); err != nil || parsed.Revision != revision {
		return 0, "", nil, false, errors.New("CANDIDATE_CORRUPT")
	}
	return revision, digest, parsed.Users, true, nil
}

// SubscriberChainKinds is the fixed publication chain of one candidate
// revision. Every revision is published as exactly these four tasks in this
// order.
var SubscriberChainKinds = protocol.PublicationKinds

// subscriberChainTask is the latest row of one kind within one candidate
// revision chain.
type subscriberChainTask struct {
	Revision  int64
	Status    string
	ErrorCode string
}

// subscriberChainTasksTx returns the latest row of every fixed-chain kind that
// belongs to exactly one candidate revision.
//
// Re-pairing may append a replacement chain for the same candidate revision
// after the previous one was terminated as IDENTITY_REPLACED. Only the latest
// row of each kind is authoritative, so an older terminated chain is never
// mistaken for the current one. Old chains are read-only here; this function
// never cancels, rewrites or reorders delivered work.
func subscriberChainTasksTx(tx *sql.Tx, nodeID string, revision int64) (map[string]subscriberChainTask, error) {
	rows, err := tx.Query(`SELECT kind, revision, status, error_code, params FROM agent_tasks
 WHERE node_id=? AND kind IN (?,?,?,?) ORDER BY revision DESC`,
		nodeID, protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := map[string]subscriberChainTask{}
	for rows.Next() {
		var kind, status, code, raw string
		var taskRevision int64
		if err := rows.Scan(&kind, &taskRevision, &status, &code, &raw); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
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
		out[kind] = subscriberChainTask{Revision: taskRevision, Status: status, ErrorCode: code}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// SubscriberLineChainHealthyTx reports whether the complete latest chain of
// exactly one candidate revision is healthy: check, stage, apply and readback
// must all be present, healthy and in publication order. A healthy readback
// alone never proves convergence when an earlier step of the same revision
// failed.
func SubscriberLineChainHealthyTx(tx *sql.Tx, nodeID string, revision int64) (bool, error) {
	tasks, err := subscriberChainTasksTx(tx, nodeID, revision)
	if err != nil {
		return false, err
	}
	if len(tasks) != len(SubscriberChainKinds) {
		return false, nil
	}
	for index, kind := range SubscriberChainKinds {
		task, ok := tasks[kind]
		if !ok || task.Status != "healthy" {
			return false, nil
		}
		if index > 0 {
			previous := tasks[SubscriberChainKinds[index-1]]
			if task.Revision <= previous.Revision {
				return false, nil
			}
		}
	}
	return true, nil
}

// subscriberLineLatestChainTx returns the latest fixed chain of one Line. The
// revision is read from the newest config task, so a stale failed chain of an
// older candidate revision never decides the state of a newer publication.
func subscriberLineLatestChainTx(tx *sql.Tx, nodeID string) (map[string]subscriberChainTask, bool, error) {
	var raw string
	err := tx.QueryRow(`SELECT params FROM agent_tasks
 WHERE node_id=? AND kind IN (?,?,?,?) ORDER BY revision DESC LIMIT 1`,
		nodeID, protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("DATABASE_UNAVAILABLE")
	}
	var params struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal([]byte(raw), &params) != nil || params.Revision < 1 {
		return nil, false, nil
	}
	tasks, err := subscriberChainTasksTx(tx, nodeID, params.Revision)
	if err != nil {
		return nil, false, err
	}
	return tasks, len(tasks) > 0, nil
}

// subscriberLineReadbackConfirmedTx reports whether the node itself proved
// exactly the published candidate: same revision, same compiled digest and a
// complete healthy chain for that revision.
func subscriberLineReadbackConfirmedTx(tx *sql.Tx, nodeID string, revision int64, digest string) (bool, error) {
	var observedRevision int64
	var observedDigest string
	var observedAt int64
	err := tx.QueryRow(`SELECT observed_revision, observed_config_sha256, observed_at FROM nodes WHERE id=?`, nodeID).
		Scan(&observedRevision, &observedDigest, &observedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	if observedAt <= 0 || observedRevision != revision || observedDigest == "" || observedDigest != digest {
		return false, nil
	}
	return SubscriberLineChainHealthyTx(tx, nodeID, revision)
}

// subscriberLineUnfinishedTasksTx counts the fixed chain that is still in
// flight for one Line.
func subscriberLineUnfinishedTasksTx(tx *sql.Tx, nodeID string) (int, error) {
	var unfinished int
	err := tx.QueryRow(`SELECT count(*) FROM agent_tasks
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, nodeID).Scan(&unfinished)
	if err != nil {
		return 0, errors.New("DATABASE_UNAVAILABLE")
	}
	return unfinished, nil
}

// SubscriberLineLatestTaskTx reports the decisive status of the newest fixed
// chain, preferring the earliest step that did not end healthy. The boolean is
// true only when that step is terminal without success. A per-revision chain
// failure can therefore never be hidden behind a later healthy readback of the
// same revision, and an older failed chain never decides a newer revision.
func SubscriberLineLatestTaskTx(tx *sql.Tx, nodeID string) (status, code string, terminalFailure bool, err error) {
	tasks, found, err := subscriberLineLatestChainTx(tx, nodeID)
	if err != nil {
		return "", "", false, err
	}
	if found {
		for _, kind := range SubscriberChainKinds {
			task, ok := tasks[kind]
			if !ok {
				continue
			}
			switch task.Status {
			case "healthy":
				continue
			case "partial", "failed", "rolled_back":
				return task.Status, SanitizeSubscriberSyncCode(task.ErrorCode), true, nil
			default:
				return task.Status, "", false, nil
			}
		}
		return "healthy", "", false, nil
	}
	scanErr := tx.QueryRow(`SELECT status, error_code FROM agent_tasks
 WHERE node_id=? ORDER BY revision DESC LIMIT 1`, nodeID).Scan(&status, &code)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if scanErr != nil {
		return "", "", false, errors.New("DATABASE_UNAVAILABLE")
	}
	switch status {
	case "partial", "failed", "rolled_back":
		return status, SanitizeSubscriberSyncCode(code), true, nil
	default:
		return status, "", false, nil
	}
}

// subscriberLineTrackedTx reports whether a node can carry proxy credentials.
// An Out node is never a subscriber Line, and an Edge node without stored Line
// settings has no transport to publish.
func subscriberLineTrackedTx(tx *sql.Tx, nodeID string) (bool, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != string(node.RoleEdge) {
		return false, nil
	}
	var settings int
	if err := tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, nodeID).Scan(&settings); err != nil {
		return false, errors.New("DATABASE_UNAVAILABLE")
	}
	return settings > 0, nil
}

// DesiredLineDigestTx builds the desired snapshot of one Line and returns its
// compiled digest. The revision only has to be positive; a configured Line's
// compiled bytes do not depend on it.
func DesiredLineDigestTx(tx *sql.Tx, nodeID string, now time.Time) (string, error) {
	candidate, err := lineSyncCandidateTx(tx, nodeID, 1, now)
	if err != nil {
		return "", err
	}
	return compiledCandidateHash(candidate)
}

// drainSubscriberNodeTx reconciles one Line with the currently persisted
// subscriber intent, without an explicit retry.
func (s *Store) DrainSubscriberNodeTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return DrainSubscriberNodeIntentTx(tx, nodeID, now, false)
}

// DrainSubscriberNodeIntentTx publishes the full desired snapshot when needed.
//
// The rules keep the operation bounded:
//   - an unfinished chain is never replaced or cancelled;
//   - an identical snapshot that was already confirmed needs no publication;
//   - an identical snapshot whose latest chain failed is only republished by
//     an explicit retry, never by an automatic poll;
//   - a changed snapshot is new intent and is published again;
//   - an offline Line keeps the durable intent but receives no state-changing
//     task.
func DrainSubscriberNodeIntentTx(tx *sql.Tx, nodeID string, now time.Time, allowRetry bool) error {
	tracked, err := subscriberLineTrackedTx(tx, nodeID)
	if err != nil {
		return err
	}
	if !tracked {
		// An Out node or an Edge node without stored Line settings carries no
		// proxy credentials and is not part of subscriber synchronization.
		return nil
	}
	desiredDigest, err := DesiredLineDigestTx(tx, nodeID, now)
	if err != nil {
		return err
	}
	latestRevision, latestDigest, latestUsers, hasCandidate, err := LatestPublishedCandidateTx(tx, nodeID)
	if err != nil {
		return err
	}

	if hasCandidate && latestDigest == desiredDigest {
		candidate, buildErr := BuildLineCandidateTx(tx, nodeID, latestRevision)
		if buildErr != nil {
			return buildErr
		}
		if !sameUserSnapshot(candidate.Users, latestUsers) {
			return errors.New("CANDIDATE_CORRUPT")
		}
		confirmed, err := subscriberLineReadbackConfirmedTx(tx, nodeID, latestRevision, latestDigest)
		if err != nil {
			return err
		}
		if confirmed {
			return nil
		}
		unfinished, err := subscriberLineUnfinishedTasksTx(tx, nodeID)
		if err != nil {
			return err
		}
		if unfinished != 0 {
			// The in-flight chain finishes first; the next hook drains again.
			return nil
		}
		_, _, failed, err := SubscriberLineLatestTaskTx(tx, nodeID)
		if err != nil {
			return err
		}
		if failed && !allowRetry {
			// Automatic reconciliation never retries an unchanged failed
			// snapshot without bound. A new desired digest still publishes.
			return nil
		}
		if !failed && !allowRetry {
			// A completed chain that did not produce matching evidence is
			// not silently repeated by an automatic poll either.
			return nil
		}
	} else if hasCandidate {
		unfinished, err := subscriberLineUnfinishedTasksTx(tx, nodeID)
		if err != nil {
			return err
		}
		if unfinished != 0 {
			return nil
		}
	}

	offline, err := SubscriberLineNodeOfflineTx(tx, nodeID, now)
	if err != nil {
		return err
	}
	if offline {
		// Do not enqueue state-changing work for a Line that cannot receive
		// it. The subscriber tables keep the intent for a later drain.
		return errors.New("LINE_OFFLINE: line is offline; synchronization stays pending")
	}
	// The Line's own Out path has to be authorized and confirmed before the
	// Line may publish: a published snapshot would make clients use an egress
	// the Out guard still drops. A Line without an enabled binding is not
	// affected, so an Out-free deployment is unchanged.
	if err := lineOutPublishGateTx(tx, nodeID, now); err != nil {
		return err
	}

	var nextRevision int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&nextRevision); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	candidate, err := lineSyncCandidateTx(tx, nodeID, nextRevision, now)
	if err != nil {
		return err
	}
	digest, err := compiledCandidateHash(candidate)
	if err != nil {
		return err
	}
	if digest != desiredDigest {
		return errors.New("CANDIDATE_RENDER_FAILED")
	}
	if _, err := publishCandidateTx(tx, nodeID, candidate, now); err != nil {
		return err
	}
	return nil
}

// sameUserSnapshot compares two user arrays by credential identity and UUID.
func sameUserSnapshot(left, right []node.VLESSUser) bool {
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

// subscriberLinesConvergedTx reports whether every historical Line of a
// deleting subscriber proved the exact desired snapshot that no longer carries
// any of the subscriber's UUIDs.
func subscriberLinesConvergedTx(tx *sql.Tx, subscriberID string, now time.Time) (bool, error) {
	lineIDs, err := subscriberHistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		return false, err
	}
	for _, lineID := range lineIDs {
		desiredDigest, err := DesiredLineDigestTx(tx, lineID, now)
		if err != nil {
			return false, err
		}
		revision, digest, users, found, err := LatestPublishedCandidateTx(tx, lineID)
		if err != nil {
			return false, err
		}
		if !found || digest != desiredDigest {
			return false, nil
		}
		confirmed, err := subscriberLineReadbackConfirmedTx(tx, lineID, revision, digest)
		if err != nil {
			return false, err
		}
		if !confirmed {
			return false, nil
		}
		historical, err := historicalCredentialUUIDsTx(tx, subscriberID, lineID)
		if err != nil {
			return false, err
		}
		for _, user := range users {
			if historical[user.UUID] {
				return false, nil
			}
		}
	}
	return true, nil
}

// historicalCredentialUUIDsTx returns every UUID the subscriber ever had on
// one Line, including deactivated rows.
func historicalCredentialUUIDsTx(tx *sql.Tx, subscriberID, nodeID string) (map[string]bool, error) {
	rows, err := tx.Query(`SELECT uuid FROM proxy_credentials WHERE subscriber_id=? AND node_id=?`, subscriberID, nodeID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var uuid string
		if err := rows.Scan(&uuid); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out[uuid] = true
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// FinalizeDeletingSubscribersTx moves a deleting subscriber to deleted only
// after every affected Line confirmed the exact snapshot without its UUIDs.
// The state is written directly: setSubscriberState must not be nested in the
// caller's transaction.
func FinalizeDeletingSubscribersTx(tx *sql.Tx, nodeID string, now time.Time) error {
	rows, err := tx.Query(`SELECT DISTINCT s.id FROM subscribers s
 JOIN proxy_credentials c ON c.subscriber_id=s.id
 WHERE s.state='deleting' AND c.node_id=?`, nodeID)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return errors.New("DATABASE_UNAVAILABLE")
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err := rows.Err(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	for _, id := range ids {
		finalized, err := subscriberLinesConvergedTx(tx, id, now)
		if err != nil {
			return err
		}
		if !finalized {
			continue
		}
		if _, err := tx.Exec(`UPDATE subscribers SET state=?, revision=revision+1, updated_at=?
 WHERE id=? AND state=?`, string(subscription.StateDeleted), now.Unix(), id, string(subscription.StateDeleting)); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
	}
	return nil
}

// prepareSubscriberSync is the explicit publication action behind a subscriber
// change. It publishes a fresh chain when the Line failed on the same intended
// snapshot; unchanged, confirmed Lines are left untouched.
func (s *Store) PrepareSubscriberSync(subscriberID string, now time.Time) error {
	return s.reconcileSubscriberSync(subscriberID, now, true)
}

// retrySubscriberSync is the explicit retry action. It re-publishes a Line
// whose last chain failed while the desired snapshot did not change.
func (s *Store) RetrySubscriberSync(subscriberID string, now time.Time) error {
	return s.reconcileSubscriberSync(subscriberID, now, true)
}

func (s *Store) reconcileSubscriberSync(subscriberID string, now time.Time, allowRetry bool) error {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	// The Out direction is deliberately not drained here. A Line may only
	// publish after the Out that serves it confirmed the authorization, so an
	// explicit subscriber publication that races the Out chain fails the gate
	// with OUT_NOT_AUTHORIZED instead of publishing an egress the Out would
	// drop. The Out's own result event releases the Line (drainLinesForOut).
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return err
	}
	lineIDs, err := subscriberHistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		return err
	}
	var firstErr error
	for _, nodeID := range lineIDs {
		if err := DrainSubscriberNodeIntentTx(tx, nodeID, now, allowRetry); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := FinalizeDeletingSubscribersTx(tx, nodeID, now); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if firstErr != nil {
		return firstErr
	}
	return nil
}

// drainSubscriberNode begins its own transaction and drains one Line. It is
// the recovery hook of the Agent endpoints. Failures must not fail the request
// they serve: the next poll, heartbeat or result retries the drain.
func (s *Store) drainSubscriberNode(nodeID string, now time.Time) {
	tx, err := s.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if err := DrainSubscriberNodeIntentTx(tx, nodeID, now, false); err != nil {
		return
	}
	if err := FinalizeDeletingSubscribersTx(tx, nodeID, now); err != nil {
		return
	}
	_ = tx.Commit()
}

// subscriberSyncStatus reports the subscriber's convergence against every
// historical Line. It never mutates state, so it is safe to use from the Web
// projection. The returned code is a stable sanitized code or empty.
func (s *Store) SubscriberSyncStatus(subscriberID string, now time.Time) (string, string, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return SubscriberSyncPending, "SUBSCRIBER_ID_INVALID", nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return SubscriberSyncPending, "DATABASE_UNAVAILABLE", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return SubscriberSyncPending, SanitizeSubscriberSyncCode(err.Error()), err
	}
	lineIDs, err := subscriberHistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		return SubscriberSyncPending, "DATABASE_UNAVAILABLE", err
	}
	if len(lineIDs) == 0 {
		return SubscriberSyncHealthy, "", nil
	}
	status := SubscriberSyncHealthy
	code := ""
	for _, nodeID := range lineIDs {
		lineStatus, lineCode, err := SubscriberLineSyncViewTx(tx, nodeID, now)
		if err != nil {
			return SubscriberSyncPending, "DATABASE_UNAVAILABLE", err
		}
		if lineStatus == SubscriberSyncPartial {
			status = SubscriberSyncPartial
			if code == "" {
				code = lineCode
			}
			continue
		}
		if lineStatus == SubscriberSyncPending && status != SubscriberSyncPartial {
			status = SubscriberSyncPending
			if code == "" {
				code = lineCode
			}
		}
	}
	return status, code, nil
}

// SubscriberLineSyncViewTx evaluates one Line against the persisted desired
// snapshot and the exact readback evidence.
func SubscriberLineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error) {
	desiredDigest, err := DesiredLineDigestTx(tx, nodeID, now)
	if err != nil {
		return SubscriberSyncPartial, SanitizeSubscriberSyncCode(err.Error()), nil
	}
	offline, err := SubscriberLineNodeOfflineTx(tx, nodeID, now)
	if err != nil {
		return SubscriberSyncPartial, SanitizeSubscriberSyncCode(err.Error()), nil
	}
	if offline {
		return SubscriberSyncPartial, "NODE_OFFLINE", nil
	}
	// A Line that egresses through an Out is only converged when the pair is:
	// the Out allowlist must authorize this Line and prove it. Reporting a
	// confirmed inbound as healthy while the Out drops the traffic would be a
	// false success.
	egress, egressCode, err := LineOutEgressStatusTx(tx, nodeID, now)
	if err != nil {
		return SubscriberSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	switch egress {
	case LineEgressDirect, LineEgressHealthy:
	case LineEgressVerifying:
		return SubscriberSyncPending, egressCode, nil
	default:
		return SubscriberSyncPartial, egressCode, nil
	}
	revision, digest, _, found, err := LatestPublishedCandidateTx(tx, nodeID)
	if err != nil {
		return SubscriberSyncPartial, SanitizeSubscriberSyncCode(err.Error()), nil
	}
	if !found || digest != desiredDigest {
		return SubscriberSyncPending, "SYNC_PENDING", nil
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, nodeID, revision, digest)
	if err != nil {
		return SubscriberSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	unfinished, err := subscriberLineUnfinishedTasksTx(tx, nodeID)
	if err != nil {
		return SubscriberSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	if confirmed && unfinished == 0 {
		return SubscriberSyncHealthy, "", nil
	}
	if unfinished != 0 {
		return SubscriberSyncPending, "SYNC_IN_PROGRESS", nil
	}
	_, code, failed, err := SubscriberLineLatestTaskTx(tx, nodeID)
	if err != nil {
		return SubscriberSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	if failed {
		return SubscriberSyncPartial, code, nil
	}
	return SubscriberSyncPending, "SYNC_PENDING", nil
}
