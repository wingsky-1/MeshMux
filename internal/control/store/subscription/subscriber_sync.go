package subscription

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
	"database/sql"
	"errors"
	"time"

	storecandidate "github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"
	storepolicy "github.com/wingsky-1/MeshMux/internal/control/store/policy"
	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// The reference source is the Task-4 edge table: the subscription selection is
// what the Line has to serve. The credential table is unioned in because a
// dropped Line still has to remove the historical UUID from its snapshot, so a
// deactivated credential can never stay authorized. Both reads are in the
// caller's transaction, so a half-applied selection cannot be observed.
// HistoricalLineIDsTx returns every Line the subscriber references now plus
// every Line that ever carried a credential of it.
func HistoricalLineIDsTx(tx *sql.Tx, subscriberID string) ([]string, error) {
	rows, err := tx.Query(`SELECT node_id FROM (
	  SELECT node_id FROM subscription_lines WHERE subscriber_id=?
	  UNION
	  SELECT node_id FROM proxy_credentials WHERE subscriber_id=?
	) ORDER BY node_id`, subscriberID, subscriberID)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return ids, nil
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
// being republished from a stale copy (see policy.LineServerRouteTx). A credential
// change therefore cannot keep a route alive that the current policy and Out
// facts no longer justify.
func lineSyncCandidateTx(tx *sql.Tx, nodeID string, revision int64, now time.Time) (nodedomain.Candidate, error) {
	candidate, err := storenode.BuildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return nodedomain.Candidate{}, err
	}
	if candidate.Role != nodedomain.RoleEdge || candidate.Reality == nil {
		return nodedomain.Candidate{}, errors.New("LINE_NOT_CONFIGURED: line transport is not configured")
	}
	route, err := storepolicy.LineServerRouteTx(tx, nodeID, now)
	if err != nil {
		return nodedomain.Candidate{}, err
	}
	candidate.Route = route
	return candidate, nil
}

// DesiredLineDigestTx builds the desired snapshot of one Line and returns its
// compiled digest. The revision only has to be positive; a configured Line's
// compiled bytes do not depend on it.
func DesiredLineDigestTx(tx *sql.Tx, nodeID string, now time.Time) (string, error) {
	candidate, err := lineSyncCandidateTx(tx, nodeID, 1, now)
	if err != nil {
		return "", err
	}
	return storecandidate.CompiledHash(candidate)
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
func (s *Store) DrainSubscriberNodeIntentTx(tx *sql.Tx, nodeID string, now time.Time, allowRetry bool) error {
	return drainSubscriberNodeIntentTx(tx, nodeID, now, allowRetry)
}

// DrainSubscriberNodeIntentTx is the handle-free spelling used by a caller that
// owns the transaction and has no assembled handle.
func DrainSubscriberNodeIntentTx(tx *sql.Tx, nodeID string, now time.Time, allowRetry bool) error {
	return drainSubscriberNodeIntentTx(tx, nodeID, now, allowRetry)
}

func drainSubscriberNodeIntentTx(tx *sql.Tx, nodeID string, now time.Time, allowRetry bool) error {
	tracked, err := storenode.LineTrackedTx(tx, nodeID)
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
	latestRevision, latestDigest, latestUsers, hasCandidate, err := storecandidate.LatestPublishedTx(tx, nodeID)
	if err != nil {
		return err
	}

	if hasCandidate && latestDigest == desiredDigest {
		candidate, buildErr := storenode.BuildLineCandidateTx(tx, nodeID, latestRevision)
		if buildErr != nil {
			return buildErr
		}
		if !storecandidate.SameUserSnapshot(candidate.Users, latestUsers) {
			return common.ErrCandidateCorrupt
		}
		confirmed, err := storecandidate.LineReadbackConfirmedTx(tx, nodeID, latestRevision, latestDigest)
		if err != nil {
			return err
		}
		if confirmed {
			return nil
		}
		unfinished, err := storecandidate.LineUnfinishedTasksTx(tx, nodeID)
		if err != nil {
			return err
		}
		if unfinished != 0 {
			// The in-flight chain finishes first; the next hook drains again.
			return nil
		}
		_, _, failed, err := storecandidate.LineLatestTaskTx(tx, nodeID)
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
		unfinished, err := storecandidate.LineUnfinishedTasksTx(tx, nodeID)
		if err != nil {
			return err
		}
		if unfinished != 0 {
			return nil
		}
	}

	offline, err := storenode.SubscriberLineNodeOfflineTx(tx, nodeID, now)
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
	if err := storenode.LineOutPublishGateTx(tx, nodeID, now); err != nil {
		return err
	}

	var nextRevision int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&nextRevision); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	candidate, err := lineSyncCandidateTx(tx, nodeID, nextRevision, now)
	if err != nil {
		return err
	}
	digest, err := storecandidate.CompiledHash(candidate)
	if err != nil {
		return err
	}
	if digest != desiredDigest {
		return common.ErrCandidateRenderFailed
	}
	if _, err := storecandidate.PublishTx(tx, nodeID, candidate, now); err != nil {
		return err
	}
	return nil
}

// subscriberLinesConvergedTx reports whether every historical Line of a
// deleting subscriber proved the exact desired snapshot that no longer carries
// any of the subscriber's UUIDs.
func subscriberLinesConvergedTx(tx *sql.Tx, subscriberID string, now time.Time) (bool, error) {
	lineIDs, err := HistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		return false, err
	}
	for _, lineID := range lineIDs {
		desiredDigest, err := DesiredLineDigestTx(tx, lineID, now)
		if err != nil {
			return false, err
		}
		revision, digest, users, found, err := storecandidate.LatestPublishedTx(tx, lineID)
		if err != nil {
			return false, err
		}
		if !found || digest != desiredDigest {
			return false, nil
		}
		confirmed, err := storecandidate.LineReadbackConfirmedTx(tx, lineID, revision, digest)
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
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var uuid string
		if err := rows.Scan(&uuid); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out[uuid] = true
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}

// FinalizeDeletingSubscribersTx moves a deleting subscriber to deleted only
// after every affected Line confirmed the exact snapshot without its UUIDs.
// The state is written directly: setSubscriberState must not be nested in the
// caller's transaction.
func (s *Store) FinalizeDeletingTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return finalizeDeletingSubscribersTx(tx, nodeID, now)
}

// FinalizeDeletingSubscribersTx is the handle-free spelling of FinalizeDeletingTx.
func FinalizeDeletingSubscribersTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return finalizeDeletingSubscribersTx(tx, nodeID, now)
}

func finalizeDeletingSubscribersTx(tx *sql.Tx, nodeID string, now time.Time) error {
	rows, err := tx.Query(`SELECT DISTINCT s.id FROM subscribers s
 JOIN proxy_credentials c ON c.subscriber_id=s.id
 WHERE s.state='deleting' AND c.node_id=?`, nodeID)
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return errors.New(common.CodeDatabaseUnavailable)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if err := rows.Err(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
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
 WHERE id=? AND state=?`, string(coredomain.StateDeleted), now.Unix(), id, string(coredomain.StateDeleting)); err != nil {
			return errors.New(common.CodeDatabaseUnavailable)
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
	if err := coredomain.ValidateID(subscriberID); err != nil {
		return common.ErrSubscriberIDInvalid()
	}
	// The Out direction is deliberately not drained here. A Line may only
	// publish after the Out that serves it confirmed the authorization, so an
	// explicit subscriber publication that races the Out chain fails the gate
	// with OUT_NOT_AUTHORIZED instead of publishing an egress the Out would
	// drop. The Out's own result event releases the Line (drainLinesForOut).
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return err
	}
	lineIDs, err := HistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		return err
	}
	var firstErr error
	for _, nodeID := range lineIDs {
		if err := s.DrainSubscriberNodeIntentTx(tx, nodeID, now, allowRetry); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := s.FinalizeDeletingTx(tx, nodeID, now); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if firstErr != nil {
		return firstErr
	}
	return nil
}

// drainSubscriberNode begins its own transaction and drains one Line. It is
// the recovery hook of the Agent endpoints. Failures must not fail the request
// they serve: the next poll, heartbeat or result retries the drain.
func (s *Store) DrainNode(nodeID string, now time.Time) {
	tx, err := s.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if err := s.DrainSubscriberNodeIntentTx(tx, nodeID, now, false); err != nil {
		return
	}
	if err := s.FinalizeDeletingTx(tx, nodeID, now); err != nil {
		return
	}
	_ = tx.Commit()
}

// SubscriberLineSyncViewTx evaluates one Line against the persisted desired
// snapshot and the exact readback evidence.
// LineSyncViewTx is the node port's spelling of SubscriberLineSyncViewTx.
func (s *Store) LineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error) {
	return s.SubscriberLineSyncViewTx(tx, nodeID, now)
}

// SubscriberLineSyncViewTx evaluates one Line against the persisted desired
// snapshot and the exact readback evidence.
// SubscriberLineSyncViewTx is the handle-free spelling used by a caller that
// owns the transaction and has no assembled handle.
func SubscriberLineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error) {
	return subscriberLineSyncViewTx(tx, nodeID, now, func(tx *sql.Tx, lineID string, now time.Time) (string, error) {
		return DesiredLineDigestTx(tx, lineID, now)
	}, storenode.LineOutEgressStatusTx)
}

func (s *Store) SubscriberLineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error) {
	return subscriberLineSyncViewTx(tx, nodeID, now, DesiredLineDigestTx, storenode.LineOutEgressStatusTx)
}

func subscriberLineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time,
	desiredOf func(tx *sql.Tx, nodeID string, now time.Time) (string, error),
	egressOf func(tx *sql.Tx, nodeID string, now time.Time) (string, string, error)) (string, string, error) {
	desiredDigest, err := DesiredLineDigestTx(tx, nodeID, now)
	if err != nil {
		return common.SubscriberSyncPartial, common.SanitizeSyncCode(err.Error()), nil
	}
	offline, err := storenode.SubscriberLineNodeOfflineTx(tx, nodeID, now)
	if err != nil {
		return common.SubscriberSyncPartial, common.SanitizeSyncCode(err.Error()), nil
	}
	if offline {
		return common.SubscriberSyncPartial, "NODE_OFFLINE", nil
	}
	// A Line that egresses through an Out is only converged when the pair is:
	// the Out allowlist must authorize this Line and prove it. Reporting a
	// confirmed inbound as healthy while the Out drops the traffic would be a
	// false success.
	egress, egressCode, err := egressOf(tx, nodeID, now)
	if err != nil {
		return common.SubscriberSyncPartial, common.CodeDatabaseUnavailable, err
	}
	switch egress {
	case storenode.LineEgressDirect, storenode.LineEgressExternal, storenode.LineEgressHealthy:
	case storenode.LineEgressVerifying:
		return common.SubscriberSyncPending, egressCode, nil
	default:
		return common.SubscriberSyncPartial, egressCode, nil
	}
	revision, digest, _, found, err := storecandidate.LatestPublishedTx(tx, nodeID)
	if err != nil {
		return common.SubscriberSyncPartial, common.SanitizeSyncCode(err.Error()), nil
	}
	if !found || digest != desiredDigest {
		return common.SubscriberSyncPending, "SYNC_PENDING", nil
	}
	confirmed, err := storecandidate.LineReadbackConfirmedTx(tx, nodeID, revision, digest)
	if err != nil {
		return common.SubscriberSyncPartial, common.CodeDatabaseUnavailable, err
	}
	unfinished, err := storecandidate.LineUnfinishedTasksTx(tx, nodeID)
	if err != nil {
		return common.SubscriberSyncPartial, common.CodeDatabaseUnavailable, err
	}
	if confirmed && unfinished == 0 {
		return common.SubscriberSyncHealthy, "", nil
	}
	if unfinished != 0 {
		return common.SubscriberSyncPending, "SYNC_IN_PROGRESS", nil
	}
	_, code, failed, err := storecandidate.LineLatestTaskTx(tx, nodeID)
	if err != nil {
		return common.SubscriberSyncPartial, common.CodeDatabaseUnavailable, err
	}
	if failed {
		return common.SubscriberSyncPartial, code, nil
	}
	return common.SubscriberSyncPending, "SYNC_PENDING", nil
}
