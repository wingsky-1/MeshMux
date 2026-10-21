package web

// Subscriber convergence projection for the management page.
//
// The function here is a store read: it opens exactly one read-only
// transaction over the subscriber intent, the immutable Line revision chain and
// the Line readback. It lives beside the other subscriber sync store code and
// is never called from a request before a page model is built.

import (
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// subscriberSyncView evaluates the subscriber's convergence against every
// historical Line and returns the per-Line evidence it aggregated.
//
// The snapshot is read-only. Exactly one transaction is opened, so the desired
// snapshot, the immutable revision chain and the local readback are all read
// from one consistent view. getSubscriberTx and every per-Line query run in
// that transaction: the store uses a single connection (SetMaxOpenConns(1)),
// so a nested store call here would deadlock.
//
// The aggregation mirrors subscriberSyncStatus (see store_subscriber_sync.go),
// including its known quirk: a later partial Line does not overwrite a code
// that an earlier pending Line already set. The quirk is intentionally
// reproduced so the page and the store summary can never disagree; fixing it
// belongs to store_subscriber_sync.go, not to this projection.
func (s *store) subscriberSyncView(subscriberID string, now time.Time) (subscriberSyncSnapshot, error) {
	snapshot := subscriberSyncSnapshot{Lines: []subscriberLineSyncSnapshot{}}
	if err := subscription.ValidateID(subscriberID); err != nil {
		snapshot.Status = subscriberSyncPending
		snapshot.Code = "SUBSCRIBER_ID_INVALID"
		return snapshot, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return snapshot, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		snapshot.Status = subscriberSyncPending
		snapshot.Code = sanitizeSubscriberSyncCode(err.Error())
		return snapshot, err
	}
	lineIDs, err := subscriberHistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		snapshot.Status = subscriberSyncPending
		snapshot.Code = "DATABASE_UNAVAILABLE"
		return snapshot, err
	}
	snapshot.Status = subscriberSyncHealthy
	for _, nodeID := range lineIDs {
		lineStatus, lineCode, err := subscriberLineSyncViewTx(tx, nodeID, now)
		if err != nil {
			snapshot.Status = subscriberSyncPending
			snapshot.Code = "DATABASE_UNAVAILABLE"
			return snapshot, err
		}
		snapshot.Lines = append(snapshot.Lines, subscriberLineSyncSnapshot{
			NodeID: nodeID, Status: lineStatus, Code: lineCode,
		})
		// TODO(#7): this aggregation intentionally copies the quirk of
		// subscriberSyncStatus at store_subscriber_sync.go:697-718, where a
		// partial Line keeps an earlier pending code. Fix both together.
		if lineStatus == subscriberSyncPartial {
			snapshot.Status = subscriberSyncPartial
			if snapshot.Code == "" {
				snapshot.Code = lineCode
			}
			continue
		}
		if lineStatus == subscriberSyncPending && snapshot.Status != subscriberSyncPartial {
			snapshot.Status = subscriberSyncPending
			if snapshot.Code == "" {
				snapshot.Code = lineCode
			}
		}
	}
	return snapshot, nil
}
