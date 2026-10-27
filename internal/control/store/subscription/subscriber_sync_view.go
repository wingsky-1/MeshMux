package subscription

// Subscriber convergence projection for the management page.
//
// The function here is a store read: it opens exactly one read-only
// transaction over the subscriber intent, the immutable Line revision chain and
// the Line readback. It lives beside the other subscriber sync store code and
// is never called from a request before a page model is built.

import (
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// SubscriberLineSyncSnapshot is the precise convergence evidence of one Line
// for exactly one subscriber, as derived from the persisted intent and the
// Line's own immutable revision chain plus readback.
type SubscriberLineSyncSnapshot struct {
	NodeID string
	Status string
	Code   string
}

// SubscriberSyncSnapshot is the subscriber-level convergence summary together
// with the per-Line evidence it was aggregated from.
type SubscriberSyncSnapshot struct {
	Status string
	Code   string
	Lines  []SubscriberLineSyncSnapshot
}

// subscriberSyncView evaluates the subscriber's convergence against every
// historical Line and returns the per-Line evidence it aggregated.
//
// The snapshot is read-only. Exactly one transaction is opened, so the desired
// snapshot, the immutable revision chain and the local readback are all read
// from one consistent view. getSubscriberTx and every per-Line query run in
// that transaction: the store uses a single connection (SetMaxOpenConns(1)),
// so a nested store call here would deadlock.
//
// The aggregation mirrors the per-Line summary in subscriber_sync.go,
// including its known quirk: a later partial Line does not overwrite a code
// that an earlier pending Line already set. The quirk is intentionally
// reproduced so the page and the store summary can never disagree; fixing it
// belongs to subscriber_sync.go, not to this projection.
func (s *Store) SubscriberSyncView(subscriberID string, now time.Time) (SubscriberSyncSnapshot, error) {
	snapshot := SubscriberSyncSnapshot{Lines: []SubscriberLineSyncSnapshot{}}
	if err := coredomain.ValidateID(subscriberID); err != nil {
		snapshot.Status = common.SubscriberSyncPending
		snapshot.Code = "SUBSCRIBER_ID_INVALID"
		return snapshot, nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return snapshot, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		snapshot.Status = common.SubscriberSyncPending
		snapshot.Code = common.SanitizeSyncCode(err.Error())
		return snapshot, err
	}
	lineIDs, err := HistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		snapshot.Status = common.SubscriberSyncPending
		snapshot.Code = common.CodeDatabaseUnavailable
		return snapshot, err
	}
	snapshot.Status = common.SubscriberSyncHealthy
	for _, nodeID := range lineIDs {
		lineStatus, lineCode, err := s.SubscriberLineSyncViewTx(tx, nodeID, now)
		if err != nil {
			snapshot.Status = common.SubscriberSyncPending
			snapshot.Code = common.CodeDatabaseUnavailable
			return snapshot, err
		}
		snapshot.Lines = append(snapshot.Lines, SubscriberLineSyncSnapshot{
			NodeID: nodeID, Status: lineStatus, Code: lineCode,
		})
		// TODO(#7): this aggregation intentionally copies the quirk of
		// subscriberSyncStatus at store_subscriber_sync.go:697-718, where a
		// partial Line keeps an earlier pending code. Fix both together.
		if lineStatus == common.SubscriberSyncPartial {
			snapshot.Status = common.SubscriberSyncPartial
			if snapshot.Code == "" {
				snapshot.Code = lineCode
			}
			continue
		}
		if lineStatus == common.SubscriberSyncPending && snapshot.Status != common.SubscriberSyncPartial {
			snapshot.Status = common.SubscriberSyncPending
			if snapshot.Code == "" {
				snapshot.Code = lineCode
			}
		}
	}
	return snapshot, nil
}
