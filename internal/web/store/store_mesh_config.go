package store

import (
	"database/sql"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// subscriptionForSubscriber resolves the proxy half of one device-scoped Mesh
// configuration. It deliberately reuses the standard subscription download
// gate: the subscriber must be active, every credential must belong to a Line
// whose current candidate is converged, and the complete desired user set must
// already be published. A paused, deleting or deleted subscriber, a stale Line
// or an unconverged credential therefore refuses the Mesh configuration before
// any Headscale pre-auth key is minted.
//
// The returned Lines are stripped of server-side secrets exactly like a public
// download; the exporter only receives the public transport fields.
func (s *Store) SubscriptionForSubscriber(subscriberID string, now time.Time) ([]subscription.Line, []subscription.Credential, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return nil, nil, ErrSubscriptionRejected
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, nil, ErrSubscriptionStoreUnavailable
	}
	defer tx.Rollback()
	lines, credentials, err := subscriptionForSubscriberTx(tx, subscriberID, now)
	if err != nil {
		return nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, ErrSubscriptionStoreUnavailable
	}
	return lines, credentials, nil
}

// subscriptionForSubscriberTx is the transaction-scoped gate shared by the
// public download and the device-scoped Mesh configuration.
func subscriptionForSubscriberTx(tx *sql.Tx, subscriberID string, now time.Time) ([]subscription.Line, []subscription.Credential, error) {
	sub, err := getSubscriberTx(tx, subscriberID)
	if err != nil {
		return nil, nil, SubscriptionStoreError(err)
	}
	if sub.State != subscription.StateActive {
		return nil, nil, ErrSubscriptionRejected
	}

	credentials, err := activeCredentialsTx(tx, subscriberID)
	if err != nil {
		return nil, nil, err
	}
	if len(credentials) == 0 || len(credentials) > maxSubscriberLines {
		return nil, nil, ErrSubscriptionRejected
	}

	lines := make([]subscription.Line, 0, len(credentials))
	for _, credential := range credentials {
		line, err := downloadLineTx(tx, credential.NodeID)
		if err != nil {
			return nil, nil, err
		}
		if err = lineConvergedTx(tx, line, credential, now); err != nil {
			return nil, nil, err
		}
		lines = append(lines, publicLine(line))
	}
	return lines, credentials, nil
}
