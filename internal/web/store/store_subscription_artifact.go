package store

// The approved subscription artifact is the download's single source of truth
// for a subscription that went through the Task-4 wizard.
//
// The bytes are still re-derived on every download, never read from a stored
// copy: the snapshot keeps only the selection and the digest of the artifact
// that passed the kernel gate. Serving a stored byte would let a Line rename,
// a rule revision or a credential change silently diverge from the approved
// document; re-deriving and comparing the digest makes that divergence a
// refusal instead of a wrong document.
//
// A subscription without a snapshot keeps the historical export path. That is
// the honest migration state: rows created before the wizard never chose rules,
// an Out or a device, so there is nothing to approve. The moment a wizard save
// records a snapshot, approval becomes mandatory and a blocked save can no
// longer fall back to the old bytes.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// SubscriptionArtifactDownload resolves one plaintext bearer into the two
// approved documents. The convergence gate of SubscriptionDownload still runs
// first: an unconverged Line refuses the download even when the artifact was
// approved.
func (s *Store) SubscriptionArtifactDownload(token string, now time.Time) ([]byte, []byte, error) {
	if err := subscription.ValidateToken(token); err != nil {
		return nil, nil, ErrSubscriptionRejected
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, nil, ErrSubscriptionStoreUnavailable
	}
	defer tx.Rollback()
	subscriberID, err := subscriptionSubscriberTx(tx, token)
	if err != nil {
		return nil, nil, err
	}
	lines, credentials, err := subscriptionForSubscriberTx(tx, subscriberID, now)
	if err != nil {
		return nil, nil, err
	}
	approved, err := approvedArtifactTx(tx, subscriberID)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, ErrSubscriptionStoreUnavailable
	}
	if approved != "" {
		documents, artifactID, err := s.SubscriptionArtifact(subscriberID)
		if err != nil {
			return nil, nil, SubscriptionStoreError(err)
		}
		if artifactID != approved {
			return nil, nil, ErrSubscriptionRejected
		}
		return documents.SingBox, documents.Mihomo, nil
	}
	singBox, err := subscription.ExportSingBox(lines, credentials)
	if err != nil {
		return nil, nil, ErrSubscriptionRejected
	}
	mihomo, err := subscription.ExportMihomo(lines, credentials)
	if err != nil {
		return nil, nil, ErrSubscriptionRejected
	}
	return singBox, mihomo, nil
}

// approvedArtifactTx reports the approved artifact digest of one subscriber, or
// "" when the subscriber never saved a selection through the wizard.
//
// A snapshot that exists but is not approved is a refusal, not a legacy
// fallback: the operator saved a choice that never passed the gate, so serving
// the old document would hide exactly that failure.
func approvedArtifactTx(tx *sql.Tx, subscriberID string) (string, error) {
	var artifactID string
	var approved int
	err := tx.QueryRow(`SELECT artifact_id, artifact_approved FROM subscription_snapshots WHERE subscriber_id=?`, subscriberID).
		Scan(&artifactID, &approved)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", ErrSubscriptionStoreUnavailable
	}
	if approved != 1 || artifactID == "" {
		return "", ErrSubscriptionRejected
	}
	return artifactID, nil
}
