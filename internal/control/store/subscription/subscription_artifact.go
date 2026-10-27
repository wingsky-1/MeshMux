package subscription

// The approved subscription artifact is the download's single source of truth
// for a subscription that went through the wizard.
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
//
// Flow of one download:
//
//	bearer -> subscriber -> convergence gate (every Line confirmed) -> snapshot
//	state -> approved digest? -> re-compose and compare (SubscriptionArtifact)
//	-> bytes. Without a snapshot the legacy exporter renders the same Lines and
//	credentials. The convergence gate always runs first: an unconverged Line
//	refuses even an approved artifact.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// SubscriptionDocuments is one resolved download: the two client documents the
// convergence gate accepted. Returning them together keeps the gate, the
// snapshot check and the byte resolution in one resolution per request.
type SubscriptionDocuments struct {
	SingBox []byte
	Mihomo  []byte
}

// SubscriptionArtifactDownload resolves one plaintext bearer into the two
// approved documents in a single resolution. The convergence gate runs inside
// that same resolution: an unconverged Line refuses the download even when the
// artifact was approved.
func (s *Store) SubscriptionArtifactDownload(token string, now time.Time) (SubscriptionDocuments, error) {
	resolved, err := s.resolveDownload(token, now)
	if err != nil {
		return SubscriptionDocuments{}, SubscriptionStoreError(err)
	}
	if resolved.hasSnapshot {
		if resolved.artifactID == "" {
			// The operator saved a choice that never passed the gate. Falling
			// back to the legacy bytes here would hide exactly that failure.
			return SubscriptionDocuments{}, ErrSubscriptionRejected
		}
		documents, artifactID, err := s.SubscriptionArtifact(resolved.subscriberID)
		if err != nil {
			return SubscriptionDocuments{}, SubscriptionStoreError(err)
		}
		if artifactID != resolved.artifactID {
			return SubscriptionDocuments{}, ErrSubscriptionRejected
		}
		return SubscriptionDocuments{SingBox: documents.SingBox, Mihomo: documents.Mihomo}, nil
	}
	singBox, err := coredomain.ExportSingBox(resolved.lines, resolved.credentials)
	if err != nil {
		return SubscriptionDocuments{}, ErrSubscriptionRejected
	}
	mihomo, err := coredomain.ExportMihomo(resolved.lines, resolved.credentials)
	if err != nil {
		return SubscriptionDocuments{}, ErrSubscriptionRejected
	}
	return SubscriptionDocuments{SingBox: singBox, Mihomo: mihomo}, nil
}

// downloadSnapshot is the read half of one download: the bearer's subscriber,
// the snapshot state of that subscriber, and the Lines and credentials the
// convergence gate validated.
type downloadSnapshot struct {
	subscriberID string
	// hasSnapshot is true when the subscriber has a wizard snapshot row at all.
	hasSnapshot bool
	// artifactID is the approved digest, or "" for a saved-but-unapproved row.
	artifactID  string
	lines       []coredomain.Line
	credentials []coredomain.Credential
}

// resolveDownload runs the convergence gate and reads the snapshot state in one
// transaction, so a bearer is never resolved against a half-applied revocation.
func (s *Store) resolveDownload(token string, now time.Time) (downloadSnapshot, error) {
	if err := coredomain.ValidateToken(token); err != nil {
		return downloadSnapshot{}, ErrSubscriptionRejected
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return downloadSnapshot{}, ErrSubscriptionStoreUnavailable
	}
	defer tx.Rollback()
	subscriberID, err := subscriptionSubscriberTx(tx, token)
	if err != nil {
		return downloadSnapshot{}, err
	}
	lines, credentials, err := subscriptionForSubscriberTx(tx, subscriberID, now)
	if err != nil {
		return downloadSnapshot{}, err
	}
	artifactID, hasSnapshot, err := snapshotArtifactTx(tx, subscriberID)
	if err != nil {
		return downloadSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return downloadSnapshot{}, ErrSubscriptionStoreUnavailable
	}
	return downloadSnapshot{
		subscriberID: subscriberID, hasSnapshot: hasSnapshot, artifactID: artifactID,
		lines: lines, credentials: credentials,
	}, nil
}

// snapshotArtifactTx reports the approved artifact digest of one subscriber and
// whether a snapshot row exists at all.
//
// Three states are distinct and must stay distinct:
//   - no snapshot row: not a wizard subscription, the legacy export applies;
//   - a snapshot row without an approval: a saved choice that never passed the
//     gate, so it is a refusal rather than a fallback;
//   - a snapshot row with a digest: the artifact must re-compose to that digest.
func snapshotArtifactTx(tx *sql.Tx, subscriberID string) (string, bool, error) {
	var artifactID string
	var approved int
	err := tx.QueryRow(`SELECT artifact_id, artifact_approved FROM subscription_snapshots WHERE subscriber_id=?`, subscriberID).
		Scan(&artifactID, &approved)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.New(common.CodeDatabaseUnavailable)
	}
	if approved != 1 || artifactID == "" {
		return "", true, nil
	}
	return artifactID, true, nil
}
