package store

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// normalizeLineSelection validates the requested Line identifiers and removes
// duplicates while keeping the caller's order.
func normalizeLineSelection(lineIDs []string) ([]string, error) {
	if len(lineIDs) == 0 {
		return nil, errors.New("LINES_REQUIRED: select at least one line")
	}
	seen := make(map[string]struct{}, len(lineIDs))
	out := make([]string, 0, len(lineIDs))
	for _, raw := range lineIDs {
		id := strings.TrimSpace(raw)
		if err := subscription.ValidateID(id); err != nil {
			return nil, common.ErrLineIDInvalid()
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) > common.MaxSubscriberLines {
		return nil, errors.New("LINES_TOO_MANY: select at most " + strconv.Itoa(common.MaxSubscriberLines) + " lines")
	}
	return out, nil
}

// validateLineTx checks that one selected Line is an existing edge node with
// stored transport settings. An Out node is never a proxy Line.
func validateLineTx(tx *sql.Tx, nodeID string) error {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("LINE_NOT_FOUND: select an existing line node")
	}
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(common.NodeRoleEdge) {
		return common.ErrLineRoleInvalid
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if count == 0 {
		return errors.New("LINE_NOT_CONFIGURED: configure the line transport before selecting it")
	}
	return nil
}

func subscriberStateAllowed(from, to subscription.State) bool {
	switch from {
	case subscription.StateActive:
		return to == subscription.StatePaused || to == subscription.StateDeleting
	case subscription.StatePaused:
		return to == subscription.StateActive || to == subscription.StateDeleting
	case subscription.StateDeleting:
		return to == subscription.StateDeleted
	default:
		// Deleted is terminal: a removed subscriber never comes back.
		return false
	}
}

func scanSubscriber(row common.RowScanner) (subscription.Subscriber, error) {
	var sub subscription.Subscriber
	var state string
	if err := row.Scan(&sub.ID, &sub.DisplayName, &state); err != nil {
		return subscription.Subscriber{}, err
	}
	sub.State = subscription.State(state)
	return sub, nil
}

func getSubscriberTx(tx *sql.Tx, id string) (subscription.Subscriber, error) {
	sub, err := scanSubscriber(tx.QueryRow(`SELECT id, display_name, state FROM subscribers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Subscriber{}, common.ErrSubscriberNotFound
	}
	if err != nil {
		return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := sub.Validate(); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_CORRUPT: stored subscriber record is invalid")
	}
	return sub, nil
}

// createSubscriber creates one subscription user, its per-Line credentials and
// the first subscription token in a single transaction. The plaintext bearer
// is returned exactly once and only its SHA-256 digest is stored.
//
// The call only validates the selection. It never mutates a running Line: the
// remote synchronization and its readback are a later, explicit stage.
func (s *Store) CreateSubscriber(displayName string, lineIDs []string, now time.Time) (subscription.Subscriber, string, error) {
	sub, err := subscription.NewSubscriber(displayName)
	if err != nil {
		return subscription.Subscriber{}, "", err
	}
	selected, err := normalizeLineSelection(lineIDs)
	if err != nil {
		return subscription.Subscriber{}, "", err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return subscription.Subscriber{}, "", errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	for _, nodeID := range selected {
		if err = validateLineTx(tx, nodeID); err != nil {
			return subscription.Subscriber{}, "", err
		}
	}
	if _, err = tx.Exec(`INSERT INTO subscribers(id, display_name, state, revision, created_at, updated_at) VALUES(?,?,?,1,?,?)`,
		sub.ID, sub.DisplayName, string(sub.State), now.Unix(), now.Unix()); err != nil {
		return subscription.Subscriber{}, "", common.ErrSubscriberCreateFailed
	}
	// The edge table is the reference source the wizard, the used-by graph and
	// the implicit recompute read. The credential stays the materialized
	// VLESS identity; both are written in this one transaction so they can
	// never disagree about which Lines the subscriber selected.
	for position, nodeID := range selected {
		if _, err = tx.Exec(`INSERT INTO subscription_lines(subscriber_id, node_id, position, line_revision, created_at) VALUES(?,?,?,0,?)`,
			sub.ID, nodeID, position, now.Unix()); err != nil {
			return subscription.Subscriber{}, "", errors.New(CodeSelectionInvalid + ": the line selection was not stored")
		}
	}
	for _, nodeID := range selected {
		credential, cErr := subscription.NewCredential(sub.ID, nodeID)
		if cErr != nil {
			return subscription.Subscriber{}, "", common.ErrCredentialCreateFailed
		}
		if _, err = tx.Exec(`INSERT INTO proxy_credentials(id, subscriber_id, node_id, uuid, active, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
			credential.ID, credential.SubscriberID, credential.NodeID, credential.UUID, now.Unix(), now.Unix()); err != nil {
			return subscription.Subscriber{}, "", common.ErrCredentialCreateFailed
		}
	}
	record, bearer, tErr := subscription.NewSubscriptionToken(sub.ID)
	if tErr != nil {
		return subscription.Subscriber{}, "", common.ErrTokenCreateFailed
	}
	if _, err = tx.Exec(`INSERT INTO subscription_tokens(id, subscriber_id, token_hash, revoked, created_at, revoked_at) VALUES(?,?,?,0,?,0)`,
		record.ID, record.SubscriberID, record.Hash, now.Unix()); err != nil {
		return subscription.Subscriber{}, "", common.ErrTokenCreateFailed
	}
	if err = tx.Commit(); err != nil {
		return subscription.Subscriber{}, "", errors.New(common.CodeDatabaseUnavailable)
	}
	return sub, bearer, nil
}

// renameSubscriber changes only the mutable display name. The subscriber ID,
// the lifecycle state, the credentials and every token stay exactly as they
// were.
//
// A deleting or deleted subscriber is a tombstone: its display name stays
// frozen. A paused subscriber may still be renamed.
func (s *Store) RenameSubscriber(id, displayName string, now time.Time) (subscription.Subscriber, error) {
	if err := subscription.ValidateID(id); err != nil {
		return subscription.Subscriber{}, common.ErrSubscriberIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	sub, err := getSubscriberTx(tx, id)
	if err != nil {
		return subscription.Subscriber{}, err
	}
	switch sub.State {
	case subscription.StateDeleting, subscription.StateDeleted:
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_TOMBSTONED: a deleting or deleted subscriber can no longer be renamed")
	case subscription.StateActive, subscription.StatePaused:
	default:
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_STATE_INVALID: state must be active, paused, deleting or deleted")
	}
	renamed, err := sub.Rename(displayName)
	if err != nil {
		return subscription.Subscriber{}, err
	}
	if _, err = tx.Exec(`UPDATE subscribers SET display_name=?, revision=revision+1, updated_at=? WHERE id=?`,
		renamed.DisplayName, now.Unix(), id); err != nil {
		return subscription.Subscriber{}, common.ErrSubscriberUpdateFailed
	}
	if err = tx.Commit(); err != nil {
		return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
	}
	return renamed, nil
}

// setSubscriberState moves one subscriber through the lifecycle. Every state
// other than active revokes the subscription tokens in the same transaction,
// so a paused or deleting subscriber can never serve a download.
//
// Repeating the current state is idempotent: it reports the existing state
// without a new revision and without touching the tokens, so a retried
// deletion request never loses the revocation of an earlier attempt.
//
// The VLESS UUIDs are not touched here: a credential may only be released
// after the remote Line confirmed the revocation by readback.
//
// The state is the desired state only: pausing records the intent and
// invalidates the download URL, but the subscriber stays in the Line snapshot
// until the remote synchronization confirmed the removal.
//
// A resumed subscriber keeps no usable bearer: the revocation of the pause is
// permanent and the operator has to rotate the token.
func (s *Store) SetSubscriberState(id string, state subscription.State, now time.Time) (subscription.Subscriber, error) {
	if err := state.Validate(); err != nil {
		return subscription.Subscriber{}, err
	}
	if err := subscription.ValidateID(id); err != nil {
		return subscription.Subscriber{}, common.ErrSubscriberIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	sub, err := getSubscriberTx(tx, id)
	if err != nil {
		return subscription.Subscriber{}, err
	}
	if sub.State == state {
		// Idempotent retry of an already applied state change.
		if err = tx.Commit(); err != nil {
			return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
		}
		return sub, nil
	}
	if !subscriberStateAllowed(sub.State, state) {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_TRANSITION_INVALID: state change is not allowed")
	}
	if state != subscription.StateActive {
		if _, err = tx.Exec(`UPDATE subscription_tokens SET revoked=1, revoked_at=? WHERE subscriber_id=? AND revoked=0`,
			now.Unix(), id); err != nil {
			return subscription.Subscriber{}, common.ErrTokenRevokeFailed
		}
	}
	if _, err = tx.Exec(`UPDATE subscribers SET state=?, revision=revision+1, updated_at=? WHERE id=?`,
		string(state), now.Unix(), id); err != nil {
		return subscription.Subscriber{}, common.ErrSubscriberUpdateFailed
	}
	if err = tx.Commit(); err != nil {
		return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
	}
	sub.State = state
	// A subscriber state change is NOT an ACL event (Ruling R10): the data plane
	// authorizes Line membership, so pausing or resuming a subscription changes only
	// which egress its client document names. The Line publication fan-out below the
	// handler boundary carries that; the Out allowlist is untouched.
	return sub, nil
}

// selectLines replaces the Line selection of an existing subscriber.
//
// A Line that stays selected keeps its historical UUID; a newly selected Line
// receives a fresh credential; a Line that is dropped is only deactivated so
// its UUID stays auditable and can never be handed out twice.
//
// The reference edge table is rewritten in the same transaction, so the
// used-by graph and the implicit recompute can never disagree with the
// credentials. Rules, Out and devices are untouched: this legacy form only
// edits the Line group, and a save through the wizard is the path that edits
// all four groups together.
//
// Policy: re-selecting a previously dropped Line reuses its original UUID
// instead of minting a new one. The UUID never leaves this subscriber, so the
// reuse cannot collide with another user. The accepted trade-off is that a
// client configuration published before the drop keeps working once the Line
// is selected again; the operator who needs a credential to stop working must
// release it explicitly.
func (s *Store) SelectLines(subscriberID string, lineIDs []string, now time.Time) ([]subscription.Credential, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return nil, common.ErrSubscriberIDInvalid()
	}
	selected, err := normalizeLineSelection(lineIDs)
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	sub, err := getSubscriberTx(tx, subscriberID)
	if err != nil {
		return nil, err
	}
	if sub.State != subscription.StateActive {
		return nil, errors.New("SUBSCRIBER_NOT_ACTIVE: activate the subscriber before changing lines")
	}
	for _, nodeID := range selected {
		if err = validateLineTx(tx, nodeID); err != nil {
			return nil, err
		}
	}
	credentials := make([]subscription.Credential, 0, len(selected))
	keep := make(map[string]struct{}, len(selected))
	changed := false
	for _, nodeID := range selected {
		keep[nodeID] = struct{}{}
		var credential subscription.Credential
		var active int
		err = tx.QueryRow(`SELECT id, subscriber_id, node_id, uuid, active FROM proxy_credentials WHERE subscriber_id=? AND node_id=?`,
			subscriberID, nodeID).Scan(&credential.ID, &credential.SubscriberID, &credential.NodeID, &credential.UUID, &active)
		if errors.Is(err, sql.ErrNoRows) {
			credential, err = subscription.NewCredential(subscriberID, nodeID)
			if err != nil {
				return nil, common.ErrCredentialCreateFailed
			}
			if _, err = tx.Exec(`INSERT INTO proxy_credentials(id, subscriber_id, node_id, uuid, active, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
				credential.ID, credential.SubscriberID, credential.NodeID, credential.UUID, now.Unix(), now.Unix()); err != nil {
				return nil, common.ErrCredentialCreateFailed
			}
			changed = true
		} else if err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		} else if active != 1 {
			// A previously dropped line is selected again: the historical UUID
			// is reused and the credential becomes active again.
			if _, err = tx.Exec(`UPDATE proxy_credentials SET active=1, updated_at=? WHERE id=?`, now.Unix(), credential.ID); err != nil {
				return nil, common.ErrCredentialUpdateFailed
			}
			changed = true
		}
		credentials = append(credentials, credential)
	}
	// The edge table is rewritten with the same selection: the wizard, the
	// used-by graph and the implicit recompute read it, so it must never lag
	// behind the credentials this call just changed.
	if err := rewriteLineEdgesTx(tx, subscriberID, selected, now.Unix()); err != nil {
		return nil, err
	}
	dropped, err := deactivateDroppedCredentials(tx, subscriberID, keep, now.Unix())
	if err != nil {
		return nil, err
	}
	if changed || dropped > 0 {
		if _, err = tx.Exec(`UPDATE subscribers SET revision=revision+1, updated_at=? WHERE id=?`, now.Unix(), subscriberID); err != nil {
			return nil, common.ErrSubscriberUpdateFailed
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	// The Line set of a subscription does not change the ACL (Ruling R10): a Line is
	// authorized at every Out by membership, so dropping or adding it here only
	// changes the client document the subscriber downloads. The Out pool is
	// reconciled by the node lifecycle instead.
	return credentials, nil
}

// rewriteLineEdgesTx replaces the Line group of one subscriber's edge table and
// bumps the snapshot version. The other three groups stay as they are: this is
// the legacy Line-only form, not the wizard.
func rewriteLineEdgesTx(tx *sql.Tx, subscriberID string, lineIDs []string, now int64) error {
	if _, err := tx.Exec(`DELETE FROM subscription_lines WHERE subscriber_id=?`, subscriberID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	for position, nodeID := range lineIDs {
		if _, err := tx.Exec(`INSERT INTO subscription_lines(subscriber_id, node_id, position, line_revision, created_at) VALUES(?,?,?,0,?)`,
			subscriberID, nodeID, position, now); err != nil {
			return errors.New(CodeSelectionInvalid + ": the line selection was not stored")
		}
	}
	// A snapshot that exists describes the selection it was approved with, so
	// the Line change clears the approval: the download refuses it until the
	// wizard saves the new selection.
	if _, err := tx.Exec(`UPDATE subscription_snapshots SET artifact_id='', artifact_approved=0, artifact_at=0, updated_at=? WHERE subscriber_id=?`, now, subscriberID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	return nil
}

// deactivateDroppedCredentials marks credentials of lines that are no longer
// selected as inactive. The UUID row itself survives for history. It reports
// how many credentials were deactivated.
func deactivateDroppedCredentials(tx *sql.Tx, subscriberID string, keep map[string]struct{}, now int64) (int, error) {
	rows, err := tx.Query(`SELECT id, node_id FROM proxy_credentials WHERE subscriber_id=? AND active=1`, subscriberID)
	if err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	type dropped struct {
		id     string
		nodeID string
	}
	var inactive []dropped
	for rows.Next() {
		var d dropped
		if err = rows.Scan(&d.id, &d.nodeID); err != nil {
			rows.Close()
			return 0, errors.New(common.CodeDatabaseUnavailable)
		}
		if _, selected := keep[d.nodeID]; !selected {
			inactive = append(inactive, d)
		}
	}
	if err = rows.Close(); err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	if err = rows.Err(); err != nil {
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
	for _, d := range inactive {
		if _, err = tx.Exec(`UPDATE proxy_credentials SET active=0, updated_at=? WHERE id=?`, now, d.id); err != nil {
			return 0, common.ErrCredentialUpdateFailed
		}
	}
	return len(inactive), nil
}

// rotateToken issues a new bearer for an active subscriber and revokes the
// previous ones in the same transaction. The new bearer is independent of
// every VLESS UUID and of the revoked token.
func (s *Store) RotateToken(subscriberID string, now time.Time) (string, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return "", common.ErrSubscriberIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	sub, err := getSubscriberTx(tx, subscriberID)
	if err != nil {
		return "", err
	}
	if sub.State != subscription.StateActive {
		return "", errors.New("SUBSCRIBER_NOT_ACTIVE: activate the subscriber before rotating a token")
	}
	record, bearer, tErr := subscription.NewSubscriptionToken(subscriberID)
	if tErr != nil {
		return "", common.ErrTokenCreateFailed
	}
	if _, err = tx.Exec(`UPDATE subscription_tokens SET revoked=1, revoked_at=? WHERE subscriber_id=? AND revoked=0`,
		now.Unix(), subscriberID); err != nil {
		return "", common.ErrTokenRevokeFailed
	}
	if _, err = tx.Exec(`INSERT INTO subscription_tokens(id, subscriber_id, token_hash, revoked, created_at, revoked_at) VALUES(?,?,?,0,?,0)`,
		record.ID, record.SubscriberID, record.Hash, now.Unix()); err != nil {
		return "", common.ErrTokenCreateFailed
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	return bearer, nil
}

// revokeTokens revokes every active token of one subscriber. It is
// idempotent and never touches the VLESS credentials.
//
// The subscriber must exist: an unknown subscriber is an error, so a mistyped
// identifier is never reported as a successful revocation.
func (s *Store) RevokeTokens(subscriberID string, now time.Time) error {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return common.ErrSubscriberIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if _, err = getSubscriberTx(tx, subscriberID); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE subscription_tokens SET revoked=1, revoked_at=? WHERE subscriber_id=? AND revoked=0`,
		now.Unix(), subscriberID); err != nil {
		return common.ErrTokenRevokeFailed
	}
	if err = tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	return nil
}

func (s *Store) GetSubscriber(id string) (subscription.Subscriber, error) {
	if err := subscription.ValidateID(id); err != nil {
		return subscription.Subscriber{}, common.ErrSubscriberIDInvalid()
	}
	sub, err := scanSubscriber(s.DB.QueryRow(`SELECT id, display_name, state FROM subscribers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Subscriber{}, common.ErrSubscriberNotFound
	}
	if err != nil {
		return subscription.Subscriber{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := sub.Validate(); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_CORRUPT: stored subscriber record is invalid")
	}
	return sub, nil
}

// listSubscribers returns the visible subscribers. Deleted subscribers stay
// in the database for history but are not part of the management list.
func (s *Store) ListSubscribers() ([]subscription.Subscriber, error) {
	rows, err := s.DB.Query(`SELECT id, display_name, state FROM subscribers WHERE state<>'deleted' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []subscription.Subscriber{}
	for rows.Next() {
		sub, err := scanSubscriber(rows)
		if err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out = append(out, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}

// listSubscriberCredentials returns every credential of one subscriber, also
// the deactivated ones. The historical UUID stays visible for auditing.
func (s *Store) ListSubscriberCredentials(subscriberID string) ([]subscription.Credential, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return nil, common.ErrSubscriberIDInvalid()
	}
	rows, err := s.DB.Query(`SELECT id, subscriber_id, node_id, uuid, active FROM proxy_credentials WHERE subscriber_id=? ORDER BY created_at ASC, id ASC`, subscriberID)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []subscription.Credential{}
	for rows.Next() {
		var credential subscription.Credential
		var active int
		if err = rows.Scan(&credential.ID, &credential.SubscriberID, &credential.NodeID, &credential.UUID, &active); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out = append(out, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}
