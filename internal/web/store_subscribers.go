package web

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	nodedomain "github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// maxSubscriberLines bounds one subscriber's Line selection so a single
// request cannot create an unbounded credential fan-out.
const maxSubscriberLines = 32

// migrateSchema4 adds the subscription domain tables. It only creates new
// tables; node, candidate and task data of schema 3 stays untouched. The
// migration is deliberately additive so a rollback never destroys history.
func migrateSchema4(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE subscribers (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active','paused','deleting','deleted')),
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE proxy_credentials (
  id TEXT PRIMARY KEY,
  subscriber_id TEXT NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  uuid TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(subscriber_id, node_id)
);
CREATE TABLE subscription_tokens (
  id TEXT PRIMARY KEY,
  subscriber_id TEXT NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
  created_at INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX subscription_tokens_subscriber ON subscription_tokens(subscriber_id, revoked);
CREATE TABLE line_settings (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  server_name TEXT NOT NULL,
  handshake_server TEXT NOT NULL,
  handshake_port INTEGER NOT NULL,
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  short_id TEXT NOT NULL,
  local INTEGER NOT NULL DEFAULT 0 CHECK(local IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
PRAGMA user_version=4;
`); err != nil {
		return err
	}
	return nil
}

// normalizeLineSelection validates the requested Line identifiers and removes
// duplicates while keeping the caller's order.
func normalizeLineSelection(lineIDs []string) ([]string, error) {
	if len(lineIDs) == 0 {
		return nil, errors.New("LINES_REQUIRED: select at least one line")
	}
	seen := make(map[string]struct{}, len(lineIDs))
	out := make([]string, 0, len(lineIDs))
	for _, id := range lineIDs {
		if err := subscription.ValidateID(id); err != nil {
			return nil, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) > maxSubscriberLines {
		return nil, errors.New("LINES_TOO_MANY: select at most 32 lines")
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
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "edge" {
		return errors.New("LINE_ROLE_INVALID: only edge nodes can serve proxy lines")
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
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

func scanSubscriber(row rowScanner) (subscription.Subscriber, error) {
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
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_NOT_FOUND: unknown subscription user")
	}
	if err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
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
func (s *store) createSubscriber(displayName string, lineIDs []string, now time.Time) (subscription.Subscriber, string, error) {
	sub, err := subscription.NewSubscriber(displayName)
	if err != nil {
		return subscription.Subscriber{}, "", err
	}
	selected, err := normalizeLineSelection(lineIDs)
	if err != nil {
		return subscription.Subscriber{}, "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return subscription.Subscriber{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	for _, nodeID := range selected {
		if err = validateLineTx(tx, nodeID); err != nil {
			return subscription.Subscriber{}, "", err
		}
	}
	if _, err = tx.Exec(`INSERT INTO subscribers(id, display_name, state, revision, created_at, updated_at) VALUES(?,?,?,1,?,?)`,
		sub.ID, sub.DisplayName, string(sub.State), now.Unix(), now.Unix()); err != nil {
		return subscription.Subscriber{}, "", errors.New("SUBSCRIBER_CREATE_FAILED")
	}
	for _, nodeID := range selected {
		credential, cErr := subscription.NewCredential(sub.ID, nodeID)
		if cErr != nil {
			return subscription.Subscriber{}, "", errors.New("CREDENTIAL_CREATE_FAILED")
		}
		if _, err = tx.Exec(`INSERT INTO proxy_credentials(id, subscriber_id, node_id, uuid, active, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
			credential.ID, credential.SubscriberID, credential.NodeID, credential.UUID, now.Unix(), now.Unix()); err != nil {
			return subscription.Subscriber{}, "", errors.New("CREDENTIAL_CREATE_FAILED")
		}
	}
	record, bearer, tErr := subscription.NewSubscriptionToken(sub.ID)
	if tErr != nil {
		return subscription.Subscriber{}, "", errors.New("TOKEN_CREATE_FAILED")
	}
	if _, err = tx.Exec(`INSERT INTO subscription_tokens(id, subscriber_id, token_hash, revoked, created_at, revoked_at) VALUES(?,?,?,0,?,0)`,
		record.ID, record.SubscriberID, record.Hash, now.Unix()); err != nil {
		return subscription.Subscriber{}, "", errors.New("TOKEN_CREATE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return subscription.Subscriber{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	return sub, bearer, nil
}

// renameSubscriber changes only the mutable display name. The subscriber ID,
// the lifecycle state, the credentials and every token stay exactly as they
// were.
//
// A deleting or deleted subscriber is a tombstone: its display name stays
// frozen. A paused subscriber may still be renamed.
func (s *store) renameSubscriber(id, displayName string, now time.Time) (subscription.Subscriber, error) {
	if err := subscription.ValidateID(id); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
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
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_UPDATE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
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
func (s *store) setSubscriberState(id string, state subscription.State, now time.Time) (subscription.Subscriber, error) {
	if err := state.Validate(); err != nil {
		return subscription.Subscriber{}, err
	}
	if err := subscription.ValidateID(id); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	sub, err := getSubscriberTx(tx, id)
	if err != nil {
		return subscription.Subscriber{}, err
	}
	if sub.State == state {
		// Idempotent retry of an already applied state change.
		if err = tx.Commit(); err != nil {
			return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
		}
		return sub, nil
	}
	if !subscriberStateAllowed(sub.State, state) {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_TRANSITION_INVALID: state change is not allowed")
	}
	if state != subscription.StateActive {
		if _, err = tx.Exec(`UPDATE subscription_tokens SET revoked=1, revoked_at=? WHERE subscriber_id=? AND revoked=0`,
			now.Unix(), id); err != nil {
			return subscription.Subscriber{}, errors.New("TOKEN_REVOKE_FAILED")
		}
	}
	if _, err = tx.Exec(`UPDATE subscribers SET state=?, revision=revision+1, updated_at=? WHERE id=?`,
		string(state), now.Unix(), id); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_UPDATE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
	}
	sub.State = state
	return sub, nil
}

// selectLines replaces the Line selection of an existing subscriber.
//
// A Line that stays selected keeps its historical UUID; a newly selected Line
// receives a fresh credential; a Line that is dropped is only deactivated so
// its UUID stays auditable and can never be handed out twice.
//
// Policy: re-selecting a previously dropped Line reuses its original UUID
// instead of minting a new one. The UUID never leaves this subscriber, so the
// reuse cannot collide with another user. The accepted trade-off is that a
// client configuration published before the drop keeps working once the Line
// is selected again; the operator who needs a credential to stop working must
// release it explicitly.
func (s *store) selectLines(subscriberID string, lineIDs []string, now time.Time) ([]subscription.Credential, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return nil, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	selected, err := normalizeLineSelection(lineIDs)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
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
				return nil, errors.New("CREDENTIAL_CREATE_FAILED")
			}
			if _, err = tx.Exec(`INSERT INTO proxy_credentials(id, subscriber_id, node_id, uuid, active, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
				credential.ID, credential.SubscriberID, credential.NodeID, credential.UUID, now.Unix(), now.Unix()); err != nil {
				return nil, errors.New("CREDENTIAL_CREATE_FAILED")
			}
			changed = true
		} else if err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		} else if active != 1 {
			// A previously dropped line is selected again: the historical UUID
			// is reused and the credential becomes active again.
			if _, err = tx.Exec(`UPDATE proxy_credentials SET active=1, updated_at=? WHERE id=?`, now.Unix(), credential.ID); err != nil {
				return nil, errors.New("CREDENTIAL_UPDATE_FAILED")
			}
			changed = true
		}
		credentials = append(credentials, credential)
	}
	dropped, err := deactivateDroppedCredentials(tx, subscriberID, keep, now.Unix())
	if err != nil {
		return nil, err
	}
	if changed || dropped > 0 {
		if _, err = tx.Exec(`UPDATE subscribers SET revision=revision+1, updated_at=? WHERE id=?`, now.Unix(), subscriberID); err != nil {
			return nil, errors.New("SUBSCRIBER_UPDATE_FAILED")
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return credentials, nil
}

// deactivateDroppedCredentials marks credentials of lines that are no longer
// selected as inactive. The UUID row itself survives for history. It reports
// how many credentials were deactivated.
func deactivateDroppedCredentials(tx *sql.Tx, subscriberID string, keep map[string]struct{}, now int64) (int, error) {
	rows, err := tx.Query(`SELECT id, node_id FROM proxy_credentials WHERE subscriber_id=? AND active=1`, subscriberID)
	if err != nil {
		return 0, errors.New("DATABASE_UNAVAILABLE")
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
			return 0, errors.New("DATABASE_UNAVAILABLE")
		}
		if _, selected := keep[d.nodeID]; !selected {
			inactive = append(inactive, d)
		}
	}
	if err = rows.Close(); err != nil {
		return 0, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = rows.Err(); err != nil {
		return 0, errors.New("DATABASE_UNAVAILABLE")
	}
	for _, d := range inactive {
		if _, err = tx.Exec(`UPDATE proxy_credentials SET active=0, updated_at=? WHERE id=?`, now, d.id); err != nil {
			return 0, errors.New("CREDENTIAL_UPDATE_FAILED")
		}
	}
	return len(inactive), nil
}

// rotateToken issues a new bearer for an active subscriber and revokes the
// previous ones in the same transaction. The new bearer is independent of
// every VLESS UUID and of the revoked token.
func (s *store) rotateToken(subscriberID string, now time.Time) (string, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return "", errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
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
		return "", errors.New("TOKEN_CREATE_FAILED")
	}
	if _, err = tx.Exec(`UPDATE subscription_tokens SET revoked=1, revoked_at=? WHERE subscriber_id=? AND revoked=0`,
		now.Unix(), subscriberID); err != nil {
		return "", errors.New("TOKEN_REVOKE_FAILED")
	}
	if _, err = tx.Exec(`INSERT INTO subscription_tokens(id, subscriber_id, token_hash, revoked, created_at, revoked_at) VALUES(?,?,?,0,?,0)`,
		record.ID, record.SubscriberID, record.Hash, now.Unix()); err != nil {
		return "", errors.New("TOKEN_CREATE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	return bearer, nil
}

// revokeTokens revokes every active token of one subscriber. It is
// idempotent and never touches the VLESS credentials.
//
// The subscriber must exist: an unknown subscriber is an error, so a mistyped
// identifier is never reported as a successful revocation.
func (s *store) revokeTokens(subscriberID string, now time.Time) error {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err = getSubscriberTx(tx, subscriberID); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE subscription_tokens SET revoked=1, revoked_at=? WHERE subscriber_id=? AND revoked=0`,
		now.Unix(), subscriberID); err != nil {
		return errors.New("TOKEN_REVOKE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

// resolveTokenSubscriber maps one plaintext bearer to its active subscriber.
// A revoked token, a token of a non-active subscriber and an unknown token are
// all rejected the same way so the endpoint cannot be enumerated.
//
// The token and the subscriber are read in one joined query, so a state change
// cannot slip between two reads. Only a missing row is a uniform rejection;
// every other failure is reported as a database failure.
func (s *store) resolveTokenSubscriber(token string) (subscription.Subscriber, error) {
	if err := subscription.ValidateToken(token); err != nil {
		return subscription.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
	}
	sub, err := scanSubscriber(s.db.QueryRow(`SELECT s.id, s.display_name, s.state
FROM subscription_tokens t JOIN subscribers s ON s.id = t.subscriber_id
WHERE t.token_hash=? AND t.revoked=0`, subscription.TokenHash(token)))
	if errors.Is(err, sql.ErrNoRows) {
		// An unknown token, a revoked token and a token of a non-active
		// subscriber are indistinguishable for the caller.
		return subscription.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
	}
	if err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if sub.State != subscription.StateActive {
		return subscription.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
	}
	if err := sub.Validate(); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_CORRUPT: stored subscriber record is invalid")
	}
	return sub, nil
}

func (s *store) getSubscriber(id string) (subscription.Subscriber, error) {
	if err := subscription.ValidateID(id); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	sub, err := scanSubscriber(s.db.QueryRow(`SELECT id, display_name, state FROM subscribers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_NOT_FOUND: unknown subscription user")
	}
	if err != nil {
		return subscription.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err := sub.Validate(); err != nil {
		return subscription.Subscriber{}, errors.New("SUBSCRIBER_CORRUPT: stored subscriber record is invalid")
	}
	return sub, nil
}

// listSubscribers returns the visible subscribers. Deleted subscribers stay
// in the database for history but are not part of the management list.
func (s *store) listSubscribers() ([]subscription.Subscriber, error) {
	rows, err := s.db.Query(`SELECT id, display_name, state FROM subscribers WHERE state<>'deleted' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []subscription.Subscriber{}
	for rows.Next() {
		sub, err := scanSubscriber(rows)
		if err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// listSubscriberCredentials returns every credential of one subscriber, also
// the deactivated ones. The historical UUID stays visible for auditing.
func (s *store) listSubscriberCredentials(subscriberID string) ([]subscription.Credential, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return nil, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	rows, err := s.db.Query(`SELECT id, subscriber_id, node_id, uuid, active FROM proxy_credentials WHERE subscriber_id=? ORDER BY created_at ASC, id ASC`, subscriberID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []subscription.Credential{}
	for rows.Next() {
		var credential subscription.Credential
		var active int
		if err = rows.Scan(&credential.ID, &credential.SubscriberID, &credential.NodeID, &credential.UUID, &active); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// setLine stores the transport of one Line. The node must be an existing edge
// node; an Out node never carries a proxy Line.
//
// The REALITY key pair and the short ID identify the transport. For an
// existing Line they are preserved, so renaming or reordering a Line can
// never invalidate a published client configuration.
//
// The listening port must equal the VLESS port of the node. A Line that points
// at a different port would publish a client configuration the Line can never
// serve.
func (s *store) setLine(line subscription.Line, now time.Time) (subscription.Line, error) {
	if err := subscription.ValidateID(line.NodeID); err != nil {
		return subscription.Line{}, errors.New("LINE_NODE_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return subscription.Line{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	var vlessPort int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, line.NodeID).Scan(&role, &vlessPort)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Line{}, errors.New("LINE_NOT_FOUND: unknown line node")
	}
	if err != nil {
		return subscription.Line{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "edge" {
		return subscription.Line{}, errors.New("LINE_ROLE_INVALID: only edge nodes can serve proxy lines")
	}
	if line.Port != vlessPort {
		return subscription.Line{}, errors.New("LINE_PORT_MISMATCH: the line port must match the vless port of the node")
	}
	// An existing Line keeps its transport identity: the caller may change the
	// label, the address or the order, but never the REALITY key pair.
	var storedPrivate, storedPublic, storedShort string
	err = tx.QueryRow(`SELECT private_key, public_key, short_id FROM line_settings WHERE node_id=?`, line.NodeID).
		Scan(&storedPrivate, &storedPublic, &storedShort)
	switch {
	case err == nil:
		line.PrivateKey = storedPrivate
		line.PublicKey = storedPublic
		line.ShortID = storedShort
	case errors.Is(err, sql.ErrNoRows):
	default:
		return subscription.Line{}, errors.New("DATABASE_UNAVAILABLE")
	}
	// The client-facing address is canonicalized to lower case, so one Line is
	// never published under two spellings of the same host. An IPv6 address
	// keeps its form.
	line.Server = strings.ToLower(line.Server)
	if err = line.Validate(); err != nil {
		return subscription.Line{}, err
	}
	// The stored transport must also satisfy the node-side REALITY contract,
	// otherwise the Line could never compile a sing-box configuration. DNS
	// names are canonicalized to lower case first; an IP address as server
	// name stays invalid because REALITY requires a real server name.
	line.ServerName = strings.ToLower(line.ServerName)
	line.HandshakeServer = strings.ToLower(line.HandshakeServer)
	reality := nodedomain.RealityConfig{
		ServerName:      line.ServerName,
		HandshakeServer: line.HandshakeServer,
		HandshakePort:   line.HandshakePort,
		PrivateKey:      line.PrivateKey,
		ShortID:         line.ShortID,
	}
	if err = reality.Validate(); err != nil {
		return subscription.Line{}, errors.New("REALITY_SETTINGS_INVALID: the line transport does not satisfy the node reality contract")
	}
	local := 0
	if line.Local {
		local = 1
	}
	result, err := tx.Exec(`UPDATE line_settings SET display_name=?, server=?, port=?, sort_order=?, server_name=?, handshake_server=?, handshake_port=?, local=?, updated_at=? WHERE node_id=?`,
		line.DisplayName, line.Server, line.Port, line.SortOrder, line.ServerName, line.HandshakeServer, line.HandshakePort, local, now.Unix(), line.NodeID)
	if err != nil {
		return subscription.Line{}, errors.New("LINE_SETTINGS_FAILED")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return subscription.Line{}, errors.New("LINE_SETTINGS_FAILED")
	}
	if affected == 0 {
		if _, err = tx.Exec(`INSERT INTO line_settings(node_id, display_name, server, port, sort_order, server_name, handshake_server, handshake_port, private_key, public_key, short_id, local, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			line.NodeID, line.DisplayName, line.Server, line.Port, line.SortOrder, line.ServerName, line.HandshakeServer, line.HandshakePort,
			line.PrivateKey, line.PublicKey, line.ShortID, local, now.Unix(), now.Unix()); err != nil {
			return subscription.Line{}, errors.New("LINE_SETTINGS_FAILED")
		}
	}
	if err = tx.Commit(); err != nil {
		return subscription.Line{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return line, nil
}

func (s *store) getLine(nodeID string) (subscription.Line, error) {
	if err := subscription.ValidateID(nodeID); err != nil {
		return subscription.Line{}, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	line, err := scanLine(s.db.QueryRow(`SELECT node_id, display_name, server, port, sort_order, server_name, handshake_server, handshake_port, private_key, public_key, short_id, local FROM line_settings WHERE node_id=?`, nodeID))
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Line{}, errors.New("LINE_NOT_FOUND: unknown line")
	}
	if errors.Is(err, errLineSettingsCorrupt) {
		return subscription.Line{}, err
	}
	if err != nil {
		return subscription.Line{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return line, nil
}

// listLines returns every stored Line ordered by its sort order.
func (s *store) listLines() ([]subscription.Line, error) {
	rows, err := s.db.Query(`SELECT node_id, display_name, server, port, sort_order, server_name, handshake_server, handshake_port, private_key, public_key, short_id, local FROM line_settings ORDER BY sort_order ASC, display_name ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []subscription.Line{}
	for rows.Next() {
		line, err := scanLine(rows)
		if errors.Is(err, errLineSettingsCorrupt) {
			return nil, err
		}
		if err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// scanLine reads one stored Line and validates it against the contract that
// setLine enforces on write.
//
// The write path only stores canonical values, so an invalid row means the
// database was modified outside the Hub. Such a row is reported as a corrupt
// record instead of reaching a client configuration, and it is never silently
// canonicalized here.
func scanLine(row rowScanner) (subscription.Line, error) {
	var line subscription.Line
	var local int
	err := row.Scan(&line.NodeID, &line.DisplayName, &line.Server, &line.Port, &line.SortOrder,
		&line.ServerName, &line.HandshakeServer, &line.HandshakePort,
		&line.PrivateKey, &line.PublicKey, &line.ShortID, &local)
	if err != nil {
		return subscription.Line{}, err
	}
	line.Local = local == 1
	if err := validateStoredLine(line); err != nil {
		return subscription.Line{}, err
	}
	return line, nil
}

// errLineSettingsCorrupt marks a stored Line that does not satisfy the
// domain contract. The message carries the stable error code only and never
// the stored values.
var errLineSettingsCorrupt = errors.New("LINE_SETTINGS_CORRUPT: stored line settings are invalid")

// validateStoredLine checks the persisted Line against the domain contract and
// against the node-side REALITY contract of setLine.
func validateStoredLine(line subscription.Line) error {
	if err := line.Validate(); err != nil {
		return errLineSettingsCorrupt
	}
	reality := nodedomain.RealityConfig{
		ServerName:      line.ServerName,
		HandshakeServer: line.HandshakeServer,
		HandshakePort:   line.HandshakePort,
		PrivateKey:      line.PrivateKey,
		ShortID:         line.ShortID,
	}
	if err := reality.Validate(); err != nil {
		return errLineSettingsCorrupt
	}
	return nil
}
