package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	nodedomain "github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The public download is a bearer credential. Every rejection - an unknown
// bearer, a revoked bearer, a suspended subscriber, a Line that is not
// converged - is the same generic failure, so the endpoint cannot be
// enumerated and no log line ever names a subscriber, a Line or a bearer.
var (
	// ErrSubscriptionRejected marks every ordinary rejection.
	ErrSubscriptionRejected = errors.New("SUBSCRIPTION_DOWNLOAD_REJECTED")
	// ErrSubscriptionStoreUnavailable marks a database failure. It is the
	// only rejection that is not hidden behind a generic 404, because the
	// operator has to be able to tell a broken database from a bad bearer.
	ErrSubscriptionStoreUnavailable = errors.New(CodeDatabaseUnavailable)
)

// subscriptionDownload resolves one plaintext bearer into the Lines and the
// credentials one subscriber may use.
//
// The whole resolution runs inside one snapshot transaction, so a bearer can
// never be resolved against a half-applied revocation.
//
// The gate is authoritative per Line. It does not only check that the
// subscriber's own credential is present: the complete desired user set of
// the Line - every active credential of every active subscriber - must
// already be published in the Line's current candidate. That prevents a
// download while the removal of another subscriber has not been confirmed by
// the Line itself.
//
// The returned Lines carry only the public transport fields. The REALITY
// private key, the handshake target and the handshake port never leave this
// package; the exporter needs the public fields only.
func (s *Store) SubscriptionDownload(token string, now time.Time) ([]subscription.Line, []subscription.Credential, error) {
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
	if err = tx.Commit(); err != nil {
		return nil, nil, ErrSubscriptionStoreUnavailable
	}
	return lines, credentials, nil
}

// publicLine strips every server-side secret from a Line. The exporter only
// needs the public transport fields, so the private key, the handshake target
// and the handshake port never reach the download handler.
func publicLine(line subscription.Line) subscription.Line {
	line.PrivateKey = ""
	line.HandshakeServer = ""
	line.HandshakePort = 0
	return line
}

// SubscriptionStoreError maps a store error onto the two public outcomes. A
// database failure is reported separately; everything else is the generic
// rejection.
//
// The database failure is recognised by its code, compared against
// codeDatabaseUnavailable, and by the sentinel this file returns itself. A
// message prefix is never matched: the detail half of an error cannot make an
// ordinary refusal look like an outage or the other way round.
func SubscriptionStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSubscriptionStoreUnavailable) || ErrorCodeOf(err) == CodeDatabaseUnavailable {
		return ErrSubscriptionStoreUnavailable
	}
	return ErrSubscriptionRejected
}

// subscriptionSubscriberTx maps one plaintext bearer to its subscriber inside
// the caller's transaction. A revoked bearer and an unknown bearer are the
// same rejection.
func subscriptionSubscriberTx(tx *sql.Tx, token string) (string, error) {
	var subscriberID string
	err := tx.QueryRow(`SELECT subscriber_id FROM subscription_tokens WHERE token_hash=? AND revoked=0`,
		subscription.TokenHash(token)).Scan(&subscriberID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrSubscriptionRejected
	}
	if err != nil {
		return "", ErrSubscriptionStoreUnavailable
	}
	return subscriberID, nil
}

// activeCredentialsTx returns the credentials one subscriber may currently
// use. A deactivated credential of a dropped Line is never published.
func activeCredentialsTx(tx *sql.Tx, subscriberID string) ([]subscription.Credential, error) {
	rows, err := tx.Query(`SELECT id, subscriber_id, node_id, uuid FROM proxy_credentials
	 WHERE subscriber_id=? AND active=1 ORDER BY node_id ASC`, subscriberID)
	if err != nil {
		return nil, ErrSubscriptionStoreUnavailable
	}
	defer rows.Close()
	credentials := []subscription.Credential{}
	for rows.Next() {
		var credential subscription.Credential
		if err = rows.Scan(&credential.ID, &credential.SubscriberID, &credential.NodeID, &credential.UUID); err != nil {
			return nil, ErrSubscriptionStoreUnavailable
		}
		credentials = append(credentials, credential)
	}
	if err = rows.Err(); err != nil {
		return nil, ErrSubscriptionStoreUnavailable
	}
	return credentials, nil
}

// downloadLineTx returns the stored transport of one Line. The stored record
// is validated as a whole before it is used, so a corrupt transport can never
// reach a download.
func downloadLineTx(tx *sql.Tx, nodeID string) (subscription.Line, error) {
	var line subscription.Line
	var local int
	err := tx.QueryRow(`SELECT node_id, display_name, server, port, sort_order, server_name,
	 handshake_server, handshake_port, private_key, public_key, short_id, local
	 FROM line_settings WHERE node_id=?`, nodeID).Scan(&line.NodeID, &line.DisplayName, &line.Server,
		&line.Port, &line.SortOrder, &line.ServerName, &line.HandshakeServer, &line.HandshakePort,
		&line.PrivateKey, &line.PublicKey, &line.ShortID, &local)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Line{}, ErrSubscriptionRejected
	}
	if err != nil {
		return subscription.Line{}, ErrSubscriptionStoreUnavailable
	}
	line.Local = local == 1
	if err = line.Validate(); err != nil {
		return subscription.Line{}, ErrSubscriptionRejected
	}
	return line, nil
}

// lineConvergedTx checks that one Line really serves the credentials the Hub
// wants it to serve.
//
// Every condition has to hold:
//
//   - the node exists, is an edge Line and still holds a valid identity;
//   - the node is currently contacting the Hub;
//   - the node confirmed the latest candidate by its own readback, with the
//     same revision and the same configuration digest;
//   - the confirmed candidate carries exactly the desired user set of this
//     Line, so no removal of any subscriber is still pending;
//   - the confirmed candidate carries the same transport as the stored Line,
//     including the listening port, so a published client configuration can
//     never disagree with the running listener.
func lineConvergedTx(tx *sql.Tx, line subscription.Line, credential subscription.Credential, now time.Time) error {
	var (
		role             string
		vlessPort        int
		lastHeartbeat    int64
		observedRevision int64
		observedDigest   string
		observedAt       int64
	)
	err := tx.QueryRow(`SELECT role, vless_port, last_heartbeat, observed_revision, observed_config_sha256, observed_at
	 FROM nodes WHERE id=?`, line.NodeID).Scan(&role, &vlessPort, &lastHeartbeat, &observedRevision, &observedDigest, &observedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSubscriptionRejected
	}
	if err != nil {
		return ErrSubscriptionStoreUnavailable
	}
	if role != "edge" {
		return ErrSubscriptionRejected
	}
	// The Line must still hold a valid identity. A revoked identity means the
	// node is no longer enrolled and can never serve a credential.
	var identities int
	if err = tx.QueryRow(`SELECT count(*) FROM node_identities WHERE node_id=? AND revoked=0`, line.NodeID).Scan(&identities); err != nil {
		return ErrSubscriptionStoreUnavailable
	}
	if identities == 0 {
		return ErrSubscriptionRejected
	}
	// The published port must be the port the Line actually listens on.
	if vlessPort != line.Port {
		return ErrSubscriptionRejected
	}
	if lastHeartbeat == 0 || now.Sub(time.Unix(lastHeartbeat, 0)) > OfflineAfter {
		return ErrSubscriptionRejected
	}
	if observedAt <= 0 {
		return ErrSubscriptionRejected
	}

	var (
		revision  int64
		candidate string
		digest    string
	)
	err = tx.QueryRow(`SELECT revision, candidate_json, config_sha256 FROM node_candidates
	 WHERE node_id=? ORDER BY revision DESC LIMIT 1`, line.NodeID).Scan(&revision, &candidate, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSubscriptionRejected
	}
	if err != nil {
		return ErrSubscriptionStoreUnavailable
	}
	if observedRevision != revision || observedDigest == "" || observedDigest != digest {
		return ErrSubscriptionRejected
	}

	var document nodedomain.CandidateDocument
	if err = json.Unmarshal([]byte(candidate), &document); err != nil {
		return ErrSubscriptionRejected
	}
	if document.NodeID != line.NodeID || document.Role != nodedomain.RoleEdge {
		return ErrSubscriptionRejected
	}
	if document.VLESSPort != line.Port {
		return ErrSubscriptionRejected
	}
	if err = candidateTransportMatches(document, line); err != nil {
		return err
	}
	desired, err := desiredUsersTx(tx, line.NodeID)
	if err != nil {
		return err
	}
	return CandidateUsersMatch(document, desired)
}

// candidateTransportMatches compares the confirmed REALITY transport with the
// stored Line transport. A Line whose transport changed after the last
// confirmed revision would otherwise publish a client configuration the Line
// can never serve.
func candidateTransportMatches(document nodedomain.CandidateDocument, line subscription.Line) error {
	reality := document.Reality
	if reality == nil {
		return ErrSubscriptionRejected
	}
	if reality.ServerName != line.ServerName ||
		reality.HandshakeServer != line.HandshakeServer ||
		reality.HandshakePort != line.HandshakePort ||
		reality.PrivateKey != line.PrivateKey ||
		reality.ShortID != line.ShortID {
		return ErrSubscriptionRejected
	}
	return nil
}

// desiredUsersTx returns the complete desired user set of one Line: every
// active credential of every active subscriber. A credential of a subscriber
// that is no longer active is not desired any more, even while its Line has
// not confirmed the removal yet.
func desiredUsersTx(tx *sql.Tx, nodeID string) (map[string]string, error) {
	rows, err := tx.Query(`SELECT c.id, c.uuid FROM proxy_credentials c
	 JOIN subscribers s ON s.id=c.subscriber_id
	 WHERE c.node_id=? AND c.active=1 AND s.state='active'`, nodeID)
	if err != nil {
		return nil, ErrSubscriptionStoreUnavailable
	}
	defer rows.Close()
	desired := map[string]string{}
	for rows.Next() {
		var id, uuid string
		if err = rows.Scan(&id, &uuid); err != nil {
			return nil, ErrSubscriptionStoreUnavailable
		}
		desired[id] = uuid
	}
	if err = rows.Err(); err != nil {
		return nil, ErrSubscriptionStoreUnavailable
	}
	return desired, nil
}

// candidateUsersMatch compares the confirmed user set of a Line with the
// desired user set. A missing credential and an extra credential are both a
// rejection: the Line does not serve exactly what the Hub wants it to serve.
//
// The comparison is a set comparison. A candidate that repeats one credential
// and drops another has the same length as the desired set, so the length
// check alone is not enough: every credential id has to appear exactly once
// and every UUID has to match.
func CandidateUsersMatch(document nodedomain.CandidateDocument, desired map[string]string) error {
	if len(document.Users) != len(desired) {
		return ErrSubscriptionRejected
	}
	seen := make(map[string]bool, len(document.Users))
	for _, user := range document.Users {
		if seen[user.CredentialID] {
			return ErrSubscriptionRejected
		}
		seen[user.CredentialID] = true
		uuid, exists := desired[user.CredentialID]
		if !exists || uuid != user.UUID {
			return ErrSubscriptionRejected
		}
	}
	return nil
}
