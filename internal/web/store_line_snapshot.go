package web

import (
	"database/sql"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// maxLineCandidateUsers mirrors the node candidate user bound. It is repeated
// here so a Line snapshot refuses an oversized user set before it reaches the
// candidate document, independent of later validation.
const maxLineCandidateUsers = 1024

// buildLineCandidateTx builds the complete desired candidate of one node in
// the caller's transaction.
//
// The frozen baseline always carries the node identity, role, revision, VLESS
// port and pinned kernel version. An Out node never receives credentials or a
// REALITY block. An Edge node without stored Line settings keeps the baseline
// too. Only an Edge node with stored transport settings extends the candidate
// with the REALITY listener and the desired user set: every active credential
// of every active subscriber of this Line, ordered by credential ID.
//
// The function is read-only. It never commits, mutates subscribers or
// publishes tasks; the caller owns the transaction and the candidate revision.
func buildLineCandidateTx(tx *sql.Tx, nodeID string, revision int64) (node.Candidate, error) {
	var role string
	var vlessPort int
	err := tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, nodeID).Scan(&role, &vlessPort)
	if errors.Is(err, sql.ErrNoRows) {
		return node.Candidate{}, errors.New("NODE_NOT_FOUND: unknown node")
	}
	if err != nil {
		return node.Candidate{}, errors.New("DATABASE_UNAVAILABLE")
	}
	candidate := node.Candidate{
		NodeID:        nodeID,
		Role:          node.Role(role),
		Revision:      revision,
		VLESSPort:     vlessPort,
		KernelVersion: node.KernelVersion,
	}
	// An Out node never carries a proxy transport or credentials.
	if node.Role(role) == node.RoleOut {
		return validateLineCandidate(candidate)
	}
	if node.Role(role) != node.RoleEdge {
		return node.Candidate{}, errors.New("CANDIDATE_INVALID: role must be edge or out")
	}

	line, err := scanLine(tx.QueryRow(`SELECT node_id, display_name, server, port, sort_order,
	 server_name, handshake_server, handshake_port, private_key, public_key, short_id, local
	 FROM line_settings WHERE node_id=?`, nodeID))
	if errors.Is(err, sql.ErrNoRows) {
		// The Line is not configured yet: keep the frozen v1 baseline.
		return validateLineCandidate(candidate)
	}
	if errors.Is(err, errLineSettingsCorrupt) {
		return node.Candidate{}, errLineSettingsCorrupt
	}
	if err != nil {
		return node.Candidate{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if line.NodeID != nodeID {
		return node.Candidate{}, errors.New("LINE_SETTINGS_CORRUPT: stored line settings are invalid")
	}
	if line.Port != vlessPort {
		return node.Candidate{}, errors.New("LINE_PORT_MISMATCH: the stored line port must match the vless port of the node")
	}
	users, err := lineCandidateUsersTx(tx, nodeID)
	if err != nil {
		return node.Candidate{}, err
	}
	candidate.Users = users
	candidate.Reality = &node.RealityConfig{
		ServerName:      line.ServerName,
		HandshakeServer: line.HandshakeServer,
		HandshakePort:   line.HandshakePort,
		PrivateKey:      line.PrivateKey,
		ShortID:         line.ShortID,
	}
	return validateLineCandidate(candidate)
}

// lineCandidateUsersTx returns the complete desired user set of one Line: the
// active credentials of active subscribers only. A paused, deleting or deleted
// subscriber stays in the database but is no longer part of the snapshot.
//
// The result is never nil, so a configured Line without users still serializes
// an explicit empty array rather than null.
func lineCandidateUsersTx(tx *sql.Tx, nodeID string) ([]node.VLESSUser, error) {
	rows, err := tx.Query(`SELECT c.id, c.uuid FROM proxy_credentials c
	 JOIN subscribers s ON s.id=c.subscriber_id
	 WHERE c.node_id=? AND c.active=1 AND s.state='active'
	 ORDER BY c.id ASC`, nodeID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	users := []node.VLESSUser{}
	for rows.Next() {
		var user node.VLESSUser
		if err = rows.Scan(&user.CredentialID, &user.UUID); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	if len(users) > maxLineCandidateUsers {
		return nil, errors.New("CANDIDATE_INVALID: at most 1024 users are allowed")
	}
	return users, nil
}

// validateLineCandidate validates the assembled candidate and replaces every
// validation detail with one stable, value-free code. A validation message may
// otherwise expose the reason a stored record was rejected.
func validateLineCandidate(candidate node.Candidate) (node.Candidate, error) {
	if err := candidate.Validate(); err != nil {
		return node.Candidate{}, errors.New("CANDIDATE_INVALID: line snapshot does not satisfy the node candidate contract")
	}
	return candidate, nil
}
