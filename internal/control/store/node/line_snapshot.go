package node

import (
	"database/sql"
	"errors"
	"strconv"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// buildLineCandidateTx builds the complete desired candidate of one node in
// the caller's transaction.
//
// The frozen baseline always carries the node identity, role, revision, VLESS
// port and pinned kernel version. An Out node never receives user credentials
// or a REALITY block; with configured transport it carries the SS link key
// (v4) for its guard listener, otherwise it keeps the baseline too. An Edge
// node without stored Line settings keeps the baseline as well.
// Only an Edge node with stored transport settings extends the candidate
// with the REALITY listener and the desired user set: every active credential
// of every active subscriber of this Line, ordered by credential ID.
//
// A Line with an enabled Out binding additionally carries the Out egress: the
// selected Out node's dial address/port plus the Hub-issued SS link key.
// The endpoint comes from the Out's own configured transport and the first
// enabled binding in node-id order, so the candidate is deterministic while
// the 1.0 model binds one Out at a time. A bound Out without transport leaves
// the egress unattached and the route renders the fail-closed block stub.
//
// The function is read-only. It never commits, mutates subscribers or
// publishes tasks; the caller owns the transaction and the candidate revision.
// BuildLineCandidateTx assembles the complete desired candidate of one node in
// the caller's transaction.
func (s *Store) BuildLineCandidateTx(tx *sql.Tx, nodeID string, revision int64) (coredomain.Candidate, error) {
	return BuildLineCandidateTxTx(tx, nodeID, revision)
}

// BuildLineCandidateTxTx is the handle-free spelling of BuildLineCandidateTx.
// The snapshot reads only tables and needs no store state, so a caller that has
// no handle (a CLI fixture, a migration check) can still build one.
func BuildLineCandidateTxTx(tx *sql.Tx, nodeID string, revision int64) (coredomain.Candidate, error) {
	var role string
	var vlessPort int
	err := tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, nodeID).Scan(&role, &vlessPort)
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.Candidate{}, common.ErrNodeNotFoundDetail
	}
	if err != nil {
		return coredomain.Candidate{}, errors.New(common.CodeDatabaseUnavailable)
	}
	candidate := coredomain.Candidate{
		NodeID:        nodeID,
		Role:          coredomain.Role(role),
		Revision:      revision,
		VLESSPort:     vlessPort,
		KernelVersion: coredomain.KernelVersion,
	}
	// An Out node never carries a proxy transport or user credentials. With
	// configured transport it carries the link key (a v4 document) so its
	// Agent renders the SS guard; without transport it keeps the frozen v1
	// baseline, so its stored digest still verifies.
	if coredomain.Role(role) == coredomain.RoleOut {
		if egress, configured, err := outEgressTx(tx, nodeID); err != nil {
			return coredomain.Candidate{}, err
		} else if configured {
			candidate.Out = &egress
		}
		return validateLineCandidate(candidate)
	}
	if coredomain.Role(role) == coredomain.RoleHTTP {
		// An external HTTP proxy has no Agent and therefore no candidate. Every
		// caller that reaches this branch (reconcile, ACL cleanup) is an Agent
		// action that a proxy node must never receive.
		return coredomain.Candidate{}, errors.New("NODE_ROLE_INVALID: an external http proxy has no candidate")
	}
	if coredomain.Role(role) != coredomain.RoleEdge {
		return coredomain.Candidate{}, errors.New("CANDIDATE_INVALID: role must be edge or out")
	}

	line, err := scanLine(tx.QueryRow(`SELECT node_id, display_name, server, port, sort_order,
	 server_name, handshake_server, handshake_port, private_key, public_key, short_id, local
	 FROM line_settings WHERE node_id=?`, nodeID))
	if errors.Is(err, sql.ErrNoRows) {
		// The Line is not configured yet: keep the frozen v1 baseline.
		return validateLineCandidate(candidate)
	}
	if errors.Is(err, common.ErrLineSettingsCorrupt) {
		return coredomain.Candidate{}, common.ErrLineSettingsCorrupt
	}
	if err != nil {
		return coredomain.Candidate{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if line.NodeID != nodeID {
		return coredomain.Candidate{}, common.ErrLineSettingsCorrupt
	}
	if line.Port != vlessPort {
		return coredomain.Candidate{}, errors.New("LINE_PORT_MISMATCH: the stored line port must match the vless port of the node")
	}
	users, err := lineCandidateUsersTx(tx, nodeID)
	if err != nil {
		return coredomain.Candidate{}, err
	}
	candidate.Users = users
	candidate.Reality = &coredomain.RealityConfig{
		ServerName:      line.ServerName,
		HandshakeServer: line.HandshakeServer,
		HandshakePort:   line.HandshakePort,
		PrivateKey:      line.PrivateKey,
		ShortID:         line.ShortID,
	}
	if err := attachLineOutEgressTx(tx, nodeID, &candidate); err != nil {
		return coredomain.Candidate{}, err
	}
	return validateLineCandidate(candidate)
}

// lineCandidateUsersTx returns the complete desired user set of one Line: the
// active credentials of active subscribers only. A paused, deleting or deleted
// subscriber stays in the database but is no longer part of the snapshot.
//
// The result is never nil, so a configured Line without users still serializes
// an explicit empty array rather than null.
func lineCandidateUsersTx(tx *sql.Tx, nodeID string) ([]coredomain.VLESSUser, error) {
	rows, err := tx.Query(`SELECT c.id, c.uuid FROM proxy_credentials c
	 JOIN subscribers s ON s.id=c.subscriber_id
	 WHERE c.node_id=? AND c.active=1 AND s.state='active'
	 ORDER BY c.id ASC`, nodeID)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	users := []coredomain.VLESSUser{}
	for rows.Next() {
		var user coredomain.VLESSUser
		if err = rows.Scan(&user.CredentialID, &user.UUID); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if len(users) > common.MaxLineCandidateUsers {
		return nil, errors.New("CANDIDATE_INVALID: at most " + strconv.Itoa(common.MaxLineCandidateUsers) + " users are allowed")
	}
	return users, nil
}

// attachLineOutEgressTx attaches the Hub-issued egress dial body to a configured
// Line candidate when a subscription selected an egress for that Line (Task 5: the
// edge is the authorization, there is no binding row). The selected egress may be a
// MeshMux Out (SS link key) or an external HTTP proxy (Ruling R11: address/port
// plus optional Basic credentials). The first egress in node-id order wins, so one
// Line never renders two endpoints while the 1.0 same-Line rule carries a single
// "out" tag. An egress without a configured dial body leaves the egress
// unattached: the route still renders the fail-closed block stub, and selecting
// such an egress is refused by validateSelectionOutTx, so this only happens for
// an egress whose endpoint was removed after it was selected (SetOutTransport
// never deletes; an HTTP proxy row is deleted with its node).
func attachLineOutEgressTx(tx *sql.Tx, nodeID string, candidate *coredomain.Candidate) error {
	outs, err := selectedEgressIDsForLineTx(tx, nodeID)
	if err != nil {
		return err
	}
	if len(outs) == 0 {
		return nil
	}
	egress, configured, err := lineEgressBodyTx(tx, outs[0])
	if err != nil {
		return err
	}
	if !configured {
		return nil
	}
	candidate.Out = &egress
	return nil
}

// validateLineCandidate validates the assembled candidate and replaces every
// validation detail with one stable, value-free code. A validation message may
// otherwise expose the reason a stored record was rejected.
func validateLineCandidate(candidate coredomain.Candidate) (coredomain.Candidate, error) {
	if err := candidate.Validate(); err != nil {
		return coredomain.Candidate{}, errors.New("CANDIDATE_INVALID: line snapshot does not satisfy the node candidate contract")
	}
	return candidate, nil
}
