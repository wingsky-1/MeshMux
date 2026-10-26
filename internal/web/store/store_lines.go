package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

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
func (s *Store) SetLine(line subscription.Line, now time.Time) (subscription.Line, error) {
	if err := subscription.ValidateID(line.NodeID); err != nil {
		return subscription.Line{}, errLineNodeIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return subscription.Line{}, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	var vlessPort int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, line.NodeID).Scan(&role, &vlessPort)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Line{}, errLineNotFound
	}
	if err != nil {
		return subscription.Line{}, errors.New(CodeDatabaseUnavailable)
	}
	if role != string(nodeRoleEdge) {
		return subscription.Line{}, errLineRoleInvalid
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
		return subscription.Line{}, errors.New(CodeDatabaseUnavailable)
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
		return subscription.Line{}, errLineSettingsFailed
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return subscription.Line{}, errLineSettingsFailed
	}
	if affected == 0 {
		if _, err = tx.Exec(`INSERT INTO line_settings(node_id, display_name, server, port, sort_order, server_name, handshake_server, handshake_port, private_key, public_key, short_id, local, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			line.NodeID, line.DisplayName, line.Server, line.Port, line.SortOrder, line.ServerName, line.HandshakeServer, line.HandshakePort,
			line.PrivateKey, line.PublicKey, line.ShortID, local, now.Unix(), now.Unix()); err != nil {
			return subscription.Line{}, errLineSettingsFailed
		}
	}
	if err = tx.Commit(); err != nil {
		return subscription.Line{}, errors.New(CodeDatabaseUnavailable)
	}
	// The stored address IS the authorized source (Ruling R10: membership authorizes a
	// Line, and its transport address is what the Out observes). A changed address is
	// therefore a membership change: leaving the old one accepted would authorize a
	// host the Hub no longer owns, and omitting the new one would drop a live Line.
	// Every Out republishes, each a no-op unless its derived list changed.
	s.RepublishOutAuthorizations(now)
	return line, nil
}

// listLines returns every stored Line ordered by its sort order.
func (s *Store) ListLines() ([]subscription.Line, error) {
	rows, err := s.DB.Query(`SELECT node_id, display_name, server, port, sort_order, server_name, handshake_server, handshake_port, private_key, public_key, short_id, local FROM line_settings ORDER BY sort_order ASC, display_name ASC`)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []subscription.Line{}
	for rows.Next() {
		line, err := scanLine(rows)
		if errors.Is(err, errLineSettingsCorrupt) {
			return nil, err
		}
		if err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
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
