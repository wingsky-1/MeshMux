package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	nodedomain "github.com/wingsky-1/MeshMux/internal/node"
)

// Out transport: the operator-entered dial address of one Out node plus the
// Hub-issued SS link key the Line presents when it egresses through that Out
// (Ruling R7: the double-hop is Shadowsocks, never bare VLESS).
//
// The table is created idempotently without a user_version bump: the
// subscription-aggregation schema numbers (12/13/14) are reserved for Task
// 3/4/5 and 11 belongs to 11d, so Task 2 takes no number. The table is purely
// additive — a fresh binary ignores it, an older binary ignores it, and the
// 11d/T3 migrations never touch it — which keeps the downgrade and rebase
// contracts intact. ensureOutTransportTable runs on every open, so fresh and
// existing databases converge without a version step.
//
// Under Ruling R7 the link key is the SS key (16 random bytes,
// base64-std), not the void Task-2 UUID. The migration drops the old column
// and reissues a fresh key for every configured Out: old credentials are
// void, not carried over (1.0 is unreleased, so no backward compat is owed).
// Fresh databases are created with the new shape directly.
//
// The key is a node secret in the same class as the per-Line VLESS UUIDs:
// it is rendered into the bound Line candidates and the Out's own v4
// document (the private Hub<->Agent channel) and never appears in a list
// projection, a log line or a subscription artifact.
func ensureOutTransportTable(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS out_settings (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  link_key TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`); err != nil {
		return err
	}
	// Void the Task-2 UUID column when it exists: the SS switch does not
	// carry old credentials over.
	var legacy int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('out_settings') WHERE name='link_uuid'`).Scan(&legacy); err != nil {
		return err
	}
	if legacy != 0 {
		if _, err := tx.Exec(`ALTER TABLE out_settings DROP COLUMN link_uuid`); err != nil {
			return err
		}
	}
	var keyed int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('out_settings') WHERE name='link_key'`).Scan(&keyed); err != nil {
		return err
	}
	if keyed == 0 {
		if _, err := tx.Exec(`ALTER TABLE out_settings ADD COLUMN link_key TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	// Reissue: every configured Out whose row predates the SS switch (or a
	// fresh row) gets a fresh link key. Drains converge the affected Line
	// and Out candidates on their next event.
	rows, err := tx.Query(`SELECT node_id FROM out_settings WHERE link_key=''`)
	if err != nil {
		return err
	}
	var bare []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		bare = append(bare, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range bare {
		key, err := nodedomain.NewOutLinkKey()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE out_settings SET link_key=? WHERE node_id=?`, key, id); err != nil {
			return err
		}
	}
	return nil
}

// OutTransport is the operator-visible half of one Out's dial parameters.
// The link key never leaves this package: list projections and the Web UI only
// see the address, never the key.
type OutTransport struct {
	OutID     string `json:"out_id"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	UpdatedAt int64  `json:"updated_at"`
}

// OutPoolEntry is one Out of the pool: the node identity, its dial parameters
// when configured, and the Lines a subscription selects it for. It is the
// selection datasource the wizard consumes; it carries no credential, no link key
// and no allowlist.
//
// LineIDs is plural because the authorization is derived from the subscription
// edges (Task 5): one Out may be selected by several subscriptions serving
// different Lines, and the pool has to show all of them. Enabled is true when at
// least one active subscription serves at least one Line through this Out, which is
// exactly the condition under which it authorizes a source.
type OutPoolEntry struct {
	OutID               string   `json:"out_id"`
	DisplayName         string   `json:"display_name"`
	VlessPort           int      `json:"vless_port"`
	Online              bool     `json:"online"`
	TransportConfigured bool     `json:"transport_configured"`
	Server              string   `json:"server,omitempty"`
	Port                int      `json:"port,omitempty"`
	LineIDs             []string `json:"line_ids,omitempty"`
	Enabled             bool     `json:"enabled"`
}

// SetOutTransport stores the dial address of one Out node. The node must
// exist with the immutable out role; the port must equal the Out's VLESS
// port, mirroring the Line port-match rule. The link key is issued on
// first set and preserved afterwards, mirroring the REALITY key preservation
// of SetLine: renaming the address never invalidates the egress the bound
// Line already dials with. Setting transport on a migrated-empty row mints
// the key now.
func (s *Store) SetOutTransport(outID, server string, port int, now time.Time) (OutTransport, error) {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return OutTransport{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	server = strings.ToLower(strings.TrimSpace(server))
	tx, err := s.DB.Begin()
	if err != nil {
		return OutTransport{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	var vlessPort int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, outID).Scan(&role, &vlessPort)
	if errors.Is(err, sql.ErrNoRows) {
		return OutTransport{}, errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return OutTransport{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return OutTransport{}, errors.New("OUT_ROLE_INVALID: only out nodes carry an out transport")
	}
	if port != vlessPort {
		return OutTransport{}, errors.New("OUT_PORT_MISMATCH: the out port must match the vless port of the node")
	}
	var linkKey string
	err = tx.QueryRow(`SELECT link_key FROM out_settings WHERE node_id=?`, outID).Scan(&linkKey)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		linkKey, err = nodedomain.NewOutLinkKey()
		if err != nil {
			return OutTransport{}, errors.New("OUT_TRANSPORT_FAILED: the link key could not be issued")
		}
	default:
		return OutTransport{}, errors.New("DATABASE_UNAVAILABLE")
	}
	// A migrated row carries link_key='' until the ensure step reissues it;
	// a set on such a row mints the key now instead of storing a void one.
	if linkKey == "" {
		linkKey, err = nodedomain.NewOutLinkKey()
		if err != nil {
			return OutTransport{}, errors.New("OUT_TRANSPORT_FAILED: the link key could not be issued")
		}
	}
	egress := nodedomain.OutEgress{Server: server, Port: port, Key: linkKey}
	if err := egress.Validate(); err != nil {
		return OutTransport{}, errors.New("OUT_TRANSPORT_INVALID: need one hostname or IP address without scheme, path, port or credentials")
	}
	stamp := now.Unix()
	if _, err = tx.Exec(`INSERT INTO out_settings(node_id, server, port, link_key, created_at, updated_at)
	 VALUES(?,?,?,?,?,?)
	 ON CONFLICT(node_id) DO UPDATE SET server=excluded.server, port=excluded.port, link_key=excluded.link_key, updated_at=excluded.updated_at`,
		outID, server, port, linkKey, stamp, stamp); err != nil {
		return OutTransport{}, errors.New("OUT_TRANSPORT_FAILED: the out transport was not stored")
	}
	if err = tx.Commit(); err != nil {
		return OutTransport{}, errors.New("DATABASE_UNAVAILABLE")
	}
	// A changed dial address invalidates every Line candidate that renders
	// this Out: each bound Line republishes with the new endpoint. The drains
	// own their own transactions and never fail the mutation.
	if lines, err := s.lineIDsForOut(outID); err == nil {
		for _, lineID := range lines {
			s.drainSubscriberNode(lineID, now)
		}
	}
	return OutTransport{OutID: outID, Server: server, Port: port, UpdatedAt: stamp}, nil
}

// GetOutTransport reads the operator-visible half of one Out's dial
// parameters. The link key is never returned.
func (s *Store) GetOutTransport(outID string) (OutTransport, error) {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return OutTransport{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	var transport OutTransport
	transport.OutID = outID
	err := s.DB.QueryRow(`SELECT server, port, updated_at FROM out_settings WHERE node_id=?`, outID).
		Scan(&transport.Server, &transport.Port, &transport.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OutTransport{}, errors.New("OUT_NOT_CONFIGURED: configure the out transport before selecting the out")
	}
	if err != nil {
		return OutTransport{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return transport, nil
}

// outEgressTx is the single derivation of one Out's dial body for candidate
// rendering: the configured server/port plus the Hub-issued link key. The
// boolean is false when the Out has no transport yet; callers render the
// fail-closed block stub in that case instead of inventing an endpoint.
func outEgressTx(tx *sql.Tx, outID string) (nodedomain.OutEgress, bool, error) {
	var egress nodedomain.OutEgress
	err := tx.QueryRow(`SELECT server, port, link_key FROM out_settings WHERE node_id=?`, outID).
		Scan(&egress.Server, &egress.Port, &egress.Key)
	if errors.Is(err, sql.ErrNoRows) {
		return nodedomain.OutEgress{}, false, nil
	}
	if err != nil {
		return nodedomain.OutEgress{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	if err := egress.Validate(); err != nil {
		return nodedomain.OutEgress{}, false, errors.New("OUT_TRANSPORT_CORRUPT: the stored out transport is invalid")
	}
	return egress, true, nil
}

// ListOutTransports returns the operator-visible dial parameters of every Out
// that has transport configured, ordered by node id. The credentials are
// never listed.
func (s *Store) ListOutTransports() ([]OutTransport, error) {
	rows, err := s.DB.Query(`SELECT node_id, server, port, updated_at FROM out_settings ORDER BY node_id ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []OutTransport{}
	for rows.Next() {
		var transport OutTransport
		if err := rows.Scan(&transport.OutID, &transport.Server, &transport.Port, &transport.UpdatedAt); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, transport)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// OutPool lists every enrolled Out node with its dial address and the Lines a
// subscription selects it for, at one clock. It never returns a key: the link key
// stays in the private table and only enters the paired Line candidates and the
// Out's own v4 document.
//
// The selection is read through the subscription edges, so the pool and the ACL
// derivation cannot disagree about which Lines an Out serves. A subscriber that is
// not active contributes no Line: it is not served by any Out, which is the same
// rule the allowlist applies.
func (s *Store) OutPool(now time.Time) ([]OutPoolEntry, error) {
	rows, err := s.DB.Query(`
SELECT n.id, n.display_name, n.vless_port, n.status, n.last_heartbeat,
 o2.server, o2.port, l.node_id, b.state
FROM nodes n
LEFT JOIN out_settings o2 ON o2.node_id=n.id
LEFT JOIN subscription_outs o ON o.out_id=n.id
LEFT JOIN subscribers b ON b.id=o.subscriber_id
LEFT JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
WHERE n.role='out'
ORDER BY n.created_at ASC, n.id ASC, l.node_id ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	byOut := map[string]*OutPoolEntry{}
	order := []string{}
	for rows.Next() {
		var (
			outID    string
			name     string
			vless    int
			status   string
			lastBeat int64
			server   sql.NullString
			port     sql.NullInt64
			lineID   sql.NullString
			state    sql.NullString
		)
		if err := rows.Scan(&outID, &name, &vless, &status, &lastBeat,
			&server, &port, &lineID, &state); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		entry, seen := byOut[outID]
		if !seen {
			entry = &OutPoolEntry{
				OutID:       outID,
				DisplayName: name,
				VlessPort:   vless,
				Online:      status != "pending" && lastBeat != 0 && now.Sub(time.Unix(lastBeat, 0)) <= OfflineAfter,
				LineIDs:     []string{},
			}
			entry.TransportConfigured = server.Valid && port.Valid
			if entry.TransportConfigured {
				entry.Server = server.String
				entry.Port = int(port.Int64)
			}
			byOut[outID] = entry
			order = append(order, outID)
		}
		if lineID.Valid && state.Valid && state.String == "active" {
			entry.LineIDs = append(entry.LineIDs, lineID.String)
			entry.Enabled = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	out := make([]OutPoolEntry, 0, len(order))
	for _, outID := range order {
		out = append(out, *byOut[outID])
	}
	return out, nil
}
