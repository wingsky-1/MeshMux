package node

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// Out transport: the operator-entered dial address of one Out node plus the
// Hub-issued SS link key that Out admits clients with (Ruling R7: the hop is
// Shadowsocks, never bare VLESS). The key is the only admission: there is no
// source allowlist.
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
// EnsureOutTransportTable creates the Out dial-parameter table on every open.
func EnsureOutTransportTable(tx *sql.Tx) error {
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
		key, err := coredomain.NewOutLinkKey()
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

// OutPoolEntry is one selectable egress of the pool: an Out node or an
// external HTTP proxy (Ruling R11). It carries the node identity, its dial
// parameters when configured, and the Lines a subscription selects it for. It
// is the selection datasource the wizard consumes; it carries no credential,
// no link key and no proxy password.
//
// LineIDs is plural because one egress may be selected by several subscriptions
// serving different Lines, and the pool has to show all of them. Enabled is true
// when at least one active subscription serves at least one Line through this
// egress; it is a wizard/UI signal only — it authorizes nothing. An Out admits
// any client that presents the link key its own candidate publishes.
type OutPoolEntry struct {
	OutID               string   `json:"out_id"`
	DisplayName         string   `json:"display_name"`
	Role                string   `json:"role"`
	VlessPort           int      `json:"vless_port"`
	Online              bool     `json:"online"`
	TransportConfigured bool     `json:"transport_configured"`
	Server              string   `json:"server,omitempty"`
	Port                int      `json:"port,omitempty"`
	LineIDs             []string `json:"line_ids,omitempty"`
	Enabled             bool     `json:"enabled"`
}

// External reports whether the entry is an external HTTP proxy. An external
// egress is always reachable as far as the Hub knows, so the UI labels it
// "外部声明" instead of online/offline or a proved Out health.
func (e OutPoolEntry) External() bool { return e.Role == string(common.NodeRoleHTTP) }

// HTTPProxy is the operator-visible half of one external proxy: the canonical
// credential-free host:port the Line renders. The Basic credentials stay in
// node_http_proxy and never leave the store.
type HTTPProxy struct {
	ProxyID   string `json:"proxy_id"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	UpdatedAt int64  `json:"updated_at"`
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
		return OutTransport{}, common.ErrOutIDInvalid()
	}
	server = strings.ToLower(strings.TrimSpace(server))
	tx, err := s.DB.Begin()
	if err != nil {
		return OutTransport{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	var vlessPort int
	err = tx.QueryRow(`SELECT role, vless_port FROM nodes WHERE id=?`, outID).Scan(&role, &vlessPort)
	if errors.Is(err, sql.ErrNoRows) {
		return OutTransport{}, common.ErrOutNotFound
	}
	if err != nil {
		return OutTransport{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(common.NodeRoleOut) {
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
		linkKey, err = coredomain.NewOutLinkKey()
		if err != nil {
			return OutTransport{}, errors.New("OUT_TRANSPORT_FAILED: the link key could not be issued")
		}
	default:
		return OutTransport{}, errors.New(common.CodeDatabaseUnavailable)
	}
	// A migrated row carries link_key='' until the ensure step reissues it;
	// a set on such a row mints the key now instead of storing a void one.
	if linkKey == "" {
		linkKey, err = coredomain.NewOutLinkKey()
		if err != nil {
			return OutTransport{}, errors.New("OUT_TRANSPORT_FAILED: the link key could not be issued")
		}
	}
	egress := coredomain.OutEgress{Server: server, Port: port, Key: linkKey}
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
		return OutTransport{}, errors.New(common.CodeDatabaseUnavailable)
	}
	// A changed dial address changes the Out's own candidate (its link-key
	// listener document): republish it. Lines embed nothing of the Out, so no
	// Line has to converge. The drain owns its own transaction and never fails
	// the mutation.
	s.drainOutNode(outID, now)
	return OutTransport{OutID: outID, Server: server, Port: port, UpdatedAt: stamp}, nil
}

// outEgressTx is the single derivation of one Out's dial body for candidate
// rendering: the configured server/port plus the Hub-issued link key. The
// boolean is false when the Out has no transport yet; callers render the frozen
// baseline in that case instead of inventing an endpoint.
func outEgressTx(tx *sql.Tx, outID string) (coredomain.OutEgress, bool, error) {
	var egress coredomain.OutEgress
	err := tx.QueryRow(`SELECT server, port, link_key FROM out_settings WHERE node_id=?`, outID).
		Scan(&egress.Server, &egress.Port, &egress.Key)
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.OutEgress{}, false, nil
	}
	if err != nil {
		return coredomain.OutEgress{}, false, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := egress.Validate(); err != nil {
		return coredomain.OutEgress{}, false, errors.New("OUT_TRANSPORT_CORRUPT: the stored out transport is invalid")
	}
	return egress, true, nil
}

// OutPool lists every enrolled Out node with its dial address and the Lines a
// subscription selects it for, at one clock. It never returns a key: the link
// key stays in the private table and only enters the Out's own v4 document and
// the subscription document composed for a client.
//
// The selection is a projection of the subscription edges: which Out the wizard
// may offer, and which Lines currently route through it. Nothing here authorizes
// anything — an Out admits by link key — so a paused subscription simply stops
// contributing Lines to this projection.
func (s *Store) OutPool(now time.Time) ([]OutPoolEntry, error) {
	rows, err := s.DB.Query(`
SELECT n.id, n.role, n.display_name, n.vless_port, n.status, n.last_heartbeat,
 o2.server, o2.port, h.url, l.node_id, b.state
FROM nodes n
LEFT JOIN out_settings o2 ON o2.node_id=n.id
LEFT JOIN node_http_proxy h ON h.node_id=n.id
LEFT JOIN subscription_outs o ON o.out_id=n.id
LEFT JOIN subscribers b ON b.id=o.subscriber_id
LEFT JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
WHERE n.role IN ('out','http')
ORDER BY n.created_at ASC, n.id ASC, l.node_id ASC`)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	byOut := map[string]*OutPoolEntry{}
	order := []string{}
	for rows.Next() {
		var (
			outID    string
			role     string
			name     string
			vless    int
			status   string
			lastBeat int64
			server   sql.NullString
			port     sql.NullInt64
			proxyURL sql.NullString
			lineID   sql.NullString
			state    sql.NullString
		)
		if err := rows.Scan(&outID, &role, &name, &vless, &status, &lastBeat,
			&server, &port, &proxyURL, &lineID, &state); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		entry, seen := byOut[outID]
		if !seen {
			entry = &OutPoolEntry{
				OutID:       outID,
				DisplayName: name,
				Role:        role,
				VlessPort:   vless,
				Online:      status != common.NodeStatusPending && lastBeat != 0 && now.Sub(time.Unix(lastBeat, 0)) <= common.OfflineAfter,
				LineIDs:     []string{},
			}
			if role == string(common.NodeRoleHTTP) {
				// The external proxy has no heartbeat: its endpoint is the
				// operator's URL and it is "reachable" only in the sense that
				// the Hub holds a configured dial body. The UI labels it 外部.
				entry.Online = true
				if proxyURL.Valid {
					if egress, parseErr := coredomain.ParseHTTPProxyURL(proxyURL.String); parseErr == nil {
						entry.TransportConfigured = true
						entry.Server = egress.Server
						entry.Port = egress.Port
					}
				}
			} else {
				entry.TransportConfigured = server.Valid && port.Valid
				if entry.TransportConfigured {
					entry.Server = server.String
					entry.Port = int(port.Int64)
				}
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
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	out := make([]OutPoolEntry, 0, len(order))
	for _, outID := range order {
		out = append(out, *byOut[outID])
	}
	return out, nil
}
