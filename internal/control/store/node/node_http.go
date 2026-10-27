package node

// External HTTP proxy nodes (Ruling R11).
//
// An HTTP proxy is a Hub-visible egress node with role "http". It is not a
// managed host: it has no Agent, no pairing code, no candidate revision, no
// task chain and no readback, and its status is always "external". It is
// therefore excluded from every convergence gate — its availability is the
// operator's external fact, not something the Hub can prove.
//
// node_http_proxy is the private half of the node, in the same class as the
// Line REALITY private key and the Out link key: the whole SQLite file is 0600
// (OpenStore enforces that), the stored URL is the credential-free canonical
// http://host:port form, and the optional Basic credentials live in their own
// columns. A list projection renders only host:port, and a credential-free
// proxy renders no username/password in the Line's egress at all.
//
// Schema 16 rebuilds the nodes table to admit role "http". SQLite cannot change
// a CHECK constraint in place, and DROP TABLE on a parent with foreign_keys=ON
// would cascade the children away, so the rebuild runs with foreign_keys=OFF in
// its own transaction after the sequential chain committed. A crash leaves the
// database at 15 and the next open retries; a successful rebuild is one atomic
// version step.

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// nodeColumns is the exact column set of nodes, in the order the rebuild
// copies it. It is repeated once because the rebuild DDL must spell it out.
const nodeColumns = `id, role, display_name, vless_port, ssh_port, status,
 agent_version, kernel_version, last_heartbeat, last_success, created_at, updated_at,
 observed_revision, observed_config_sha256, observed_architecture,
 observed_agent_version, observed_agent_sha256, observed_kernel_version,
 observed_kernel_sha256, observed_out_default_deny, observed_at,
 observed_task_revision, observed_task_operation_id, last_success_at`

// nodeHTTPProxyDDL is the one definition of the private proxy table.
const nodeHTTPProxyDDL = `CREATE TABLE IF NOT EXISTS node_http_proxy (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  username TEXT,
  password TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);`

// migrateSchema16 rebuilds nodes with the http role and creates the private
// proxy table.
//
// The rebuild cannot run inside the normal migration transaction: SQLite's
// DROP TABLE performs an implicit DELETE on the parent with foreign_keys=ON,
// which would cascade every node's candidates, tasks, identities, credentials
// and subscription edges away. The pragma is per connection, so with the
// single-connection pool it is toggled around one transaction and restored on
// every path.
// MigrateSchema16 rebuilds the nodes table with the http role.
func MigrateSchema16(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= 16 {
		// A database already rebuilt (16) or a newer binary's file (17 after the
		// payload rewrite) keeps its rows; ensure the additive table is present
		// so a manually damaged/older fixture converges instead of failing at the
		// first proxy read.
		_, err := db.Exec(nodeHTTPProxyDDL)
		return err
	}
	if version != 15 {
		return errors.New("SCHEMA_MIGRATION_FAILED: schema 16 requires the schema 15 chain")
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer func() {
		_, _ = db.Exec(`PRAGMA foreign_keys=ON`)
	}()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
CREATE TABLE nodes_new (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK(role IN ('edge','out','http')),
  display_name TEXT NOT NULL,
  vless_port INTEGER NOT NULL,
  ssh_port INTEGER NOT NULL,
  status TEXT NOT NULL,
  agent_version TEXT NOT NULL DEFAULT '',
  kernel_version TEXT NOT NULL DEFAULT '',
  last_heartbeat INTEGER NOT NULL DEFAULT 0,
  last_success TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  observed_revision INTEGER NOT NULL DEFAULT 0,
  observed_config_sha256 TEXT NOT NULL DEFAULT '',
  observed_architecture TEXT NOT NULL DEFAULT '',
  observed_agent_version TEXT NOT NULL DEFAULT '',
  observed_agent_sha256 TEXT NOT NULL DEFAULT '',
  observed_kernel_version TEXT NOT NULL DEFAULT '',
  observed_kernel_sha256 TEXT NOT NULL DEFAULT '',
  observed_out_default_deny INTEGER NOT NULL DEFAULT 0,
  observed_at INTEGER NOT NULL DEFAULT 0,
  observed_task_revision INTEGER NOT NULL DEFAULT 0,
  observed_task_operation_id TEXT NOT NULL DEFAULT '',
  last_success_at INTEGER NOT NULL DEFAULT 0
);
INSERT INTO nodes_new(` + nodeColumns + `) SELECT ` + nodeColumns + ` FROM nodes;
-- The candidate trigger's WHEN clause names nodes. SQLite reparses every
-- trigger on ALTER TABLE RENAME, and the table is momentarily absent while the
-- rebuild runs, so the trigger is dropped first and recreated after the rename
-- with the exact schema-15 body.
DROP TRIGGER IF EXISTS node_candidates_immutable_delete;
DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;
CREATE TRIGGER node_candidates_immutable_delete BEFORE DELETE ON node_candidates
WHEN EXISTS (SELECT 1 FROM nodes WHERE id = OLD.node_id)
BEGIN
  SELECT RAISE(ABORT, 'CANDIDATE_IMMUTABLE');
END;
` + nodeHTTPProxyDDL + `
PRAGMA user_version=16;
`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// CreateHTTPProxyNode stores one external HTTP proxy as an egress node. It
// mints only the node identity: no pairing row, no candidate and no task, so
// the node can never reach an Agent.
func (s *Store) CreateHTTPProxyNode(displayName, proxyURL string, now time.Time) (Node, error) {
	if err := protocol.ValidateNodeDisplayName(displayName); err != nil {
		return Node{}, err
	}
	egress, err := coredomain.ParseHTTPProxyURL(proxyURL)
	if err != nil {
		return Node{}, err
	}
	id, err := protocol.NewID()
	if err != nil {
		return Node{}, errors.New("NODE_ID_FAILED")
	}
	// The columns stay NULL when the proxy has no Basic auth, so "no
	// credential" is one state instead of an empty-string guess.
	var username, password any
	if egress.Username != "" {
		username = egress.Username
	}
	if egress.Password != "" {
		password = egress.Password
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return Node{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO nodes(id, role, display_name, vless_port, ssh_port, status, agent_version, kernel_version, last_heartbeat, last_success, created_at, updated_at)
 VALUES(?,?,?,0,0,'external','','',0,'',?,?)`,
		id, string(coredomain.RoleHTTP), strings.TrimSpace(displayName), now.Unix(), now.Unix()); err != nil {
		return Node{}, common.ErrNodeCreateFailed
	}
	if _, err := tx.Exec(`INSERT INTO node_http_proxy(node_id, url, username, password, created_at, updated_at)
 VALUES(?,?,?,?,?,?)`, id, egress.ProxyURL(), username, password, now.Unix(), now.Unix()); err != nil {
		return Node{}, common.ErrNodeCreateFailed
	}
	if err := tx.Commit(); err != nil {
		return Node{}, errors.New(common.CodeDatabaseUnavailable)
	}
	return Node{
		ID: id, Role: string(coredomain.RoleHTTP), DisplayName: strings.TrimSpace(displayName),
		Status: "external", CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
	}, nil
}

// SetHTTPProxy replaces the dial body of one external HTTP proxy. It is the
// exact twin of SetOutTransport (Ruling R11): the two egress forms are handled
// the same way, so a proxy URL change converges the Lines that render it
// instead of leaving a stale endpoint in their last candidate.
//
// The URL is validated by the same parser that created the node, so a stored
// row can never hold a shape the renderer refuses. Credentials are replaced
// together with the URL: an operator who resubmits a credential-free URL
// removes the old Basic auth instead of keeping a secret the UI no longer
// shows.
//
// The relayed drain happens after the commit and never fails the mutation: each
// Line publication owns its own transaction, and the next event retries it.
func (s *Store) SetHTTPProxy(proxyID, proxyURL string, now time.Time) (HTTPProxy, error) {
	proxyID = strings.TrimSpace(proxyID)
	if !validNodeID(proxyID) {
		return HTTPProxy{}, errors.New("OUT_BINDING_INVALID: proxy_id must be 32 lowercase hex characters")
	}
	egress, err := coredomain.ParseHTTPProxyURL(proxyURL)
	if err != nil {
		return HTTPProxy{}, err
	}
	var username, password any
	if egress.Username != "" {
		username = egress.Username
	}
	if egress.Password != "" {
		password = egress.Password
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return HTTPProxy{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, proxyID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return HTTPProxy{}, errors.New("OUT_NOT_FOUND: unknown egress node")
	}
	if err != nil {
		return HTTPProxy{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if coredomain.Role(role) != coredomain.RoleHTTP {
		return HTTPProxy{}, errors.New("OUT_ROLE_INVALID: only an external http proxy carries a proxy URL")
	}
	stamp := now.Unix()
	if _, err = tx.Exec(`UPDATE node_http_proxy SET url=?, username=?, password=?, updated_at=? WHERE node_id=?`,
		egress.ProxyURL(), username, password, stamp, proxyID); err != nil {
		return HTTPProxy{}, errors.New("HTTP_PROXY_UPDATE_FAILED: the proxy URL was not stored")
	}
	if err = tx.Commit(); err != nil {
		return HTTPProxy{}, errors.New(common.CodeDatabaseUnavailable)
	}
	// A changed dial body invalidates every Line candidate that renders this
	// proxy: the exact post-commit drain SetOutTransport performs for a managed
	// Out. No Out chain is involved (there is no Agent), so the Lines are the
	// only state to converge.
	if lines, err := s.lineIDsForOut(proxyID); err == nil {
		for _, lineID := range lines {
			s.Subscribers.DrainNode(lineID, now)
		}
	}
	return HTTPProxy{ProxyID: proxyID, Server: egress.Server, Port: egress.Port, UpdatedAt: stamp}, nil
}

// scanHTTPProxy reads one stored proxy row into its dial body. The stored URL
// is canonical and credential-free; the two credential columns are nullable.
func scanHTTPProxy(row common.RowScanner) (coredomain.OutEgress, error) {
	var rawURL string
	var username, password sql.NullString
	if err := row.Scan(&rawURL, &username, &password); err != nil {
		return coredomain.OutEgress{}, err
	}
	egress, err := coredomain.ParseHTTPProxyURL(rawURL)
	if err != nil {
		return coredomain.OutEgress{}, errors.New("HTTP_PROXY_CORRUPT: the stored proxy URL is invalid")
	}
	egress.Username = username.String
	egress.Password = password.String
	if err := egress.Validate(); err != nil {
		return coredomain.OutEgress{}, errors.New("HTTP_PROXY_CORRUPT: the stored proxy credentials are invalid")
	}
	return egress, nil
}

// httpProxyTx is the transaction-scoped read of one HTTP proxy's dial body.
// The boolean is false when the node has no proxy row (an unconfigured or
// non-http node), never an invented endpoint.
func httpProxyTx(tx *sql.Tx, nodeID string) (coredomain.OutEgress, bool, error) {
	egress, err := scanHTTPProxy(tx.QueryRow(`SELECT url, username, password FROM node_http_proxy WHERE node_id=?`, nodeID))
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.OutEgress{}, false, nil
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "HTTP_PROXY_CORRUPT") {
			return coredomain.OutEgress{}, false, err
		}
		return coredomain.OutEgress{}, false, errors.New(common.CodeDatabaseUnavailable)
	}
	return egress, true, nil
}

// lineEgressBodyTx resolves one selected egress node into the candidate dial
// body: an Out link key or an HTTP proxy credential. The boolean is false when
// the egress has no configured endpoint; callers keep the fail-closed block
// stub in that case.
func lineEgressBodyTx(tx *sql.Tx, nodeID string) (coredomain.OutEgress, bool, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.OutEgress{}, false, errors.New("EGRESS_NOT_FOUND: unknown egress node")
	}
	if err != nil {
		return coredomain.OutEgress{}, false, errors.New(common.CodeDatabaseUnavailable)
	}
	switch coredomain.Role(role) {
	case coredomain.RoleOut:
		return outEgressTx(tx, nodeID)
	case coredomain.RoleHTTP:
		return httpProxyTx(tx, nodeID)
	default:
		return coredomain.OutEgress{}, false, nil
	}
}
