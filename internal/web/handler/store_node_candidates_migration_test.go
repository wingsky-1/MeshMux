package handler

import (
	"database/sql"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSchemaV2MigrationPreservesNodesAndSeedsCandidate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "meshmux.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err = db.Exec(`
CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL);
CREATE TABLE sessions (token_hash BLOB PRIMARY KEY, csrf TEXT NOT NULL, authenticated INTEGER NOT NULL CHECK(authenticated IN (0,1)), expires INTEGER NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE bootstrap (id INTEGER PRIMARY KEY CHECK(id=1), token_hash BLOB NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE auth_limit (id INTEGER PRIMARY KEY CHECK(id=1), started INTEGER NOT NULL, attempts INTEGER NOT NULL);
INSERT INTO auth_limit VALUES(1,0,0);
CREATE TABLE nodes (id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('edge','out')), display_name TEXT NOT NULL, vless_port INTEGER NOT NULL, ssh_port INTEGER NOT NULL, status TEXT NOT NULL, agent_version TEXT NOT NULL DEFAULT '', kernel_version TEXT NOT NULL DEFAULT '', last_heartbeat INTEGER NOT NULL DEFAULT 0, last_success TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE node_pairing (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, code_hash BLOB NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE node_identities (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, token_hash BLOB NOT NULL, created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE agent_tasks (operation_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, kind TEXT NOT NULL, revision INTEGER NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '', params TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX agent_tasks_node ON agent_tasks(node_id);
PRAGMA user_version=2;
INSERT INTO nodes VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','edge','legacy',8443,2222,'paired','','',0,'',?,?);
INSERT INTO node_identities VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',x'0102',?,0);
INSERT INTO agent_tasks VALUES('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','health.status',1,'cccccccccccccccccccccccccccccccc','healthy','','{}',?,?);
`, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	// Hermetic fixture: explicit 0700/0600 independent of ambient umask
	// (local 077 masks this; CI 022 exposes DATA_PERMISSIONS). Industry
	// practice is never to inherit permissions from the environment.
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(dir, "meshmux.db"), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := store.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("user_version=%d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	n, err := s.GetNodeAt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", time.Now())
	if err != nil || n.DisplayName != "legacy" || n.LatestConfigRevision != 1 {
		t.Fatalf("node migration lost data: %+v err=%v", n, err)
	}
	var identity int
	if err = s.DB.QueryRow(`SELECT count(*) FROM node_identities WHERE token_hash=x'0102'`).Scan(&identity); err != nil || identity != 1 {
		t.Fatalf("identity lost: %d err=%v", identity, err)
	}
	var taskDetail string
	if err = s.DB.QueryRow(`SELECT detail FROM agent_tasks WHERE operation_id='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'`).Scan(&taskDetail); err != nil || taskDetail != "" {
		t.Fatalf("task migration lost detail column: %q err=%v", taskDetail, err)
	}
	if _, err = s.DB.Exec(`UPDATE node_candidates SET config_sha256=config_sha256 WHERE node_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'`); err == nil {
		t.Fatal("candidate table was mutable")
	}
}
