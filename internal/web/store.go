package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const sessionLifetime = 8 * time.Hour
const idleLifetime = 30 * time.Minute
const anonymousLifetime = 15 * time.Minute

type store struct {
	db   *sql.DB
	lock *os.File
	dir  string
}
type session struct {
	Hash    []byte
	CSRF    string
	Auth    bool
	Expires int64
}

// The dedicated directory is the security boundary for SQLite and its WAL/SHM.
// Reject unsafe existing state instead of silently chmod'ing someone else's files.
func privatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || info.Mode().Perm()&0077 != 0 || (!directory && !info.Mode().IsRegular()) {
		return errors.New("DATA_PERMISSIONS: require owned private directory/files without symlinks")
	}
	return nil
}

func openStore(dir string) (*store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	if resolved != filepath.Dir(abs) {
		return nil, errors.New("DATA_PERMISSIONS: parent path must not contain symlinks")
	}
	if err = os.Mkdir(abs, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err = privatePath(abs, true); err != nil {
		return nil, err
	}
	for _, name := range []string{"meshmux.db", "meshmux.db-wal", "meshmux.db-shm", ".lock", "bootstrap.token"} {
		if e := privatePath(filepath.Join(abs, name), false); e != nil && !os.IsNotExist(e) {
			return nil, e
		}
	}
	lock, err := os.OpenFile(filepath.Join(abs, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("DATA_LOCKED: another Web process uses this directory")
	}
	s := &store{lock: lock, dir: abs}
	f, err := os.OpenFile(filepath.Join(abs, "meshmux.db"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		s.Close()
		return nil, err
	}
	f.Close()
	u := url.URL{Scheme: "file", Path: filepath.Join(abs, "meshmux.db")}
	s.db, err = sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		s.Close()
		return nil, err
	}
	s.db.SetMaxOpenConns(1)
	if err = s.migrate(); err != nil {
		s.Close()
		return nil, err
	}
	for _, name := range []string{"meshmux.db", "meshmux.db-wal", "meshmux.db-shm"} {
		if e := privatePath(filepath.Join(abs, name), false); e != nil && !os.IsNotExist(e) {
			s.Close()
			return nil, e
		}
	}
	return s, nil
}

func (s *store) Close() error {
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
	}
	return err
}

func (s *store) migrate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 7 {
		return errors.New("SCHEMA_TOO_NEW: restore matching binary and database; do not downgrade in place")
	}
	if version == 0 {
		_, err = tx.Exec(`
   CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL);
   CREATE TABLE sessions (token_hash BLOB PRIMARY KEY, csrf TEXT NOT NULL, authenticated INTEGER NOT NULL CHECK(authenticated IN (0,1)), expires INTEGER NOT NULL, seen INTEGER NOT NULL);
   CREATE INDEX sessions_expiry ON sessions(expires);
   CREATE TABLE bootstrap (id INTEGER PRIMARY KEY CHECK(id=1), token_hash BLOB NOT NULL, expires INTEGER NOT NULL);
   CREATE TABLE auth_limit (id INTEGER PRIMARY KEY CHECK(id=1), started INTEGER NOT NULL, attempts INTEGER NOT NULL);
   INSERT INTO auth_limit VALUES(1,0,0);
   PRAGMA user_version=2;
   CREATE TABLE nodes (id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('edge','out')), display_name TEXT NOT NULL, vless_port INTEGER NOT NULL, ssh_port INTEGER NOT NULL, status TEXT NOT NULL, agent_version TEXT NOT NULL DEFAULT '', kernel_version TEXT NOT NULL DEFAULT '', last_heartbeat INTEGER NOT NULL DEFAULT 0, last_success TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
   CREATE TABLE node_pairing (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, code_hash BLOB NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
   CREATE TABLE node_identities (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, token_hash BLOB NOT NULL, created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
   CREATE TABLE agent_tasks (operation_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, kind TEXT NOT NULL, revision INTEGER NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '', params TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
   CREATE INDEX agent_tasks_node ON agent_tasks(node_id);
  `)
		if err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 2
	}
	if version == 1 {
		_, err = tx.Exec(`
   CREATE TABLE nodes (id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('edge','out')), display_name TEXT NOT NULL, vless_port INTEGER NOT NULL, ssh_port INTEGER NOT NULL, status TEXT NOT NULL, agent_version TEXT NOT NULL DEFAULT '', kernel_version TEXT NOT NULL DEFAULT '', last_heartbeat INTEGER NOT NULL DEFAULT 0, last_success TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
   CREATE TABLE node_pairing (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, code_hash BLOB NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
   CREATE TABLE node_identities (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, token_hash BLOB NOT NULL, created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
   CREATE TABLE agent_tasks (operation_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, kind TEXT NOT NULL, revision INTEGER NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '', params TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
   CREATE INDEX agent_tasks_node ON agent_tasks(node_id);
   PRAGMA user_version=2;
   `)
		if err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 2
	}
	if version == 2 {
		if err = migrateSchema3(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 3
	}
	if version == 3 {
		if err = migrateSchema4(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 4
	}
	if version == 4 {
		if err = migrateSchema5(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 5
	}
	if version == 5 {
		if err = migrateSchema6(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 6
	}
	if version == 6 {
		if err = migrateSchema7(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 7
	}
	return tx.Commit()
}

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

func (s *store) adminHash() (string, error) {
	var hash string
	err := s.db.QueryRow("SELECT password_hash FROM admin WHERE id=1").Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

// Restart before setup rotates the bootstrap secret, never resetting the login
// limiter. After setup, a stale secret file can never initialize another admin.
func (s *store) prepareBootstrap(now time.Time) error {
	hash, err := s.adminHash()
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "bootstrap.token")
	if hash != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	token := randomToken()
	if err = os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT OR REPLACE INTO bootstrap VALUES(1,?,?)", tokenHash(token), now.Add(30*time.Minute).Unix())
	return err
}

func (s *store) newSession(auth bool, now time.Time) (string, session, error) {
	token := randomToken()
	duration := anonymousLifetime
	if auth {
		duration = sessionLifetime
	}
	sess := session{Hash: tokenHash(token), CSRF: randomToken(), Auth: auth, Expires: now.Add(duration).Unix()}
	tx, err := s.db.Begin()
	if err != nil {
		return "", sess, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM sessions WHERE expires<=? OR seen<=?", now.Unix(), now.Add(-idleLifetime).Unix()); err != nil {
		return "", sess, err
	}
	// Bound anonymous sessions even when clients repeatedly discard their cookies.
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM sessions WHERE authenticated=0").Scan(&count); err != nil {
		return "", sess, err
	}
	if !auth && count >= 256 {
		return "", sess, errors.New("SESSION_CAPACITY")
	}
	_, err = tx.Exec("INSERT INTO sessions VALUES(?,?,?,?,?)", sess.Hash, sess.CSRF, auth, sess.Expires, now.Unix())
	if err != nil {
		return "", sess, err
	}
	return token, sess, tx.Commit()
}

func (s *store) session(token string, now time.Time) (session, error) {
	var sess session
	if len(token) != 43 {
		return sess, sql.ErrNoRows
	}
	sess.Hash = tokenHash(token)
	err := s.db.QueryRow("UPDATE sessions SET seen=? WHERE token_hash=? AND expires>? AND seen>? RETURNING csrf, authenticated, expires", now.Unix(), sess.Hash, now.Unix(), now.Add(-idleLifetime).Unix()).Scan(&sess.CSRF, &sess.Auth, &sess.Expires)
	if errors.Is(err, sql.ErrNoRows) {
		// Once expiry is observed, persist revocation so a later clock correction
		// or restart cannot make this expired token valid again.
		if _, cleanupErr := s.db.Exec("DELETE FROM sessions WHERE token_hash=? AND (expires<=? OR seen<=?)", sess.Hash, now.Unix(), now.Add(-idleLifetime).Unix()); cleanupErr != nil {
			return sess, cleanupErr
		}
	}
	return sess, err
}

// A durable global budget protects the single administrator and bounds KDF cost,
// including when a proxy hides addresses. Never keyed by an untrusted header.
func (s *store) attempt(now time.Time) (bool, error) {
	var attempts int
	err := s.db.QueryRow(`UPDATE auth_limit SET
 attempts=CASE WHEN started<=? THEN 1 ELSE attempts+1 END,
 started=CASE WHEN started<=? THEN ? ELSE started END
 WHERE id=1 RETURNING attempts`, now.Add(-10*time.Minute).Unix(), now.Add(-10*time.Minute).Unix(), now.Unix()).Scan(&attempts)
	return attempts <= 10, err
}
