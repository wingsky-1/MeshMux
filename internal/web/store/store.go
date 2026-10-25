package store

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

const SessionLifetime = 8 * time.Hour
const idleLifetime = 30 * time.Minute

// The durable global authentication budget: ten attempts per rolling ten
// minutes, shared by setup, login and password change. The window opens at its
// first attempt and is measured from that instant, so spending a slot never
// extends the lockout, and restarting the service does not clear it.
const authWindow = 10 * time.Minute
const authBudget = 10

type Store struct {
	DB   *sql.DB
	lock *os.File
	Dir  string
}
type Session struct {
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

func OpenStore(dir string) (*Store, error) {
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
	s := &Store{lock: lock, Dir: abs}
	f, err := os.OpenFile(filepath.Join(abs, "meshmux.db"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		s.Close()
		return nil, err
	}
	f.Close()
	u := url.URL{Scheme: "file", Path: filepath.Join(abs, "meshmux.db")}
	s.DB, err = sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		s.Close()
		return nil, err
	}
	s.DB.SetMaxOpenConns(1)
	if err = s.Migrate(); err != nil {
		s.Close()
		return nil, err
	}
	for _, name := range []string{"meshmux.db", "meshmux.db-wal", "meshmux.db-shm"} {
		if e := privatePath(filepath.Join(abs, name), false); e != nil && !os.IsNotExist(e) {
			s.Close()
			return nil, e
		}
	}
	// The last-known-good row is written only after the migration transaction
	// committed and the database was read back at the schema this binary owns.
	// A database still inside a migration, or one that failed its file-mode
	// readback, never claims to be last known good.
	if err = s.confirmDatabaseVersion(time.Now()); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// scratchDir returns the private data directory of this Hub. The publish gate
// writes its check documents there, so they never leave the private boundary.
func (s *Store) ScratchDir() (string, error) {
	if s.Dir == "" || !filepath.IsAbs(s.Dir) {
		return "", errors.New("PUBLISH_GATE_FAILED: the hub data directory is unavailable")
	}
	return s.Dir, nil
}

func (s *Store) Close() error {
	var err error
	if s.DB != nil {
		err = s.DB.Close()
	}
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
	}
	return err
}

func (s *Store) Migrate() error {
	// The sequential chain stops at schema 15. Schema 16 rebuilds the nodes
	// table with role "http" and must toggle foreign_keys OFF, which SQLite
	// only honours outside a transaction; it therefore runs as its own atomic
	// leg after this chain committed.
	if err := s.migrateSchemaChain(); err != nil {
		return err
	}
	if err := migrateSchema16(s); err != nil {
		return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
	}
	if err := migrateSchema17(s); err != nil {
		return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
	}
	return nil
}

// migrateSchemaChain applies every additive leg up to schema 15. It is one
// transaction; a failure leaves the database at its previous version.
func (s *Store) migrateSchemaChain() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	// SCHEMA_TOO_NEW is about the storage schema only. The route policy
	// contract (`policy_schema`, currently 8) is validated by the upgrade
	// approval and never moves this ceiling (spec §4.13).
	if version > DatabaseSchemaVersion {
		return s.schemaTooNew(version)
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
	if version == 7 {
		if err = migrateSchema8(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 8
	}
	if version == 8 {
		if err = migrateSchema9(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 9
	}
	if version == 9 {
		if err = migrateSchema10(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 10
	}
	if version == 10 || version == 11 {
		if err = migrateSchema12(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 12
	}
	if version == 12 {
		if err = migrateSchema13(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 13
	}
	if version == 13 {
		if err = migrateSchema14(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 14
	}
	if version == 14 {
		if err = migrateSchema15(tx); err != nil {
			return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
		}
		version = 15
	}
	// The 11d-reserved leg backfill (C2) runs on every open after the version
	// chain, like the Out transport table below: a database that already sits
	// at 12 keeps the 11d mirror table it would otherwise have skipped
	// forever. Idempotent by construction; an older binary ignores the table.
	if err = ensureSchema11Mirror(tx); err != nil {
		return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
	}
	// The Out dial-parameter table is ensured on every open without a version
	// step: the aggregation schema numbers above 10 are reserved (11 for 11d,
	// 12/13/14 for Tasks 3/4/5), so Task 2 takes no number. The table is
	// purely additive and referenced by nothing older, so an older binary
	// keeps working against a database that already carries it.
	if err = ensureOutTransportTable(tx); err != nil {
		return fmt.Errorf("SCHEMA_MIGRATION_FAILED: %w", err)
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

func (s *Store) AdminHash() (string, error) {
	var hash string
	err := s.DB.QueryRow("SELECT password_hash FROM admin WHERE id=1").Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

// Restart before setup rotates the bootstrap secret, never resetting the login
// limiter. After setup, a stale secret file can never initialize another admin.
func (s *Store) PrepareBootstrap(now time.Time) error {
	hash, err := s.AdminHash()
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, "bootstrap.token")
	if hash != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	token := RandomToken()
	if err = os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return err
	}
	_, err = s.DB.Exec("INSERT OR REPLACE INTO bootstrap VALUES(1,?,?)", TokenHash(token), now.Add(30*time.Minute).Unix())
	return err
}

// newSession is gone: the login and setup forms no longer store an anonymous
// row (see form_token.go), and the single administrator session is inserted by
// login in its own transaction. `sessions` therefore only ever holds
// authenticated rows, so no anonymous flood can fill a cap and lock the
// administrator out of the page that exists to restore access (#113 3-3).

func (s *Store) Session(token string, now time.Time) (Session, error) {
	var sess Session
	if len(token) != 43 {
		return sess, sql.ErrNoRows
	}
	sess.Hash = TokenHash(token)
	err := s.DB.QueryRow("UPDATE sessions SET seen=? WHERE token_hash=? AND expires>? AND seen>? RETURNING csrf, authenticated, expires", now.Unix(), sess.Hash, now.Unix(), now.Add(-idleLifetime).Unix()).Scan(&sess.CSRF, &sess.Auth, &sess.Expires)
	if errors.Is(err, sql.ErrNoRows) {
		// Once expiry is observed, persist revocation so a later clock correction
		// or restart cannot make this expired token valid again.
		if _, cleanupErr := s.DB.Exec("DELETE FROM sessions WHERE token_hash=? AND (expires<=? OR seen<=?)", sess.Hash, now.Unix(), now.Add(-idleLifetime).Unix()); cleanupErr != nil {
			return sess, cleanupErr
		}
	}
	return sess, err
}

// A durable global budget protects the single administrator and bounds KDF cost,
// including when a proxy hides addresses. Never keyed by an untrusted header.
//
// The window opens at its first attempt and is measured from that instant, so a
// spent slot never extends the lockout and a restart does not clear it. A denied
// attempt reports how long the caller must wait; that is the only actionable
// information, and it never depends on whether a password was correct.
func (s *Store) Attempt(now time.Time) (bool, time.Duration, error) {
	var attempts int
	var started int64
	err := s.DB.QueryRow(`UPDATE auth_limit SET
 attempts=CASE WHEN started<=? THEN 1 ELSE attempts+1 END,
 started=CASE WHEN started<=? THEN ? ELSE started END
 WHERE id=1 RETURNING attempts, started`, now.Add(-authWindow).Unix(), now.Add(-authWindow).Unix(), now.Unix()).Scan(&attempts, &started)
	if err != nil {
		return false, 0, err
	}
	if attempts <= authBudget {
		return true, 0, nil
	}
	retry := time.Unix(started, 0).Add(authWindow).Sub(now)
	if retry <= 0 {
		retry = time.Second
	}
	return false, retry, nil
}

// resetAuthBudget clears the shared budget. It is called in the same
// transaction as the write that proved the credential, so a successful
// authentication cannot fail halfway into a self-inflicted lockout. Only proof
// of a credential resets it; a wrong password never does.
func ResetAuthBudget(tx *sql.Tx) error {
	_, err := tx.Exec("UPDATE auth_limit SET started=0, attempts=0 WHERE id=1")
	return err
}
