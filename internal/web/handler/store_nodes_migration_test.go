package handler

import (
	"database/sql"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSchemaV1MigrationPreservesAdminSessions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "meshmux.DB"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := store.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err = db.Exec(`
CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL);
CREATE TABLE sessions (token_hash BLOB PRIMARY KEY, csrf TEXT NOT NULL, authenticated INTEGER NOT NULL CHECK(authenticated IN (0,1)), expires INTEGER NOT NULL, seen INTEGER NOT NULL);
CREATE INDEX sessions_expiry ON sessions(expires);
CREATE TABLE bootstrap (id INTEGER PRIMARY KEY CHECK(id=1), token_hash BLOB NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE auth_limit (id INTEGER PRIMARY KEY CHECK(id=1), started INTEGER NOT NULL, attempts INTEGER NOT NULL);
INSERT INTO auth_limit VALUES(1,0,0);
PRAGMA user_version=1;
`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO admin VALUES(1,?)", hash); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO sessions VALUES(x'73657373696F6E2D746F6B656E2D68617368', 'session-csrf', 1, ?, ?)", now+3600, now); err != nil {
		t.Fatal(err)
	}
	var seeded int
	if err = db.QueryRow("SELECT count(*) FROM sessions").Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if seeded != 1 {
		t.Fatalf("seeded sessions = %d, want 1", seeded)
	}
	var kind string
	if err = db.QueryRow("SELECT typeof(token_hash) FROM sessions").Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "blob" {
		t.Fatalf("token_hash type = %s, want blob", kind)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}

	// Hermetic fixture: explicit 0700/0600 independent of ambient umask
	// (local 077 masks this; CI 022 exposes DATA_PERMISSIONS).
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(dir, "meshmux.DB"), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := store.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err = s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 10 {
		t.Fatalf("user_version = %d, want 10", version)
	}
	adminHash, err := s.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	if !store.VerifyPassword(adminHash, testPassword) {
		t.Fatal("admin password not preserved")
	}
	if adminHash != hash {
		t.Fatal("admin password hash changed during migration")
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM sessions WHERE hex(token_hash)='73657373696F6E2D746F6B656E2D68617368' AND csrf='session-csrf' AND authenticated=1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("preserved sessions = %d, want 1", count)
	}
	var errorCode string
	err = s.DB.QueryRow("SELECT error_code FROM agent_tasks LIMIT 1").Scan(&errorCode)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
}
