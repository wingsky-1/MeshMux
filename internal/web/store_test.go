package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationBoundary(t *testing.T) {
	base := Config{Listen: "127.0.0.1:9080", Origin: testOrigin, DataDir: "state"}
	if err := base.Validate(1000); err != nil {
		t.Fatal(err)
	}
	if err := base.Validate(0); err == nil {
		t.Fatal("root allowed")
	}
	for _, listen := range []string{"0.0.0.0:9080", "[::]:9080", "localhost:9080", "192.0.2.1:9080", "127.0.0.1:0", "127.0.0.1:99999"} {
		c := base
		c.Listen = listen
		if c.Validate(1000) == nil {
			t.Fatalf("unsafe listen %s", listen)
		}
	}
	for _, origin := range []string{"http://admin.example.invalid", "https://admin.example.invalid/", "https://x@admin.example.invalid", "https://admin.example.invalid?x=y", "https://admin.example.invalid#x", "https://admin.example.invalid?"} {
		c := base
		c.Origin = origin
		if c.Validate(1000) == nil {
			t.Fatalf("unsafe origin %s", origin)
		}
	}
	c := base
	c.DevHTTP = true
	c.Origin = "http://127.0.0.1:9080"
	if err := c.Validate(1000); err != nil {
		t.Fatal(err)
	}
	c.DirectProxy = true
	if c.Validate(1000) == nil {
		t.Fatal("dev proxy trusted")
	}
	c = base
	c.Listen = "[::1]:9080"
	if err := c.Validate(1000); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateStateAndSchema(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.migrate(); err != nil {
		t.Fatal(err)
	}
	if other, err := openStore(dir); err == nil {
		other.Close()
		t.Fatal("concurrent process accepted")
	}
	if _, err = s.db.Exec("PRAGMA user_version=6"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err := openStore(dir); err == nil {
		s.Close()
		t.Fatal("future schema accepted")
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := openStore(dir); err == nil {
		s.Close()
		t.Fatal("public dir accepted")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(dir, "meshmux.db"), 0644); err != nil {
		t.Fatal(err)
	}
	if s, err := openStore(dir); err == nil {
		s.Close()
		t.Fatal("public DB accepted")
	}
	for _, name := range []string{"meshmux.db", "bootstrap.token", ".lock", "meshmux.db-wal"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			os.Mkdir(dir, 0700)
			target := filepath.Join(t.TempDir(), "target")
			os.WriteFile(target, []byte("untouched"), 0600)
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if s, err := openStore(dir); err == nil {
				s.Close()
				t.Fatal("symlink accepted")
			}
			b, _ := os.ReadFile(target)
			if string(b) != "untouched" {
				t.Fatal("target modified")
			}
		})
	}
}

func TestPasswordHashPolicy(t *testing.T) {
	hash, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	other, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if hash == other || strings.Contains(hash, testPassword) {
		t.Fatal("missing random salt")
	}
	if !verifyPassword(hash, testPassword) || verifyPassword(hash, "wrong") {
		t.Fatal("password mismatch")
	}
	for _, bad := range []string{"short", "", strings.Repeat("x", 257)} {
		if _, err := hashPassword(bad); err == nil {
			t.Fatal("weak/oversize accepted")
		}
	}
	for _, bad := range []string{"", "$argon2id$v=19$m=999999999,t=99,p=99$abc$def", passwordPrefix + "bad$hash", passwordPrefix + "AA$AA$AA"} {
		if verifyPassword(bad, testPassword) {
			t.Fatal("corrupt hash accepted")
		}
	}
}
