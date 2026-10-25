package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateStateAndSchema(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenStore(dir); err == nil {
		other.Close()
		t.Fatal("concurrent process accepted")
	}
	if _, err = s.DB.Exec("PRAGMA user_version=17"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err := OpenStore(dir); err == nil {
		s.Close()
		t.Fatal("future schema accepted")
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenStore(dir); err == nil {
		s.Close()
		t.Fatal("public dir accepted")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(dir, "meshmux.db"), 0644); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenStore(dir); err == nil {
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
			if s, err := OpenStore(dir); err == nil {
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
	hash, err := HashPassword("test-only-long-password-47!")
	if err != nil {
		t.Fatal(err)
	}
	other, err := HashPassword("test-only-long-password-47!")
	if err != nil {
		t.Fatal(err)
	}
	if hash == other || strings.Contains(hash, "test-only-long-password-47!") {
		t.Fatal("missing random salt")
	}
	if !VerifyPassword(hash, "test-only-long-password-47!") || VerifyPassword(hash, "wrong") {
		t.Fatal("password mismatch")
	}
	for _, bad := range []string{"short", "", strings.Repeat("x", 257)} {
		if _, err := HashPassword(bad); err == nil {
			t.Fatal("weak/oversize accepted")
		}
	}
	for _, bad := range []string{"", "$argon2id$v=19$m=999999999,t=99,p=99$abc$def", PasswordPrefix + "bad$hash", PasswordPrefix + "AA$AA$AA"} {
		if VerifyPassword(bad, "test-only-long-password-47!") {
			t.Fatal("corrupt hash accepted")
		}
	}
}
