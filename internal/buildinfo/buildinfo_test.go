package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDigestMatchesSelfExe pins the identity anchor of #11d: Digest is the
// SHA-256 of the running executable's bytes, computed from /proc/self/exe, and
// never a value read from a manifest or an environment variable.
func TestDigestMatchesSelfExe(t *testing.T) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, io.LimitReader(f, maxExecutableBytes+1)); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(sum.Sum(nil))
	got, err := Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != want {
		t.Fatalf("Digest = %q, want sha256(/proc/self/exe) = %q", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("Digest = %q, want 64 lowercase hex", got)
	}
}

// TestDigestUnavailable refuses to guess: an executable path that cannot be
// read or is not a bounded non-empty file is HUB_DIGEST_UNAVAILABLE, never a
// digest of something else.
func TestDigestUnavailable(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path string }{
		{"missing", filepath.Join(dir, "missing")},
		{"directory", dir},
		{"empty file", empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := digestFile(tc.path); err == nil || !strings.HasPrefix(err.Error(), "HUB_DIGEST_UNAVAILABLE") {
				t.Fatalf("digestFile(%s) err = %v, want HUB_DIGEST_UNAVAILABLE", tc.path, err)
			}
		})
	}
}

// TestDigestRejectsOversize pins the size bound: a regular file larger than
// maxExecutableBytes is HUB_DIGEST_UNAVAILABLE before any byte is hashed. The
// read bound (n > maxExecutableBytes) is the same refusal for a file that grows
// between the stat and the read; a stable regular file cannot reach it, so it
// stays defence in depth rather than a reachable test fixture.
func TestDigestRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxExecutableBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := digestFile(path); err == nil || !strings.HasPrefix(err.Error(), "HUB_DIGEST_UNAVAILABLE") {
		t.Fatalf("digestFile(oversize) err = %v, want HUB_DIGEST_UNAVAILABLE", err)
	}
}
