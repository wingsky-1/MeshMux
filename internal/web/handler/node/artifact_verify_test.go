package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestCopyArtifactVerifiedReportsWhatWentWrong keeps the failure classes apart: a
// completed copy with the wrong digest is the abortable INSTALL_ARTIFACT_CHANGED,
// a short read is io.ErrUnexpectedEOF and a failed read keeps its own error, so
// the caller never reports a transport fault as a changed artifact.
func TestCopyArtifactVerifiedReportsWhatWentWrong(t *testing.T) {
	body := []byte("fixed-test-cli")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	chunk := make([]byte, 4)

	if n, err := copyArtifactVerified(io.Discard, strings.NewReader(string(body)), int64(len(body)), digest, chunk); err != nil || n != int64(len(body)) {
		t.Fatalf("verified copy: n=%d err=%v", n, err)
	}
	if _, err := copyArtifactVerified(io.Discard, strings.NewReader(string(body)), int64(len(body)), strings.Repeat("0", 64), chunk); !errors.Is(err, errInstallArtifactChanged) {
		t.Fatalf("digest mismatch: err=%v", err)
	}
	// A reader that ends early must not be reported as a changed artifact.
	if _, err := copyArtifactVerified(io.Discard, strings.NewReader("fixed"), int64(len(body)), digest, chunk); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short read: err=%v", err)
	}
	sentinel := errors.New("READ_FAILED")
	if _, err := copyArtifactVerified(io.Discard, failingReader{sentinel}, int64(len(body)), digest, chunk); !errors.Is(err, sentinel) {
		t.Fatalf("read failure: err=%v", err)
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }
