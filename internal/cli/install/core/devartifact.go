package core

// The development executor pin of the #12e dev lane.
//
// The executor table used to be a placeholder: a dev-<stamp> version with a
// file:// source and two made-up digests, so every real upgrade failed closed at
// the checksum gate. A development build has no published release asset, so the
// pin now names bytes that exist and can be verified:
//
//   - the running architecture pins /proc/self/exe, the inode actually
//     executing. That is exactly the artifact the installer copied out of the
//     dev drop, and it needs no link-time injection (injecting a build's own
//     digest into itself is circular);
//   - another architecture is pinned only when the deployed dev drop carries a
//     `sha256sum`-format SHA256SUMS naming that artifact. The drop is written by
//     `make dev-artifacts` and installed by root, so the digest is data the
//     build produced, not a constant guessed by a developer.
//
// When neither source exists there is no pin, and PinnedMeshmuxd returns no
// entry. The manifest gates then refuse that architecture (MANIFEST_ARCH_INVALID
// / MANIFEST_SET_INCOMPLETE) instead of naming an artifact whose bytes nobody
// verified: fail-closed, never a placeholder.
//
// A release build (a version that is not a dev pre-release) is refused here on
// purpose: 12e owns the published GitHub asset table, and until it lands a
// release build must not borrow the dev source class.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// devChecksumsMaxBytes bounds the one checksum document a reader parses.
const devChecksumsMaxBytes = 64 << 10

// runningExecutableDigest is the running build's own digest. It is computed once:
// /proc/self/exe cannot change under a running process, and hashing a 20+ MiB
// binary on every manifest projection would be waste, not safety.
var runningExecutableDigest = sync.OnceValues(func() (string, error) { return buildinfo.Digest() })

// devExecutorDigest resolves the pinned digest of one architecture's dev
// executor artifact. A missing or unsafe drop is simply "no pin", never a guess.
func devExecutorDigest(architecture string) (string, bool) {
	if !versions.IsDevVersion(buildinfo.Version) || !versions.IsSupportedArchitecture(architecture) {
		return "", false
	}
	if architecture == runtime.GOARCH {
		digest, err := runningExecutableDigest()
		if err != nil || !backup.DigestPattern.MatchString(digest) {
			return "", false
		}
		return digest, true
	}
	return devDropDigest(versions.DevArtifactPrefix + architecture)
}

// devDropDigest reads the deployed drop's SHA256SUMS and returns the digest it
// records for name. The document is a trust input for the *served* manifest, so
// it must be a private-enough regular file of root or of this account: a
// group/world-writable checksum file would let any local writer re-point the pin.
func devDropDigest(name string) (string, bool) {
	path := versions.DevChecksumsPath()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0022 != 0 || !devDropOwned(info) ||
		info.Size() < 1 || info.Size() > devChecksumsMaxBytes {
		return "", false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(file, devChecksumsMaxBytes+1))
	if err != nil || len(body) > devChecksumsMaxBytes {
		return "", false
	}
	sums, err := parseDevChecksums(body)
	if err != nil {
		return "", false
	}
	digest, ok := sums[name]
	return digest, ok
}

// devDropOwned accepts root (production) and the calling account (a fixture, or
// a developer's own drop). Being readable is never the check; being owned by a
// writer other than root is what would make the digest untrustworthy.
func devDropOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := int(stat.Uid)
	return uid == 0 || uid == os.Geteuid()
}

// parseDevChecksums decodes one `sha256sum` document into name -> digest. It
// refuses anything it cannot account for: a line that is not exactly a digest
// and a plain file name, a duplicate name, or an empty document. A name that is
// not a base name could otherwise address a file outside the drop.
func parseDevChecksums(body []byte) (map[string]string, error) {
	out := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, errDevChecksums
		}
		digest := fields[0]
		// sha256sum prefixes a binary-mode entry with '*'.
		name := strings.TrimPrefix(fields[1], "*")
		if !backup.DigestPattern.MatchString(digest) || name == "" ||
			name == "." || name == ".." || filepath.Base(name) != name ||
			strings.ContainsAny(name, `/\`) {
			return nil, errDevChecksums
		}
		if _, duplicate := out[name]; duplicate {
			return nil, errDevChecksums
		}
		out[name] = digest
	}
	if len(out) == 0 {
		return nil, errDevChecksums
	}
	return out, nil
}

var errDevChecksums = errors.New("ARTIFACT_MANIFEST_INVALID: the development checksum document is not a sha256sum list")
