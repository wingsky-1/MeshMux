// Package buildinfo is the single source of this build's version identity
// (#11d spec §5.3). It imports only the standard library, so every other
// package — including internal/node — can depend on it without a cycle.
//
// The version is injected at link time:
//
//	go build -ldflags "-X github.com/wingsky-1/MeshMux/internal/cli/buildinfo.Version=1.0.1"
//
// Nothing else assigns Version. The read-only projection is
// node.CurrentAgentVersion, a function rather than a package variable: a
// writable variable could be reassigned by any importing package at runtime,
// which would silently move the release manifest projection, the
// `database_versions` identity row and the upgrade confirmation together. A
// function cannot be assigned, so the three can only ever name this build.
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// Version is this build's release identity. The default is the development
// identity; a release build injects the published version with -ldflags -X.
//
// Development builds use a SemVer pre-release, never a bare "dev" stamp:
//
//	1.0.0-dev.<stamp>[.<sequence>]     e.g. 1.0.0-dev.20261027, 1.0.0-dev.20261027.2
//
// `make dev-artifacts` injects that value together with the artifact digests it
// publishes, so the running build, the release manifest and the artifact table
// all name the same release. The zero default stays a valid pre-release of the
// v1.0.0 line so an uninjected `go build` still parses as a dev build rather
// than as a release.
//
// It is a variable only because the linker can only set variables. Production
// code never writes it; the tests that prove the single-source property save
// and restore it.
var Version = "1.0.0-dev.0"

// MaxExecutableBytes bounds a running executable/package read. It is exported
// because the installer, the Agent updater, the Hub producer and the Web
// launcher all apply the same 128 MiB artifact bound; they must not grow four
// private copies that drift into different limits.
const MaxExecutableBytes = 128 << 20

// ExecutablePath is the proc entry that names the inode actually executing.
// It is shared with the Hub producer, which stages that inode as the restore
// source, so both readers always name the same object.
const ExecutablePath = "/proc/self/exe"

// Digest returns the SHA-256 of the bytes of the running executable. It reads
// /proc/self/exe instead of os.Executable(): the proc entry names the inode
// that is actually executing, while a path can be replaced by an upgrade while
// the old image keeps running. An unreadable or out-of-bound executable is
// HUB_DIGEST_UNAVAILABLE — the digest is never guessed, and a caller that
// needs it (backup `from_agent_sha256`, upgrade confirmation) must refuse.
func Digest() (string, error) {
	return digestFile(ExecutablePath)
}

// digestFile is the testable half of Digest: the same bounded read over an
// explicit path, so the failure branches need no /proc mutation.
func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("HUB_DIGEST_UNAVAILABLE: the running executable could not be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxExecutableBytes {
		return "", errors.New("HUB_DIGEST_UNAVAILABLE: the running executable is not a bounded regular file")
	}
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(f, MaxExecutableBytes+1))
	if err != nil || n > MaxExecutableBytes {
		return "", errors.New("HUB_DIGEST_UNAVAILABLE: the running executable could not be read within the size bound")
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
