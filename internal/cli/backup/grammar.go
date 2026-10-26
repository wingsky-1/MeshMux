package backup

import "regexp"

// This file is the single definition of the lexical grammar shared by every
// producer and consumer of an upgrade operation record: the operation id, the
// SHA-256 digests a record pins and the SemVer release shape it names.
//
// Why here: internal/backup owns the frozen record.json schema 1, and these
// three values are exactly the field grammar of that record. The package is
// also a stdlib-only leaf, so the installer, the Agent updater, the release
// domain and the Hub producer can all import it without creating a module
// cycle — and without compiling a fourth copy of the same expression.
//
// Do not add a per-package copy. A new consumer imports one of the exported
// values below (or its Valid* helper).
var (
	// OperationIDPattern is the one accepted operation id shape: 32 lowercase
	// hexadecimal characters. It is also the frozen file-name shape used by
	// the journals and requests.
	OperationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// DigestPattern is a lowercase SHA-256 in hexadecimal.
	DigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// ReleaseVersionPattern is the one accepted release version shape: a
	// SemVer core with an optional prerelease suffix. Build metadata is not a
	// release identity here and is refused.
	ReleaseVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
)

// ValidOperationID reports whether id is the fixed 32-hex operation shape.
func ValidOperationID(id string) bool {
	return OperationIDPattern.MatchString(id)
}

// ValidDigest reports whether value is a lowercase SHA-256 digest.
func ValidDigest(value string) bool {
	return DigestPattern.MatchString(value)
}

// ValidReleaseVersion reports whether version is a pinned SemVer release.
func ValidReleaseVersion(version string) bool {
	return ReleaseVersionPattern.MatchString(version)
}
