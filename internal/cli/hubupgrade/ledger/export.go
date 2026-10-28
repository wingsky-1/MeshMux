package ledger

// The exported seams of the ledger group. The journal, claim, paths and semver
// helpers are one owner of the operation grammar; the backup and dispatch groups
// (and the root forwarding package) read them through these names instead of
// compiling a second copy. The lowercase originals stay private to this package
// so a reader of the files still sees one definition.

import "os"

// Fail builds one stable-code error.
func Fail(code, detail string) error { return fail(code, detail) }

// CodeOf returns the stable code of one error.
func CodeOf(err error) string { return codeOf(err) }

// DataPath joins one relative location to an absolute data directory.
func DataPath(dataDir, relative string) (string, error) { return dataPath(dataDir, relative) }

// OwnedBy is the ownership half of the private-file rule.
func OwnedBy(owner int, info os.FileInfo) bool { return ownedBy(owner, info) }

// EnsurePrivateDir prepares a 0700 journal-owned directory.
func EnsurePrivateDir(path string) error { return ensurePrivateDir(path) }

// SyncDir flushes one journal directory with the journal error group.
func SyncDir(dir string) error { return syncDir(dir) }

// CompareRelease compares two SemVer releases; an unparsable side is an error.
func CompareRelease(a, b string) (int, error) { return compareRelease(a, b) }

// JournalError maps the journal's own corruption code onto the backup group.
func JournalError(err error) error { return backupJournalError(err) }

// MarshalIndentNoHTML encodes one fixed metadata document.
func MarshalIndentNoHTML(document any) ([]byte, error) { return marshalIndentNoHTML(document) }

// MeshmuxGroupID resolves the Web account's group.
func MeshmuxGroupID() (int, bool) { return meshmuxGroupID() }

// SyncDirectory flushes a directory and returns the raw error.
func SyncDirectory(dir string) error { return syncDirectory(dir) }

// The one frozen record grammar of internal/cli/backup, re-exported as values
// so a sibling group reads the same expression objects.
var (
	OperationIDPattern    = opIDRE
	DigestPattern         = digestRE
	ReleaseVersionPattern = targetRE
)
