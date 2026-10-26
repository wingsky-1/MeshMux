package rootexec

// The one ledger read point of the privileged dispatcher (#11d Task 4, spec
// §5.9). internal/install owns the strict ledger decoder; this wrapper adds the
// ownership half the decoder intentionally does not: root must reject a ledger
// it can read but another account owns (bytes reachable is not authorization).
//
// The identity cross-check is deliberately split in two: a missing/unreadable
// ledger or a missing digest is HUB_BACKUP_IDENTITY_MISSING; a readable ledger
// that names a different package than the frozen record is
// UPDATE_BACKUP_MISMATCH. Both refuse before any exec.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/versions"
)

const (
	// hubLedgerPath is the fixed root-owned installer ledger. It is not
	// configurable and never derived from a request.
	hubLedgerPath = versions.InstallerStatePath
	// hubRuntimeBinaryPath is the installed Hub/Agent runtime the ledger
	// managed_files entry names.
	hubRuntimeBinaryPath = versions.RuntimeBinaryPath
	// sharedAgentKey is the frozen key of install.SharedBinaries for the
	// MeshMux runtime build a co-located Line reuses.
	sharedAgentKey = "meshmuxd"

	codeIdentityMissing  = hubupgrade.CodeBackupIdentityMissing
	codeIdentityMismatch = backup.CodeMismatch
)

var ledgerDigestRE = backup.DigestPattern

func readHubLedger() (install.InstallState, bool, error) {
	return readLedgerAt("/", os.Geteuid())
}

// readLedgerAt reads the fixed ledger below root and proves the expected owner.
// It is the testable half of readHubLedger; production always passes "/" and
// the current effective uid (root).
func readLedgerAt(root string, expectedOwner int) (install.InstallState, bool, error) {
	state, found, err := install.ReadState(root)
	if err != nil || !found {
		return state, found, err
	}
	path := ledgerPath(root)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0077 != 0 || !statOwnedBy(info, expectedOwner) {
		return install.InstallState{}, false, &installError{code: codeIdentityMissing}
	}
	return state, true, nil
}

// ledgerPath joins the fixed absolute ledger path to a fiction root.
func ledgerPath(root string) string {
	if root == "" || root == "/" {
		return hubLedgerPath
	}
	return filepath.Join(root, strings.TrimPrefix(hubLedgerPath, "/"))
}

// checkLedgerIdentity proves the frozen record still names the ledger's installed
// runtime. The record keeps from_package and from_agent as separate fields even
// though a Hub install makes them equal; the code never merges or substitutes
// them, so a fixture with two different digests stays meaningful.
func checkLedgerIdentity(record backup.Record, state install.InstallState, found bool) error {
	if !found {
		return fail(codeIdentityMissing, "the installer ledger is not available")
	}
	if !ledgerDigestRE.MatchString(record.FromPackageSHA256) ||
		!ledgerDigestRE.MatchString(record.FromAgentSHA256) {
		return fail(codeIdentityMissing, "the frozen record has no complete from-* identity")
	}
	managed, ok := state.ManagedFiles[hubRuntimeBinaryPath]
	if !ok || !ledgerDigestRE.MatchString(managed) {
		return fail(codeIdentityMissing, "the ledger does not name the installed meshmuxd digest")
	}
	shared, ok := state.SharedBinaries[sharedAgentKey]
	if !ok || shared.Path != hubRuntimeBinaryPath ||
		!ledgerDigestRE.MatchString(shared.SHA256) ||
		shared.SHA256 != record.FromAgentSHA256 {
		return fail(codeIdentityMissing, "the ledger shared-binary pin does not match the frozen running digest")
	}
	if managed != record.FromPackageSHA256 {
		return fail(codeIdentityMismatch, "the installed package digest differs from the frozen record")
	}
	return nil
}

// installError is the minimal stable-code error of this package; install's
// sentinel errors are prose-only and must not be parsed for a code.
type installError struct{ code string }

func (e *installError) Error() string {
	return e.code + ": the installer ledger failed its ownership check"
}
