// Package hubupgrade is the non-privileged half of the Hub self-upgrade of
// #11d (spec §5.2, §5.5, §5.8, §5.9): the operation journal, the root target
// manifest gate, the space derivation and the verified flat database backup
// producer. It is imported by internal/web, which owns the SQLite handle and
// therefore supplies the VACUUM, integrity, schema and space callbacks; it must
// never import internal/web or internal/install.
//
// The privileged executor lives in the separate subpackage rootexec and is
// started only by the fixed systemd dispatcher. The Web process has no
// privilege, no ledger read and no way to name an executable: it writes the
// backup record, the journal and (Task 5) a request file under /run.
package hubupgrade

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// Data-directory-relative locations of the Hub upgrade. They are relative on
// purpose: the whole tree moves with --data-dir, including a restore target.
const (
	// DatabaseBackupDir is the single-generation Hub backup slot (spec C1).
	DatabaseBackupDir = "database-backup"
	// UpgradeDir stages the old and target Hub packages.
	UpgradeDir = "upgrade"
	// HubUpgradeDir carries the operation journal and, after a restore, the
	// restored marker.
	HubUpgradeDir = "hub-upgrade"
	// OpsDir is the journal directory below HubUpgradeDir.
	OpsDir = HubUpgradeDir + "/ops"
)

// RootManifestDir is where a root operator pre-places target manifests. The Web
// process can read it (the installer makes the tree traversable) but never
// writes it (spec §5.9).
const RootManifestDir = "/var/lib/meshmux-installer/upgrade"

// Operation kinds and the journal's schema. A request and its journal entry
// carry exactly these two kinds; anything else is refused.
const (
	KindUpdate  = "update"
	KindRestore = "restore"

	// OpSchema is the frozen journal document schema.
	OpSchema = 1

	// JournalMaxBytes bounds the one metadata document a reader parses.
	JournalMaxBytes = 64 << 10
)

var (
	// opIDRE is the one accepted operation id shape: 32 lowercase hex. It is
	// also the file name inside the journal and the fixed name of a request.
	opIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// digestRE is a lowercase SHA-256 in hex.
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// targetRE mirrors upgrade's release shape and internal/update's targetRE.
	// Keep the three in step; a target that is not a SemVer release is never
	// turned into a path or a journal field.
	targetRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	// archRE bounds the architecture component of a package name.
	archRE = regexp.MustCompile(`^[a-z0-9]+$`)
)

// PackageName is the fixed file name of the target package inside UpgradeDir:
// meshmuxd-<target>-<arch>. It is the same helper shape the dispatcher derives,
// so a staged file can never be named by the Web form directly.
func PackageName(target, arch string) (string, error) {
	return packageName(target, arch, "HUB_BACKUP_STAGE_FAILED")
}

// OldPackageName is the fixed file name of the running binary staged as the
// restore source: meshmuxd-<from_version>-<arch>.
func OldPackageName(version, arch string) (string, error) {
	return packageName(version, arch, "HUB_BACKUP_BINARY_STAGE_FAILED")
}

func packageName(version, arch, code string) (string, error) {
	if !targetRE.MatchString(version) {
		return "", fail(code, "the package version is not a SemVer release")
	}
	if !archRE.MatchString(arch) {
		return "", fail(code, "the package architecture is not a plain identifier")
	}
	return "meshmuxd-" + version + "-" + arch, nil
}

// fail builds one stable-code error. Every failure of this package starts with
// a code from spec §5.9's management/execution group, so a caller never has to
// parse prose to choose a receipt.
func fail(code, detail string) error { return errors.New(code + ": " + detail) }

// codeOf returns the stable code of one error, or "" when it was not built by
// fail or a caller's code-shaped error.
func codeOf(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	for i := 0; i < len(text); i++ {
		if text[i] == ':' {
			return text[:i]
		}
	}
	return ""
}

// dataPath joins one relative location to an absolute data directory.
func dataPath(dataDir, relative string) (string, error) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return "", fail("HUB_BACKUP_FAILED", "the Hub data directory is not absolute")
	}
	return filepath.Join(dataDir, relative), nil
}

// ownedBy is the ownership half of the private-file rule: a caller names the
// account it expects, and being able to open the file is never proof. The Web
// process names itself; the root dispatcher names meshmux (spec §5.9).
func ownedBy(owner int, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == owner
}
