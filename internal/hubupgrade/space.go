package hubupgrade

// Space derivation of #11d (spec §5.9, C14). The Node constant is not reused:
// the Hub adds a database copy and a restore directory to the package and
// snapshot terms, so the floor is re-derived here.
//
//	hubRequiredSpace = 128 MiB (target package) + 2 x dbSize (VACUUM copy and
//	                   the previous generation) + 128 MiB (old package) +
//	                   dbSize (restore directory) + 256 MiB (journal, result,
//	                   exec copy and slack)
//	hubSpaceFloor    = max(hubRequiredSpace, 1 GiB)
//
// The 1 GiB term is the installer's own preflight floor, so this gate can never
// be weaker than the check the installer already performed.

import (
	"math"
	"syscall"
)

const (
	mib = uint64(1 << 20)
	// targetPackageSpace is the largest Hub package the fetch path accepts.
	targetPackageSpace = 128 * mib
	// oldPackageSpace is the running binary copied aside for restore.
	oldPackageSpace = 128 * mib
	// restoreHeadroom covers the restore directory, journal, result, exec copy
	// and filesystem slack.
	restoreHeadroom = 256 * mib
	// spaceFloor is the installer preflight floor.
	spaceFloor = uint64(1 << 30)
)

// RequiredSpace is the free bytes one Hub upgrade needs with a database of
// dbSize. It is monotonic in dbSize; the three copies of the database are the
// VACUUM copy, the previous generation and the restore directory.
func RequiredSpace(dbSize uint64) uint64 {
	if dbSize > (math.MaxUint64-restoreHeadroom-targetPackageSpace-oldPackageSpace)/3 {
		return math.MaxUint64
	}
	return targetPackageSpace + oldPackageSpace + restoreHeadroom + 3*dbSize
}

// Floor raises the requirement to the installer's 1 GiB preflight floor.
func Floor(dbSize uint64) uint64 {
	if required := RequiredSpace(dbSize); required > spaceFloor {
		return required
	}
	return spaceFloor
}

// freeBytes reports the unprivileged free bytes of the filesystem holding path.
func freeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fail("HUB_SPACE_INSUFFICIENT", "the free bytes of the Hub data directory could not be read")
	}
	if stat.Bsize <= 0 {
		return 0, fail("HUB_SPACE_INSUFFICIENT", "the Hub filesystem reports an unusable block size")
	}
	// Bavail is the space available to an unprivileged process; the Web runs as
	// meshmux and must not consume root-reserved blocks it can never use.
	// (Bavail is uint64: no negative check possible or needed.)
	available := uint64(stat.Bavail)
	block := uint64(stat.Bsize)
	if available > math.MaxUint64/block {
		return math.MaxUint64, nil
	}
	return available * block, nil
}

// CheckFreeSpace is the production Space callback: it refuses a copy that would
// leave the filesystem below need. It never creates anything.
func CheckFreeSpace(path string, need uint64) error {
	available, err := freeBytes(path)
	if err != nil {
		return err
	}
	if available < need {
		return fail("HUB_SPACE_INSUFFICIENT", "the Hub filesystem does not have the required free space")
	}
	return nil
}
