package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	// The Agent's private host layout. These derive from the exported layout in
	// config.go so the whole host layout is one edit, not two.
	agentDataDir    = AgentDataDir
	stagedDir       = AgentDataDir + "/staged"
	activeConfigDir = ActiveConfigDir
	// maxRuntimeFileSize bounds the small runtime files: the agent config,
	// the identity record, the active candidate, the staged revisions and the
	// active kernel config. A candidate carries at most 1024 users and the
	// Hub candidate body stays bounded at 1 MiB, so these files stay small.
	maxRuntimeFileSize = 1 << 20
	// maxRuntimeStateSize bounds the runtime state file. The state carries the
	// LKG config, the apply journal (candidate and config, base64 inflated by
	// the JSON encoding) and the idempotency and final-result caches with up
	// to 1024 entries each, so it needs more room than the small files. The
	// state is written atomically and a write above this bound is refused, so
	// a state that was accepted stays readable after the next start.
	maxRuntimeStateSize = 4 << 20
)

func rooted(root, path string) string {
	if root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func trustedRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("ROOT_INVALID: root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil || abs != filepath.Clean(root) {
		return "", errors.New("ROOT_INVALID: root must be absolute and clean")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("ROOT_UNSAFE: root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return "", errors.New("ROOT_UNSAFE: root path must not contain symlinks")
	}
	return abs, nil
}

func ensureNoSymlinkAncestors(root, path string) error {
	root, err := trustedRoot(root)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("PATH_ESCAPE: path is outside the runtime root")
	}
	current := root
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			return nil
		}
		if statErr != nil {
			return errors.New("PATH_UNAVAILABLE")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("PATH_UNSAFE: symlink rejected")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return errors.New("PATH_UNSAFE: parent is not a directory")
		}
	}
	return nil
}

func ensurePrivateDir(path string) error {
	return ensurePrivateDirOwnedBy(path, os.Geteuid())
}

func ensurePrivateDirOwnedBy(path string, uid int) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil {
			return errors.New("DATA_DIRECTORY_CREATE_FAILED")
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return errors.New("DATA_DIRECTORY_UNAVAILABLE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0700 || int(stat.Uid) != uid {
		return errors.New("DATA_PERMISSIONS: Agent directory must be owned 0700")
	}
	return nil
}

func ensureManagedDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("ACTIVE_DIRECTORY_UNSAFE")
	}
	return nil
}

// managedFileCodes names the stable error codes of one managed runtime file.
// Each target reports its own vocabulary (ACTIVE_CONFIG_*, ACTIVE_CANDIDATE_*,
// ACL_*), so the caller supplies the codes instead of the helper flattening
// them into a shared set.
type managedFileCodes struct {
	directoryCreateFailed string
	permissions           string
	ownerInvalid          string
	unavailable           string
}

// prepareManagedFile is the shared prepare path of a managed runtime file:
// reject a symlinked directory, create the directory with dirMode, validate it
// with dirCheck, reject a symlinked target, then write the file through
// writeManagedFile. Only the constants differ between the active config and the
// active candidate; the failure codes stay per target.
func prepareManagedFile(root, dirPath, filePath string, data []byte, dirMode, fileMode os.FileMode, dirCheck func(string) error, codes managedFileCodes) error {
	dir := rooted(root, dirPath)
	path := rooted(root, filePath)
	if err := ensureNoSymlinkAncestors(root, dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, dirMode); err != nil && !os.IsExist(err) {
		return errors.New(codes.directoryCreateFailed)
	}
	if err := dirCheck(dir); err != nil {
		return err
	}
	if err := ensureNoSymlinkAncestors(root, path); err != nil {
		return err
	}
	return writeManagedFile(root, path, data, fileMode, codes)
}

// writeManagedFile writes a managed runtime file after its ancestors were
// checked. An existing target must be a regular file with exactly mode and the
// managed owner; it is replaced atomically while preserving its owner. A
// missing target is created atomically with the managed owner.
func writeManagedFile(root, path string, data []byte, mode os.FileMode, codes managedFileCodes) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode.Perm() {
			return errors.New(codes.permissions)
		}
		if err := verifyOwner(info, managedFileUID(root)); err != nil {
			return errors.New(codes.ownerInvalid)
		}
		return writeAtomic(path, data, mode, true)
	} else if !os.IsNotExist(err) {
		return errors.New(codes.unavailable)
	}
	return writeAtomicOwned(path, data, mode, managedFileUID(root), -1)
}

func prepareActiveConfig(root string, data []byte) error {
	return prepareManagedFile(root, activeConfigDir, ActiveConfigPath, data, 0750, 0640, ensureManagedDir, managedFileCodes{
		directoryCreateFailed: "ACTIVE_DIRECTORY_CREATE_FAILED",
		permissions:           "ACTIVE_CONFIG_PERMISSIONS",
		ownerInvalid:          "ACTIVE_CONFIG_OWNER_INVALID",
		unavailable:           "ACTIVE_CONFIG_UNAVAILABLE",
	})
}

func prepareCandidate(root string, data []byte) error {
	return prepareManagedFile(root, agentDataDir, ActiveCandidatePath, data, 0700, 0600, ensurePrivateDir, managedFileCodes{
		directoryCreateFailed: "DATA_DIRECTORY_CREATE_FAILED",
		permissions:           "ACTIVE_CANDIDATE_PERMISSIONS",
		ownerInvalid:          "ACTIVE_CANDIDATE_OWNER_INVALID",
		unavailable:           "ACTIVE_CANDIDATE_UNAVAILABLE",
	})
}

// prepareACL keeps its own prefix: it never creates the agent directory and it
// checks the target's ancestors before the directory, so an unsafe path still
// wins over a bad directory. Only the write tail is shared.
func prepareACL(root string, data []byte) error {
	dir := rooted(root, agentDataDir)
	path := rooted(root, ACLPath)
	if err := ensureNoSymlinkAncestors(root, path); err != nil {
		return err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	return writeManagedFile(root, path, data, 0600, managedFileCodes{
		permissions:  "ACL_PERMISSIONS",
		ownerInvalid: "ACL_OWNER_INVALID",
		unavailable:  "ACL_UNAVAILABLE",
	})
}

func verifyOwner(info os.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return errors.New("OWNER_INVALID")
	}
	return nil
}

func readRegularFile(path string, requirePrivate bool) ([]byte, os.FileInfo, error) {
	return readRegularFileLimited(path, requirePrivate, maxRuntimeFileSize)
}

// readRegularFileLimited reads one regular file and refuses anything above
// the given limit. The limit is applied while reading, so an oversized file
// is never fully buffered.
func readRegularFileLimited(path string, requirePrivate bool, limit int64) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("FILE_NOT_REGULAR")
	}
	if requirePrivate && info.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("FILE_PERMISSIONS")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New("FILE_TOO_LARGE")
	}
	return data, info, nil
}

func readRegularFileOwnedBy(path string, mode os.FileMode, uid int) ([]byte, os.FileInfo, error) {
	data, info, err := readRegularFile(path, false)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != mode.Perm() || int(stat.Uid) != uid {
		return nil, nil, errors.New("FILE_OWNER_OR_MODE_INVALID")
	}
	return data, info, nil
}

func readPrivateFile(path string) ([]byte, os.FileInfo, error) {
	return readPrivateFileLimited(path, maxRuntimeFileSize)
}

// readPrivateFileLimited reads one private file and refuses anything above
// the given limit. The limit is applied while reading, so an oversized file
// is never fully buffered.
func readPrivateFileLimited(path string, limit int64) ([]byte, os.FileInfo, error) {
	data, info, err := readRegularFileLimited(path, true, limit)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm() != 0600 {
		return nil, nil, errors.New("FILE_PERMISSIONS: private file must be owned 0600")
	}
	return data, info, nil
}

// readRuntimeStateFile reads the runtime state file with the state limit. The
// state carries the LKG config, the apply journal and the task caches, so it
// gets its own bound instead of the small runtime-file bound.
func readRuntimeStateFile(path string) ([]byte, os.FileInfo, error) {
	return readPrivateFileLimited(path, maxRuntimeStateSize)
}

func managedFileUID(root string) int {
	if filepath.Clean(root) == "/" {
		return 0
	}
	return os.Geteuid()
}

func writeStageAtomic(root, path string, data []byte) error {
	if err := ensureNoSymlinkAncestors(root, path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("STAGE_DIRECTORY_CREATE_FAILED")
	}
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
			return errors.New("STAGED_FILE_UNSAFE")
		}
		existing, _, err := readPrivateFile(path)
		if err != nil {
			return err
		}
		if sha256Hex(existing) != sha256Hex(data) {
			return errors.New("REVISION_CONFLICT: staged content is immutable")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return errors.New("STAGED_FILE_UNAVAILABLE")
	}
	return writeAtomic(path, data, 0600, false)
}

func writeAtomic(path string, data []byte, mode os.FileMode, preserveOwner bool) error {
	var uid, gid int
	if preserveOwner {
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("TARGET_UNAVAILABLE")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("TARGET_OWNER_UNAVAILABLE")
		}
		uid, gid = int(stat.Uid), int(stat.Gid)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".meshmux-runtime-*")
	if err != nil {
		return errors.New("ATOMIC_WRITE_CREATE_FAILED")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_PERMISSIONS_FAILED")
	}
	if preserveOwner {
		if err = tmp.Chown(uid, gid); err != nil {
			tmp.Close()
			return errors.New("ATOMIC_WRITE_OWNER_FAILED")
		}
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_FAILED")
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_SYNC_FAILED")
	}
	if err = tmp.Close(); err != nil {
		return errors.New("ATOMIC_WRITE_CLOSE_FAILED")
	}
	if err = os.Rename(tmpName, path); err != nil {
		return errors.New("ATOMIC_WRITE_RENAME_FAILED")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("ATOMIC_WRITE_DIRECTORY_FAILED")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("ATOMIC_WRITE_DIRECTORY_SYNC_FAILED")
	}
	return nil
}

func writeAtomicOwned(path string, data []byte, mode os.FileMode, uid, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".meshmux-runtime-*")
	if err != nil {
		return errors.New("ATOMIC_WRITE_CREATE_FAILED")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chown(uid, gid); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_OWNER_FAILED")
	}
	if err = tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_PERMISSIONS_FAILED")
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_FAILED")
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return errors.New("ATOMIC_WRITE_SYNC_FAILED")
	}
	if err = tmp.Close(); err != nil {
		return errors.New("ATOMIC_WRITE_CLOSE_FAILED")
	}
	if err = os.Rename(tmpName, path); err != nil {
		return errors.New("ATOMIC_WRITE_RENAME_FAILED")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("ATOMIC_WRITE_DIRECTORY_FAILED")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("ATOMIC_WRITE_DIRECTORY_SYNC_FAILED")
	}
	return nil
}

func stagedCandidatePath(root string, revision int64) string {
	return rooted(root, fmt.Sprintf("%s/%020d-candidate.json", stagedDir, revision))
}

func stagedConfigPath(root string, revision int64) string {
	return rooted(root, fmt.Sprintf("%s/%020d-config.json", stagedDir, revision))
}

// stagedKeepRevisions is how many staged revisions survive a healthy
// apply+readback: the revision that just became the LKG and the one before it.
// The LKG candidate is read back from staged/<revision>-candidate.json, so the
// current revision is never collected; the previous revision stays as the
// window a revert can return to, mirroring the N-1 rule of the 11c-3 rollback
// store (update.backupKeepConfirmed = 1). Without this bound the directory grew
// by one candidate/config pair per applied revision, forever.
const stagedKeepRevisions = 2

// stagedRevisionSuffixes are the two files of one staged revision. They are
// collected as a pair: a crash can leave only one of them behind, and half a
// revision is never usable.
var stagedRevisionSuffixes = []string{"-candidate.json", "-config.json"}

// stagedRevisionName parses the revision out of a staged file name. Anything
// else in the directory is foreign and never collected.
func stagedRevisionName(name string) (int64, bool) {
	for _, suffix := range stagedRevisionSuffixes {
		digits, ok := strings.CutSuffix(name, suffix)
		if !ok || len(digits) != 20 {
			continue
		}
		revision, err := strconv.ParseInt(digits, 10, 64)
		if err != nil || revision < 1 {
			return 0, false
		}
		return revision, true
	}
	return 0, false
}

// gcStagedRevisions removes the staged candidate/config pairs that fell out of
// the retention window. current is the revision state.json now records as the
// LKG and previous the revision it recorded before this apply (0 when there is
// none). Both are always retained: the current revision is what loadLKGCandidate
// and every readback read, and the previous one is the release a revert restores
// — a Hub that jumps revisions (5 → 9) must not leave that anchor without its
// staged candidate. Beyond them, the newest keep revisions are retained; an
// older entry that is not a regular file (a symlink, a directory) is left alone
// instead of being followed or removed recursively. A missing staged directory
// is not an error: a fresh host has nothing to collect.
func gcStagedRevisions(root string, current, previous int64, keep int) ([]string, error) {
	if current < 1 || keep < 1 {
		return nil, errors.New("STAGED_GC_FAILED")
	}
	dir := rooted(root, stagedDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("STAGED_GC_FAILED")
	}
	oldest := current - int64(keep) + 1
	var removed []string
	for _, entry := range entries {
		revision, ok := stagedRevisionName(entry.Name())
		if !ok || revision >= oldest || revision == current || revision == previous {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return removed, errors.New("STAGED_GC_FAILED")
		}
		removed = append(removed, entry.Name())
	}
	return removed, nil
}

func temporaryCandidatePath(root string) (string, *os.File, error) {
	dir := rooted(root, agentDataDir)
	if err := ensurePrivateDir(dir); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, ".check-candidate-*")
	if err != nil {
		return "", nil, errors.New("CHECK_FILE_CREATE_FAILED")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, errors.New("CHECK_FILE_PERMISSIONS_FAILED")
	}
	return f.Name(), f, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("BINARY_UNAVAILABLE")
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", errors.New("BINARY_READ_FAILED")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
