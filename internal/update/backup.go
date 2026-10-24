package update

// The rollback record (#11c-3, spec §4.1-§4.4, §6). Every upgrade operation
// leaves one verified rollback source before anything is fetched or handed
// off: a private 0700 directory under the fixed store, one 0600 metadata record
// and one 0600 payload copy of the installer snapshot. The record names the
// exact installed state it can restore — (operation_id, from_version,
// db_schema, policy_schema) — so a revert never guesses and a handoff without
// that record is refused.
//
// The record is metadata only: no key, token or subscription URL is ever
// written into it. The payload may contain secrets (Reality keys, the
// subscription credential block, the active sing-box configuration), so it is
// 0700/0600, root-owned and never leaves the host; it is part of the GC set.
// Staged packages live in the update work directory and are never collected
// here (TestBackupGCNeverCollectsStagedPackages).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	// DefaultBackupRoot is the fixed rollback store of a Node (spec §6). The
	// installer snapshot is promoted from its operation directory to here so
	// it survives the installer's own cleanup and a restart.
	DefaultBackupRoot = "/var/lib/meshmux-agent/upgrade-backups"
	// BackupRecordSchema is the on-disk schema of one rollback record. The
	// field set below is frozen for 11c-3: Task 3 writes State/ConfirmedAt,
	// 11d/Task 5 writes the irreversible approval bit, and Task 4's revert
	// reads every anchor verbatim. A new field requires a schema bump.
	BackupRecordSchema = 1

	backupRecordName  = "record.json"
	backupPayloadDir  = "payload"
	backupPayloadPart = "payload.part"
	backupRecordPart  = "record.json.part"

	// backupRecordMaxBytes bounds the metadata file a reader will parse.
	backupRecordMaxBytes = 64 << 10

	// backupKeepConfirmed is N-1: after a confirmed upgrade the store keeps
	// the single newest confirmed generation, because that is the release a
	// revert must be able to go back to. Failed and staged records are always
	// retained (D1, spec §4.20).
	backupKeepConfirmed = 1
)

// BackupRecord states. The record is written staged and only a confirmed
// readback (Task 3) may release an older generation to GC.
const (
	BackupStateStaged    = "staged"
	BackupStateConfirmed = "confirmed"
	BackupStateFailed    = "failed"
)

// BackupRecord is the metadata anchor of one rollback source. It is written
// before the package fetch and re-verified before the handoff; restore reads
// the payload through PayloadPath and checks PayloadSHA256 before applying any
// byte.
type BackupRecord struct {
	Schema        int    `json:"schema"`
	OperationID   string `json:"operation_id"`
	FromVersion   string `json:"from_version"`
	TargetVersion string `json:"target_version"`
	// DBSchema is the installed database schema (user_version) the payload was
	// taken from; a Node records 0 because it owns no database.
	DBSchema int64 `json:"db_schema"`
	// PolicySchema is the stored route policy schema (upgrade.PolicySchema),
	// deliberately distinct from DBSchema (spec §4.13).
	PolicySchema   int    `json:"policy_schema"`
	ManifestSHA256 string `json:"manifest_sha256"`
	PackageSHA256  string `json:"package_sha256"`
	// FromPackageSHA256 and FromAgentSHA256 anchor the replaced package and
	// Agent binary; restore only trusts a package that matches them. Either is
	// empty when the host did not record it (legacy install).
	FromPackageSHA256 string `json:"from_package_sha256"`
	FromAgentSHA256   string `json:"from_agent_sha256"`
	// PayloadPath is the absolute 0700 directory holding the copied snapshot.
	PayloadPath   string `json:"payload_path"`
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadFiles  int    `json:"payload_files"`
	// IntegrityOK records the post-copy readback of this payload. A Hub DB
	// backup sets it only after PRAGMA integrity_check (Task 5/11d).
	IntegrityOK bool       `json:"integrity_ok"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	// IrreversibleApproved is the Web confirm bit for an irreversible DB
	// migration, stored on the record and never bypassed by a flag (spec
	// §4.15). Metadata only; Task 5 writes it.
	IrreversibleApproved bool `json:"irreversible_approved,omitempty"`
}

// RollbackComplete reports whether the record actually holds files to restore.
// A record written before the installer snapshot retention lands (Task 4) has
// an empty payload: it proves the record exists, not that a revert can run.
// The handoff gate (Task 2) requires this, so an empty record never counts as a
// rollback source.
func (record BackupRecord) RollbackComplete() bool {
	return record.IntegrityOK && record.PayloadFiles > 0
}

// BackupSpec is one operation's rollback source as the handoff knows it.
type BackupSpec struct {
	OperationID       string
	FromVersion       string
	TargetVersion     string
	DBSchema          int64
	PolicySchema      int
	ManifestSHA256    string
	PackageSHA256     string
	FromPackageSHA256 string
	FromAgentSHA256   string
	// SnapshotDir is the installer-provided snapshot to promote into the
	// store. It may be empty before 11c-3 Task 4 retains the installer copy;
	// the record then covers an empty payload and still verifies intact.
	SnapshotDir string
}

// backupRoot resolves the store root. Production leaves Config.BackupRoot
// empty and sets WorkDir to DefaultWorkDir, whose sibling is exactly
// DefaultBackupRoot; tests point either field at a private fixture.
func (cfg Config) backupRoot() string {
	if cfg.BackupRoot != "" {
		return cfg.BackupRoot
	}
	if cfg.WorkDir != "" {
		return filepath.Join(filepath.Dir(cfg.WorkDir), "upgrade-backups")
	}
	return DefaultBackupRoot
}

func backupRootOf(root string) string {
	if root == "" {
		return DefaultBackupRoot
	}
	return root
}

// RequireBackupDir returns the 0700 directory of one operation, creating the
// store and the operation directory when absent. An existing directory must
// already be 0700 and owned by this process; a loose directory is never
// adopted, because its payload may contain secrets.
func RequireBackupDir(root, operationID string) (string, error) {
	if !opIDRE.MatchString(operationID) {
		return "", fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	}
	root = backupRootOf(root)
	if !filepath.IsAbs(root) {
		return "", fail("UPDATE_BACKUP_MISSING", "the rollback store path must be absolute")
	}
	if err := ensureBackupRoot(root); err != nil {
		return "", err
	}
	dir := filepath.Join(root, operationID)
	if err := ensurePrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// ensureBackupRoot prepares the dedicated store root. It creates a missing
// root 0700 and narrows a pre-existing owned root to 0700; it never adopts a
// symlink or a directory owned by someone else. The root itself holds only
// operation directories, so tightening it can never break a payload.
func ensureBackupRoot(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fail("UPDATE_BACKUP_MISSING", "the rollback store is unavailable")
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fail("UPDATE_BACKUP_MISSING", "the rollback store is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback store path is not a private directory")
	}
	if !ownedByEUID(info) {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback store is not owned by this process")
	}
	if info.Mode().Perm() != 0700 {
		if err := os.Chmod(path, 0700); err != nil {
			return fail("UPDATE_BACKUP_CORRUPT", "the rollback store could not be made private")
		}
	}
	return nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fail("UPDATE_BACKUP_MISSING", "the rollback store is unavailable")
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fail("UPDATE_BACKUP_MISSING", "the rollback store is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback store path is not a private directory")
	}
	if info.Mode().Perm() != 0700 || !ownedByEUID(info) {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback store directory is not 0700 and owned by this process")
	}
	return nil
}

// WriteBackupRecord promotes the installer snapshot into the private store and
// writes the metadata record. Order is fixed: copy, digest both trees, compare,
// publish, record. A retry of the same operation re-verifies the existing
// record instead of overwriting a rollback source, and any other identity at
// the same operation ID is a mismatch. The returned path is the record file.
func WriteBackupRecord(root string, spec BackupSpec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	opDir, err := RequireBackupDir(root, spec.OperationID)
	if err != nil {
		return "", err
	}
	recordPath := filepath.Join(opDir, backupRecordName)
	switch info, statErr := os.Lstat(recordPath); {
	case statErr == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fail("UPDATE_BACKUP_CORRUPT", "the rollback record is not a regular file")
		}
		existing, readErr := readBackupRecord(opDir, spec.OperationID)
		if readErr != nil {
			return "", readErr
		}
		if !existing.sameIdentity(spec) {
			return "", fail("UPDATE_BACKUP_MISMATCH", "another rollback record already owns this operation")
		}
		if err := verifyPayload(existing, opDir); err != nil {
			return "", err
		}
		return recordPath, nil
	case !os.IsNotExist(statErr):
		return "", fail("UPDATE_BACKUP_CORRUPT", "the rollback record could not be inspected")
	}

	payloadPath := filepath.Join(opDir, backupPayloadDir)
	part := filepath.Join(opDir, backupPayloadPart)
	if err := os.RemoveAll(part); err != nil {
		return "", fail("UPDATE_BACKUP_MISSING", "the rollback payload scratch directory could not be cleared")
	}
	// A payload without a record was never bound to a verified snapshot: it is
	// re-copied, never trusted.
	if _, err := os.Lstat(payloadPath); err == nil {
		if err := os.RemoveAll(payloadPath); err != nil {
			return "", fail("UPDATE_BACKUP_CORRUPT", "the unrecorded rollback payload could not be replaced")
		}
	}
	sourceDigest, sourceFiles, err := hashPayloadTree(spec.SnapshotDir, false)
	if err != nil {
		return "", fail("UPDATE_BACKUP_CORRUPT", "the installer snapshot is not a safe file tree")
	}
	if err := copyPayloadTree(spec.SnapshotDir, part); err != nil {
		_ = os.RemoveAll(part)
		return "", fail("UPDATE_BACKUP_CORRUPT", "the rollback payload could not be copied")
	}
	payloadDigest, payloadFiles, err := hashPayloadTree(part, true)
	if err != nil || payloadDigest != sourceDigest || payloadFiles != sourceFiles {
		_ = os.RemoveAll(part)
		return "", fail("UPDATE_BACKUP_CORRUPT", "the rollback payload copy does not match the installer snapshot")
	}
	if err := os.Rename(part, payloadPath); err != nil {
		_ = os.RemoveAll(part)
		return "", fail("UPDATE_BACKUP_CORRUPT", "the rollback payload could not be published")
	}
	record := BackupRecord{
		Schema: BackupRecordSchema, OperationID: spec.OperationID,
		FromVersion: spec.FromVersion, TargetVersion: spec.TargetVersion,
		DBSchema: spec.DBSchema, PolicySchema: spec.PolicySchema,
		ManifestSHA256: spec.ManifestSHA256, PackageSHA256: spec.PackageSHA256,
		FromPackageSHA256: spec.FromPackageSHA256, FromAgentSHA256: spec.FromAgentSHA256,
		PayloadPath: payloadPath, PayloadSHA256: payloadDigest, PayloadFiles: payloadFiles,
		IntegrityOK: true, State: BackupStateStaged, CreatedAt: time.Now().UTC(),
	}
	if err := writeRecordFile(opDir, record); err != nil {
		return "", err
	}
	return recordPath, nil
}

// VerifyBackupRecord is the handoff precondition (11c-3 Task 2). It reads the
// record and payload back from disk under the private-mode rules and refuses a
// missing store/record with UPDATE_BACKUP_MISSING, a damaged record or payload
// with UPDATE_BACKUP_CORRUPT, and a record for another installed state with
// UPDATE_BACKUP_MISMATCH. It never mutates anything.
func VerifyBackupRecord(root, operationID, fromVersion string, dbSchema int64, policySchema int) (BackupRecord, error) {
	if !opIDRE.MatchString(operationID) {
		return BackupRecord{}, fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	}
	if fromVersion == "" {
		return BackupRecord{}, fail("UPDATE_BACKUP_MISMATCH", "no from version was supplied for verification")
	}
	root = backupRootOf(root)
	opDir := filepath.Join(root, operationID)
	info, statErr := os.Lstat(opDir)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return BackupRecord{}, fail("UPDATE_BACKUP_MISSING", "no verified rollback record exists")
	}
	if info.Mode().Perm() != 0700 || !ownedByEUID(info) {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback operation directory is not 0700 and owned by this process")
	}
	record, err := readBackupRecord(opDir, operationID)
	if err != nil {
		return BackupRecord{}, err
	}
	if record.FromVersion != fromVersion || record.DBSchema != dbSchema || record.PolicySchema != policySchema {
		return BackupRecord{}, fail("UPDATE_BACKUP_MISMATCH", "the rollback record names another installed state")
	}
	if err := verifyPayload(record, opDir); err != nil {
		return BackupRecord{}, err
	}
	return record, nil
}

// GCBackups collects confirmed generations beyond keep, newest first. Staged
// and failed records are never candidates: a failed upgrade still needs its
// rollback source. Records that cannot be read are retained (fail closed), and
// only direct operation directories of the store are ever removed; staged
// packages and every other path are untouched.
func GCBackups(root string, keep int) ([]string, error) {
	if keep < 0 {
		return nil, fail("UPDATE_BACKUP_CORRUPT", "the GC keep count is negative")
	}
	root = backupRootOf(root)
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fail("UPDATE_BACKUP_MISSING", "the rollback store could not be read")
	}
	type candidate struct {
		op      string
		created time.Time
	}
	var confirmed []candidate
	for _, entry := range entries {
		if !entry.IsDir() || !opIDRE.MatchString(entry.Name()) {
			continue
		}
		opDir := filepath.Join(root, entry.Name())
		info, err := os.Lstat(opDir)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		record, err := readBackupRecord(opDir, entry.Name())
		if err != nil || record.State != BackupStateConfirmed {
			continue
		}
		confirmed = append(confirmed, candidate{op: entry.Name(), created: record.CreatedAt})
	}
	sort.Slice(confirmed, func(i, j int) bool {
		if confirmed[i].created.Equal(confirmed[j].created) {
			return confirmed[i].op < confirmed[j].op
		}
		return confirmed[i].created.After(confirmed[j].created)
	})
	var removed []string
	for i := keep; i < len(confirmed); i++ {
		path := filepath.Join(root, confirmed[i].op)
		if err := os.RemoveAll(path); err != nil {
			return removed, fail("UPDATE_BACKUP_CORRUPT", "a confirmed rollback generation could not be collected")
		}
		removed = append(removed, confirmed[i].op)
	}
	return removed, nil
}

func (spec BackupSpec) validate() error {
	switch {
	case !opIDRE.MatchString(spec.OperationID):
		return fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	case spec.FromVersion == "" || len(spec.FromVersion) > 128 || strings.ContainsAny(spec.FromVersion, "\x00\n\r/"):
		return fail("UPDATE_BACKUP_CORRUPT", "from version is not a plain release string")
	case !targetRE.MatchString(spec.TargetVersion):
		return fail("UPDATE_TARGET_INVALID", "target is not a SemVer release")
	case spec.DBSchema < 0:
		return fail("UPDATE_BACKUP_CORRUPT", "database schema is negative")
	case spec.PolicySchema < 1:
		return fail("UPDATE_BACKUP_CORRUPT", "policy schema is not recorded")
	case !digestRE.MatchString(spec.ManifestSHA256):
		return fail("UPDATE_DIGEST_INVALID", "manifest SHA-256 is not 64 lowercase hex")
	case !digestRE.MatchString(spec.PackageSHA256):
		return fail("UPDATE_DIGEST_INVALID", "package SHA-256 is not 64 lowercase hex")
	}
	for _, digest := range []string{spec.FromPackageSHA256, spec.FromAgentSHA256} {
		if digest != "" && !digestRE.MatchString(digest) {
			return fail("UPDATE_BACKUP_CORRUPT", "from-* digest is not 64 lowercase hex")
		}
	}
	return nil
}

func (record BackupRecord) sameIdentity(spec BackupSpec) bool {
	return record.OperationID == spec.OperationID && record.FromVersion == spec.FromVersion &&
		record.TargetVersion == spec.TargetVersion && record.DBSchema == spec.DBSchema &&
		record.PolicySchema == spec.PolicySchema && record.ManifestSHA256 == spec.ManifestSHA256 &&
		record.PackageSHA256 == spec.PackageSHA256 &&
		record.FromPackageSHA256 == spec.FromPackageSHA256 && record.FromAgentSHA256 == spec.FromAgentSHA256
}

func verifyPayload(record BackupRecord, opDir string) error {
	payloadPath := filepath.Join(opDir, backupPayloadDir)
	if filepath.Clean(record.PayloadPath) != filepath.Clean(payloadPath) {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback record names another payload path")
	}
	if !record.IntegrityOK {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback payload has no integrity readback")
	}
	digest, files, err := hashPayloadTree(payloadPath, true)
	if err != nil {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback payload is not a private file tree")
	}
	if digest != record.PayloadSHA256 || files != record.PayloadFiles {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback payload does not match its record")
	}
	return nil
}

func readBackupRecord(opDir, operationID string) (BackupRecord, error) {
	path := filepath.Join(opDir, backupRecordName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return BackupRecord{}, fail("UPDATE_BACKUP_MISSING", "no verified rollback record exists")
	}
	if err != nil {
		return BackupRecord{}, fail("UPDATE_BACKUP_MISSING", "the rollback record could not be read")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		!ownedByEUID(info) || info.Size() > backupRecordMaxBytes {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback record is not a private 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback record could not be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record BackupRecord
	if err := decoder.Decode(&record); err != nil {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback record is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback record carries trailing data")
	}
	if record.Schema != BackupRecordSchema || record.OperationID != operationID {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback record does not belong to this operation")
	}
	return record, nil
}

func writeRecordFile(opDir string, record BackupRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback record could not be encoded")
	}
	part := filepath.Join(opDir, backupRecordPart)
	if err := os.WriteFile(part, data, 0600); err != nil {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback record could not be written")
	}
	if err := os.Rename(part, filepath.Join(opDir, backupRecordName)); err != nil {
		_ = os.Remove(part)
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback record could not be published")
	}
	return nil
}

// hashPayloadTree hashes one payload tree without following symlinks. The
// digest covers relative path, size and content of every regular file, sorted
// by path; it deliberately excludes modes so a 0755 installer binary and its
// 0600 store copy are the same bytes. private also enforces the store rule on
// every directory (0700) and file (0600) and requires this process's
// ownership.
func hashPayloadTree(dir string, private bool) (string, int, error) {
	if dir == "" {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), 0, nil
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", 0, errPayloadUnsafe
	}
	if private && (info.Mode().Perm() != 0700 || !ownedByEUID(info)) {
		return "", 0, errPayloadUnsafe
	}
	var entries []string
	files := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == dir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errPayloadUnsafe
		}
		if info.IsDir() {
			if private && (info.Mode().Perm() != 0700 || !ownedByEUID(info)) {
				return errPayloadUnsafe
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() > int64(updatePackageMaxBytes) {
			return errPayloadUnsafe
		}
		if private && (info.Mode().Perm() != 0600 || !ownedByEUID(info)) {
			return errPayloadUnsafe
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		fileDigest, err := hashFile(path)
		if err != nil {
			return err
		}
		files++
		entries = append(entries, fmt.Sprintf("%s\x00%d\x00%s", filepath.ToSlash(relative), info.Size(), fileDigest))
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(entries)
	outer := sha256.New()
	for _, entry := range entries {
		_, _ = io.WriteString(outer, entry+"\n")
	}
	return hex.EncodeToString(outer.Sum(nil)), files, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// copyPayloadTree copies regular files and directories only, normalizing every
// copy to the private store mode. A symlink or device node anywhere in the
// snapshot is refused instead of followed.
func copyPayloadTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	if src == "" {
		return nil
	}
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errPayloadUnsafe
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == src {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errPayloadUnsafe
		}
		relative, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !info.Mode().IsRegular() || info.Size() > int64(updatePackageMaxBytes) {
			return errPayloadUnsafe
		}
		return copyPrivateFile(path, target)
	})
}

func copyPrivateFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(in, int64(updatePackageMaxBytes)+1))
	if copyErr == nil {
		info, statErr := out.Stat()
		if statErr != nil || info.Size() > int64(updatePackageMaxBytes) {
			copyErr = errPayloadUnsafe
		}
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	return nil
}

func ownedByEUID(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

var errPayloadUnsafe = errors.New("payload tree is unsafe")
