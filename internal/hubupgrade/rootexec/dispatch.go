package rootexec

// The privileged dispatch boundary of #11d Task 4 (spec §5.1).
//
// The Web process never invokes root. It writes one unprivileged request under
// /run; PID 1 starts this fixed oneshot from a path unit. This file turns that
// request into exactly one exec of a root-owned copy:
//
//  1. >1 request: drain everything, write HUB_HANDOFF_BUSY results, never exec;
//  2. parse the Web unit (including drop-ins) and require request.data_dir to
//     equal its --data-dir;
//  3. read the journal and the flat record with expectedOwner = meshmux;
//  4. for update, cross-check the root installer ledger (from_package and the
//     shared running digest); for restore, skip the ledger (it may have moved);
//  5. re-authenticate the root manifest and re-derive the package digest;
//  6. open the staged package O_NOFOLLOW, hash it while copying into a
//     root-only exec-<op>, then exec the copy. Never exec the Web-writable path.
//
// Cross-process note (Task-1 carry 2): backup.Read on LayoutFlat runs
// recoverFlatSlot, a write, in this root process. The Web's in-process
// LockFlatSlot does not cover another process. That is safe here because the
// dispatcher is only reachable after the Web committed `queued`; a new backup is
// blocked by the non-terminal journal (Busy) and cannot publish over the slot
// while this read runs. This is documented, not re-architected.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

const (
	// DefaultExecRoot is the fixed root-owned directory of the verified exec
	// copy. The staged package lives in the Web-writable data directory; this
	// one does not.
	DefaultExecRoot = "/var/lib/meshmux-installer/upgrade"
	// DefaultWebUnit is the unit whose effective --data-dir bounds the request.
	DefaultWebUnit = "/etc/systemd/system/meshmux-web.service"

	stagedPackageMax = 128 << 20
	unitMaxBytes     = 1 << 20
	execCopyPrefix   = "exec-"

	codeDispatchFailed   = "HUB_HANDOFF_FAILED"
	codeBusy             = "HUB_HANDOFF_BUSY"
	codeRequestInvalid   = "HUB_HANDOFF_REQUEST_INVALID"
	codeDataDirMismatch  = "HUB_HANDOFF_DATA_DIR_MISMATCH"
	codeStateInvalid     = "HUB_HANDOFF_STATE_INVALID"
	codeDrainFailed      = "HUB_HANDOFF_DRAIN_FAILED"
	codeOwnerUnavailable = "HUB_HANDOFF_OWNER_UNAVAILABLE"
	codeDigestMismatch   = "HUB_UPDATE_DIGEST_MISMATCH"
	codeStagedMissing    = "HUB_UPDATE_STAGED_PACKAGE_MISSING"
	codeCopyFailed       = "HUB_UPDATE_EXEC_COPY_FAILED"
	codeExecFailed       = "HUB_UPDATE_EXEC_FAILED"
	codeManifestMismatch = "HUB_MANIFEST_PACKAGE_MISMATCH"

	codeRestoreDigestMismatch = "HUB_RESTORE_DIGEST_MISMATCH"
	codeRestoreMissing        = "HUB_RESTORE_BINARY_MISSING"
	codeRestoreCopyFailed     = "HUB_RESTORE_EXEC_COPY_FAILED"
	codeRestoreExecFailed     = "HUB_RESTORE_EXEC_FAILED"
)

var dispatchOpIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// DispatchConfig is one dispatch run. Empty directories fall back to the fixed
// production paths. Owner, RecordOwner, ManifestOwner and RootOwner are explicit
// account seams for B-level fixtures; production leaves them zero, which means
// the meshmux account for Web files and root for root files.
type DispatchConfig struct {
	DataDir     string
	ManifestDir string
	RequestDir  string
	DoneDir     string
	ExecRoot    string
	ResultsDir  string
	WebUnit     string

	Now        func() time.Time
	Exec       func(path string, argv, env []string) error
	ReadLedger func() (install.InstallState, bool, error)

	Owner         int
	RecordOwner   int
	ManifestOwner int
	RootOwner     int
}

// RunDispatch performs one dispatcher pass. A missing/empty request directory is
// a successful no-op; every actual request either ends in exactly one exec of a
// verified copy or in a failed result with no exec.
//
// The watched directory is opened O_NOFOLLOW|O_DIRECTORY and must be the
// dispatcher account's exact 0730 directory; every list, read and rename after
// that is relative to the open handle. The directory is group-writable by the
// Web (it must publish there), so a path-based pass could be redirected by
// renaming the directory away and substituting a symlink or another directory
// between the check and the use.
func RunDispatch(ctx context.Context, cfg DispatchConfig, _ node.CommandRunner) error {
	if err := normalizeDispatchConfig(&cfg); err != nil {
		return err
	}
	requestDir, err := openOptionalRequestDir(cfg.RequestDir, cfg.RootOwner)
	if err != nil {
		return err
	}
	if requestDir == nil {
		return nil
	}
	defer requestDir.Close()
	entries, err := requestDir.ReadDir(-1)
	if err != nil {
		return fail(codeRequestInvalid, "the request directory could not be read")
	}
	// Only <op32hex>.json is a request. The writer stages in the unwatched
	// sibling, so no half-written document can appear here; any other name is
	// unsupported debris and is deliberately left alone rather than guessed at.
	// It cannot widen the boundary (nothing is executed without a validated
	// request), but it does keep the path unit non-empty, so a later queued
	// operation times out with HUB_HANDOFF_TIMEOUT instead of re-arming.
	var requests []string
	for _, entry := range entries {
		if _, ok := requestOperationID(entry.Name()); ok {
			requests = append(requests, entry.Name())
		}
	}
	if len(requests) == 0 {
		return nil
	}

	doneDir, err := openRequestDoneDir(cfg.DoneDir, cfg.RootOwner)
	if err != nil {
		return err
	}
	defer doneDir.Close()

	if len(requests) > 1 {
		for _, name := range requests {
			opID, _ := requestOperationID(name)
			writeFailureResult(cfg, opID, codeBusy, nil)
		}
		if _, err := hubupgrade.DrainAt(requestDir, doneDir, requests, true, cfg.Now()); err != nil {
			return err
		}
		return fail(codeBusy, "more than one request is queued; every request was drained")
	}

	name := requests[0]
	opID, _ := requestOperationID(name)
	drain := func(rejected bool) error {
		if _, err := hubupgrade.DrainAt(requestDir, doneDir, []string{name}, rejected, cfg.Now()); err != nil {
			return err
		}
		return nil
	}
	refuse := func(code string, cause error, op *hubupgrade.Op) error {
		if code == "" {
			code = codeDispatchFailed
		}
		writeFailureResult(cfg, opID, code, op)
		if err := drain(true); err != nil {
			return err
		}
		return cause
	}

	request, err := hubupgrade.ReadRequestAt(int(requestDir.Fd()), name, cfg.Owner)
	if err != nil {
		return refuse(codeOfError(err), err, nil)
	}
	expectedDataDir, err := webDataDir(cfg.WebUnit, cfg.RootOwner)
	if err != nil {
		return refuse(codeOfError(err), err, nil)
	}
	if request.DataDir != expectedDataDir || (cfg.DataDir != "" && cfg.DataDir != request.DataDir) {
		// Recovery hint in the log line only: inspect `systemctl cat
		// meshmux-web.service` and move any hand-made ExecStart drop-in into the
		// /etc drop-in directory this check reads.
		return refuse(codeDataDirMismatch, fail(codeDataDirMismatch,
			"the request data directory is not the Web unit's current --data-dir; inspect systemctl cat meshmux-web.service and keep ExecStart drop-ins under /etc/systemd/system/meshmux-web.service.d"), nil)
	}

	op, found, err := hubupgrade.ReadOp(request.DataDir, request.OperationID, cfg.Owner)
	if err != nil {
		return refuse(codeOfError(err), err, nil)
	}
	if !found {
		return refuse(codeStateInvalid, fail(codeStateInvalid, "the journal has no such operation"), nil)
	}
	opCopy := op
	if op.Kind != request.Kind {
		return refuse(codeStateInvalid, fail(codeStateInvalid, "the request kind and the journal kind differ"), &opCopy)
	}
	if !dispatchStateAllowed(op) {
		return refuse(codeStateInvalid, fail(codeStateInvalid, "the operation is not in a state this boundary may execute"), &opCopy)
	}

	// LayoutFlat's reader runs recoverFlatSlot (a write) in this process. The
	// safety argument is in the package comment above.
	record, err := backup.Read(filepath.Join(request.DataDir, hubupgrade.DatabaseBackupDir),
		request.OperationID, backup.LayoutFlat, cfg.RecordOwner)
	if err != nil {
		return refuse(codeOfError(err), err, &opCopy)
	}
	if !recordNamesOperation(record, op) {
		return refuse(backup.CodeMismatch, fail(backup.CodeMismatch, "the frozen record and the journal name different operations"), &opCopy)
	}
	if op.Kind == hubupgrade.KindUpdate {
		if record.State != backup.StateStaged {
			return refuse(backup.CodeMismatch, fail(backup.CodeMismatch, "the update source record is not staged"), &opCopy)
		}
	} else if record.State != backup.StateStaged && record.State != backup.StateConfirmed {
		return refuse(backup.CodeMismatch, fail(backup.CodeMismatch, "the restore source record is not staged or confirmed"), &opCopy)
	}

	if op.Kind == hubupgrade.KindUpdate {
		state, found, err := cfg.ReadLedger()
		if err != nil {
			return refuse(codeIdentityMissing, fail(codeIdentityMissing, "the installer ledger is not readable"), &opCopy)
		}
		if err := checkLedgerIdentity(record, state, found); err != nil {
			return refuse(codeOfError(err), err, &opCopy)
		}
		manifest, err := hubupgrade.ReadRootManifestFor(cfg.ManifestDir, op.TargetVersion, cfg.ManifestOwner)
		if err != nil {
			return refuse(codeOfError(err), err, &opCopy)
		}
		if manifest.SHA256 != op.ManifestSHA256 || manifest.Package.SHA256 != op.PackageSHA256 {
			return refuse(codeManifestMismatch, fail(codeManifestMismatch, "the root manifest no longer names the frozen package"), &opCopy)
		}
	}

	update := op.Kind == hubupgrade.KindUpdate
	var fileName, expectedDigest string
	if update {
		fileName, err = hubupgrade.PackageName(op.TargetVersion, runtime.GOARCH)
		expectedDigest = record.PackageSHA256
	} else {
		fileName, err = hubupgrade.OldPackageName(op.FromVersion, runtime.GOARCH)
		expectedDigest = record.FromAgentSHA256
	}
	if err != nil {
		return refuse(codeOfError(err), err, &opCopy)
	}
	stagedPath := filepath.Join(request.DataDir, hubupgrade.UpgradeDir, fileName)
	execPath, err := copyVerifiedPackage(stagedPath, expectedDigest, cfg.ExecRoot, op.OperationID,
		cfg.Owner, cfg.RootOwner, update)
	if err != nil {
		return refuse(codeOfError(err), err, &opCopy)
	}

	if err := ctx.Err(); err != nil {
		return refuse(codeDispatchFailed, fail(codeDispatchFailed, "the dispatch context was cancelled before exec"), &opCopy)
	}
	// The request is consumed before exec: the process image is replaced and
	// cannot re-arm the path unit afterwards.
	if err := drain(false); err != nil {
		return refuse(codeDrainFailed, err, &opCopy)
	}
	argv := dispatchArgv(execPath, op, record, request.DataDir, cfg.Now())
	if err := cfg.Exec(execPath, argv, dispatchEnv()); err != nil {
		code := codeExecFailed
		if !update {
			code = codeRestoreExecFailed
		}
		writeFailureResult(cfg, opID, code, &opCopy)
		return err
	}
	return nil
}

func normalizeDispatchConfig(cfg *DispatchConfig) error {
	if cfg.ManifestDir == "" {
		cfg.ManifestDir = hubupgrade.RootManifestDir
	}
	if cfg.RequestDir == "" {
		cfg.RequestDir = hubupgrade.RequestDir
	}
	if cfg.DoneDir == "" {
		cfg.DoneDir = hubupgrade.RequestDoneDir
	}
	if cfg.ExecRoot == "" {
		cfg.ExecRoot = DefaultExecRoot
	}
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = hubupgrade.ResultsDir
	}
	if cfg.WebUnit == "" {
		cfg.WebUnit = DefaultWebUnit
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Exec == nil {
		cfg.Exec = func(path string, argv, env []string) error {
			return syscall.Exec(path, argv, env)
		}
	}
	if cfg.ReadLedger == nil {
		cfg.ReadLedger = readHubLedger
	}
	if cfg.Owner == 0 {
		owner, err := lookupAccountID("meshmux")
		if err != nil {
			return fail(codeOwnerUnavailable, "the meshmux account is not available")
		}
		cfg.Owner = owner
	}
	if cfg.RecordOwner == 0 {
		cfg.RecordOwner = cfg.Owner
	}
	return nil
}

func lookupAccountID(name string) (int, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(account.Uid)
}

// openOptionalRequestDir is OpenRequestDir with the one benign absence: a host
// whose tmpfiles drop-in has not created the directory yet has no request.
func openOptionalRequestDir(dir string, expectedOwner int) (*os.File, error) {
	handle, err := hubupgrade.OpenRequestDir(dir, expectedOwner)
	if err == nil {
		return handle, nil
	}
	if _, statErr := os.Lstat(dir); os.IsNotExist(statErr) {
		return nil, nil
	}
	return nil, err
}

// openRequestDoneDir creates the dispatcher's own done directory 0700 when it is
// absent, then proves it through the same open-handle check.
func openRequestDoneDir(dir string, expectedOwner int) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fail(codeDrainFailed, "the request done directory is unavailable")
	}
	return hubupgrade.OpenRequestDoneDir(dir, expectedOwner)
}

func requestOperationID(name string) (string, bool) {
	if !strings.HasSuffix(name, ".json") {
		return "", false
	}
	id := strings.TrimSuffix(name, ".json")
	return id, dispatchOpIDRE.MatchString(id)
}

func dispatchStateAllowed(op hubupgrade.Op) bool {
	if op.Kind == hubupgrade.KindUpdate {
		// Only the single queued handoff may exec. A later applying/restarting
		// operation has already been consumed (the dispatcher drains before
		// exec); a second request for it would be a replay, not a new handoff.
		return op.State == hubupgrade.StateQueued
	}
	switch op.State {
	case hubupgrade.StateFailed, hubupgrade.StatePartial, hubupgrade.StateVerifying:
		return true
	}
	return false
}

func recordNamesOperation(record backup.Record, op hubupgrade.Op) bool {
	return record.OperationID == op.OperationID &&
		record.FromVersion == op.FromVersion &&
		record.TargetVersion == op.TargetVersion &&
		record.ManifestSHA256 == op.ManifestSHA256 &&
		record.PackageSHA256 == op.PackageSHA256 &&
		record.DBSchema == op.DBSchema
}

func dispatchArgv(execPath string, op hubupgrade.Op, record backup.Record, dataDir string, now time.Time) []string {
	if op.Kind == hubupgrade.KindRestore {
		restoreDir := filepath.Join(dataDir, "restore-"+op.OperationID+"-"+strconv.FormatInt(now.Unix(), 10))
		return []string{execPath, "__internal-hub-restore",
			"--expected-sha256", record.FromAgentSHA256,
			"--operation-id", op.OperationID,
			"--data-dir", dataDir,
			"--restore-dir", restoreDir}
	}
	return []string{execPath, "__internal-hub-update",
		"--target", op.TargetVersion,
		"--expected-sha256", op.PackageSHA256,
		"--operation-id", op.OperationID,
		"--data-dir", dataDir,
		"--from-version", op.FromVersion}
}

// dispatchEnv is deliberately minimal and deterministic. The staged executors
// read no caller environment; systemd's own environment is not forwarded.
func dispatchEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}
}

func writeFailureResult(cfg DispatchConfig, opID, code string, op *hubupgrade.Op) {
	if !dispatchOpIDRE.MatchString(opID) {
		return
	}
	result := hubupgrade.Result{
		Schema: hubupgrade.ResultSchema, OperationID: opID,
		Phase: hubupgrade.ResultFailed, ErrorCode: code, UpdatedAt: cfg.Now().UTC(),
	}
	if op != nil {
		result.TargetVersion = op.TargetVersion
		result.PackageSHA256 = op.PackageSHA256
	}
	// Result evidence is best-effort: it is never an authorization, so a write
	// failure must not change the refusal itself.
	_, _ = hubupgrade.WriteResult(cfg.ResultsDir, result)
}

// webDataDir returns the data directory of the effective Web ExecStart, applying
// root-owned drop-ins in lexicographic order. A drop-in may reset ExecStart with
// an empty value and then name exactly one replacement, which is exactly the
// shape Task 7 writes for a restore.
//
// Caveat: only /etc/systemd/system/meshmux-web.service.d/*.conf is read. That is
// the tree the installer and the restore executor write; a hand-made drop-in
// under /usr/lib/systemd/system or /run/systemd/system would make this comparison
// disagree with the running unit. The refusal is HUB_HANDOFF_DATA_DIR_MISMATCH;
// the recovery hint is to inspect `systemctl cat meshmux-web.service` and keep
// data-dir overrides in the /etc drop-in directory.
func webDataDir(unitPath string, expectedOwner int) (string, error) {
	body, err := readUnitFile(unitPath, expectedOwner)
	if err != nil {
		return "", err
	}
	argv, err := hubupgrade.ParseWebExecStart(string(body))
	if err != nil {
		return "", err
	}
	dropDir := unitPath + ".d"
	entries, err := os.ReadDir(dropDir)
	if os.IsNotExist(err) {
		return hubupgrade.DataDirFromArgv(argv)
	}
	if err != nil {
		return "", fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web drop-in directory could not be read")
	}
	dirInfo, err := os.Lstat(dropDir)
	if err != nil || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() ||
		dirInfo.Mode().Perm()&0022 != 0 || !statOwnedBy(dirInfo, expectedOwner) {
		return "", fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web drop-in directory is not root-owned and private")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dropDir, entry.Name())
		dropIn, err := readUnitFile(path, expectedOwner)
		if err != nil {
			return "", err
		}
		argv, err = applyExecStartDropIn(argv, string(dropIn))
		if err != nil {
			return "", err
		}
	}
	if len(argv) == 0 {
		return "", fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web unit has no effective ExecStart")
	}
	return hubupgrade.DataDirFromArgv(argv)
}

func readUnitFile(path string, expectedOwner int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0022 != 0 || !statOwnedBy(info, expectedOwner) ||
		info.Size() < 1 || info.Size() > unitMaxBytes {
		return nil, fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web unit is not a private root-owned file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web unit could not be opened without following a link")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web unit changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, unitMaxBytes+1))
	if err != nil || len(body) > unitMaxBytes {
		return nil, fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web unit could not be read within its bound")
	}
	return body, nil
}

// applyExecStartDropIn applies the ExecStart assignments of one drop-in to the
// effective argv. Empty resets, a non-empty line replaces (and a second
// non-empty line is refused, because a simple service may only have one).
func applyExecStartDropIn(current []string, unit string) ([]string, error) {
	section := ""
	for _, raw := range strings.Split(unit, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Service" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "ExecStart" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			current = nil
			continue
		}
		if current != nil {
			return nil, fail("HUB_RESTORE_UNIT_SHAPE_INVALID", "the web drop-in adds a second effective ExecStart")
		}
		parsed, err := hubupgrade.ParseWebExecStart("[Service]\nExecStart=" + value + "\n")
		if err != nil {
			return nil, err
		}
		current = parsed
	}
	return current, nil
}

// copyVerifiedPackage validates the staged package by descriptor and copies the
// exact bytes into a root-only exec-<op> while hashing them. The digest is
// checked against the copy, so a replacement of the staged path after validation
// cannot change what runs. The destination is fsynced, chmod 0700 and renamed
// into place before it is returned.
func copyVerifiedPackage(stagedPath, expectedDigest, execRoot, operationID string, webOwner, rootOwner int, update bool) (string, error) {
	missingCode, digestCode, copyCode := codeStagedMissing, codeDigestMismatch, codeCopyFailed
	if !update {
		missingCode, digestCode, copyCode = codeRestoreMissing, codeRestoreDigestMismatch, codeRestoreCopyFailed
	}
	if execRoot == "" || !filepath.IsAbs(execRoot) {
		return "", fail(copyCode, "the exec root is not absolute")
	}
	if err := os.MkdirAll(execRoot, 0755); err != nil {
		return "", fail(copyCode, "the exec root is unavailable")
	}
	rootInfo, err := os.Lstat(execRoot)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() ||
		rootInfo.Mode().Perm()&0022 != 0 || !statOwnedBy(rootInfo, rootOwner) {
		return "", fail(copyCode, "the exec root is not a root-owned private-enough directory")
	}

	info, err := os.Lstat(stagedPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0022 != 0 || !statOwnedBy(info, webOwner) ||
		info.Size() < 1 || info.Size() > stagedPackageMax {
		return "", fail(missingCode, "the staged package is not a private executable of the Web account")
	}
	source, err := os.OpenFile(stagedPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fail(missingCode, "the staged package could not be opened without following a link")
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return "", fail(missingCode, "the staged package changed while it was being opened")
	}

	execPath := filepath.Join(execRoot, execCopyPrefix+operationID)
	part := execPath + ".part"
	if err := os.Remove(part); err != nil && !os.IsNotExist(err) {
		return "", fail(copyCode, "the exec scratch path could not be cleared")
	}
	if err := os.Remove(execPath); err != nil && !os.IsNotExist(err) {
		return "", fail(copyCode, "the previous exec copy could not be cleared")
	}
	destination, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return "", fail(copyCode, "the exec copy could not be created")
	}
	cleanup := func() {
		_ = destination.Close()
		_ = os.Remove(part)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(source, stagedPackageMax+1))
	if copyErr != nil || written < 1 || written > stagedPackageMax {
		cleanup()
		return "", fail(copyCode, "the exec copy did not complete within its bound")
	}
	if err := destination.Sync(); err != nil {
		cleanup()
		return "", fail(copyCode, "the exec copy could not be flushed")
	}
	if err := destination.Close(); err != nil {
		_ = os.Remove(part)
		return "", fail(copyCode, "the exec copy could not be closed")
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != expectedDigest {
		_ = os.Remove(part)
		return "", fail(digestCode, "the staged package bytes do not match the frozen digest")
	}
	if err := os.Chmod(part, 0700); err != nil {
		_ = os.Remove(part)
		return "", fail(copyCode, "the exec copy could not be made root-only")
	}
	if err := os.Rename(part, execPath); err != nil {
		_ = os.Remove(part)
		return "", fail(copyCode, "the exec copy could not be published")
	}
	if err := syncDirEntry(execRoot); err != nil {
		_ = os.Remove(execPath)
		return "", fail(copyCode, "the exec root could not be flushed")
	}
	return execPath, nil
}

func syncDirEntry(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func statOwnedBy(info os.FileInfo, owner int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == owner
}

func fail(code, detail string) error { return errors.New(code + ": " + detail) }

// codeOfError returns the stable prefix of an error built by this package or
// by a lower package's fail helper. It never parses prose for a decision.
func codeOfError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if i := strings.IndexByte(text, ':'); i > 0 {
		return text[:i]
	}
	return text
}
