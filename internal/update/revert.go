package update

// The revert executor (#11c-3 Task 4, spec §4.7/§4.12/§4.17).
//
// A failed upgrade is undone by a SEPARATE transient unit, never in the Agent
// process: restoring the Agent binary and restarting the Agent would kill a
// child of the Agent's cgroup, and the Agent must survive to report the
// outcome. The unit's ExecStart is the verified OLD package staged out of the
// rollback payload (from_agent_sha256 is the trust anchor); its fixed argv is
// `__internal-update-revert`. The Agent-side Reverter starts that argv with
// systemd-run --wait and returns only when the unit's verdict exists. --wait is
// a convenience, not the guarantee: the unit restarts the Agent, which can kill
// the waiting client. The guarantee is the <operation_id>.revert.json verdict
// plus done=false (the caller keeps the receipt non-terminal) whenever the
// client cannot observe the finished unit. The first terminal receipt is cached
// and replayed by Execute, so a revert that lands asynchronously could never be
// reported (binding review carry).
//
// The unit restores the recorded change set through the installer's
// rollbackNodeFiles path (see install.RestoreNodeSnapshot), reconciles the
// ledger/agent.json disagreement a failed upgrade may leave behind, restarts
// the restored services and writes <operation_id>.revert.json. It never
// retries: a failed revert is terminal with manual guidance.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

const (
	// revertUnitPrefix names the one-shot revert unit. It is distinct from the
	// install and convergence units so a hung install can never be mistaken
	// for a revert (or vice versa).
	revertUnitPrefix = "meshmux-revert-"
	// revertHiddenCommand is the staged old package's only subcommand.
	revertHiddenCommand = "__internal-update-revert"
	// revertExecSuffix names the staged copy of the old package inside the
	// private work directory.
	revertExecSuffix = ".revert-exec"
	// revertRWPaths is the write set of the revert unit. It is the install
	// set: the restored files, the installer ledger, the private Agent
	// directory (the rollback store by default) and the unit cache.
	revertRWPaths = transientRWPaths
	// revertAddressFamilies is the socket allowlist: systemctl speaks AF_UNIX
	// and nothing in the revert opens a network socket.
	revertAddressFamilies = "AF_UNIX"
	// revertCaps: rollbackNodeFiles chowns every restored file on a real root;
	// starting the restored units is systemd's, not the unit's, privilege.
	revertCaps = "CAP_CHOWN"

	// RevertSchema is the frozen separate revert-result schema (Task 3). The
	// 11c-2 install result is left byte-identical.
	RevertSchema = "meshmux-upgrade-revert/v1"
	// revertMaxBytes bounds the verdict read.
	revertMaxBytes = 4096

	// RevertOutcomeRolledBack means the recorded change set was restored and
	// the restored services started.
	RevertOutcomeRolledBack = "rolled_back"
	// RevertOutcomeFailed is terminal: manual action is required and the
	// attempt is never retried.
	RevertOutcomeFailed = "failed"
)

// RevertResult is the <operation_id>.revert.json verdict written by the
// transient revert executor. It is read by the Agent (node.readUpgradeRevert)
// exactly as frozen by Task 3.
type RevertResult struct {
	Schema        string `json:"schema"`
	OperationID   string `json:"operation_id"`
	TargetVersion string `json:"target_version"`
	FromVersion   string `json:"from_version"`
	Outcome       string `json:"outcome"`
	ExitCode      int    `json:"exit_code"`
	ErrorCode     string `json:"error_code,omitempty"`
	Timestamp     int64  `json:"ts"`
}

// RevertResultPath is the fixed verdict path of one operation.
func RevertResultPath(dir, operationID string) string {
	return filepath.Join(dir, operationID+".revert.json")
}

// RevertExecPath is the staged old package of one operation. The name derives
// from the operation ID, never from a caller.
func RevertExecPath(dir, operationID string) string {
	return filepath.Join(dir, operationID+revertExecSuffix)
}

func (cfg Config) revertRoot() string {
	if cfg.Root != "" {
		return cfg.Root
	}
	return "/"
}

// BuildRevertArgv builds the one fixed `systemd-run` command line of a revert
// (spec §4.17). `--wait` is a best-effort convenience, not the ordering
// guarantee: the unit restarts the Agent, so the waiting client can be killed
// before it observes the exit. The ordering guarantee is the verdict file plus
// done=false: the caller never caches a terminal receipt while the change set
// may still be restoring.
func BuildRevertArgv(cfg Config) ([]string, error) {
	switch {
	case cfg.OperationID == "":
		return nil, fail("OPERATION_REQUIRED", "an operation ID is required")
	case !opIDRE.MatchString(cfg.OperationID):
		return nil, fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	case !digestRE.MatchString(cfg.FromAgentSHA256):
		return nil, fail("UPDATE_DIGEST_INVALID", "the old Agent digest is not 64 lowercase hex")
	}
	dir, err := transientWorkDir(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	return []string{
		systemdRunPath,
		"--unit=" + revertUnitPrefix + cfg.OperationID,
		"--collect",
		"--wait",
		"--property=Type=oneshot",
		"--property=Restart=no",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=" + revertRWPaths,
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=RestrictAddressFamilies=" + revertAddressFamilies,
		"--property=CapabilityBoundingSet=" + revertCaps,
		RevertExecPath(dir, cfg.OperationID),
		revertHiddenCommand,
		"--operation-id", cfg.OperationID,
		"--expected-sha256", cfg.FromAgentSHA256,
	}, nil
}

// WriteRevertResult validates and publishes one verdict atomically with mode
// 0600. A crash leaves either the previous file or the complete new one.
func WriteRevertResult(path string, result RevertResult) error {
	if err := validateRevertResult(path, result); err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fail("UPDATE_REVERT_RESULT_WRITE_FAILED", "the revert record could not be encoded")
	}
	data = append(data, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".revert-*.part")
	if err != nil {
		return fail("UPDATE_REVERT_RESULT_WRITE_FAILED", "the revert result directory is not writable")
	}
	temp := file.Name()
	defer func() {
		if temp != "" {
			_ = os.Remove(temp)
		}
	}()
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fail("UPDATE_REVERT_RESULT_WRITE_FAILED", "the revert record could not be written")
	}
	if err = os.Rename(temp, path); err != nil {
		return fail("UPDATE_REVERT_RESULT_WRITE_FAILED", "the revert record could not be published")
	}
	temp = ""
	return nil
}

// ReadRevertResult reads one verdict under the same strict, private rules as
// the install result: the name derives from the operation, unknown fields and
// trailing data are corruption, and the two frozen outcomes are the only
// verdicts.
func ReadRevertResult(path string) (RevertResult, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return RevertResult{}, fail("UPDATE_REVERT_RESULT_UNAVAILABLE", "the revert result could not be read")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return RevertResult{}, fail("UPDATE_REVERT_RESULT_UNAVAILABLE", "the revert result could not be read")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(stat.Uid) != os.Geteuid() {
		return RevertResult{}, fail("UPDATE_REVERT_RESULT_UNSAFE", "the revert result is not a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, revertMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > revertMaxBytes {
		return RevertResult{}, fail("UPDATE_REVERT_RESULT_INVALID", "the revert result is empty, unreadable or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result RevertResult
	if err = decoder.Decode(&result); err != nil {
		return RevertResult{}, fail("UPDATE_REVERT_RESULT_INVALID", "the revert result is not the fixed schema")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return RevertResult{}, fail("UPDATE_REVERT_RESULT_INVALID", "the revert result has trailing data")
	}
	if err = validateRevertResult(path, result); err != nil {
		return RevertResult{}, err
	}
	return result, nil
}

func validateRevertResult(path string, result RevertResult) error {
	if filepath.Base(path) != result.OperationID+".revert.json" {
		return fail("UPDATE_REVERT_RESULT_INVALID", "the file name must be <operation_id>.revert.json")
	}
	if result.Schema != RevertSchema || !opIDRE.MatchString(result.OperationID) ||
		!targetRE.MatchString(result.TargetVersion) || !targetRE.MatchString(result.FromVersion) ||
		result.ExitCode < 0 || result.ExitCode > 255 || result.Timestamp < 1 {
		return fail("UPDATE_REVERT_RESULT_INVALID", "the revert result does not carry the frozen identity fields")
	}
	switch result.Outcome {
	case RevertOutcomeRolledBack:
		if result.ErrorCode != "" || result.ExitCode != 0 {
			return fail("UPDATE_REVERT_RESULT_INVALID", "a rolled_back revert carries no error code and exit 0")
		}
	case RevertOutcomeFailed:
		if !handoffCodeRE.MatchString(result.ErrorCode) || result.ExitCode == 0 {
			return fail("UPDATE_REVERT_RESULT_INVALID", "a failed revert must name a stable code and a non-zero exit")
		}
	default:
		return fail("UPDATE_REVERT_RESULT_INVALID", "outcome is not rolled_back or failed")
	}
	return nil
}

var handoffCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// RunRevert is the body of `__internal-update-revert`: the transient unit
// restores the recorded change set, reconciles the ledger, starts the restored
// services and writes the verdict. It is fail-closed and never retries.
func RunRevert(ctx context.Context, cfg Config, runner node.CommandRunner) (RevertResult, error) {
	if err := validateRevertConfig(cfg, runner); err != nil {
		return RevertResult{}, err
	}
	self, err := installExecutable(cfg)
	if err != nil {
		return RevertResult{}, err
	}
	// The self-check is first: no record read and no host mutation may happen
	// when the bytes on disk are not the verified old package.
	if err := verifyInstallDigest(self, cfg.FromAgentSHA256); err != nil {
		return RevertResult{}, err
	}
	record, err := readRevertRecord(cfg)
	if err != nil {
		return RevertResult{}, err
	}
	result := RevertResult{
		Schema: RevertSchema, OperationID: cfg.OperationID,
		TargetVersion: record.TargetVersion, FromVersion: record.FromVersion,
		Timestamp: time.Now().Unix(),
	}
	failed := func(code, detail string) (RevertResult, error) {
		result.Outcome, result.ErrorCode, result.ExitCode = RevertOutcomeFailed, code, 1
		result.Timestamp = time.Now().Unix()
		if writeErr := WriteRevertResult(RevertResultPath(cfg.WorkDir, cfg.OperationID), result); writeErr != nil {
			return result, writeErr
		}
		return result, fail(code, detail)
	}
	root := cfg.revertRoot()
	if _, err := install.RestoreNodeSnapshot(ctx, install.NodeApplyOptions{Root: root, Runner: runner},
		record.PayloadPath, install.RestoreAnchors{
			FromAgentSHA256: record.FromAgentSHA256, FromPackageSHA256: record.FromPackageSHA256,
		}); err != nil {
		return failed(revertCode(err), err.Error())
	}
	// The restored release and the ledger must agree before the Agent starts;
	// this is the deliberate §4.17 path, not CONFIG_CONFLICT.
	if err := install.AdoptRestoredRelease(root, cfg.OperationID); err != nil {
		return failed(revertCode(err), err.Error())
	}
	if err := install.StartRestoredNode(ctx, runner, root); err != nil {
		return failed(revertCode(err), err.Error())
	}
	result.Outcome, result.ErrorCode, result.ExitCode = RevertOutcomeRolledBack, "", 0
	result.Timestamp = time.Now().Unix()
	resultPath := RevertResultPath(cfg.WorkDir, cfg.OperationID)
	if err := WriteRevertResult(resultPath, result); err != nil {
		return result, err
	}
	// The failed attempt's install result is the Agent's confirmation anchor;
	// after a successful revert it must not outlive the attempt it describes.
	_ = os.Remove(ResultPath(cfg.WorkDir, cfg.OperationID))
	// Mark the record failed so a later accepted readback of the restored
	// release can never confirm the operation that was just undone. A missing
	// write is logged by the receipt path, never a reason to fail a successful
	// restore (ConfirmVersion also refuses a stale revert result).
	markRevertedRecord(cfg, record)
	_ = os.Remove(RevertExecPath(cfg.WorkDir, cfg.OperationID))
	return result, nil
}

// validateRevertConfig checks the fixed argv fields without touching the host.
func validateRevertConfig(cfg Config, runner node.CommandRunner) error {
	switch {
	case cfg.OperationID == "":
		return fail("OPERATION_REQUIRED", "an operation ID is required")
	case !opIDRE.MatchString(cfg.OperationID):
		return fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	case !digestRE.MatchString(cfg.FromAgentSHA256):
		return fail("UPDATE_DIGEST_INVALID", "the old Agent digest is not 64 lowercase hex")
	case runner == nil:
		return fail("UPDATE_REVERT_UNAVAILABLE", "no command runner is configured")
	}
	if _, err := transientWorkDir(cfg.WorkDir); err != nil {
		return err
	}
	root := cfg.revertRoot()
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, "\n\r\x00") {
		return fail("UPDATE_REVERT_INVALID", "the revert root is not a clean absolute path")
	}
	return nil
}

// readRevertRecord reads the rollback record state-agnostically: a confirmed
// record is a legitimate explicit rollback target, and a failed one must stay
// readable for manual recovery. The handoff-only staged rule belongs to
// requireVerifiedBackup and is deliberately not reused here.
func readRevertRecord(cfg Config) (BackupRecord, error) {
	root := cfg.backupRoot()
	opDir := filepath.Join(root, cfg.OperationID)
	record, err := readBackupRecord(opDir, cfg.OperationID)
	if err != nil {
		return BackupRecord{}, err
	}
	if _, err := VerifyBackupRecord(root, cfg.OperationID, record.FromVersion, record.DBSchema, record.PolicySchema); err != nil {
		return BackupRecord{}, err
	}
	if record.FromVersion == "" || !targetRE.MatchString(record.TargetVersion) {
		return BackupRecord{}, fail("UPDATE_BACKUP_CORRUPT", "the rollback record has no usable release identity")
	}
	return record, nil
}

func markRevertedRecord(cfg Config, record BackupRecord) {
	record.State = BackupStateFailed
	if err := writeRecordFile(filepath.Join(cfg.backupRoot(), cfg.OperationID), record); err != nil {
		return
	}
}

// revertCode maps installer-side revert codes to the stable codes the Agent
// receipt and the revert result carry. Unmapped failures stay generic.
func revertCode(err error) string {
	var ie *install.InstallError
	if errors.As(err, &ie) {
		switch ie.Code {
		case "ROLLBACK_SNAPSHOT_INVALID":
			return "UPDATE_BACKUP_CORRUPT"
		case "ROLLBACK_ANCHOR_MISMATCH":
			return "UPDATE_BACKUP_MISMATCH"
		case "ROLLBACK_RESTORE_FAILED":
			return "UPDATE_REVERT_RESTORE_FAILED"
		case "ROLLBACK_LEDGER_INVALID", "ROLLBACK_LEDGER_FAILED":
			return "UPDATE_REVERT_LEDGER_FAILED"
		case "ROLLBACK_CLAIM_CLEAR_FAILED":
			return "UPDATE_REVERT_CLAIM_CLEAR_FAILED"
		case "ROLLBACK_START_FAILED":
			return "UPDATE_REVERT_START_FAILED"
		case "CONFIG_CONFLICT":
			return "CONFIG_CONFLICT"
		}
	}
	if code := handoffCodeRE.FindString(err.Error()); code != "" {
		return code
	}
	return "UPDATE_REVERT_FAILED"
}

// Reverter is the Agent-side half of the revert trigger. It stages the verified
// old package, starts the fixed transient argv and waits for the verdict. The
// unit restarts the Agent, so the waiting client may be killed; that case is
// done=false (keep the receipt non-terminal) and the next Agent boot reads the
// verdict. RevertOperation is idempotent: an existing verdict, a still-running
// unit and a finished-but-verdict-less unit are each reported without starting
// a second revert.
type Reverter struct {
	BackupRoot string
	WorkDir    string
	Runner     node.CommandRunner
}

// NewReverter wires the production paths and the fixed command boundary.
func NewReverter() *Reverter {
	return &Reverter{BackupRoot: DefaultBackupRoot, WorkDir: DefaultWorkDir, Runner: node.ExecRunner{}}
}

// RevertOperation returns done=true only when the revert has a finished
// verdict (or there is nothing to revert). done=false means the unit is still
// running: the caller must keep the receipt non-terminal and never cache it.
func (r *Reverter) RevertOperation(ctx context.Context, operationID string) (bool, error) {
	if !opIDRE.MatchString(operationID) {
		return true, fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	}
	if r == nil || r.Runner == nil {
		return true, fail("UPDATE_REVERT_UNAVAILABLE", "no revert executor is configured")
	}
	if _, err := transientWorkDir(r.WorkDir); err != nil {
		return true, err
	}
	resultPath := RevertResultPath(r.WorkDir, operationID)
	if _, err := os.Lstat(resultPath); err == nil {
		return true, nil
	}
	cfg := Config{OperationID: operationID, BackupRoot: r.BackupRoot, WorkDir: r.WorkDir}
	record, err := readRevertRecord(cfg)
	if err != nil {
		// No rollback source means nothing was replaced by this attempt. The
		// honest handoff failure stands; no verdict is invented.
		return true, err
	}
	manifest, err := install.ReadSnapshotManifest(record.PayloadPath)
	if err != nil {
		r.writeUnavailable(cfg, record, revertCode(err))
		return true, err
	}
	entry, ok := snapshotAgent(manifest)
	if !ok || entry.SHA256 != record.FromAgentSHA256 ||
		(record.FromPackageSHA256 != "" && record.FromPackageSHA256 != record.FromAgentSHA256) {
		r.writeUnavailable(cfg, record, "UPDATE_BACKUP_MISMATCH")
		return true, fail("UPDATE_BACKUP_MISMATCH", "the rollback payload's Agent binary does not match the record")
	}
	if err := stageRevertExec(manifest, record, r.WorkDir); err != nil {
		r.writeUnavailable(cfg, record, revertCode(err))
		return true, err
	}
	argv, err := BuildRevertArgv(Config{OperationID: operationID, WorkDir: r.WorkDir,
		FromAgentSHA256: record.FromAgentSHA256})
	if err != nil {
		r.writeUnavailable(cfg, record, revertCode(err))
		return true, err
	}
	if _, err := r.Runner.Run(ctx, argv[0], argv[1:]...); err != nil {
		if _, statErr := os.Lstat(resultPath); statErr == nil {
			return true, nil
		}
		if revertUnitActive(ctx, r.Runner, operationID) {
			return false, err
		}
		r.writeUnavailable(cfg, record, "UPDATE_REVERT_UNIT_FAILED")
		return true, err
	}
	if _, statErr := os.Lstat(resultPath); statErr != nil {
		// The unit exited 0 without a verdict: this is not success.
		r.writeUnavailable(cfg, record, "UPDATE_REVERT_RESULT_MISSING")
		return true, fail("UPDATE_REVERT_RESULT_MISSING", "the revert unit finished without a verdict")
	}
	return true, nil
}

// writeUnavailable records a terminal verdict when the revert could not run.
// It never hides the outcome: the receipt names the code and manual guidance.
func (r *Reverter) writeUnavailable(cfg Config, record BackupRecord, code string) {
	result := RevertResult{Schema: RevertSchema, OperationID: cfg.OperationID,
		TargetVersion: record.TargetVersion, FromVersion: record.FromVersion,
		Outcome: RevertOutcomeFailed, ExitCode: 1, ErrorCode: code, Timestamp: time.Now().Unix()}
	_ = WriteRevertResult(RevertResultPath(cfg.WorkDir, cfg.OperationID), result)
}

// revertUnitActive reports whether the transient revert unit is still running.
// A cancelled helper cannot prove the unit finished, so it is treated as
// running; an unobservable unit on a live context is treated as finished
// (systemd --collect unloads a completed unit, and the verdict file is the
// authority either way).
func revertUnitActive(ctx context.Context, runner node.CommandRunner, operationID string) bool {
	out, err := runner.Run(ctx, systemctlPath, "show", "-p", "ActiveState", "-p", "ExecMainStatus",
		revertUnitPrefix+operationID)
	if err != nil {
		// A cancelled helper cannot prove the unit finished. Assume it is still
		// running: caching a failed verdict while the change set is being
		// restored is exactly the ordering violation this trigger exists to
		// prevent. The next poll queries again with a fresh context.
		return ctx.Err() != nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "ActiveState" {
			continue
		}
		switch value {
		case "active", "activating", "reloading", "deactivating":
			return true
		}
	}
	return false
}

// stageRevertExec copies the payload's Agent binary to the fixed private path
// the transient unit executes, then verifies the bytes again. The payload copy
// is 0600; the staged copy is 0700 so it can be executed.
func stageRevertExec(manifest install.SnapshotManifest, record BackupRecord, workDir string) error {
	entry, ok := snapshotAgent(manifest)
	if !ok || !entry.Exists {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback payload does not hold the Agent binary")
	}
	source := filepath.Join(record.PayloadPath, filepath.FromSlash(entry.Payload))
	data, err := os.ReadFile(source)
	if err != nil || len(data) == 0 {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback payload's Agent binary could not be read")
	}
	if hexDigest(data) != record.FromAgentSHA256 {
		return fail("UPDATE_BACKUP_MISMATCH", "the rollback payload's Agent binary does not match from_agent_sha256")
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return fail("UPDATE_REVERT_STAGE_FAILED", "the private work directory could not be created")
	}
	final := RevertExecPath(workDir, record.OperationID)
	part := final + ".part"
	if err := os.WriteFile(part, data, 0700); err != nil {
		return fail("UPDATE_REVERT_STAGE_FAILED", "the old package could not be staged for the revert unit")
	}
	if err := os.Rename(part, final); err != nil {
		_ = os.Remove(part)
		return fail("UPDATE_REVERT_STAGE_FAILED", "the staged old package could not be published")
	}
	return nil
}

func snapshotAgent(manifest install.SnapshotManifest) (install.SnapshotEntry, bool) {
	for _, entry := range manifest.Files {
		if entry.Target == node.AgentBinaryPath {
			return entry, true
		}
	}
	return install.SnapshotEntry{}, false
}

// RollbackStore is the rollback-store half of the health-gated finalize
// (node.UpgradeConfirmer). It confirms one staged record and releases older
// confirmed generations to the N-1 GC.
type RollbackStore struct {
	BackupRoot string
	WorkDir    string
	// Root is the installed-system root used to refresh the next upgrade's
	// durable rollback snapshot after a confirmed readback. Production is "/".
	// Empty disables the refresh (fixture stores that do not own a host tree).
	Root string
}

// NewRollbackStore wires the production store paths.
func NewRollbackStore() *RollbackStore {
	return &RollbackStore{BackupRoot: DefaultBackupRoot, WorkDir: DefaultWorkDir, Root: "/"}
}

// ConfirmVersion implements node.UpgradeConfirmer exactly as the Task 3
// contract froze it. The target/digest anchors are checked FIRST, before the
// idempotent confirmed short-circuit: a readback that names another release or
// another package must never "confirm" (and GC) a record merely because that
// record is already confirmed. Then an already-confirmed record is an
// idempotent success BEFORE the staged-only rule (otherwise every later
// accepted readback of the same operation would log UPDATE_CONFIRM_FAILED
// forever); a failed record is refused; and the N-1 GC runs after the confirm
// write, never before it. A successful revert also blocks confirmation, because
// its stale install result must never release the pointer the revert depends
// on.
//
// The record write itself is backup.Confirm (the neutral package), which keeps
// the same order and the same re-verification of the payload before the write.
// GC and the durable-source refresh stay here: they are this package's timing
// contract, not the record layer's.
func (s *RollbackStore) ConfirmVersion(_ context.Context, operationID, targetVersion, agentSHA256 string) error {
	if !opIDRE.MatchString(operationID) {
		return fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	}
	if !targetRE.MatchString(targetVersion) || !digestRE.MatchString(agentSHA256) {
		return fail("UPDATE_BACKUP_MISMATCH", "the readback anchors are not a release and a digest")
	}
	if s == nil {
		return fail("UPDATE_CONFIRM_UNAVAILABLE", "no rollback store is configured")
	}
	root := backupRootOf(s.BackupRoot)
	if _, err := os.Lstat(RevertResultPath(s.WorkDir, operationID)); err == nil {
		return fail("UPDATE_CONFIRM_REFUSED", "the operation was reverted; its rollback record is never confirmed")
	}
	// backup.Confirm re-reads the record, checks the anchors before the
	// confirmed short-circuit, refuses a non-staged record, re-verifies the
	// payload and only then writes the confirmed state.
	if _, err := backup.Confirm(root, operationID, targetVersion, agentSHA256, backup.LayoutPerOp, time.Now().UTC()); err != nil {
		return err
	}
	s.refreshSource(agentSHA256)
	return s.gc(root)
}

// refreshSource refreshes the durable rollback source of the NEXT upgrade from
// the accepted readback's live state. It is best effort by design: the
// confirmation is already written and must not be undone by a snapshot error;
// the next accepted readback retries the refresh through the idempotent path,
// and the previous snapshot stays usable until then.
func (s *RollbackStore) refreshSource(agentSHA256 string) {
	if s.Root == "" {
		return
	}
	if current, ok := install.UpgradeSourceAgentSHA(s.Root); ok && current == agentSHA256 {
		return
	}
	_ = install.RefreshUpgradeSource(s.Root)
}

func (s *RollbackStore) gc(root string) error {
	_, err := GCBackups(root, backupKeepConfirmed)
	return err
}

var _ node.UpgradeConfirmer = (*RollbackStore)(nil)
var _ node.UpgradeReverter = (*Reverter)(nil)
