package rootexec

// The update executor of #11d Task 6 (spec §5.6).
//
// This process is the staged target package, started by the dispatcher from a
// root-only exec copy with the fixed argv pinned by TestDispatchArgvPinned. It
// is the only process allowed to change the running Hub binary and the four
// Line/Hub pins, and it is deliberately dull: every fact is re-read from the
// frozen journal, record and root manifest, every check happens before the
// first system write, and the crash claim is on disk before the rename.
//
//	argv shape → self digest → version binding → journal/record/manifest
//	→ Line four-pin precheck → database pre-flight → claim(swapping)
//	→ result accepted → result swapping → binary.new+rename+fsync
//	→ four-pin write (all staged, all renamed) → Line restart (if active)
//	→ claim(repinned) → delete claim → result restarting
//	→ restart meshmux-web → result restart-accepted
//
// Any failure after the first system write rolls the binary back from the old
// staged package and restores the complete old pin set; a rollback that cannot
// finish writes partial, never a clean failure. The journal and the database
// are never written here.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	codeUpdateArgv     = "HUB_UPDATE_ARGV_INVALID"
	codeUpdateVersion  = "HUB_UPDATE_VERSION_MISMATCH"
	codeUpdateState    = "HUB_UPDATE_STATE_INVALID"
	codePrecheck       = "HUB_SHARED_BINARY_PRECHECK_FAILED"
	codePreflight      = "HUB_UPDATE_PREFLIGHT_FAILED"
	codeRepinFailed    = hubupgrade.CodeSharedBinaryRepinFailed
	codeWebRestart     = "HUB_UPGRADE_RESTART_FAILED"
	codeUpdateIdentity = hubupgrade.CodeBackupIdentityMissing

	lineUnit        = node.AgentUnit
	webUnit         = versions.WebUnitName
	maxBinaryBytes  = buildinfo.MaxExecutableBytes
	maxPayloadBytes = 4 << 30
)

var updateVersionRE = backup.ReleaseVersionPattern

// UpdateConfig is one executor run. Root is the fixture seam for the fixed
// /var/lib/meshmux-installer and /etc/meshmux paths; production leaves it "/".
// Owner is the Web account that owns the record/journal (meshmux in production);
// RootOwner is the account that owns the ledgers, agent.json and claim (root).
type UpdateConfig struct {
	Target         string
	ExpectedSHA256 string
	OperationID    string
	DataDir        string
	FromVersion    string
	Root           string
	ClaimDir       string

	Now          func() time.Time
	CheckVersion func() string
	Preflight    func(copyPath string, wantSchema int64) error

	Owner       int
	RootOwner   int
	ResultsDir  string
	ExecRoot    string
	ManifestDir string

	// BeforeSwap is a test seam observed after the claim and the swapping
	// result exist and immediately before the binary rename. Production leaves
	// it nil.
	BeforeSwap func()
}

type updateRun struct {
	cfg    UpdateConfig
	op     hubupgrade.Op
	record backup.Record
	old    Pins
}

// RunUpdate performs one staged target update. All configuration checks finish
// before any write; a failure after the claim exists is rolled back or reported
// partial.
// Contract:
//
//	input     the frozen dispatch argv (target, expected digest, operation id,
//	          data dir, from version) and the fixed command runner;
//	validate  argv shapes, self digest, version binding, journal/record/manifest
//	          agreement, the Line four-pin precheck and the database pre-flight;
//	assemble  the new binary scratch plus the complete old pin set;
//	effects   claim(swapping) -> result accepted/swapping -> rename -> re-pin ->
//	          restart; any post-write failure rolls back from the old package;
//	return    nil only when the new binary is running and its pins are written;
//	          otherwise a stable HUB_* code with a partial receipt when a write
//	          already happened.
func RunUpdate(ctx context.Context, cfg UpdateConfig, runner node.CommandRunner) error {
	if err := normalizeUpdateConfig(&cfg); err != nil {
		return err
	}
	if err := validateUpdateArgv(cfg); err != nil {
		return err
	}
	if runner == nil {
		runner = node.ExecRunner{}
	}

	self, err := buildinfo.Digest()
	if err != nil {
		return fail(codeDigestMismatch, "the running executable digest is unavailable")
	}
	if self != cfg.ExpectedSHA256 {
		return fail(codeDigestMismatch, "the running executable is not the frozen target package")
	}
	if cfg.CheckVersion() != cfg.Target {
		return fail(codeUpdateVersion, "the running build does not report the requested target version")
	}

	op, record, err := readUpdateInputs(cfg)
	if err != nil {
		return err
	}
	if err := checkUpdateIdentity(cfg, op, record); err != nil {
		return err
	}
	installedSHA, err := digestBinaryFile(rootedPath(cfg.Root, node.AgentBinaryPath))
	if err != nil {
		return fail(codePrecheck, "the installed MeshMux binary digest is unavailable")
	}
	if installedSHA != record.FromAgentSHA256 {
		return fail(codePrecheck, "the installed binary is not the frozen rollback source")
	}
	oldPins, err := readPins(cfg.Root, cfg.RootOwner, record.FromVersion, installedSHA)
	if err != nil {
		return err
	}
	if oldPins.HubManagedSHA != record.FromPackageSHA256 {
		return fail(codePrecheck, "the Hub ledger managed-file pin differs from the frozen package digest")
	}

	copyPath := filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir, op.OperationID, backup.PayloadDir, backup.SingleDBName)
	// The plan's "digest was verified earlier" is not true inside T6: the
	// dispatcher verified the target PACKAGE, not this payload. Prove the
	// record's own readback and the exact copy bytes before the pre-flight
	// opens them; otherwise a swapped payload would only fail later.
	if !record.IntegrityOK || record.PayloadFiles != 1 || !ledgerDigestRE.MatchString(record.PayloadSHA256) {
		return fail(backup.CodeMismatch, "the frozen record does not prove the database copy")
	}
	payloadSHA, err := digestRegularFile(copyPath, maxPayloadBytes)
	if err != nil || payloadSHA != record.PayloadSHA256 {
		return fail(backup.CodeMismatch, "the staged database copy does not match the frozen payload digest")
	}
	if err := cfg.Preflight(copyPath, record.DBSchema); err != nil {
		return fail(codePreflight, "the staged database copy failed the pre-flight trial")
	}

	// Everything up to here is a pre-claim refusal: no result file is written,
	// so the dispatcher sees only the returned stable code and the operation id
	// it already owns. This is a plan-level observability gap for T7 docs.
	now := cfg.Now().UTC()
	nextPins, err := advancePins(cfg.Root, oldPins, cfg.Target, cfg.ExpectedSHA256)
	if err != nil {
		return err
	}
	claim := hubupgrade.Claim{
		Schema: hubupgrade.ClaimSchema, Phase: hubupgrade.ClaimPhaseSwapping,
		OperationID: op.OperationID, TargetVersion: record.TargetVersion, FromVersion: record.FromVersion,
		NewSHA256: cfg.ExpectedSHA256, OldPins: oldPins, CreatedAt: now,
	}
	if err := hubupgrade.WriteClaim(cfg.ClaimDir, claim); err != nil {
		return err
	}
	run := &updateRun{cfg: cfg, op: op, record: record, old: oldPins}

	if err := run.progress(hubupgrade.ResultAccepted, now); err != nil {
		_ = hubupgrade.RemoveClaim(cfg.ClaimDir)
		return err
	}
	if err := run.progress(hubupgrade.ResultSwapping, now); err != nil {
		_ = hubupgrade.RemoveClaim(cfg.ClaimDir)
		return err
	}

	if cfg.BeforeSwap != nil {
		cfg.BeforeSwap()
	}
	if err := swapInSelfBinaryAt(cfg.Root, cfg.ExpectedSHA256); err != nil {
		return run.fail(ctx, runner, codeRepinFailed, err)
	}
	if err := writePins(cfg.Root, nextPins, oldPins); err != nil {
		var repinned *repinError
		if errors.As(err, &repinned) && repinned.mutated {
			// The pin writer could not restore every file it had begun to
			// rename. Try once more before declaring the host partial.
			if secondErr := writePins(cfg.Root, oldPins, oldPins); secondErr != nil {
				// Keep the old binary next to the mixed pins when possible; the
				// receipt stays partial either way and the Web is not restarted.
				_ = restoreOldBinary(cfg, record)
				return run.partial(codeRepinFailed)
			}
		}
		return run.fail(ctx, runner, codeRepinFailed, err)
	}
	if oldPins.HasLine() {
		// Observability limit: the result schema has no free-form note field,
		// so "Line unit inactive, restart skipped" is visible only in this
		// process's log; the receipt cannot carry it (T7 docs).
		if err := restartLineIfActive(ctx, runner); err != nil {
			return run.fail(ctx, runner, codeRepinFailed, err)
		}
	}

	// The restarting result must exist before the claim disappears: a crash
	// after the claim unlink but before this write would leave a fully
	// re-pinned host with no claim and an `applying` journal, which ages to
	// ORPHANED instead of confirming. The claim stays swapping until here.
	if err := run.progress(hubupgrade.ResultRestarting, now); err != nil {
		return run.fail(ctx, runner, codeRepinFailed, err)
	}
	claim.Phase = hubupgrade.ClaimPhaseRepinned
	if err := hubupgrade.WriteClaim(cfg.ClaimDir, claim); err != nil {
		return run.fail(ctx, runner, codeRepinFailed, err)
	}
	// The claim is inert from here on; a failed unlink only leaves debris.
	_ = hubupgrade.RemoveClaim(cfg.ClaimDir)

	if _, err := runner.Run(ctx, "systemctl", "restart", webUnit); err != nil {
		return run.fail(ctx, runner, codeWebRestart, err)
	}
	// Best effort: the Web restart already happened, and the new process's
	// startup reconcile (or age bound) is the authority from now on.
	_ = run.progress(hubupgrade.ResultRestartAccepted, now)
	removeExecCopy(cfg)
	return nil
}

func normalizeUpdateConfig(cfg *UpdateConfig) error {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	if !filepath.IsAbs(cfg.Root) {
		return fail(codeUpdateArgv, "the installer root is not absolute")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CheckVersion == nil {
		cfg.CheckVersion = func() string { return buildinfo.Version }
	}
	if cfg.Preflight == nil {
		cfg.Preflight = PreflightDatabase
	}
	if cfg.ClaimDir == "" {
		cfg.ClaimDir = rootedPath(cfg.Root, hubupgrade.ClaimDir)
	}
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = rootedPath(cfg.Root, hubupgrade.ResultsDir)
	}
	if cfg.ExecRoot == "" {
		cfg.ExecRoot = rootedPath(cfg.Root, DefaultExecRoot)
	}
	if cfg.ManifestDir == "" {
		cfg.ManifestDir = rootedPath(cfg.Root, hubupgrade.RootManifestDir)
	}
	if cfg.Owner == 0 {
		owner, err := lookupAccountID("meshmux")
		if err != nil {
			owner = os.Geteuid()
		}
		cfg.Owner = owner
	}
	if cfg.RootOwner == 0 {
		cfg.RootOwner = os.Geteuid()
	}
	return nil
}

func validateUpdateArgv(cfg UpdateConfig) error {
	switch {
	case !updateVersionRE.MatchString(cfg.Target):
		return fail(codeUpdateArgv, "the target is not a SemVer release")
	case !ledgerDigestRE.MatchString(cfg.ExpectedSHA256):
		return fail(codeUpdateArgv, "the expected digest is not SHA-256 hex")
	case !dispatchOpIDRE.MatchString(cfg.OperationID):
		return fail(codeUpdateArgv, "the operation id is not 32 lowercase hex")
	case cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir):
		return fail(codeUpdateArgv, "the data directory is not absolute")
	case cfg.FromVersion == "" || strings.ContainsAny(cfg.FromVersion, "\x00\n\r/"):
		return fail(codeUpdateArgv, "the from-version is not a plain release")
	}
	return nil
}

// readUpdateInputs performs the strict, read-only half of step 3. It reads
// exactly this operation: the journal by id, the per-operation record by id and
// the root manifest for the named target. No directory listing is consulted.
func readUpdateInputs(cfg UpdateConfig) (hubupgrade.Op, backup.Record, error) {
	op, found, err := hubupgrade.ReadOp(cfg.DataDir, cfg.OperationID, cfg.Owner)
	if err != nil {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateState, "the operation journal is not readable")
	}
	if !found {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateState, "the journal has no such operation")
	}
	if op.Kind != hubupgrade.KindUpdate {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateState, "the operation is not an update")
	}
	if op.State != hubupgrade.StateQueued && op.State != hubupgrade.StateApplying {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateState, "the operation is not queued or applying")
	}
	if op.FromVersion != cfg.FromVersion {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateVersion, "the journal from-version does not name this argv")
	}
	if op.TargetVersion != cfg.Target {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateVersion, "the journal target does not name this argv")
	}
	if op.PackageSHA256 != cfg.ExpectedSHA256 {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateState, "the journal package digest does not name this argv")
	}
	record, err := backup.Read(filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir), cfg.OperationID, cfg.Owner)
	if err != nil {
		return hubupgrade.Op{}, backup.Record{}, fail(codeUpdateIdentity, "the per-operation backup record is not readable")
	}
	manifest, err := hubupgrade.ReadRootManifestFor(cfg.ManifestDir, cfg.Target, cfg.RootOwner)
	if err != nil {
		return hubupgrade.Op{}, backup.Record{}, err
	}
	if manifest.SHA256 != op.ManifestSHA256 || manifest.Package.SHA256 != op.PackageSHA256 {
		return hubupgrade.Op{}, backup.Record{}, fail(codeManifestMismatch, "the root manifest no longer names the frozen target")
	}
	return op, record, nil
}

func checkUpdateIdentity(cfg UpdateConfig, op hubupgrade.Op, record backup.Record) error {
	if record.State != backup.StateStaged {
		return fail(backup.CodeMismatch, "the update source record is not staged")
	}
	if record.OperationID != op.OperationID || record.FromVersion != op.FromVersion ||
		record.TargetVersion != op.TargetVersion || record.ManifestSHA256 != op.ManifestSHA256 ||
		record.PackageSHA256 != op.PackageSHA256 || record.DBSchema != op.DBSchema {
		return fail(backup.CodeMismatch, "the frozen record and the journal name different operations")
	}
	if !ledgerDigestRE.MatchString(record.FromAgentSHA256) || !ledgerDigestRE.MatchString(record.FromPackageSHA256) {
		return fail(codeUpdateIdentity, "the frozen record has no complete from-* identity")
	}
	expectedPayload := filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir, op.OperationID, backup.PayloadDir)
	if record.PayloadPath == "" || filepath.Clean(record.PayloadPath) != expectedPayload {
		return fail(backup.CodeMismatch, "the record payload path is not this operation's staged copy")
	}
	return nil
}

// advancePins derives the complete next pin set, including the Line ledger's
// managed_files digest of the agent.json bytes the re-pin will write. Leaving
// that field empty would make Pins self-inconsistent and force writePinSet to
// recompute a value the caller never validated.
func advancePins(root string, old Pins, target, newSHA string) (Pins, error) {
	next := Pins{HubSharedSHA: newSHA, HubManagedSHA: newSHA}
	if !old.HasLine() {
		return next, nil
	}
	next.LineSharedSHA = newSHA
	next.LineAgentVersion = target
	next.LineAgentSHA = newSHA
	next.AgentJSONVersion = target
	next.AgentJSONSHA = newSHA
	agentCfg, _, err := readAgentConfig(rootedPath(root, node.AgentConfigPath), os.Geteuid())
	if err != nil {
		return Pins{}, err
	}
	agentCfg.AgentVersion, agentCfg.AgentSHA256 = target, newSHA
	agentBody, err := renderAgentConfig(agentCfg)
	if err != nil {
		return Pins{}, err
	}
	next.LineAgentManagedSHA = sha256Of(agentBody)
	return next, nil
}

func (r *updateRun) progress(phase hubupgrade.ResultPhase, now time.Time) error {
	_, err := hubupgrade.WriteResult(r.cfg.ResultsDir, hubupgrade.Result{
		Schema: hubupgrade.ResultSchema, OperationID: r.op.OperationID,
		Phase: phase, TargetVersion: r.record.TargetVersion, PackageSHA256: r.record.PackageSHA256,
		UpdatedAt: now,
	})
	return err
}

func (r *updateRun) terminal(phase hubupgrade.ResultPhase, code string) {
	_, _ = hubupgrade.WriteResult(r.cfg.ResultsDir, hubupgrade.Result{
		Schema: hubupgrade.ResultSchema, OperationID: r.op.OperationID,
		Phase: phase, ErrorCode: code, TargetVersion: r.record.TargetVersion,
		PackageSHA256: r.record.PackageSHA256, UpdatedAt: r.cfg.Now().UTC(),
	})
}

// fail rolls the host back to the old binary and the complete old pin set. A
// clean rollback writes failed and removes the claim; an incomplete one writes
// partial and keeps the swapping claim, because the claim is removed only after
// both halves are provably old again.
func (r *updateRun) fail(ctx context.Context, runner node.CommandRunner, code string, cause error) error {
	if err := r.rollback(ctx, runner); err != nil {
		r.terminal(hubupgrade.ResultPartial, code)
		return fail(code, "the update failed and its rollback is incomplete: "+cause.Error())
	}
	r.terminal(hubupgrade.ResultFailed, code)
	return fail(code, cause.Error())
}

func (r *updateRun) partial(code string) error {
	r.terminal(hubupgrade.ResultPartial, code)
	return fail(code, "the pin set could not be restored; the host is partial")
}

func (r *updateRun) rollback(ctx context.Context, runner node.CommandRunner) error {
	var firstErr error
	if err := restoreOldBinary(r.cfg, r.record); err != nil {
		firstErr = err
	}
	if !pinsAlreadyOld(r.cfg.Root, r.old, r.record.FromVersion, r.record.FromAgentSHA256) {
		if err := writePins(r.cfg.Root, r.old, r.old); err != nil {
			var repinned *repinError
			// A staging failure reports mutated=false: the targets still hold
			// the old bytes, so the rollback of the pins is already complete.
			if !errors.As(err, &repinned) || repinned.mutated {
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	// A Line restart failure does not make the bytes or pins wrong; the next
	// Line start performs the same check. Try, never mask a byte failure.
	if r.old.HasLine() {
		_ = restartLineIfActive(ctx, runner)
	}
	// The claim is removed only after BOTH halves — binary and every pin — are
	// provably old again. An incomplete rollback keeps the swapping claim as the
	// boot anchor; the Web cannot delete it anyway (C22) and a failed unlink of
	// an inert claim is debris, not partial.
	if firstErr == nil {
		_ = hubupgrade.RemoveClaim(r.cfg.ClaimDir)
	}
	return firstErr
}

// pinsAlreadyOld is the byte-preserving rollback fast path: after a
// rename-failure restore the three files already equal the pre-write bytes, so
// rewriting them would only move Line updated_at and destroy the proof that the
// restore was complete. Any read/compare failure falls through to the real
// write.
func pinsAlreadyOld(root string, old Pins, fromVersion, oldSHA string) bool {
	got, err := readPins(root, os.Geteuid(), fromVersion, oldSHA)
	return err == nil && got == old
}

func restartLineIfActive(ctx context.Context, runner node.CommandRunner) error {
	out, err := runner.Run(ctx, "systemctl", "is-active", lineUnit)
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return nil
	}
	_, err = runner.Run(ctx, "systemctl", "restart", lineUnit)
	return err
}

func digestBinaryFile(path string) (string, error) {
	return digestRegularFile(path, maxBinaryBytes)
}

func digestRegularFile(path string, max int64) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max {
		return "", errors.New("the file is not a bounded regular file")
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(file, max+1))
	if err != nil || n > max {
		return "", errors.New("the file could not be read within its bound")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// swapInSelfBinaryAt writes this process's own bytes beside the installed
// binary, fsyncs, renames over it and fsyncs the directory (spec §5.6 step 5).
// The source is /proc/self/exe, never a path a Web process could replace.
func swapInSelfBinaryAt(root, expectedSHA string) error {
	return installBinary("/proc/self/exe", expectedSHA, rootedPath(root, node.AgentBinaryPath))
}

func installBinary(sourcePath, expectedSHA, targetPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fail(codeRepinFailed, "the new binary bytes are unavailable")
	}
	defer source.Close()
	return installBinaryFrom(source, expectedSHA, targetPath)
}

func installBinaryFrom(source io.Reader, expectedSHA, targetPath string) error {
	dir := filepath.Dir(targetPath)
	info, err := os.Lstat(targetPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fail(codeRepinFailed, "the installed binary is not a regular file")
	}
	scratch := targetPath + ".new"
	if err := os.Remove(scratch); err != nil && !os.IsNotExist(err) {
		return fail(codeRepinFailed, "the binary scratch path could not be cleared")
	}
	file, err := os.OpenFile(scratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return fail(codeRepinFailed, "the binary scratch file could not be created")
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(scratch)
	}
	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(source, maxBinaryBytes+1))
	if copyErr != nil || n < 1 || n > maxBinaryBytes {
		cleanup()
		return fail(codeRepinFailed, "the binary could not be copied within its bound")
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != expectedSHA {
		cleanup()
		return fail(codeRepinFailed, "the binary bytes do not match the frozen digest")
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return fail(codeRepinFailed, "the binary could not be flushed")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(scratch)
		return fail(codeRepinFailed, "the binary could not be closed")
	}
	if err := os.Chmod(scratch, 0755); err != nil {
		_ = os.Remove(scratch)
		return fail(codeRepinFailed, "the binary could not be made executable")
	}
	if err := os.Rename(scratch, targetPath); err != nil {
		_ = os.Remove(scratch)
		return fail(codeRepinFailed, "the binary could not be published")
	}
	if err := syncDirEntry(dir); err != nil {
		return fail(codeRepinFailed, "the binary directory could not be flushed")
	}
	return nil
}

func restoreOldBinary(cfg UpdateConfig, record backup.Record) error {
	name, err := hubupgrade.OldPackageName(record.FromVersion, runtime.GOARCH)
	if err != nil {
		return fail(codeRepinFailed, "the old package name is invalid")
	}
	sourcePath := filepath.Join(cfg.DataDir, hubupgrade.UpgradeDir, name)
	source, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(codeRepinFailed, "the staged old package is missing")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || !statOwnedBy(info, cfg.Owner) ||
		info.Size() < 1 || info.Size() > maxBinaryBytes {
		return fail(codeRepinFailed, "the staged old package is not a private Web-owned regular file")
	}
	return installBinaryFrom(source, record.FromAgentSHA256, rootedPath(cfg.Root, node.AgentBinaryPath))
}

func removeExecCopy(cfg UpdateConfig) {
	if cfg.ExecRoot == "" {
		return
	}
	_ = os.Remove(filepath.Join(cfg.ExecRoot, execCopyPrefix+cfg.OperationID))
}
