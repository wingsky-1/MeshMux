package rootexec

// The restore executor of #11d Task 7 (spec §5.7, D2).
//
// This process is the OLD staged package: the dispatcher starts
// <data-dir>/upgrade/meshmuxd-<from_version>-<arch> from a root-only exec copy
// with the frozen restore argv, or root starts the same package directly from a
// console. Using the binary of the database's own generation is what makes the
// restore safe: a new binary opening an old copy is exactly the migration trap
// §5.7 avoids.
//
// The order is fixed. Every read-only check and the complete new data directory
// are proven BEFORE the Web stops:
//
//	argv → self digest → journal state → no queued request → per-op record
//	→ payload digest → old package digest → web unit shape → drop-in body
//	→ space → copy payload + integrity + raw identity → carried trees → chown
//
// Only then:
//
//	stop web → swap old binary → four pins back to from_* (+ agent.json)
//	→ delete the crash claim → write 10-data-dir.conf → daemon-reload
//	→ start web → poll /healthz (60s) → read-only identity readback
//	→ result restored
//
// A failure before the stop changes nothing and writes no result. A failure
// after a write is a terminal partial receipt with a stable code and the Web
// left down; the original data directory is never modified. The journal and the
// database are never written here. The new Web's first reconcile pass writes
// hub-upgrade/restored.json (schema 1, operation_id, snapshot_at, lossy=true)
// and moves the journal to reverted, so the lossy fact is visible in /tasks.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	codeRestoreArgv          = "HUB_RESTORE_ARGV_INVALID"
	codeRestoreDigest        = hubupgrade.CodeRestoreDigestMismatch
	codeRestorePayload       = "HUB_RESTORE_PAYLOAD_MISMATCH"
	codeRestoreBinMissing    = hubupgrade.CodeRestoreBinaryMissing
	codeRestoreCarried       = "HUB_RESTORE_CARRIED_SOURCE"
	codeRestoreDropIn        = "HUB_RESTORE_DROPIN_FAILED"
	codeRestoreHealth        = "HUB_RESTORE_HEALTH_FAILED"
	codeRestoreIdentity      = "HUB_RESTORE_IDENTITY_MISMATCH"
	codeRestoreStop          = "HUB_RESTORE_STOP_FAILED"
	codeRestoreStart         = "HUB_RESTORE_START_FAILED"
	codeRestoreConfig        = versions.CodeConfigConflict
	codeRestorePin           = hubupgrade.CodeSharedBinaryRepinFailed
	codeRestoreState         = hubupgrade.CodeHandoffInvalidState
	codeRestoreBusy          = hubupgrade.CodeHandoffBusy
	restoreDataDirDropInName = "10-data-dir.conf"

	defaultProbeTimeout  = 60 * time.Second
	defaultProbeInterval = 500 * time.Millisecond
	restoreDirPrefix     = "restore-"
)

var restoreVersionRE = backup.ReleaseVersionPattern

// RestoreConfig is one restore run. Root is the fixture seam for the fixed
// installer paths; production leaves it "/". Owner is the Web account that owns
// the data directory (meshmux in production) and RootOwner owns the ledgers,
// agent.json, unit and claim (root in production).
type RestoreConfig struct {
	OperationID    string
	DataDir        string
	RestoreDir     string
	ExpectedSHA256 string
	Root           string
	ClaimDir       string

	Now   func() time.Time
	Probe func(ctx context.Context) error
	Space func(path string, need uint64) error

	Owner         int
	RootOwner     int
	ResultsDir    string
	RequestDir    string
	WebUnit       string
	ProbeTimeout  time.Duration
	ProbeInterval time.Duration
}

type restoreRun struct {
	cfg    RestoreConfig
	op     hubupgrade.Op
	record backup.Record
}

// RunRestore performs one lossy restore from the operation's verified per-op
// backup. It never selects another generation and never retries by itself.
// Contract:
//
//	input     the frozen restore argv (operation id, expected digest, data dir,
//	          restore dir) and the fixed command runner;
//	validate  argv shapes, self digest, journal state, absence of a queued
//	          request, the per-op record and payload digest, the old package
//	          digest, the web unit shape and the drop-in body;
//	assemble  the complete new data directory (payload + integrity + identity +
//	          carried trees) before the Web stops;
//	effects   stop web -> swap the old binary -> restore the four pins -> write
//	          the --data-dir drop-in -> reload -> start -> health poll -> identity
//	          readback; the original data directory is never modified;
//	return    nil only when the restored release answers its own identity; a
//	          failure after the stop is a terminal partial receipt with a code.
func RunRestore(ctx context.Context, cfg RestoreConfig, runner node.CommandRunner) error {
	if err := normalizeRestoreConfig(&cfg); err != nil {
		return err
	}
	if err := validateRestoreArgv(cfg); err != nil {
		return err
	}
	if runner == nil {
		runner = node.ExecRunner{}
	}

	// Verify-then-exec, the trust discipline RAUC and Mender use for update
	// payloads: the dispatcher already hashed these bytes while copying them
	// into a root-only exec-<op>, and this check names the image that actually
	// runs. A self-check performed after exec cannot protect the exec itself,
	// which is why ACCEPTANCE makes the pre-exec `sha256sum -c` of the staged
	// old package mandatory for the console path.
	self, err := buildinfo.Digest()
	if err != nil {
		return fail(codeRestoreDigest, "the running executable digest is unavailable")
	}
	if self != cfg.ExpectedSHA256 {
		return fail(codeRestoreDigest, "the running executable is not the frozen old package")
	}

	op, found, err := hubupgrade.ReadOp(cfg.DataDir, cfg.OperationID, cfg.Owner)
	if err != nil {
		return fail(codeRestoreState, "the operation journal is not readable")
	}
	if !found || op.Kind != hubupgrade.KindUpdate {
		return fail(codeRestoreState, "the journal has no update operation with this id")
	}
	switch op.State {
	case hubupgrade.StateFailed, hubupgrade.StatePartial, hubupgrade.StateVerifying:
	default:
		// The ruling of plan §7: restore is legal only after the operation is
		// already terminal-or-verifying; a live handoff owns the host.
		return fail(codeRestoreBusy, "the operation is not failed, partial or verifying")
	}
	if op.FromVersion == "" || !restoreVersionRE.MatchString(op.FromVersion) {
		return fail(codeRestoreState, "the journal from-version is not a release")
	}
	if op.OperationID != cfg.OperationID {
		return fail(codeRestoreState, "the journal names another operation")
	}

	if err := restoreNoRequestQueued(cfg.RequestDir); err != nil {
		return err
	}
	// A carried record is an existence-only diagnostic after a restore, never a
	// source for the next restore (spec §5.7). The marker is Web-written, so the
	// root executor names the meshmux account rather than assuming its own euid.
	// The refusal is op-scoped: a fresh operation in a restored data directory
	// must still be recoverable when the Web is down and its next reconcile pass
	// (which would clear the marker) never runs. Carried records of other
	// operations are already unusable because their payload_path names the old
	// data directory.
	if marker, ok, err := hubupgrade.ReadRestoredMarkerFor(cfg.DataDir, cfg.Owner); err != nil {
		return err
	} else if ok && marker.OperationID == op.OperationID {
		return fail(codeRestoreCarried, "this operation was already restored; its carried record is not a restore source")
	}

	record, err := readRestoreRecord(cfg, op)
	if err != nil {
		return err
	}
	payloadPath := filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir, op.OperationID, backup.PayloadDir, backup.SingleDBName)
	payloadSHA, err := digestRegularFile(payloadPath, maxPayloadBytes)
	if err != nil || payloadSHA != record.PayloadSHA256 {
		return fail(codeRestorePayload, "the staged database copy does not match the frozen payload digest")
	}

	oldPackage, err := restoreOldPackagePath(cfg, record)
	if err != nil {
		return err
	}
	argv, err := webExecArgv(rootedPath(cfg.Root, cfg.WebUnit), cfg.RootOwner)
	if err != nil {
		return err
	}
	if currentDir, err := hubupgrade.DataDirFromArgv(argv); err != nil || filepath.Clean(currentDir) != filepath.Clean(cfg.DataDir) {
		return fail(codeRestoreConfig, "the web unit does not serve the journal's data directory")
	}
	dropInBody, err := hubupgrade.RenderDataDirDropIn(argv, cfg.RestoreDir)
	if err != nil {
		return err
	}

	oldPins, err := restorePins(cfg.Root, cfg.RootOwner, record)
	if err != nil {
		return err
	}
	if err := validatePinSet(oldPins); err != nil {
		return err
	}
	if cfg.Probe == nil {
		cfg.Probe = probeWebHealth(argv)
	}

	info, err := os.Lstat(payloadPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 {
		return fail(codeRestorePayload, "the staged database copy is not a regular file")
	}
	if err := cfg.Space(cfg.DataDir, hubupgrade.Floor(uint64(info.Size()))); err != nil {
		return err
	}

	// Everything below this point is still pre-stop. The complete new data
	// directory is built and proven before the Web may be stopped.
	if err := prepareRestoreDir(cfg, record); err != nil {
		_ = os.RemoveAll(cfg.RestoreDir)
		return err
	}

	run := &restoreRun{cfg: cfg, op: op, record: record}

	if _, err := runner.Run(ctx, "systemctl", "stop", webUnit); err != nil {
		// The Web is still running; nothing changed. No result: this is a
		// pre-stop refusal.
		_ = os.RemoveAll(cfg.RestoreDir)
		return fail(codeRestoreStop, "the Web service could not be stopped; no change was made")
	}

	if err := installBinary(oldPackage, record.FromAgentSHA256, rootedPath(cfg.Root, node.AgentBinaryPath)); err != nil {
		return run.partial(codeRestoreBinMissing, err)
	}
	if err := writePins(cfg.Root, oldPins, oldPins); err != nil {
		return run.partial(codeRestorePin, err)
	}
	// The pins are provably old again, so a swapping claim is inert; removing it
	// is still the last act of the swap section (a failed unlink is debris).
	_ = hubupgrade.RemoveClaim(cfg.ClaimDir)
	if oldPins.HasLine() {
		// Same observability limit as Task 6: a skipped restart when the Line
		// unit is inactive is visible only in this process's log.
		if err := restartLineIfActive(ctx, runner); err != nil {
			return run.partial(codeRestorePin, err)
		}
	}

	if err := writeRestoreDropIn(cfg, dropInBody); err != nil {
		return run.partial(codeRestoreDropIn, err)
	}
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return run.partial(codeRestoreDropIn, err)
	}
	if _, err := runner.Run(ctx, "systemctl", "start", webUnit); err != nil {
		return run.partial(codeRestoreStart, err)
	}
	if err := run.waitHealthy(ctx); err != nil {
		return run.partial(codeRestoreHealth, err)
	}
	if err := verifyRestoredIdentity(filepath.Join(cfg.RestoreDir, backup.SingleDBName), record); err != nil {
		return run.partial(codeRestoreIdentity, err)
	}

	_, err = hubupgrade.WriteResult(cfg.ResultsDir, hubupgrade.Result{
		Schema: hubupgrade.ResultSchema, OperationID: op.OperationID,
		Phase: hubupgrade.ResultRestored, TargetVersion: record.TargetVersion,
		PackageSHA256: record.PackageSHA256, UpdatedAt: cfg.Now().UTC(),
	})
	return err
}

func normalizeRestoreConfig(cfg *RestoreConfig) error {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	if !filepath.IsAbs(cfg.Root) {
		return fail(codeRestoreArgv, "the installer root is not absolute")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Space == nil {
		cfg.Space = hubupgrade.CheckFreeSpace
	}
	if cfg.ClaimDir == "" {
		cfg.ClaimDir = rootedPath(cfg.Root, hubupgrade.ClaimDir)
	}
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = rootedPath(cfg.Root, hubupgrade.ResultsDir)
	}
	if cfg.RequestDir == "" {
		cfg.RequestDir = hubupgrade.RequestDir
	}
	if cfg.WebUnit == "" {
		cfg.WebUnit = DefaultWebUnit
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = defaultProbeTimeout
	}
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = defaultProbeInterval
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

func validateRestoreArgv(cfg RestoreConfig) error {
	switch {
	case !ledgerDigestRE.MatchString(cfg.ExpectedSHA256):
		return fail(codeRestoreArgv, "the expected digest is not SHA-256 hex")
	case !dispatchOpIDRE.MatchString(cfg.OperationID):
		return fail(codeRestoreArgv, "the operation id is not 32 lowercase hex")
	case cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) || filepath.Clean(cfg.DataDir) != cfg.DataDir:
		return fail(codeRestoreArgv, "the data directory is not a clean absolute path")
	case cfg.RestoreDir == "" || !filepath.IsAbs(cfg.RestoreDir) || filepath.Clean(cfg.RestoreDir) != cfg.RestoreDir:
		return fail(codeRestoreArgv, "the restore directory is not a clean absolute path")
	case filepath.Dir(cfg.RestoreDir) != cfg.DataDir:
		return fail(codeRestoreArgv, "the restore directory is not a child of the data directory")
	case !strings.HasPrefix(filepath.Base(cfg.RestoreDir), restoreDirPrefix+cfg.OperationID+"-"):
		return fail(codeRestoreArgv, "the restore directory is not named restore-<operation>-<unix>")
	}
	return nil
}

// restoreNoRequestQueued is the "no request file" half of the restore ruling:
// a queued handoff still owns the host, and the dispatcher is the only writer
// that may consume it.
func restoreNoRequestQueued(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fail(codeRestoreBusy, "the request directory could not be read")
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			return fail(codeRestoreBusy, "a request is still queued")
		}
	}
	return nil
}

// readRestoreRecord reads exactly this operation's per-op record. It never scans
// the store and never reads the flat existence-only pointer.
func readRestoreRecord(cfg RestoreConfig, op hubupgrade.Op) (backup.Record, error) {
	root := filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir)
	record, err := backup.Read(root, op.OperationID, cfg.Owner)
	if err != nil {
		return backup.Record{}, err
	}
	if record.State != backup.StateStaged && record.State != backup.StateConfirmed {
		return backup.Record{}, fail(backup.CodeMismatch, "the restore source record is not staged or confirmed")
	}
	if !record.IntegrityOK || record.PayloadFiles < 1 || !ledgerDigestRE.MatchString(record.PayloadSHA256) {
		return backup.Record{}, fail(backup.CodeMismatch, "the restore source record does not prove an integrity-checked copy")
	}
	if !ledgerDigestRE.MatchString(record.FromAgentSHA256) || !ledgerDigestRE.MatchString(record.FromPackageSHA256) {
		return backup.Record{}, fail(codeUpdateIdentity, "the restore source record has no complete from-* identity")
	}
	if record.OperationID != op.OperationID || record.FromVersion != op.FromVersion ||
		record.DBSchema != op.DBSchema {
		return backup.Record{}, fail(backup.CodeMismatch, "the restore record and the journal name different operations")
	}
	expectedPayload := filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir, op.OperationID, backup.PayloadDir)
	if record.PayloadPath == "" || filepath.Clean(record.PayloadPath) != expectedPayload {
		return backup.Record{}, fail(backup.CodeMismatch, "the restore record payload path is not this operation's copy")
	}
	return record, nil
}

// restoreOldPackagePath proves the staged old package is the bytes the record
// froze. A missing or foreign package is refused before the stop; otherwise a
// restore would discover it has nothing to boot only after killing the Web.
func restoreOldPackagePath(cfg RestoreConfig, record backup.Record) (string, error) {
	name, err := hubupgrade.OldPackageName(record.FromVersion, runtime.GOARCH)
	if err != nil {
		return "", fail(codeRestoreBinMissing, "the staged old package name is invalid")
	}
	path := filepath.Join(cfg.DataDir, hubupgrade.UpgradeDir, name)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0022 != 0 || !statOwnedBy(info, cfg.Owner) ||
		info.Size() < 1 || info.Size() > maxBinaryBytes {
		return "", fail(codeRestoreBinMissing, "the staged old package is not a private Web-owned regular file")
	}
	digest, err := digestBinaryFile(path)
	if err != nil || digest != record.FromAgentSHA256 {
		return "", fail(codeRestoreBinMissing, "the staged old package does not match the frozen from_agent digest")
	}
	return path, nil
}

// restorePins derives the complete old pin set from the record. It is not
// readPins: a failed upgrade may leave pins in any half-moved shape, and restore
// must be able to force every one of them back to from_* without first agreeing
// with the current bytes.
func restorePins(root string, expectedOwner int, record backup.Record) (Pins, error) {
	pins := Pins{HubSharedSHA: record.FromAgentSHA256, HubManagedSHA: record.FromPackageSHA256}
	linePath := rootedPath(root, lineLedgerFilePath)
	_, hasLine, err := install.ReadLocalLineState(root)
	if err != nil {
		return Pins{}, fail(codePrecheck, "the co-located Line ledger is not readable")
	}
	if !hasLine {
		return pins, nil
	}
	if err := requireOwnedFile(linePath, expectedOwner); err != nil {
		return Pins{}, err
	}
	agentCfg, _, err := readAgentConfig(rootedPath(root, node.AgentConfigPath), expectedOwner)
	if err != nil {
		return Pins{}, err
	}
	agentCfg.AgentVersion, agentCfg.AgentSHA256 = record.FromVersion, record.FromAgentSHA256
	agentBody, err := renderAgentConfig(agentCfg)
	if err != nil {
		return Pins{}, err
	}
	pins.LineSharedSHA = record.FromAgentSHA256
	pins.LineAgentVersion = record.FromVersion
	pins.LineAgentSHA = record.FromAgentSHA256
	pins.AgentJSONVersion = record.FromVersion
	pins.AgentJSONSHA = record.FromAgentSHA256
	pins.LineAgentManagedSHA = sha256Of(agentBody)
	return pins, nil
}

// prepareRestoreDir builds the complete new data directory before the stop:
// 0700 root, the restored database copy, carried database-backup/ and
// hub-upgrade/ trees, integrity, raw identity and meshmux ownership.
func prepareRestoreDir(cfg RestoreConfig, record backup.Record) error {
	if _, err := os.Lstat(cfg.RestoreDir); err == nil {
		return fail(codeRestoreArgv, "the restore directory already exists")
	} else if !os.IsNotExist(err) {
		return fail(codeRestoreArgv, "the restore directory could not be inspected")
	}
	if err := os.Mkdir(cfg.RestoreDir, 0700); err != nil {
		return fail(codeRestoreArgv, "the restore directory could not be created")
	}
	if err := os.Chmod(cfg.RestoreDir, 0700); err != nil {
		return fail(codeRestoreArgv, "the restore directory could not be made private")
	}
	source := filepath.Join(cfg.DataDir, hubupgrade.DatabaseBackupDir, record.OperationID, backup.PayloadDir, backup.SingleDBName)
	target := filepath.Join(cfg.RestoreDir, backup.SingleDBName)
	if err := copyRegularFile(source, target, 0600); err != nil {
		return fail(backup.CodeMismatch, "the database copy could not be written")
	}
	if err := checkRestoreCopy(target, record); err != nil {
		return err
	}
	for _, name := range []string{hubupgrade.DatabaseBackupDir, hubupgrade.HubUpgradeDir} {
		from := filepath.Join(cfg.DataDir, name)
		to := filepath.Join(cfg.RestoreDir, name)
		if err := copyTree(from, to); err != nil {
			return fail(codeRestoreArgv, "the carried "+name+" tree could not be copied")
		}
	}
	uid, gid := restoreOwner(cfg)
	if err := chownTree(cfg.RestoreDir, uid, gid); err != nil {
		return fail(codeRestoreArgv, "the restore directory could not be handed to the Web account")
	}
	return nil
}

// restoreOwner resolves the account the new data directory must belong to. A
// missing meshmux account means a fixture or a broken host; the configured
// Web owner and the current effective group are then the only defensible
// values and chown is a no-op for a same-uid run.
func restoreOwner(cfg RestoreConfig) (int, int) {
	if os.Geteuid() != 0 {
		// A non-root fixture cannot chown to another account; the configured
		// owner is already the account that owns the copy.
		return cfg.Owner, os.Getegid()
	}
	account, err := user.Lookup("meshmux")
	if err == nil {
		uid, uidErr := strconv.Atoi(account.Uid)
		gid, gidErr := strconv.Atoi(account.Gid)
		if uidErr == nil && gidErr == nil {
			return uid, gid
		}
	}
	return cfg.Owner, os.Getegid()
}

// checkRestoreCopy runs integrity_check on the copy, then reads the copy's own
// user_version and database_versions row through the raw immutable connection,
// comparing them with the record's from_version/db_schema. A foreign schema is
// CONFIG_CONFLICT before the stop, never a guess after it.
func checkRestoreCopy(path string, record backup.Record) error {
	identity, err := readDatabaseIdentity(path)
	if err != nil {
		return fail(codeRestoreConfig, "the database copy is not a readable SQLite database")
	}
	if identity.UserVersion != record.DBSchema {
		return fail(codeRestoreConfig, "the database copy's schema does not match the frozen record")
	}
	if !identity.HasVersionRow {
		return fail(codeRestoreConfig, "the database copy has no last-known-good version row")
	}
	if identity.LastGoodVersion != record.FromVersion || identity.LastGoodSchema != record.DBSchema {
		return fail(codeRestoreConfig, "the database copy does not belong to the record's from-version")
	}
	return nil
}

type databaseIdentity struct {
	UserVersion     int64
	LastGoodVersion string
	LastGoodSchema  int64
	HasVersionRow   bool
}

// readDatabaseIdentity opens mode=ro&immutable=1: no store-open, no migration,
// no write. The same function proves the copy before the stop and the restored
// file after the health check.
func readDatabaseIdentity(path string) (databaseIdentity, error) {
	var identity databaseIdentity
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 {
		return identity, errors.New("the database copy is not a regular file")
	}
	u := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro&immutable=1")
	if err != nil {
		return identity, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return identity, errors.New("the database copy did not pass integrity_check")
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&identity.UserVersion); err != nil {
		return identity, err
	}
	row := db.QueryRowContext(ctx, `SELECT last_good_version, last_good_schema FROM database_versions WHERE id=1`)
	switch err := row.Scan(&identity.LastGoodVersion, &identity.LastGoodSchema); {
	case err == nil:
		identity.HasVersionRow = true
	case errors.Is(err, sql.ErrNoRows):
		identity.HasVersionRow = false
	default:
		return identity, err
	}
	return identity, nil
}

func verifyRestoredIdentity(path string, record backup.Record) error {
	identity, err := readDatabaseIdentity(path)
	if err != nil {
		return fail(codeRestoreIdentity, "the restored database is not readable")
	}
	if identity.UserVersion != record.DBSchema || !identity.HasVersionRow ||
		identity.LastGoodVersion != record.FromVersion || identity.LastGoodSchema != record.DBSchema {
		return fail(codeRestoreIdentity, "the restored database does not match the frozen identity")
	}
	return nil
}

func (r *restoreRun) partial(code string, cause error) error {
	_, _ = hubupgrade.WriteResult(r.cfg.ResultsDir, hubupgrade.Result{
		Schema: hubupgrade.ResultSchema, OperationID: r.op.OperationID,
		Phase: hubupgrade.ResultPartial, ErrorCode: code,
		TargetVersion: r.record.TargetVersion, PackageSHA256: r.record.PackageSHA256,
		UpdatedAt: r.cfg.Now().UTC(),
	})
	return fail(code, "the restore failed after a write and is partial: "+cause.Error())
}

// waitHealthy polls the injected probe inside the 60s budget. The probe proves
// /healthz 200 (SELECT 1) only; identity is verified separately through the
// immutable connection.
func (r *restoreRun) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(r.cfg.ProbeTimeout)
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := r.cfg.Probe(probeCtx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fail(codeRestoreHealth, "the restored Web did not answer /healthz within the budget")
		}
		select {
		case <-ctx.Done():
			return fail(codeRestoreHealth, "the restore was cancelled before /healthz answered")
		case <-time.After(r.cfg.ProbeInterval):
		}
	}
}

// writeRestoreDropIn publishes the one drop-in that flips --data-dir. The write
// is atomic; the directory is the root-owned Web drop-in tree the dispatcher
// already reads.
func writeRestoreDropIn(cfg RestoreConfig, body string) error {
	dir := rootedPath(cfg.Root, cfg.WebUnit) + ".d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fail(codeRestoreDropIn, "the web drop-in directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm()&0022 != 0 || !statOwnedBy(info, cfg.RootOwner) {
		return fail(codeRestoreDropIn, "the web drop-in directory is not root-owned and private")
	}
	target := filepath.Join(dir, restoreDataDirDropInName)
	part := target + ".part"
	_ = os.Remove(part)
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fail(codeRestoreDropIn, "the web drop-in could not be written")
	}
	_, writeErr := file.WriteString(body)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(part)
		return fail(codeRestoreDropIn, "the web drop-in could not be flushed")
	}
	if err := os.Rename(part, target); err != nil {
		_ = os.Remove(part)
		return fail(codeRestoreDropIn, "the web drop-in could not be published")
	}
	if err := syncDirEntry(dir); err != nil {
		return fail(codeRestoreDropIn, "the web drop-in directory could not be flushed")
	}
	return nil
}

// copyRegularFile copies one regular file within a size bound, fsyncs it and
// sets the exact mode. The source must not be a symlink.
func copyRegularFile(source, target string, mode os.FileMode) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maxPayloadBytes {
		return errors.New("the source is not a bounded regular file")
	}
	in, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = out.Close()
		_ = os.Remove(target)
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, maxPayloadBytes+1))
	if copyErr != nil || n < 1 || n > maxPayloadBytes {
		cleanup()
		return errors.New("the copy did not complete within its bound")
	}
	if err := out.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := out.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(target)
		return err
	}
	return syncDirEntry(filepath.Dir(target))
}

// copyTree copies a directory of regular files and directories. A symlink is
// refused rather than followed: the carried journal/backup tree is Web-written
// and must never redirect a root restore outside the new data directory.
func copyTree(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("the source tree is not a real directory")
	}
	if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chmod(target, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		from := filepath.Join(source, entry.Name())
		to := filepath.Join(target, entry.Name())
		entryInfo, err := os.Lstat(from)
		if err != nil {
			return err
		}
		switch {
		case entryInfo.Mode()&os.ModeSymlink != 0:
			return errors.New("the carried tree contains a symlink")
		case entryInfo.IsDir():
			if err := copyTree(from, to); err != nil {
				return err
			}
		case entryInfo.Mode().IsRegular():
			if entryInfo.Size() > maxPayloadBytes {
				return errors.New("a carried file is larger than the bound")
			}
			if err := copyRegularFile(from, to, entryInfo.Mode().Perm()); err != nil {
				return err
			}
		default:
			return errors.New("the carried tree contains a special file")
		}
	}
	return syncDirEntry(target)
}

// chownTree hands the complete new tree to the Web account; a restore directory
// the Web cannot open is not a restore.
func chownTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("the restore tree contains a symlink")
		}
		return os.Chown(path, uid, gid)
	})
}

// probeWebHealth is the production /healthz probe. The listen address comes
// from the effective Web argv; the restore never assumes a port.
func probeWebHealth(argv []string) func(context.Context) error {
	return func(ctx context.Context) error {
		address, err := flagValue(argv, "--listen")
		if err != nil || address == "" {
			address = versions.WebListenAddress()
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/healthz", nil)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 2 * time.Second}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return errors.New("the restored Web is not healthy")
		}
		return nil
	}
}

// flagValue reads one exact --name or --name=value argument.
func flagValue(argv []string, name string) (string, error) {
	value, found := "", false
	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == name:
			if i+1 >= len(argv) {
				return "", errors.New("the flag has no value")
			}
			value, found = argv[i+1], true
			i++
		case strings.HasPrefix(argv[i], name+"="):
			value, found = strings.TrimPrefix(argv[i], name+"="), true
		}
	}
	if !found {
		return "", errors.New("the flag is absent")
	}
	return value, nil
}
