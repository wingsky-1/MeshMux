package handler

// The Hub backup producer surface of #11d (spec §5.2). It is one authenticated
// admin mutation on the existing boundary: one session, exact Origin, CSRF
// token, a bounded form, and an operation id on every receipt.
//
// The Web process owns the SQLite handle, so it supplies the four database
// callbacks while internal/hubupgrade owns the order and every file write. The
// receipt only claims "staged": it names the operation and the verified
// per-operation backup, never an applied upgrade. The irreversible approval bit
// is not read here: single flight is journal-only (R2), and Task 5 re-reads the
// bit before a destructive step.
import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/web/store"
)

// hubUpgradeReconcileInterval is the bounded reconcile period of the journal
// state machine (spec §5.5). The identity refresher has its own 30s bound; the
// two never share a snapshot, because one writes journal files and the other is
// read-only by construction.
const hubUpgradeReconcileInterval = 30 * time.Second

// hubBackupReceipt is the management receipt. OperationID is the upgrade
// operation the operator carries to apply and approve; on a refusal it is the
// request's tracing id and ErrorCode is the stable reason.
type hubBackupReceipt struct {
	OK          bool   `json:"ok"`
	Status      string `json:"status"`
	OperationID string `json:"operation_id,omitempty"`
	FromVersion string `json:"from_version,omitempty"`
	DBSchema    int64  `json:"db_schema,omitempty"`
	IntegrityOK bool   `json:"integrity_ok"`
	ErrorCode   string `json:"error_code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	NextAction  string `json:"next_action,omitempty"`
}

func (app *Server) tasksHubUpgradeBackup(w http.ResponseWriter, r *http.Request, _ session) {
	target := strings.TrimSpace(r.PostForm.Get("target_version"))
	if !isValidReleaseVersion(target) {
		app.event(r, "MANIFEST_UNAVAILABLE")
		app.writeJSON(w, http.StatusBadRequest, hubBackupReceipt{
			Status: "failed", ErrorCode: "MANIFEST_UNAVAILABLE", OperationID: operation(r),
			Detail:     "目标版本不是 SemVer 发行版。",
			NextAction: "请选择 root 已预置目标 manifest 的发行版后重试；本次没有写入任何备份。",
		})
		return
	}
	create := app.hubBackup
	if create == nil {
		create = hubupgrade.CreateBackup
	}
	receipt, err := create(r.Context(), hubupgrade.BackupConfig{
		DataDir:        app.store.Dir,
		Target:         target,
		ManifestDir:    hubupgrade.RootManifestDir,
		Vacuum:         app.store.VacuumDatabaseCopy,
		Integrity:      app.store.IntegrityCheckCopy,
		Schema:         app.store.LiveDatabaseSchemaVersion,
		Space:          hubupgrade.CheckFreeSpace,
		PublishPointer: hubupgrade.PublishFlatPointer,
		Log: func(code, operationID string) {
			// Allowlisted fields only: a stable code and the operation id. The
			// code is either HUB_BACKUP_POINTER_STALE (nothing new published) or
			// HUB_BACKUP_POINTER_UNFLUSHED (published but not fsynced).
			app.log.Info("web_event", "operation_id", operation(r), "backup_operation_id", operationID, "stage", "hub_backup", "error_code", code)
		},
	})
	if err != nil {
		code := store.ErrorCodeOf(err)
		app.event(r, code)
		app.writeJSON(w, hubBackupHTTPStatus(code), hubBackupReceipt{
			Status: "failed", ErrorCode: code, OperationID: operation(r),
			Detail:     "Hub 数据库备份未完成。",
			NextAction: hubBackupNextAction(code),
		})
		return
	}
	app.event(r, "HUB_UPGRADE_BACKUP_STAGED")
	app.writeJSON(w, http.StatusOK, hubBackupReceipt{
		OK: true, Status: receipt.Status, OperationID: receipt.OperationID,
		FromVersion: receipt.FromVersion, DBSchema: receipt.DBSchema, IntegrityOK: receipt.IntegrityOK,
	})
}

// hubBackupHTTPStatus maps the producer's stable codes onto the boundary status.
// The mapping is by code, never by message text.
func hubBackupHTTPStatus(code string) int {
	switch code {
	case "HUB_UPGRADE_BUSY", "MANIFEST_UNAVAILABLE", "HUB_SPACE_INSUFFICIENT", "HUB_BACKUP_STORE_UNSAFE":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func hubBackupNextAction(code string) string {
	switch code {
	case "HUB_UPGRADE_BUSY":
		return "已有未完成的 Hub 升级操作；请先完成或恢复该操作，本次没有写入任何备份。"
	case "MANIFEST_UNAVAILABLE":
		return "请由 root 预置并校验 manifest-<target>.json；Web 不下载、不转发 manifest，本次没有写入任何备份。"
	case "HUB_SPACE_INSUFFICIENT":
		return "请释放 Hub 数据目录所在文件系统的空间后重试；本次没有写入任何备份。"
	case "HUB_BACKUP_STORE_UNSAFE":
		return "请检查 database-backup 及其操作目录的属主与 0700 权限；本次没有写入任何备份。"
	default:
		return "请凭操作编号检查服务日志；旧备份保持不变，本次没有可交接的备份。"
	}
}

// hubApplyReceipt is the handoff receipt. Status is "queued": the operation is
// durable in the journal and one request exists, nothing more. On a refusal
// OperationID is the request's tracing id and ErrorCode is the stable reason.
type hubApplyReceipt struct {
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	OperationID   string `json:"operation_id,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	PackageSHA256 string `json:"package_sha256,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	Detail        string `json:"detail,omitempty"`
	NextAction    string `json:"next_action,omitempty"`
}

// tasksHubUpgradeApply hands one backed-up operation to the root dispatcher
// (#11d Task 5, spec §5.2/§5.11). The form names the operation; the target,
// package and digests come from the journal, the per-operation record and the
// root manifest, never from the form. The route never waits for the upgrade:
// queued is the honest maximum it can claim.
func (app *Server) tasksHubUpgradeApply(w http.ResponseWriter, r *http.Request, _ session) {
	operationID := strings.TrimSpace(r.PostForm.Get("operation_id"))
	if !isValidOperationID(operationID) {
		app.event(r, "HUB_HANDOFF_REQUEST_INVALID")
		app.writeJSON(w, http.StatusBadRequest, hubApplyReceipt{
			Status: "failed", ErrorCode: "HUB_HANDOFF_REQUEST_INVALID", OperationID: operation(r),
			Detail:     "升级操作编号不正确。",
			NextAction: "请从 Hub 自升级的备份回执复制 32 位十六进制 operation_id 后重试；未写入任何请求。",
		})
		return
	}
	apply := app.hubApply
	if apply == nil {
		apply = hubupgrade.Handoff
	}
	receipt, err := apply(r.Context(), hubupgrade.HandoffConfig{
		DataDir:       app.store.Dir,
		OperationID:   operationID,
		ManifestDir:   hubupgrade.RootManifestDir,
		ManifestOwner: 0,
		RecordOwner:   0,
		RequestDir:    hubupgrade.RequestDir,
		Now:           app.now,
		Space:         hubupgrade.CheckFreeSpace,
	})
	if err != nil {
		code := store.ErrorCodeOf(err)
		app.event(r, code)
		app.writeJSON(w, hubApplyHTTPStatus(code), hubApplyReceipt{
			Status: "failed", ErrorCode: code, OperationID: operation(r),
			Detail:     "Hub 升级未交接。",
			NextAction: hubApplyNextAction(code),
		})
		return
	}
	app.event(r, "HUB_UPGRADE_QUEUED")
	app.writeJSON(w, http.StatusOK, hubApplyReceipt{
		OK: true, Status: receipt.Status, OperationID: receipt.OperationID,
		TargetVersion: receipt.TargetVersion, PackageSHA256: receipt.PackageSHA256,
	})
}

// hubApplyHTTPStatus maps the handoff's stable codes onto the boundary status.
// The mapping is by code, never by message text.
func hubApplyHTTPStatus(code string) int {
	switch code {
	case "UPDATE_BACKUP_MISSING":
		return http.StatusNotFound
	case "HUB_HANDOFF_INVALID_STATE", "HUB_UPGRADE_BUSY", "MANIFEST_UNAVAILABLE",
		"HUB_MANIFEST_PACKAGE_MISMATCH", "IRREVERSIBLE_CONFIRM_REQUIRED",
		"HUB_SPACE_INSUFFICIENT", "UPDATE_BACKUP_MISMATCH", "UPDATE_BACKUP_CORRUPT":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func hubApplyNextAction(code string) string {
	switch code {
	case "HUB_HANDOFF_INVALID_STATE":
		return "该操作不在可交接的 backed_up 状态；请确认 journal 与 /tasks 的当前操作，本次没有写入任何请求。"
	case "HUB_UPGRADE_BUSY":
		return "已有未完成的 Hub 升级操作；请先完成或恢复该操作，本次没有写入任何请求。"
	case "MANIFEST_UNAVAILABLE":
		return "请由 root 预置并校验 manifest-<target>.json；Web 不下载、不转发 manifest，本次没有写入任何请求。"
	case "HUB_MANIFEST_PACKAGE_MISMATCH":
		return "root manifest 已不再描述该操作冻结的目标包；请重新完成 Hub 数据库备份后再升级，本次没有写入任何请求。"
	case "IRREVERSIBLE_CONFIRM_REQUIRED":
		return "目标声明了不可逆数据库迁移；请先在 /tasks/db-migration/approve 写入该操作的显式确认位，本次没有写入任何请求。"
	case "HUB_SPACE_INSUFFICIENT":
		return "请释放 Hub 数据目录所在文件系统的空间后重试；本次没有写入任何请求。"
	case "UPDATE_BACKUP_MISSING", "UPDATE_BACKUP_MISMATCH", "UPDATE_BACKUP_CORRUPT":
		return "该操作的备份记录不存在或不可信；请重新完成 Hub 数据库备份，本次没有写入任何请求。"
	case "HUB_BACKUP_STAGE_FAILED":
		return "目标包未能校验或落盘；备份仍然有效，请核对 root manifest 的包来源与摘要后重试同一操作。"
	default:
		return "请凭操作编号检查服务日志；journal 未交接，本次没有可执行的请求。"
	}
}

// hubReconcileConfig is the production wiring of the reconcile pass: the store's
// data directory, the fixed result path the root dispatcher writes, the real
// confirmation side effects and the fixed request directory.
func (app *Server) hubReconcileConfig(startup bool) hubupgrade.ReconcileConfig {
	dataDir := app.store.Dir
	return hubupgrade.ReconcileConfig{
		DataDir: dataDir,
		Startup: startup,
		Now:     app.now,
		Result: func(operationID string) (hubupgrade.Result, bool, error) {
			return hubupgrade.ReadResult(app.hubResultsDirValue(), operationID)
		},
		Confirm: func(_ context.Context, operationID, target, pkg string) error {
			_, err := hubupgrade.ConfirmAndCollect(dataDir, operationID, target, pkg, app.now().UTC(), hubupgrade.ConfirmHooks{
				Publish: hubupgrade.PublishFlatPointer,
				Collect: hubupgrade.CleanupConfirmed,
				Log: func(code, backupOperationID string) {
					// Allowlisted fields only: a stable code and the operation
					// id. Either HUB_BACKUP_POINTER_STALE/_UNFLUSHED or
					// HUB_BACKUP_GC_FAILED; the confirmation stands regardless.
					app.log.Info("web_event", "backup_operation_id", backupOperationID, "stage", "hub_upgrade_confirm", "error_code", code)
				},
			})
			return err
		},
		RemoveRequest: func(operationID string) error {
			return hubupgrade.RemoveRequest(hubupgrade.RequestDir, operationID)
		},
	}
}

// reconcileHubUpgrade runs one pass and reports it through the log. A journal
// that cannot be read is logged, never fatal: the service must keep serving and
// /healthz must keep its SELECT 1 contract.
func (app *Server) reconcileHubUpgrade(ctx context.Context, startup bool) hubupgrade.ReconcileReport {
	report, err := hubupgrade.Reconcile(ctx, app.hubReconcileConfig(startup))
	if err != nil {
		app.log.Warn("web_event", "stage", "hub_upgrade_reconcile", "startup", startup, "error_code", store.ErrorCodeOf(err))
		return report
	}
	for _, change := range report.Changes {
		app.log.Info("web_event", "stage", "hub_upgrade_reconcile", "startup", startup,
			"backup_operation_id", change.OperationID, "from", string(change.From), "to", string(change.To), "error_code", change.Code)
	}
	for _, failure := range report.Errors {
		app.log.Warn("web_event", "stage", "hub_upgrade_reconcile", "startup", startup,
			"backup_operation_id", failure.OperationID, "error_code", failure.Code)
	}
	return report
}

// startHubUpgradeReconcile starts the one bounded reconcile ticker. It is a
// lifecycle twin of startHubIdentityRefresh: a second start replaces the first
// loop, and Close stops it and waits for the pass in flight.
func (app *Server) startHubUpgradeReconcile(ctx context.Context) {
	app.stopHubUpgradeReconcile()
	interval := hubUpgradeReconcileInterval
	if app.reconcileInterval > 0 {
		interval = app.reconcileInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	app.reconcileMu.Lock()
	app.reconcileCancel, app.reconcileDone = cancel, done
	app.reconcileMu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				app.reconcileHubUpgrade(ctx, false)
			}
		}
	}()
}

// hubRequestDirValue is the fixed request directory unless a test points it at
// a private fixture. It is not a configuration option: the path unit watches
// only /run/meshmux-hub/requests.
func (app *Server) hubRequestDirValue() string {
	if app.hubRequestDir != "" {
		return app.hubRequestDir
	}
	return hubupgrade.RequestDir
}

// hubResultsDirValue is the fixed root:meshmux result tree unless a test points
// it at a private fixture.
func (app *Server) hubResultsDirValue() string {
	if app.hubResultsDir != "" {
		return app.hubResultsDir
	}
	return hubupgrade.ResultsDir
}

// hubRestoreReceipt is the honest restore receipt: a request is queued for the
// old package's executor. It never claims the database was restored; that fact
// is the root-written result plus the restored.json marker the page shows.
type hubRestoreReceipt struct {
	OK          bool   `json:"ok"`
	Status      string `json:"status"`
	OperationID string `json:"operation_id,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	NextAction  string `json:"next_action,omitempty"`
}

// tasksHubUpgradeRestore queues one restore of a failed/partial/verifying
// operation (spec §5.7/§5.11). The gate is journal-only: a live handoff owns the
// host, a queued request must be consumed first, and a carried record after an
// earlier restore is never a source. The privileged executor re-derives every
// byte, schema and pin check on the root side.
func (app *Server) tasksHubUpgradeRestore(w http.ResponseWriter, r *http.Request, _ session) {
	operationID := strings.TrimSpace(r.PostForm.Get("operation_id"))
	if !isValidOperationID(operationID) {
		app.event(r, "HUB_HANDOFF_REQUEST_INVALID")
		app.writeJSON(w, http.StatusBadRequest, hubRestoreReceipt{
			Status: "failed", ErrorCode: "HUB_HANDOFF_REQUEST_INVALID", OperationID: operation(r),
			Detail:     "恢复操作编号不正确。",
			NextAction: "请从 Hub 自升级区块复制失败操作的 32 位十六进制 operation_id；未写入任何恢复请求。",
		})
		return
	}
	receipt, err := app.queueHubRestore(operationID)
	if err != nil {
		code := store.ErrorCodeOf(err)
		app.event(r, code)
		app.writeJSON(w, hubRestoreHTTPStatus(code), hubRestoreReceipt{
			Status: "failed", ErrorCode: code, OperationID: operation(r),
			Detail:     "Hub 恢复未排队。",
			NextAction: hubRestoreNextAction(code),
		})
		return
	}
	app.event(r, "HUB_UPGRADE_RESTORE_QUEUED")
	app.writeJSON(w, http.StatusOK, receipt)
}

// queueHubRestore is the unprivileged half of §5.7: prove the journal permits a
// restore, prove no request is pending and prove the per-op record still holds
// an integrity-checked copy, then publish exactly one kind=restore request.
func (app *Server) queueHubRestore(operationID string) (hubRestoreReceipt, error) {
	op, found, err := hubupgrade.ReadOp(app.store.Dir, operationID, os.Geteuid())
	if err != nil {
		return hubRestoreReceipt{}, errors.New("HUB_BACKUP_JOURNAL_FAILED: the journal could not be read")
	}
	if !found {
		return hubRestoreReceipt{}, errors.New("UPDATE_BACKUP_MISSING: the operation has no journal entry")
	}
	if op.Kind != hubupgrade.KindUpdate {
		return hubRestoreReceipt{}, errors.New("HUB_HANDOFF_INVALID_STATE: the operation is not an update")
	}
	switch op.State {
	case hubupgrade.StateFailed, hubupgrade.StatePartial, hubupgrade.StateVerifying:
	default:
		return hubRestoreReceipt{}, errors.New("HUB_UPGRADE_BUSY: the operation is not failed, partial or verifying")
	}
	if _, ok, err := hubupgrade.ReadRestoredMarker(app.store.Dir); err != nil {
		return hubRestoreReceipt{}, err
	} else if ok {
		// Any marker means this data directory was produced by a restore. Its
		// carried records are diagnostic only; a new committed backup clears the
		// marker before a new operation can fail.
		return hubRestoreReceipt{}, errors.New("HUB_RESTORE_CARRIED_SOURCE: this data directory was restored; its carried records are not sources")
	}
	root := filepath.Join(app.store.Dir, hubupgrade.DatabaseBackupDir)
	record, err := backup.Read(root, op.OperationID, os.Geteuid())
	if err != nil {
		return hubRestoreReceipt{}, err
	}
	if record.State != backup.StateStaged && record.State != backup.StateConfirmed {
		return hubRestoreReceipt{}, errors.New("UPDATE_BACKUP_MISMATCH: the record is not a restore source")
	}
	if record.OperationID != op.OperationID || record.FromVersion != op.FromVersion || record.DBSchema != op.DBSchema {
		return hubRestoreReceipt{}, errors.New("UPDATE_BACKUP_MISMATCH: the record and the journal name different operations")
	}
	if !record.IntegrityOK || record.PayloadFiles < 1 {
		return hubRestoreReceipt{}, errors.New("UPDATE_BACKUP_CORRUPT: the record has no verified payload")
	}
	pending, err := hubRequestPending(app.hubRequestDirValue(), op.OperationID)
	if err != nil {
		return hubRestoreReceipt{}, err
	}
	if pending {
		return hubRestoreReceipt{}, errors.New("HUB_HANDOFF_BUSY: a request is still queued")
	}
	if _, err := hubupgrade.WriteRequest(app.hubRequestDirValue(), hubupgrade.Request{
		Schema: hubupgrade.RequestSchema, Kind: hubupgrade.KindRestore,
		OperationID: op.OperationID, DataDir: app.store.Dir,
	}); err != nil {
		return hubRestoreReceipt{}, err
	}
	return hubRestoreReceipt{OK: true, Status: "restoring", OperationID: op.OperationID}, nil
}

// hubRequestPending reports whether this operation's completed request is
// already in the watched directory. The Web may write but not read the 0730
// request directory (it has write+execute only), so this must be a single-name
// Lstat: listing it would fail with EACCES after the journal says the request is
// live. The dispatcher and the executor re-verify the rest; a request for
// another operation is not this route's to judge (the dispatcher drains multiple
// requests with HUB_HANDOFF_BUSY, and the executor independently refuses while a
// request exists).
func hubRequestPending(dir, operationID string) (bool, error) {
	if !isValidOperationID(operationID) {
		return false, errors.New("HUB_HANDOFF_REQUEST_INVALID: the operation id is not 32 lowercase hex")
	}
	path := filepath.Join(dir, operationID+".json")
	if _, err := os.Lstat(path); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, errors.New("HUB_HANDOFF_REQUEST_INVALID: the request could not be inspected")
	}
	return false, nil
}

func hubRestoreHTTPStatus(code string) int {
	switch code {
	case "HUB_HANDOFF_REQUEST_INVALID":
		return http.StatusBadRequest
	case "UPDATE_BACKUP_MISSING":
		return http.StatusNotFound
	case "HUB_HANDOFF_BUSY", "HUB_UPGRADE_BUSY", "HUB_HANDOFF_INVALID_STATE",
		"UPDATE_BACKUP_MISMATCH", "UPDATE_BACKUP_CORRUPT", "HUB_RESTORE_CARRIED_SOURCE":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func hubRestoreNextAction(code string) string {
	switch code {
	case "HUB_HANDOFF_INVALID_STATE":
		return "该操作不是一次 update；恢复只针对失败的 Hub 升级操作，未写入任何恢复请求。"
	case "HUB_UPGRADE_BUSY":
		return "该操作仍在交接或执行中（或已确认/已恢复）；只有 failed/partial/verifying 可排队恢复，未写入任何恢复请求。"
	case "HUB_HANDOFF_BUSY":
		return "已有一个请求等待 root dispatcher 消费；请等它完成或超时后重试，未写入任何恢复请求。"
	case "HUB_RESTORE_CARRIED_SOURCE":
		return "该数据目录已由恢复产生；随目录携带的旧记录只能作诊断，不能再次恢复。请先完成一次新的 Hub 数据库备份。"
	case "UPDATE_BACKUP_MISSING", "UPDATE_BACKUP_MISMATCH", "UPDATE_BACKUP_CORRUPT":
		return "该操作的备份记录不存在或不再可信；恢复必须使用带 integrity_ok 的 staged/confirmed per-op 副本。"
	default:
		return "请凭操作编号检查服务日志；未声称恢复已排队或已完成。"
	}
}

// stopHubUpgradeReconcile cancels the ticker and waits for the goroutine to
// leave its current pass, so the store is never closed under it. It is safe to
// call more than once and when no ticker was started.
func (app *Server) stopHubUpgradeReconcile() {
	app.reconcileMu.Lock()
	cancel, done := app.reconcileCancel, app.reconcileDone
	app.reconcileCancel, app.reconcileDone = nil, nil
	app.reconcileMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
