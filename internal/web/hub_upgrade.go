package web

// The Hub backup producer surface of #11d (spec §5.2). It is one authenticated
// admin mutation on the existing boundary: one session, exact Origin, CSRF
// token, a bounded form, and an operation id on every receipt.
//
// The Web process owns the SQLite handle, so it supplies the four database
// callbacks while internal/hubupgrade owns the order and every file write. The
// receipt only claims "staged": it names the operation and the verified backup,
// never an applied upgrade. The irreversible approval bit is not read here; the
// producer refuses while it is set, and Task 5 re-reads it before a destructive
// step.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
)

// hubTargetPattern mirrors the manifest and record target shape. It is checked
// before the target can become part of a manifest path.
var hubTargetPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

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
	if !hubTargetPattern.MatchString(target) {
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
		DataDir:     app.store.dir,
		Target:      target,
		ManifestDir: hubupgrade.RootManifestDir,
		Vacuum:      app.store.vacuumDatabaseCopy,
		Integrity:   app.store.integrityCheckCopy,
		Schema:      app.store.databaseSchemaVersion,
		Space:       hubupgrade.CheckFreeSpace,
	})
	if err != nil {
		code := errorCodeOf(err)
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

func hubBackupHTTPStatus(code string) int {
	switch code {
	case "HUB_UPGRADE_BUSY", "MANIFEST_UNAVAILABLE", "HUB_SPACE_INSUFFICIENT", "HUB_BACKUP_SLOT_CORRUPT":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func hubBackupNextAction(code string) string {
	switch code {
	case "HUB_UPGRADE_BUSY":
		return "已有未完成的 Hub 升级操作或不可逆确认位；请先完成或恢复该操作，本次没有写入任何备份。"
	case "MANIFEST_UNAVAILABLE":
		return "请由 root 预置并校验 manifest-<target>.json；Web 不下载、不转发 manifest，本次没有写入任何备份。"
	case "HUB_SPACE_INSUFFICIENT":
		return "请释放 Hub 数据目录所在文件系统的空间后重试；本次没有写入任何备份。"
	default:
		return "请凭操作编号检查服务日志；旧备份保持不变，本次没有可交接的备份。"
	}
}

// vacuumDatabaseCopy is the production VACUUM INTO callback. The destination is
// fixed by the producer and must not exist: SQLite refuses an existing target,
// and a stale copy is deleted by the producer after slot reconciliation. VACUUM
// runs outside any transaction on the store's single connection.
func (s *store) vacuumDatabaseCopy(ctx context.Context, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return errors.New("HUB_BACKUP_VACUUM_FAILED: the VACUUM destination already exists")
	} else if !os.IsNotExist(err) {
		return errors.New("HUB_BACKUP_VACUUM_FAILED: the VACUUM destination could not be inspected")
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return errors.New("HUB_BACKUP_VACUUM_FAILED: VACUUM INTO did not produce the copy")
	}
	return nil
}

// integrityCheckCopy opens the finished copy read-only and runs
// PRAGMA integrity_check. It never opens the live database and never writes the
// copy through a writer connection; immutable=1 makes the check itself prove it
// cannot touch the file.
func (s *store) integrityCheckCopy(ctx context.Context, path string) error {
	u := url.URL{Scheme: "file", Path: path}
	copyDB, err := sql.Open("sqlite", u.String()+"?mode=ro&immutable=1")
	if err != nil {
		return errors.New("HUB_BACKUP_INTEGRITY_FAILED: the database copy could not be opened")
	}
	defer copyDB.Close()
	copyDB.SetMaxOpenConns(1)
	var result string
	if err := copyDB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return errors.New("HUB_BACKUP_INTEGRITY_FAILED: integrity_check could not run on the copy")
	}
	if result != "ok" {
		return errors.New("HUB_BACKUP_INTEGRITY_FAILED: integrity_check did not return ok")
	}
	return nil
}

// databaseSchemaVersion is the live PRAGMA user_version. The producer records it
// as db_schema; it is never guessed from this build's constant, because a
// restore compares the copy against the record.
func (s *store) databaseSchemaVersion(ctx context.Context) (int64, error) {
	var version int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, errors.New("HUB_BACKUP_SCHEMA_FAILED: the database schema could not be read")
	}
	if version <= 0 {
		return 0, errors.New("HUB_BACKUP_SCHEMA_FAILED: the database reports no schema version")
	}
	return version, nil
}
