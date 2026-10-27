package handler

// The Web surface that stores the explicit irreversible-migration confirmation
// (#11c-3 Task 5, spec §4.15). It is an admin mutation on the existing boundary:
// one authenticated session, exact Origin, CSRF token, bounded form and an
// operation id on the receipt. It never starts a migration and never edits the
// database: 11d applies the Hub upgrade and reads the bit from the backup
// record before it runs a destructive step.
//
// There is deliberately no flag or environment switch: an approval without the
// literal form value `irreversible_confirm=1` is refused and writes nothing.

import (
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strings"
)

const (
	// codeIrreversibleConfirmRequired is the stable refusal for an approval that
	// did not carry the explicit confirmation bit.
	codeIrreversibleConfirmRequired = "IRREVERSIBLE_CONFIRM_REQUIRED"
	// databaseMigrationConfirmField is the one accepted confirmation field. Its
	// only truthful value is "1": "on"/"true" are HTML/JS truthiness, not an
	// explicit operator decision this surface accepts.
	databaseMigrationConfirmField = "irreversible_confirm"
)

// databaseMigrationReceipt reports the stored confirmation, never that a
// migration was applied.
type databaseMigrationReceipt struct {
	OK                   bool   `json:"ok"`
	Status               string `json:"status"`
	BackupOperationID    string `json:"backup_operation_id,omitempty"`
	BackupRecord         string `json:"backup_record,omitempty"`
	FromVersion          string `json:"from_version,omitempty"`
	DBSchema             int64  `json:"db_schema,omitempty"`
	PolicySchema         int    `json:"policy_schema,omitempty"`
	IrreversibleApproved bool   `json:"irreversible_approved"`
	ErrorCode            string `json:"error_code,omitempty"`
	Detail               string `json:"detail,omitempty"`
	NextAction           string `json:"next_action,omitempty"`
	OperationID          string `json:"operation_id"`
}

// tasksDatabaseMigrationApprove stores the confirmation bit on the Hub database
// backup record. The operator names the backup operation; the record must exist,
// be private, staged and verified, and belong to exactly that operation.
//
// Flow: validate the backup operation id against the frozen grammar → require
// the literal confirmation field value "1" → store the bit → answer one
// receipt. There is deliberately no flag or environment switch.
func (app *Server) tasksDatabaseMigrationApprove(w http.ResponseWriter, r *http.Request, _ session) {
	operationID := strings.TrimSpace(r.PostForm.Get("backup_operation_id"))
	if !infra.IsValidOperationID(operationID) {
		app.writeDatabaseMigrationFailure(w, r, http.StatusBadRequest, "DB_BACKUP_OPERATION_INVALID",
			"备份操作编号不正确。", "请从本页 Hub 自升级区块的备份回执复制 32 位十六进制 operation_id（即 backup_operation_id）后重试；未写入任何确认。")
		return
	}
	if r.PostForm.Get(databaseMigrationConfirmField) != "1" {
		app.writeDatabaseMigrationFailure(w, r, http.StatusConflict, codeIrreversibleConfirmRequired,
			"不可逆数据库迁移未经显式确认。",
			"请由管理员在 Web 显式勾选“我确认这是不可逆迁移”后再批准，随后回到本页 Hub 自升级区块使用同一 backup_operation_id；不存在命令行开关或其他绕过方式，未写入任何确认。")
		return
	}
	approval, err := app.Store.ApproveIrreversibleMigration(operationID, true)
	if err != nil {
		app.failDatabaseMigration(w, r, err)
		return
	}
	status := "approved"
	if approval.AlreadyApproved {
		status = "already_approved"
	}
	app.Event(r, "DB_MIGRATION_APPROVED")
	app.writeJSON(w, http.StatusOK, databaseMigrationReceipt{
		OK: true, Status: status, BackupOperationID: operationID, BackupRecord: approval.RecordPath,
		FromVersion: approval.Record.FromVersion, DBSchema: approval.Record.DBSchema,
		PolicySchema: approval.Record.PolicySchema, IrreversibleApproved: true,
		OperationID: infra.Operation(r),
		Detail:      "确认位已写入 Hub 数据库备份记录；本次请求没有执行任何迁移。",
		NextAction:  "确认位等于操作员同意，不等于迁移已完成；请回到本页 Hub 自升级区块，用同一 operation_id 执行交接或恢复，root 执行体在应用不可逆步骤前读取该位。",
	})
}

// failDatabaseMigration maps one store refusal onto its status and operator
// hint. Every branch returns: the writer must never emit two JSON bodies for one
// request.
func (app *Server) failDatabaseMigration(w http.ResponseWriter, r *http.Request, err error) {
	code := err.Error()
	switch {
	case strings.HasPrefix(code, "DB_BACKUP_OPERATION_INVALID"):
		app.writeDatabaseMigrationFailure(w, r, http.StatusBadRequest, "DB_BACKUP_OPERATION_INVALID",
			"备份操作编号不正确。", "请从本页 Hub 自升级区块的备份回执复制 32 位十六进制 operation_id（即 backup_operation_id）后重试；未写入任何确认。")
	case strings.HasPrefix(code, codeIrreversibleConfirmRequired):
		app.writeDatabaseMigrationFailure(w, r, http.StatusConflict, codeIrreversibleConfirmRequired,
			"不可逆数据库迁移未经显式确认。",
			"请由管理员在 Web 显式勾选“我确认这是不可逆迁移”后再批准，随后回到本页 Hub 自升级区块使用同一 backup_operation_id；不存在命令行开关或其他绕过方式，未写入任何确认。")
	case strings.HasPrefix(code, "DB_BACKUP_RECORD_MISSING"):
		app.writeDatabaseMigrationFailure(w, r, http.StatusNotFound, "DB_BACKUP_RECORD_MISSING",
			"没有该操作的 Hub 数据库备份记录。", "请先完成带完整性校验的 Hub 数据库备份；未写入任何确认。")
	case strings.HasPrefix(code, "DB_BACKUP_RECORD_UNVERIFIED"):
		app.writeDatabaseMigrationFailure(w, r, http.StatusConflict, "DB_BACKUP_RECORD_UNVERIFIED",
			"该 Hub 数据库备份没有完整性回读。", "请重新做可验证的备份（VACUUM INTO + integrity_check）后再确认；未写入任何确认。")
	case strings.HasPrefix(code, "DB_BACKUP_RECORD_NOT_STAGED"):
		app.writeDatabaseMigrationFailure(w, r, http.StatusConflict, "DB_BACKUP_RECORD_NOT_STAGED",
			"该备份记录不在待升级状态。", "已确认或失败的备份不能补写不可逆确认；请使用当前这次升级的 staged 记录。")
	case strings.HasPrefix(code, "DB_BACKUP_RECORD_CORRUPT"):
		app.writeDatabaseMigrationFailure(w, r, http.StatusConflict, "DB_BACKUP_RECORD_CORRUPT",
			"Hub 数据库备份记录不可信。", "请检查记录文件的所有者、0600 权限、JSON 形状与 operation_id；未写入任何确认。")
	default:
		app.writeDatabaseMigrationFailure(w, r, http.StatusServiceUnavailable, "DB_BACKUP_APPROVAL_FAILED",
			"确认未完成。", "请凭操作编号检查服务日志；未声称确认已写入。")
	}
}

// writeDatabaseMigrationFailure writes the refusal in the management JSON shape.
func (app *Server) writeDatabaseMigrationFailure(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	app.Event(r, code)
	app.writeJSON(w, status, databaseMigrationReceipt{
		Status: "failed", ErrorCode: code, Detail: message, NextAction: next, OperationID: infra.Operation(r),
	})
}
