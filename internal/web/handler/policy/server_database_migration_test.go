package policy_test

// HTTP tests for the irreversible database migration approval (#11c-3 Task 5,
// spec §4.15, §6). The migration itself is 11d; this surface is the only way the
// explicit bit may reach the Hub database backup record, and it deliberately
// keeps the existing admin mutation boundary: one authenticated session, exact
// Origin, CSRF token and a bounded form.
//
// A flag cannot bypass the bit: the handler refuses anything but the literal
// "1" in the explicit confirmation field, and a refused request writes nothing.

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
)

const databaseMigrationApprovePath = "/tasks/db-migration/approve"

// TestIrreversibleNeedsExplicitConfirm is the review gate: without the explicit
// Web bit an irreversible migration approval is refused and the backup record
// stays byte-identical; with the bit the approval is stored on that record.
func TestIrreversibleNeedsExplicitConfirm(t *testing.T) {
	b, app := handlertest.DatabaseMigrationBrowser(t)
	operationID := strings.Repeat("d", 32)
	recordPath, _ := storetest.HubDatabaseRecord(t, app.Store.Dir, operationID, nil)
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}

	refused := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath,
		url.Values{"backup_operation_id": {operationID}}), http.StatusConflict)
	if refused.ErrorCode != "IRREVERSIBLE_CONFIRM_REQUIRED" || refused.IrreversibleApproved {
		t.Fatalf("missing bit was not refused: %+v", refused)
	}
	if !strings.Contains(refused.Detail, "不可逆") || refused.NextAction == "" {
		t.Fatalf("refusal does not explain the explicit confirmation: %+v", refused)
	}
	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("refused approval changed the backup record")
	}
	for _, truthy := range []string{"on", "true", "yes", "0", ""} {
		receipt := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath,
			url.Values{"backup_operation_id": {operationID}, "irreversible_confirm": {truthy}}), http.StatusConflict)
		if receipt.ErrorCode != "IRREVERSIBLE_CONFIRM_REQUIRED" {
			t.Fatalf("inexplicit bit %q accepted: %+v", truthy, receipt)
		}
	}
	if stored := storetest.ReadStoredDatabaseRecord(t, recordPath); stored.IrreversibleApproved {
		t.Fatal("refusals set the bit anyway")
	}

	approved := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath,
		url.Values{"backup_operation_id": {operationID}, "irreversible_confirm": {"1"}}), http.StatusOK)
	if !approved.OK || approved.Status != "approved" || !approved.IrreversibleApproved {
		t.Fatalf("explicit approval receipt: %+v", approved)
	}
	if approved.BackupOperationID != operationID || approved.BackupRecord != recordPath {
		t.Fatalf("receipt does not name the confirmed record: %+v", approved)
	}
	// The approval acts on the operation directory, never on the flat pointer
	// <database-backup>/record.json that only the old binary's schemaTooNew
	// existence check reads.
	wantRecord := filepath.Join(app.Store.Dir, store.DatabaseBackupDirName, operationID, store.DatabaseBackupRecordName)
	if approved.BackupRecord != wantRecord {
		t.Fatalf("approval record = %q, want %q", approved.BackupRecord, wantRecord)
	}
	if filepath.Dir(approved.BackupRecord) == filepath.Join(app.Store.Dir, store.DatabaseBackupDirName) {
		t.Fatalf("approval wrote the flat pointer %q", approved.BackupRecord)
	}
	if stored := storetest.ReadStoredDatabaseRecord(t, recordPath); !stored.IrreversibleApproved {
		t.Fatal("bit was not stored on the backup record")
	}

	// Retrying the operator action is idempotent and never says "applied".
	again := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath,
		url.Values{"backup_operation_id": {operationID}, "irreversible_confirm": {"1"}}), http.StatusOK)
	if again.Status != "already_approved" || !again.IrreversibleApproved {
		t.Fatalf("retry receipt: %+v", again)
	}
}

// TestIrreversibleConfirmMatrix covers the ways the approval surface must not
// be usable: unauthenticated, cross-site, CSRF-less, malformed or non-private
// records, a foreign operation and an unverified backup.
func TestIrreversibleConfirmMatrix(t *testing.T) {
	operationID := strings.Repeat("e", 32)
	approvedForm := func() url.Values {
		return url.Values{"backup_operation_id": {operationID}, "irreversible_confirm": {"1"}}
	}

	t.Run("authentication, origin and csrf stay required", func(t *testing.T) {
		b, app := handlertest.DatabaseMigrationBrowser(t)
		storetest.HubDatabaseRecord(t, app.Store.Dir, operationID, nil)
		anonymous := &handlertest.Browser{App: app}
		handlertest.RequireStatus(t, anonymous.Req("POST", databaseMigrationApprovePath, approvedForm(), nil), http.StatusUnauthorized)
		handlertest.RequireStatus(t, b.Req("POST", databaseMigrationApprovePath,
			url.Values{"backup_operation_id": {operationID}, "irreversible_confirm": {"1"}, "csrf": {"wrong"}}, nil),
			http.StatusForbidden)
		handlertest.RequireStatus(t, b.Req("POST", databaseMigrationApprovePath,
			url.Values{"backup_operation_id": {operationID}, "irreversible_confirm": {"1"}, "csrf": {b.CSRF}},
			http.Header{"Origin": {"https://evil.example.invalid"}}), http.StatusForbidden)
	})

	t.Run("invalid operation id", func(t *testing.T) {
		b, _ := handlertest.DatabaseMigrationBrowser(t)
		receipt := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath,
			url.Values{"backup_operation_id": {"../../etc"}, "irreversible_confirm": {"1"}}), http.StatusBadRequest)
		if receipt.ErrorCode != "DB_BACKUP_OPERATION_INVALID" {
			t.Fatalf("receipt: %+v", receipt)
		}
	})

	t.Run("missing record", func(t *testing.T) {
		b, _ := handlertest.DatabaseMigrationBrowser(t)
		receipt := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath, approvedForm()), http.StatusNotFound)
		if receipt.ErrorCode != "DB_BACKUP_RECORD_MISSING" || receipt.IrreversibleApproved {
			t.Fatalf("receipt: %+v", receipt)
		}
	})

	cases := []struct {
		name   string
		mutate func(*backup.Record)
		write  func(path string)
		code   string
		status int
	}{
		{"unverified backup", func(r *backup.Record) { r.IntegrityOK = false }, nil, "DB_BACKUP_RECORD_UNVERIFIED", http.StatusConflict},
		{"no payload files", func(r *backup.Record) { r.PayloadFiles = 0 }, nil, "DB_BACKUP_RECORD_UNVERIFIED", http.StatusConflict},
		{"payload named elsewhere", func(r *backup.Record) { r.PayloadPath = "/var/tmp/elsewhere" }, nil, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"empty payload directory", nil, func(path string) {
			if err := os.Remove(filepath.Join(filepath.Dir(path), store.DatabaseBackupPayloadDirName, "meshmux.db")); err != nil {
				t.Fatal(err)
			}
		}, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"public payload directory", nil, func(path string) {
			if err := os.Chmod(filepath.Join(filepath.Dir(path), store.DatabaseBackupPayloadDirName), 0755); err != nil {
				t.Fatal(err)
			}
		}, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"foreign operation inside the record", func(r *backup.Record) { r.OperationID = strings.Repeat("f", 32) }, nil, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"no source schema", func(r *backup.Record) { r.DBSchema = 0 }, nil, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"future record schema", func(r *backup.Record) { r.Schema = backup.RecordSchema + 1 }, nil, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"not staged", func(r *backup.Record) { r.State = backup.StateConfirmed }, nil, "DB_BACKUP_RECORD_NOT_STAGED", http.StatusConflict},
		{"unknown future field", nil, func(path string) {
			if err := os.WriteFile(path, []byte(`{"schema":1,"operation_id":"`+operationID+`","future":true}`), 0600); err != nil {
				t.Fatal(err)
			}
		}, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"not json", nil, func(path string) {
			if err := os.WriteFile(path, []byte("{not a record"), 0600); err != nil {
				t.Fatal(err)
			}
		}, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"public record mode", nil, func(path string) {
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		}, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
		{"symlinked record", nil, func(path string) {
			target := path + ".target"
			if err := os.WriteFile(target, []byte(`{"schema":1}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}, "DB_BACKUP_RECORD_CORRUPT", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, app := handlertest.DatabaseMigrationBrowser(t)
			path, _ := storetest.HubDatabaseRecord(t, app.Store.Dir, operationID, tc.mutate)
			if tc.write != nil {
				tc.write(path)
			}
			receipt := handlertest.DecodeDatabaseMigration(t, b.Post(databaseMigrationApprovePath, approvedForm()), tc.status)
			if receipt.ErrorCode != tc.code || receipt.IrreversibleApproved {
				t.Fatalf("receipt: %+v", receipt)
			}
			if tc.write == nil {
				if stored := storetest.ReadStoredDatabaseRecord(t, path); stored.IrreversibleApproved {
					t.Fatal("refused approval set the bit")
				}
			}
		})
	}
}
