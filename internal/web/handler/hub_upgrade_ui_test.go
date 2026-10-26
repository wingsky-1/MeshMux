package handler

// Tests for the #11d Task 7 /tasks Hub block (spec §5.11). The block is a
// readback plus three existing-boundary mutations: backup, handoff and restore.
// It must show the record facts, the irreversible bit, the result phase and the
// lossy restore fact, and it must not offer a flag/environment bypass.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
)

func plantHubUpgradePage(t *testing.T, app *Server, state hubupgrade.State) (string, backup.Record) {
	t.Helper()
	app.hubResultsDir = t.TempDir()
	operationID := strings.Repeat("a", 32)
	_, record := hubDatabaseRecord(t, app.store.Dir, operationID, func(record *backup.Record) {
		record.IrreversibleApproved = true
	})
	op := hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: operationID, Kind: hubupgrade.KindUpdate,
		State: state, TargetVersion: "1.0.1", FromVersion: "1.0.0",
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: strings.Repeat("c", 64),
		DBSchema: record.DBSchema, BackupGeneration: 1, UpdatedAt: time.Now().UTC().Add(-time.Minute),
	}
	if err := hubupgrade.WriteOp(app.store.Dir, op); err != nil {
		t.Fatal(err)
	}
	if _, err := hubupgrade.WriteResult(app.hubResultsDir, hubupgrade.Result{
		Schema: hubupgrade.ResultSchema, OperationID: operationID,
		Phase: hubupgrade.ResultFailed, ErrorCode: "HUB_SHARED_BINARY_REPIN_INCOMPLETE",
		TargetVersion: "1.0.1", PackageSHA256: strings.Repeat("c", 64),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeTestRestoredMarker(app, hubupgrade.RestoredMarker{
		Schema: hubupgrade.RestoredSchema, OperationID: operationID,
		SnapshotAt: time.Date(2026, 10, 26, 9, 30, 0, 0, time.UTC), Lossy: true,
	}); err != nil {
		t.Fatal(err)
	}
	return operationID, record
}

func TestHubUpgradePage(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	operationID, record := plantHubUpgradePage(t, app, hubupgrade.StateFailed)

	w := b.req("GET", "/tasks", nil, nil)
	requireStatus(t, w, 200)
	body := w.Body.String()
	for _, want := range []string{
		"Hub 自升级",
		operationID,
		"from_version 1.0.0",
		"db_schema " + strconv.FormatInt(record.DBSchema, 10),
		"payload 文件 1",
		"integrity_ok true",
		"不可逆确认位：<b>已确认</b>",
		"HUB_SHARED_BINARY_REPIN_INCOMPLETE",
		"有损恢复（LOSSY）",
		"snapshot_at=2026-10-26T09:30:00Z",
		"恢复是有损的（LOSSY）",
		"不存在 flag 或环境变量绕过",
		`action="/tasks/hub-upgrade/backup"`,
		`action="/tasks/hub-upgrade/restore"`,
		`name="csrf"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Hub block is missing %q", want)
		}
	}
	// A failed operation is not offered a handoff until it is backed up again.
	if strings.Contains(body, `action="/tasks/hub-upgrade/apply"`) {
		t.Fatal("a failed operation offered the apply form")
	}
	// The restore form carries exactly the operation the block names.
	if !strings.Contains(body, `name="operation_id" value="`+operationID+`"`) {
		t.Fatal("restore form does not carry the operation id")
	}
}

func TestHubUpgradePageOffersHandoffForBackedUp(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	operationID, _ := plantHubUpgradePage(t, app, hubupgrade.StateBackedUp)
	w := b.req("GET", "/tasks", nil, nil)
	requireStatus(t, w, 200)
	body := w.Body.String()
	if !strings.Contains(body, `action="/tasks/hub-upgrade/apply"`) {
		t.Fatal("a backed_up operation did not offer the handoff form")
	}
	if !strings.Contains(body, `name="operation_id" value="`+operationID+`"`) {
		t.Fatal("handoff form does not carry the operation id")
	}
	if strings.Contains(body, `action="/tasks/hub-upgrade/restore"`) {
		t.Fatal("a backed_up operation offered a restore")
	}
}

// TestApproveHintPointsToHubUpgrade pins the dangling-copy fix: the approval
// hint names the Hub block and the same operation_id the backup receipt gave.
func TestApproveHintPointsToHubUpgrade(t *testing.T) {
	b, _ := databaseMigrationBrowser(t)
	receipt := decodeDatabaseMigration(t, b.post(databaseMigrationApprovePath,
		url.Values{"backup_operation_id": {strings.Repeat("d", 32)}}), http.StatusConflict)
	if receipt.ErrorCode != "IRREVERSIBLE_CONFIRM_REQUIRED" {
		t.Fatalf("receipt: %+v", receipt)
	}
	for _, want := range []string{"Hub 自升级", "backup_operation_id"} {
		if !strings.Contains(receipt.NextAction, want) {
			t.Fatalf("approval hint does not name %q: %s", want, receipt.NextAction)
		}
	}
}
