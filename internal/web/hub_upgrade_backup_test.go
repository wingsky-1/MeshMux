package web

// HTTP tests for the Hub backup producer surface (#11d Task 3, spec §5.2):
// one authenticated management mutation on the existing boundary, with the
// callbacks the Web process alone can supply (VACUUM, integrity check, real
// user_version, free space). The producer itself is tested in
// internal/hubupgrade; here we prove the route, the receipt and the shared
// flat-slot lock the approval reader must also take.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
)

const hubBackupPath = "/tasks/hub-upgrade/backup"

type hubBackupReceiptJSON struct {
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	OperationID   string `json:"operation_id"`
	TargetVersion string `json:"target_version"`
	FromVersion   string `json:"from_version"`
	DBSchema      int64  `json:"db_schema"`
	IntegrityOK   bool   `json:"integrity_ok"`
	ErrorCode     string `json:"error_code"`
}

func decodeHubBackup(t *testing.T, w *httptest.ResponseRecorder, status int) hubBackupReceiptJSON {
	t.Helper()
	requireStatus(t, w, status)
	var receipt hubBackupReceiptJSON
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("hub backup receipt: %v %.300s", err, w.Body.String())
	}
	return receipt
}

func TestHubBackupReceipt(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	operationID := strings.Repeat("a", 32)
	var got hubupgrade.BackupConfig
	app.hubBackup = func(_ context.Context, cfg hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
		got = cfg
		return hubupgrade.BackupReceipt{
			Status: "staged", OperationID: operationID, FromVersion: "1.0.0",
			DBSchema: 10, IntegrityOK: true,
		}, nil
	}
	receipt := decodeHubBackup(t, b.post(hubBackupPath,
		url.Values{"target_version": {"1.0.1"}}), http.StatusOK)
	if !receipt.OK || receipt.Status != "staged" || receipt.OperationID != operationID ||
		receipt.FromVersion != "1.0.0" || receipt.DBSchema != 10 || !receipt.IntegrityOK {
		t.Fatalf("receipt: %+v", receipt)
	}
	if got.DataDir != app.store.dir || got.Target != "1.0.1" ||
		got.ManifestDir != hubupgrade.RootManifestDir {
		t.Fatalf("producer config: %+v", got)
	}
	if got.Vacuum == nil || got.Integrity == nil || got.Schema == nil || got.Space == nil {
		t.Fatalf("Web callbacks are incomplete: %+v", got)
	}

	// The mutation boundary stays the existing one: session, exact Origin and
	// CSRF are all still required, and a refusal writes nothing.
	requireStatus(t, b.req("POST", hubBackupPath,
		url.Values{"target_version": {"1.0.1"}}, nil), http.StatusForbidden)
	requireStatus(t, b.req("POST", hubBackupPath,
		url.Values{"target_version": {"1.0.1"}, "csrf": {b.csrf}},
		http.Header{"Origin": {"https://evil.example.invalid"}}), http.StatusForbidden)
	anonymous := &browser{app: app}
	requireStatus(t, anonymous.req("POST", hubBackupPath,
		url.Values{"target_version": {"1.0.1"}, "csrf": {b.csrf}}, nil), http.StatusUnauthorized)
}

func TestHubBackupFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		err    string
		status int
	}{
		{"HUB_UPGRADE_BUSY: another operation is in flight", http.StatusConflict},
		{"MANIFEST_UNAVAILABLE: no root manifest", http.StatusConflict},
		{"HUB_SPACE_INSUFFICIENT: need more space", http.StatusConflict},
		{"HUB_BACKUP_INTEGRITY_FAILED: copy not ok", http.StatusInternalServerError},
	} {
		t.Run(strings.SplitN(tc.err, ":", 2)[0], func(t *testing.T) {
			b, app := databaseMigrationBrowser(t)
			app.hubBackup = func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
				return hubupgrade.BackupReceipt{}, &hubBackupError{tc.err}
			}
			receipt := decodeHubBackup(t, b.post(hubBackupPath,
				url.Values{"target_version": {"1.0.1"}}), tc.status)
			if receipt.OK || receipt.Status == "staged" ||
				receipt.ErrorCode != strings.SplitN(tc.err, ":", 2)[0] {
				t.Fatalf("failure receipt: %+v", receipt)
			}
		})
	}
}

type hubBackupError struct{ text string }

func (e *hubBackupError) Error() string { return e.text }

func TestHubBackupCallbacksUseTheStore(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	var got hubupgrade.BackupConfig
	app.hubBackup = func(_ context.Context, cfg hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
		got = cfg
		return hubupgrade.BackupReceipt{Status: "staged", OperationID: strings.Repeat("b", 32)}, nil
	}
	decodeHubBackup(t, b.post(hubBackupPath, url.Values{"target_version": {"1.0.1"}}), http.StatusOK)

	ctx := context.Background()
	dst := filepath.Join(t.TempDir(), backup.SingleDBName)
	if err := got.Vacuum(ctx, dst); err != nil {
		t.Fatalf("VACUUM callback: %v", err)
	}
	info, err := os.Lstat(dst)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("VACUUM produced no copy: %v", err)
	}
	if err := got.Integrity(ctx, dst); err != nil {
		t.Fatalf("integrity callback: %v", err)
	}
	schema, err := got.Schema(ctx)
	if err != nil || schema != databaseSchemaVersion {
		t.Fatalf("schema callback = %d, %v", schema, err)
	}
	if err := got.Space(got.DataDir, 1); err != nil {
		t.Fatalf("space callback: %v", err)
	}
}

func TestApprovalReadTakesTheFlatSlotLock(t *testing.T) {
	_, app := databaseMigrationBrowser(t)
	operationID := strings.Repeat("c", 32)
	hubDatabaseRecord(t, app.store.dir, operationID, nil)
	unlock := hubupgrade.LockFlatSlot()
	done := make(chan error, 1)
	go func() {
		_, err := app.store.approveIrreversibleMigration(operationID, true)
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("approval read ignored the shared flat-slot lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("approval after unlock: %v", err)
	}
	record, err := backup.Read(filepath.Join(app.store.dir, databaseBackupDirName), operationID, backup.LayoutFlat, os.Geteuid())
	if err != nil || !record.IrreversibleApproved {
		t.Fatalf("approval did not store the bit: %+v %v", record, err)
	}
}
