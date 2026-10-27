package handler

// HTTP tests for the Hub backup producer surface (#11d Task 3r, spec §5.2): one
// authenticated management mutation on the existing boundary, with the callbacks
// the Web process alone can supply (VACUUM, integrity check, real user_version,
// free space). The producer itself is tested in internal/cli/hubupgrade; here we
// prove the route, the receipt and the wiring of the store-backed callbacks.

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

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
)

const hubBackupPath = "/tasks/hub-upgrade/backup"

type hubBackupReceiptJSON struct {
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	OperationID   string `json:"operation_id"`
	FromVersion   string `json:"from_version"`
	DBSchema      int64  `json:"db_schema"`
	IntegrityOK   bool   `json:"integrity_ok"`
	ErrorCode     string `json:"error_code"`
	Detail        string `json:"detail"`
	NextAction    string `json:"next_action"`
	TargetVersion string `json:"target_version"`
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

// TestHubBackupReceipt pins the success receipt and the producer config the route
// builds: the store's data directory, the root manifest directory, and all four
// database callbacks plus the pointer publisher.
func TestHubBackupReceipt(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	operationID := strings.Repeat("a", 32)
	var got hubupgrade.BackupConfig
	app.upgradeServer.SetHubBackupForTest(func(_ context.Context, cfg hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
		got = cfg
		return hubupgrade.BackupReceipt{
			Status: "staged", OperationID: operationID, FromVersion: "1.0.0",
			DBSchema: 10, IntegrityOK: true,
		}, nil
	})
	receipt := decodeHubBackup(t, b.post(hubBackupPath,
		url.Values{"target_version": {"1.0.1"}}), http.StatusOK)
	if !receipt.OK || receipt.Status != "staged" || receipt.OperationID != operationID ||
		receipt.FromVersion != "1.0.0" || receipt.DBSchema != 10 || !receipt.IntegrityOK {
		t.Fatalf("receipt: %+v", receipt)
	}
	if got.DataDir != app.Store.Dir || got.Target != "1.0.1" ||
		got.ManifestDir != hubupgrade.RootManifestDir {
		t.Fatalf("producer config: %+v", got)
	}
	if got.Vacuum == nil || got.Integrity == nil || got.Schema == nil || got.Space == nil {
		t.Fatalf("Web callbacks are incomplete: %+v", got)
	}
	if got.PublishPointer == nil {
		t.Fatal("the route does not wire the flat pointer publisher")
	}

	// The mutation boundary stays the existing one: session, exact Origin and
	// CSRF are all still required.
	requireStatus(t, b.req("POST", hubBackupPath,
		url.Values{"target_version": {"1.0.1"}}, nil), http.StatusForbidden)
	requireStatus(t, b.req("POST", hubBackupPath,
		url.Values{"target_version": {"1.0.1"}, "csrf": {b.csrf}},
		http.Header{"Origin": {"https://evil.example.invalid"}}), http.StatusForbidden)
	anonymous := &browser{app: app}
	requireStatus(t, anonymous.req("POST", hubBackupPath,
		url.Values{"target_version": {"1.0.1"}, "csrf": {b.csrf}}, nil), http.StatusUnauthorized)
}

// TestHubBackupRejectsMalformedTarget pins the pre-gate: a target that is not a
// SemVer release never reaches the producer, so it can never become a manifest
// path.
func TestHubBackupRejectsMalformedTarget(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	called := false
	app.upgradeServer.SetHubBackupForTest(func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
		called = true
		return hubupgrade.BackupReceipt{}, nil
	})
	for _, target := range []string{"", "latest", "1.0", "../1.0.1", "1.0.1/../../etc"} {
		receipt := decodeHubBackup(t, b.post(hubBackupPath,
			url.Values{"target_version": {target}}), http.StatusBadRequest)
		if receipt.OK || receipt.ErrorCode != "MANIFEST_UNAVAILABLE" {
			t.Fatalf("target %q receipt: %+v", target, receipt)
		}
	}
	if called {
		t.Fatal("a malformed target reached the producer")
	}
}

// TestHubBackupFailureCodes pins the code-to-status mapping and that a refusal
// never claims staged.
func TestHubBackupFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		err    string
		status int
	}{
		{"HUB_UPGRADE_BUSY: another operation is in flight", http.StatusConflict},
		{"MANIFEST_UNAVAILABLE: no root manifest", http.StatusConflict},
		{"HUB_SPACE_INSUFFICIENT: need more space", http.StatusConflict},
		{"HUB_BACKUP_INTEGRITY_FAILED: copy not ok", http.StatusInternalServerError},
		{"HUB_BACKUP_POINTER_STALE: pointer not refreshed", http.StatusInternalServerError},
	} {
		t.Run(strings.SplitN(tc.err, ":", 2)[0], func(t *testing.T) {
			b, app := databaseMigrationBrowser(t)
			app.upgradeServer.SetHubBackupForTest(func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
				return hubupgrade.BackupReceipt{}, &hubBackupError{tc.err}
			})
			receipt := decodeHubBackup(t, b.post(hubBackupPath,
				url.Values{"target_version": {"1.0.1"}}), tc.status)
			if receipt.OK || receipt.Status == "staged" ||
				receipt.ErrorCode != strings.SplitN(tc.err, ":", 2)[0] {
				t.Fatalf("failure receipt: %+v", receipt)
			}
			if receipt.Detail == "" || receipt.NextAction == "" {
				t.Fatalf("refusal without an operator hint: %+v", receipt)
			}
		})
	}
}

type hubBackupError struct{ text string }

func (e *hubBackupError) Error() string { return e.text }

// TestHubBackupCallbacksUseTheStore runs the real store-backed callbacks: VACUUM
// INTO a fresh path, integrity_check on the copy, the live user_version (the
// owned storage schema) and the free-space check.
func TestHubBackupCallbacksUseTheStore(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	var got hubupgrade.BackupConfig
	app.upgradeServer.SetHubBackupForTest(func(_ context.Context, cfg hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
		got = cfg
		return hubupgrade.BackupReceipt{Status: "staged", OperationID: strings.Repeat("b", 32)}, nil
	})
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
	if err != nil || schema != int64(store.DatabaseSchemaVersion) {
		t.Fatalf("schema callback = %d, %v want %d", schema, err, store.DatabaseSchemaVersion)
	}
	if err := got.Space(got.DataDir, 1); err != nil {
		t.Fatalf("space callback: %v", err)
	}
	// VACUUM refuses an existing target, so a second call on the same path must
	// fail closed instead of overwriting the first copy.
	if err := got.Vacuum(ctx, dst); err == nil {
		t.Fatal("VACUUM overwrote an existing destination")
	}
}

// TestHubBackupRouteDoesNotReadTheApprovalBit pins R2 on the boundary: the route
// hands the producer no record and no approval bit, so an approved-but-inert
// record can never turn into a BUSY at the HTTP layer.
func TestHubBackupRouteDoesNotReadTheApprovalBit(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	operationID := strings.Repeat("d", 32)
	hubDatabaseRecord(t, app.Store.Dir, operationID, func(record *backup.Record) {
		record.IrreversibleApproved = true
	})
	var got hubupgrade.BackupConfig
	app.upgradeServer.SetHubBackupForTest(func(_ context.Context, cfg hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error) {
		got = cfg
		return hubupgrade.BackupReceipt{Status: "staged", OperationID: strings.Repeat("e", 32), IntegrityOK: true}, nil
	})
	receipt := decodeHubBackup(t, b.post(hubBackupPath,
		url.Values{"target_version": {"1.0.1"}}), http.StatusOK)
	if !receipt.OK || receipt.Status != "staged" {
		t.Fatalf("receipt with an approved record: %+v", receipt)
	}
	if got.DataDir == "" {
		t.Fatal("producer config was not built")
	}
}
