package web

// Tests for the #11d Task 5 Web surface: the handoff route, the journal
// authoritative readback adapter, and the lifecycle wiring (startup reconcile
// before the identity refresher, then a 30s reconcile ticker).
//
// The review gates are TestApplyReceipt (queued is the honest maximum, and the
// form never supplies the target) and TestNoSchema11 (D3: no mirror table and no
// schema bump; the journal survives a restore on schema 10).

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const hubApplyPath = "/tasks/hub-upgrade/apply"

type hubApplyReceiptJSON struct {
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	OperationID   string `json:"operation_id"`
	TargetVersion string `json:"target_version"`
	PackageSHA256 string `json:"package_sha256"`
	ErrorCode     string `json:"error_code"`
	Detail        string `json:"detail"`
	NextAction    string `json:"next_action"`
}

func decodeHubApply(t *testing.T, w *httptest.ResponseRecorder, status int) hubApplyReceiptJSON {
	t.Helper()
	requireStatus(t, w, status)
	var receipt hubApplyReceiptJSON
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("hub apply receipt: %v %.300s", err, w.Body.String())
	}
	return receipt
}

// TestApplyReceipt pins the success receipt and the handoff config the route
// builds: the form supplies only the operation id, and the target, package and
// digests come from the journal, the record and the root manifest.
func TestApplyReceipt(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	operationID := strings.Repeat("a", 32)
	var got hubupgrade.HandoffConfig
	app.hubApply = func(_ context.Context, cfg hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error) {
		got = cfg
		return hubupgrade.HandoffReceipt{
			Status: "queued", OperationID: cfg.OperationID,
			TargetVersion: "1.0.1", PackageSHA256: strings.Repeat("b", 64),
		}, nil
	}
	receipt := decodeHubApply(t, b.post(hubApplyPath,
		url.Values{"operation_id": {operationID}}), http.StatusOK)
	if !receipt.OK || receipt.Status != "queued" || receipt.OperationID != operationID ||
		receipt.TargetVersion != "1.0.1" || receipt.PackageSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("receipt: %+v", receipt)
	}
	if got.DataDir != app.store.dir || got.OperationID != operationID ||
		got.ManifestDir != hubupgrade.RootManifestDir || got.RequestDir != hubupgrade.RequestDir {
		t.Fatalf("handoff config: %+v", got)
	}
	if got.Space == nil || got.Fetch != nil {
		t.Fatalf("handoff config callbacks: %+v", got)
	}

	// The mutation boundary stays the existing one: session, exact Origin and
	// CSRF are all still required.
	requireStatus(t, b.req("POST", hubApplyPath,
		url.Values{"operation_id": {operationID}}, nil), http.StatusForbidden)
	requireStatus(t, b.req("POST", hubApplyPath,
		url.Values{"operation_id": {operationID}, "csrf": {b.csrf}},
		http.Header{"Origin": {"https://evil.example.invalid"}}), http.StatusForbidden)
	anonymous := &browser{app: app}
	requireStatus(t, anonymous.req("POST", hubApplyPath,
		url.Values{"operation_id": {operationID}, "csrf": {b.csrf}}, nil), http.StatusUnauthorized)
}

// TestApplyRejectsMalformedOperation pins the pre-gate: an operation id that is
// not 32 lowercase hex never reaches the handoff, so it can never become a
// journal or request path.
func TestApplyRejectsMalformedOperation(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	called := false
	app.hubApply = func(context.Context, hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error) {
		called = true
		return hubupgrade.HandoffReceipt{}, nil
	}
	for _, id := range []string{"", "latest", strings.Repeat("A", 32), strings.Repeat("a", 31), "../" + strings.Repeat("a", 29)} {
		receipt := decodeHubApply(t, b.post(hubApplyPath,
			url.Values{"operation_id": {id}}), http.StatusBadRequest)
		if receipt.OK || receipt.ErrorCode != "HUB_HANDOFF_REQUEST_INVALID" {
			t.Fatalf("operation %q receipt: %+v", id, receipt)
		}
	}
	if called {
		t.Fatal("a malformed operation id reached the handoff")
	}
}

// TestApplyFailureCodes pins the code-to-status mapping and that a refusal never
// claims queued.
func TestApplyFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
	}{
		{"HUB_HANDOFF_INVALID_STATE", http.StatusConflict},
		{"HUB_UPGRADE_BUSY", http.StatusConflict},
		{"MANIFEST_UNAVAILABLE", http.StatusConflict},
		{"HUB_MANIFEST_PACKAGE_MISMATCH", http.StatusConflict},
		{"IRREVERSIBLE_CONFIRM_REQUIRED", http.StatusConflict},
		{"HUB_SPACE_INSUFFICIENT", http.StatusConflict},
		{"UPDATE_BACKUP_MISSING", http.StatusNotFound},
		{"UPDATE_BACKUP_CORRUPT", http.StatusConflict},
		{"HUB_BACKUP_STAGE_FAILED", http.StatusInternalServerError},
		{"HUB_HANDOFF_WRITE_FAILED", http.StatusInternalServerError},
	} {
		t.Run(tc.code, func(t *testing.T) {
			b, app := databaseMigrationBrowser(t)
			app.hubApply = func(context.Context, hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error) {
				return hubupgrade.HandoffReceipt{}, &hubApplyError{code: tc.code}
			}
			receipt := decodeHubApply(t, b.post(hubApplyPath,
				url.Values{"operation_id": {strings.Repeat("a", 32)}}), tc.status)
			if receipt.OK || receipt.Status == "queued" || receipt.ErrorCode != tc.code {
				t.Fatalf("failure receipt: %+v", receipt)
			}
			if receipt.Detail == "" || receipt.NextAction == "" {
				t.Fatalf("refusal without an operator hint: %+v", receipt)
			}
		})
	}
}

type hubApplyError struct{ code string }

func (e *hubApplyError) Error() string { return e.code + ": injected refusal" }

// TestNoSchema11 pins D3: the Hub self-upgrade introduces no mirror table and no
// schema bump. `user_version` stays 10 and the deleted mirror table does not
// exist anywhere in the migrated database. The name is assembled at run time so
// the mechanical "no mirror DDL" grep over internal/ stays empty: only the
// absence assertion may mention it.
func TestNoSchema11(t *testing.T) {
	app, _ := testApp(t)
	if databaseSchemaVersion != 10 {
		t.Fatalf("databaseSchemaVersion = %d, want the frozen 10", databaseSchemaVersion)
	}
	var version int
	if err := app.store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 10 {
		t.Fatalf("user_version = %d, want 10", version)
	}
	mirrorTable := "hub_upgrade_" + "operations"
	var tables int
	if err := app.store.db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, mirrorTable).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("the deleted " + mirrorTable + " mirror table exists")
	}
}

// TestNewRunsStartupReconcile pins the lifecycle wiring: New installs the
// journal adapter and runs the one startup pass before the identity refresher,
// so a verifying operation whose running identity matches is confirmed (record,
// journal and flat pointer) without any request.
func TestNewRunsStartupReconcile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	digest, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("f", 32)
	record := plantWebVerifiedRecord(t, dir, operationID, buildinfo.Version, digest)
	if err := hubupgrade.WriteOp(dir, hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: operationID, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateVerifying, TargetVersion: buildinfo.Version, FromVersion: "0.9.0",
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: digest,
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	app, err := New(Config{Listen: "127.0.0.1:9080", Origin: testOrigin, DataDir: dir},
		slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Close is deferred after the assertions: the startup pass must already have
	// completed before New returned.
	op, ok, err := hubupgrade.ReadOp(dir, operationID, os.Geteuid())
	if err != nil || !ok {
		t.Fatalf("journal: ok=%v err=%v", ok, err)
	}
	if op.State != hubupgrade.StateConfirmed {
		t.Fatalf("journal state = %s, want confirmed (logs: %s)", op.State, logs.String())
	}
	stored, err := backup.Read(filepath.Join(dir, databaseBackupDirName), operationID, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != backup.StateConfirmed || stored.ConfirmedAt == nil {
		t.Fatalf("record = %+v, want confirmed", stored)
	}
	if _, err := os.Lstat(filepath.Join(dir, databaseBackupDirName, backup.RecordName)); err != nil {
		t.Fatalf("the flat pointer was not refreshed: %v", err)
	}
	if record.State != backup.StateStaged {
		t.Fatalf("the fixture record was not staged before New: %q", record.State)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileTickerAdvancesJournal pins the 30s lifecycle twin: the ticker
// advances the journal without a browser, applies the orphan timeout, and Close
// stops it.
func TestReconcileTickerAdvancesJournal(t *testing.T) {
	app, _ := testApp(t)
	app.reconcileInterval = time.Millisecond
	operationID := strings.Repeat("1", 32)
	if err := hubupgrade.WriteOp(app.store.dir, hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: operationID, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateBackingUp, TargetVersion: "1.0.1", FromVersion: "1.0.0-dev",
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("c", 64),
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: time.Now().UTC().Add(-hubupgrade.OrphanTimeout - time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	app.startHubUpgradeReconcile(t.Context())
	deadline := time.Now().Add(5 * time.Second)
	for {
		op, ok, err := hubupgrade.ReadOp(app.store.dir, operationID, os.Geteuid())
		if err == nil && ok && op.State == hubupgrade.StateFailed && op.ErrorCode == "HUB_BACKUP_ORPHANED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ticker never failed the orphan: ok=%v err=%v op=%+v", ok, err, op)
		}
		time.Sleep(time.Millisecond)
	}
	app.stopHubUpgradeReconcile()
}

// plantWebVerifiedRecord writes one readable per-operation generation whose
// payload is a fixture copy. backup.Verify only re-hashes the file, so a fixture
// copy is sufficient for the identity wiring.
func plantWebVerifiedRecord(t *testing.T, dataDir, operationID, target, packageSHA string) backup.Record {
	t.Helper()
	root := filepath.Join(dataDir, databaseBackupDirName)
	opDir, err := backup.Dir(root, operationID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := backup.Write(root, backup.Spec{
		OperationID: operationID, FromVersion: "0.9.0", TargetVersion: target,
		DBSchema: 10, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: packageSHA,
	}, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// TestUpgradeViewMergesJournalReadOnly pins the /tasks Hub block input: the
// current journal operation, the latest verified record, the expiry the
// reconcile pass will apply, and the identity snapshot — all read-only, with no
// mirror table and no directory scan.
func TestUpgradeViewMergesJournalReadOnly(t *testing.T) {
	app, _ := testApp(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	operationID := strings.Repeat("d", 32)
	plantWebVerifiedRecord(t, app.store.dir, operationID, "1.0.1", strings.Repeat("c", 64))
	updated := now.Add(-time.Minute)
	if err := hubupgrade.WriteOp(app.store.dir, hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: operationID, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateBackedUp, TargetVersion: "1.0.1", FromVersion: "1.0.0-dev",
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("c", 64),
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: updated,
	}); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(app.store.dir, hubupgrade.OpsDir, operationID+".json")
	recordPath := filepath.Join(app.store.dir, databaseBackupDirName, operationID, backup.RecordName)
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	recordBefore, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}

	view, err := app.upgradeView(now)
	if err != nil {
		t.Fatalf("upgradeView: %v", err)
	}
	if !view.Hub.HasOp || view.Hub.Op.OperationID != operationID || view.Hub.Op.State != hubupgrade.StateBackedUp {
		t.Fatalf("Hub op: %+v", view.Hub)
	}
	if !view.Hub.HasRecord || view.Hub.Record.OperationID != operationID {
		t.Fatalf("Hub record: %+v", view.Hub)
	}
	if !view.Hub.ExpiresAt.Equal(updated.Add(hubupgrade.OrphanTimeout)) {
		t.Fatalf("expiry = %v, want %v", view.Hub.ExpiresAt, updated.Add(hubupgrade.OrphanTimeout))
	}
	if view.Hub.HasResult || view.Hub.HasRestored || view.Hub.Err != "" || view.Hub.ResultErr != "" {
		t.Fatalf("unexpected Hub block evidence: %+v", view.Hub)
	}
	if !view.Hub.Identity.Confirmed() {
		t.Fatalf("identity snapshot: %+v", view.Hub.Identity)
	}
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	recordAfter, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(journalBefore) != string(journalAfter) || string(recordBefore) != string(recordAfter) {
		t.Fatal("the /tasks view changed the journal or the record")
	}
}
