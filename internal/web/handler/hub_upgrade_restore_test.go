package handler

// Tests for the #11d Task 7 restore route. The route is one authenticated
// mutation on the existing boundary: it never claims a restored host, it only
// queues one request for the old package's root executor and refuses a live
// handoff, a pending request and a carried record.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
)

const hubRestorePath = "/tasks/hub-upgrade/restore"

type hubRestoreReceiptJSON struct {
	OK          bool   `json:"ok"`
	Status      string `json:"status"`
	OperationID string `json:"operation_id"`
	ErrorCode   string `json:"error_code"`
	Detail      string `json:"detail"`
	NextAction  string `json:"next_action"`
}

func decodeHubRestore(t *testing.T, w *httptest.ResponseRecorder, status int) hubRestoreReceiptJSON {
	t.Helper()
	requireStatus(t, w, status)
	var receipt hubRestoreReceiptJSON
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("hub restore receipt: %v %.300s", err, w.Body.String())
	}
	return receipt
}

// plantHubRestoreOperation writes the journal entry and per-operation record a
// failed upgrade leaves behind. The record is metadata-only here; the root
// executor is the only consumer that opens the payload.
func plantHubRestoreOperation(t *testing.T, app *Server, state hubupgrade.State) (string, hubupgrade.Op) {
	t.Helper()
	operationID := strings.Repeat("a", 32)
	_, record := hubDatabaseRecord(t, app.store.Dir, operationID, nil)
	op := hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: operationID, Kind: hubupgrade.KindUpdate,
		State: state, TargetVersion: "1.0.1", FromVersion: "1.0.0",
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: strings.Repeat("c", 64),
		DBSchema: record.DBSchema, BackupGeneration: 1, UpdatedAt: time.Now().UTC(),
	}
	if err := hubupgrade.WriteOp(app.store.Dir, op); err != nil {
		t.Fatal(err)
	}
	return operationID, op
}

func TestRestoreReceipt(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	app.hubRequestDir = filepath.Join(t.TempDir(), "requests")
	operationID, _ := plantHubRestoreOperation(t, app, hubupgrade.StateFailed)

	receipt := decodeHubRestore(t, b.post(hubRestorePath,
		url.Values{"operation_id": {operationID}}), http.StatusOK)
	if !receipt.OK || receipt.Status != "restoring" || receipt.OperationID != operationID {
		t.Fatalf("receipt: %+v", receipt)
	}
	request, err := hubupgrade.ReadRequest(filepath.Join(app.hubRequestDir, operationID+".json"), os.Geteuid())
	if err != nil {
		t.Fatalf("queued request: %v", err)
	}
	if request.Kind != hubupgrade.KindRestore || request.OperationID != operationID ||
		request.DataDir != app.store.Dir {
		t.Fatalf("request = %+v", request)
	}

	// The successful receipt still required the existing mutation boundary.
	requireStatus(t, b.req("POST", hubRestorePath,
		url.Values{"operation_id": {operationID}}, nil), http.StatusForbidden)
	anonymous := &browser{app: app}
	requireStatus(t, anonymous.req("POST", hubRestorePath,
		url.Values{"operation_id": {operationID}, "csrf": {b.csrf}},
		http.Header{"Origin": {"https://evil.example.invalid"}}), http.StatusForbidden)
}

func TestRestoreSecondRequestBusy(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	app.hubRequestDir = filepath.Join(t.TempDir(), "requests")
	operationID, _ := plantHubRestoreOperation(t, app, hubupgrade.StateFailed)
	if _, err := hubupgrade.WriteRequest(app.hubRequestDir, hubupgrade.Request{
		Schema: hubupgrade.RequestSchema, Kind: hubupgrade.KindRestore,
		OperationID: operationID, DataDir: app.store.Dir,
	}); err != nil {
		t.Fatal(err)
	}
	receipt := decodeHubRestore(t, b.post(hubRestorePath,
		url.Values{"operation_id": {operationID}}), http.StatusConflict)
	if receipt.OK || receipt.ErrorCode != "HUB_HANDOFF_BUSY" || receipt.NextAction == "" {
		t.Fatalf("busy receipt: %+v", receipt)
	}
}

func TestRestoreRejectsLiveOperation(t *testing.T) {
	for _, state := range []hubupgrade.State{
		hubupgrade.StateBackedUp, hubupgrade.StateQueued, hubupgrade.StateApplying,
		hubupgrade.StateRestarting, hubupgrade.StateConfirmed, hubupgrade.StateReverted,
	} {
		t.Run(string(state), func(t *testing.T) {
			b, app := databaseMigrationBrowser(t)
			app.hubRequestDir = filepath.Join(t.TempDir(), "requests")
			operationID, _ := plantHubRestoreOperation(t, app, state)
			receipt := decodeHubRestore(t, b.post(hubRestorePath,
				url.Values{"operation_id": {operationID}}), http.StatusConflict)
			if receipt.OK || receipt.ErrorCode != "HUB_UPGRADE_BUSY" {
				t.Fatalf("state %s receipt: %+v", state, receipt)
			}
			if _, err := os.Stat(filepath.Join(app.hubRequestDir, operationID+".json")); !os.IsNotExist(err) {
				t.Fatal("a request was queued for a live operation")
			}
		})
	}
}

// TestRestoreRouteDoesNotListRequestDir is the EACCES regression: the watched
// requests directory is 0730 root:meshmux, so the Web has write+execute and no
// read. 0330 on the owner reproduces exactly that shape for an unprivileged
// test. The route must decide via a single-name Lstat, not ReadDir, or a live
// request turns into HUB_HANDOFF_REQUEST_INVALID after the journal is settled.
func TestRestoreRouteDoesNotListRequestDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0330 directory; the mode simulation needs an unprivileged uid")
	}
	b, app := databaseMigrationBrowser(t)
	parent := t.TempDir()
	app.hubRequestDir = filepath.Join(parent, "requests")
	if err := os.Mkdir(app.hubRequestDir, 0730); err != nil {
		t.Fatal(err)
	}
	operationID, _ := plantHubRestoreOperation(t, app, hubupgrade.StateFailed)
	if err := os.Chmod(app.hubRequestDir, 0330); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(app.hubRequestDir, 0730) })

	receipt := decodeHubRestore(t, b.post(hubRestorePath,
		url.Values{"operation_id": {operationID}}), http.StatusOK)
	if receipt.Status != "restoring" {
		t.Fatalf("receipt: %+v", receipt)
	}
	if _, err := os.Lstat(filepath.Join(app.hubRequestDir, operationID+".json")); err != nil {
		t.Fatalf("request was not published through a write-only directory: %v", err)
	}

	// A request already at the known name is busy without listing the dir.
	busy := decodeHubRestore(t, b.post(hubRestorePath,
		url.Values{"operation_id": {operationID}}), http.StatusConflict)
	if busy.ErrorCode != "HUB_HANDOFF_BUSY" {
		t.Fatalf("existing request receipt: %+v", busy)
	}
}

func TestRestoreRejectsCarriedRecord(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	app.hubRequestDir = filepath.Join(t.TempDir(), "requests")
	operationID, _ := plantHubRestoreOperation(t, app, hubupgrade.StatePartial)
	marker := hubupgrade.RestoredMarker{
		Schema: hubupgrade.RestoredSchema, OperationID: operationID,
		SnapshotAt: time.Now().Add(-time.Hour).UTC(), Lossy: true,
	}
	if err := writeTestRestoredMarker(app, marker); err != nil {
		t.Fatal(err)
	}
	receipt := decodeHubRestore(t, b.post(hubRestorePath,
		url.Values{"operation_id": {operationID}}), http.StatusConflict)
	if receipt.OK || receipt.ErrorCode != "HUB_RESTORE_CARRIED_SOURCE" {
		t.Fatalf("carried record receipt: %+v", receipt)
	}
}

// writeTestRestoredMarker publishes a fixture marker with the frozen shape; the
// production writer is hubupgrade's reconcile pass.
func writeTestRestoredMarker(app *Server, marker hubupgrade.RestoredMarker) error {
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(app.store.Dir, hubupgrade.HubUpgradeDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "restored.json"), body, 0600)
}

func TestRestoreRejectsMalformedOperation(t *testing.T) {
	b, app := databaseMigrationBrowser(t)
	app.hubRequestDir = filepath.Join(t.TempDir(), "requests")
	for _, id := range []string{"", "latest", strings.Repeat("A", 32), strings.Repeat("a", 31)} {
		receipt := decodeHubRestore(t, b.post(hubRestorePath,
			url.Values{"operation_id": {id}}), http.StatusBadRequest)
		if receipt.ErrorCode != "HUB_HANDOFF_REQUEST_INVALID" {
			t.Fatalf("operation %q receipt: %+v", id, receipt)
		}
	}
	if entries, err := os.ReadDir(app.hubRequestDir); err == nil && len(entries) != 0 {
		t.Fatal("a malformed operation queued a request")
	}
}
