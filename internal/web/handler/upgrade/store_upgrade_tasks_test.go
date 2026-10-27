package upgrade_test

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// stampTargetTx drives the transaction-scoped stamp the way the approval path
// does: one transaction, committed here.
func stampTargetTx(app *handler.Server, operationID string, target upgrade.Target) error {
	tx, err := app.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := store.StampUpgradeTargetTx(tx, operationID, target, app.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// TestUpgradeTaskRecordRoundTripAndPage pins #11b: the target release snapshot
// rides on the existing pending task row, the /tasks view prefers it over the
// #11a derivation, and no upgrade kind becomes deliverable.
func TestUpgradeTaskRecordRoundTripAndPage(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	created, code := handlertest.CreatePendingNode(t, app, "edge", "upgrade-record", 8443, 2222)
	handlertest.RequireStatus(t, handlertest.PairJSON(t, app, created.ID, "edge", code), 200)
	latest, err := app.Store.LatestCandidate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	tasks := handlertest.FixedTasksForRevision(t, app, created.ID, latest.Revision)
	target := upgrade.Target{
		Version: "1.2.3", ManifestSHA256: strings.Repeat("cd", 32),
		PolicySchema: upgrade.PolicySchema, CandidateRevision: latest.Revision,
	}
	if err := stampTargetTx(app, "", target); err == nil {
		t.Fatal("empty operation_id accepted")
	}
	bad := target
	bad.Version = "latest"
	if err := stampTargetTx(app, tasks[1].OperationID, bad); err == nil {
		t.Fatal("floating target accepted")
	}
	if err := stampTargetTx(app, tasks[1].OperationID, target); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.ReportResultAudited(created.ID, protocol.TaskResult{
		OperationID: tasks[1].OperationID, Status: "healthy",
	}, app.Now()); err != nil {
		t.Fatal(err)
	}
	if err := stampTargetTx(app, tasks[1].OperationID, target); err == nil {
		t.Fatal("healthy task accepted a new target")
	}
	staged, err := app.Store.StagedReadbacks()
	if err != nil {
		t.Fatal(err)
	}
	got := staged[created.ID]
	if got.Derived || got.TargetVersion != target.Version || got.ManifestSHA256 != target.ManifestSHA256 ||
		got.PolicySchema != target.PolicySchema || got.Revision != latest.Revision || got.ConfigSHA256 != latest.ConfigSHA256 {
		t.Fatalf("staged record = %+v", got)
	}

	b := &handlertest.Browser{App: app}
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)
	body := b.Req("GET", "/tasks", nil, nil).Body.String()
	for _, want := range []string{target.Version, target.ManifestSHA256, "policy_schema 8", "upgrade-record"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	if strings.Contains(body, `<span class="badge">派生</span>`) {
		t.Fatal("a persisted record was still shown as derived")
	}

	// The persisted record does not widen the Agent allowlist: the same kernel
	// that stores upgrade targets still rejects an upgrade kind.
	task := protocol.Task{
		Schema: protocol.Schema, Version: protocol.Version, OperationID: tasks[1].OperationID,
		Revision: 99, IdempotencyKey: tasks[1].OperationID, NodeID: created.ID,
		Kind: "upgrade.agent", Params: []byte(`{}`),
	}
	if err := protocol.ValidateTask(task); err == nil || !strings.Contains(err.Error(), "UPGRADE_NOT_IMPLEMENTED") {
		t.Fatalf("upgrade kind = %v, want UPGRADE_NOT_IMPLEMENTED", err)
	}
}
