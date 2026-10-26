package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"net/http"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// markStagedAndActive drives the two existing task results the read-only
// upgrade view consumes: one healthy config.stage and one healthy
// config.readback. It never calls an upgrade path, because none exists yet.
func markStagedAndActive(t *testing.T, app *Server, nodeID string) int64 {
	t.Helper()
	latest, err := app.store.LatestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	tasks := fixedTasksForRevision(t, app, nodeID, latest.Revision)
	if len(tasks) != 4 {
		t.Fatalf("fixed chain = %d tasks, want 4", len(tasks))
	}
	if _, err = app.store.ReportResultAudited(nodeID, protocol.TaskResult{
		OperationID: tasks[1].OperationID, Status: "healthy",
	}, app.now()); err != nil {
		t.Fatal(err)
	}
	release, ok := node.KernelReleaseFor("amd64")
	if !ok {
		t.Fatal("missing amd64 kernel release")
	}
	detail, err := json.Marshal(node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion(),
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: release.Version,
		KernelSHA256: release.BinarySHA256, ActiveRevision: latest.Revision,
		ConfigSHA256: latest.ConfigSHA256, LocalActive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.store.ReportResultAudited(nodeID, protocol.TaskResult{
		OperationID: tasks[3].OperationID, Status: "healthy", Detail: string(detail),
	}, app.now()); err != nil {
		t.Fatal(err)
	}
	return latest.Revision
}

// TestUpgradePageShowsManifestAndStagedVersusActive pins the read-only readback
// of #11a: the manifest comes from the pinned tables and each node shows its
// staged revision next to the observed active one.
func TestUpgradePageShowsManifestAndStagedVersusActive(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "upgrade-line", 8443, 2222)
	requireStatus(t, pairJSON(t, app, created.ID, "edge", code), 200)
	if revision := markStagedAndActive(t, app, created.ID); revision != 1 {
		t.Fatalf("staged revision = %d, want 1", revision)
	}

	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.req("GET", "/tasks", nil, nil)
	requireStatus(t, w, 200)
	body := w.Body.String()
	for _, want := range []string{"meshmux-release/v1", node.CurrentAgentVersion(), "2.11.7", "0.29.5",
		"1.14.3", "1.19.32", "policy_schema", "route_policy_revisions", "upgrade-line",
		"staged 已回读为 active", "rev 1", `<span class="badge">派生</span>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	// The view offers one gated approval and no direct apply/rollback control.
	for _, forbidden := range []string{"升级到此版本", "立即升级", `/tasks/apply`, `/tasks/upgrade`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("page offered %q", forbidden)
		}
	}
	// #11c-1 replaced the read-only boundary with a gated approval: the page
	// says that a queued chain is not an applied release.
	for _, want := range []string{"逐台批准", "queued", "不等于已生效"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page does not declare %q", want)
		}
	}
	if w = (&browser{app: app}).req("GET", "/tasks", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /tasks status=%d, want 401", w.Code)
	}
}

// TestUpgradePageWithoutNodesIsExplicit keeps an empty Hub from implying that it
// has converged or that it has a staged release.
func TestUpgradePageWithoutNodesIsExplicit(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.req("GET", "/tasks", nil, nil)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "尚未纳管节点") {
		t.Fatal("empty Hub did not state that there is nothing to show")
	}
	view, err := app.upgradeView(app.now())
	if err != nil {
		t.Fatal(err)
	}
	if view.ManifestErr != "" || len(view.Nodes) != 0 {
		t.Fatalf("empty snapshot = %+v", view)
	}
}

// TestStagedReadbackRequiresAStoredCandidate refuses a stage row whose params no
// longer name a stored candidate: the page must not invent a revision.
func TestStagedReadbackRequiresAStoredCandidate(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "corrupt-stage", 8443, 2222)
	requireStatus(t, pairJSON(t, app, created.ID, "edge", code), 200)
	markStagedAndActive(t, app, created.ID)
	if _, err := app.store.DB.Exec(`UPDATE agent_tasks SET params='{"revision":99}' WHERE node_id=? AND kind=? AND status='healthy'`,
		created.ID, protocol.KindConfigStage); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.StagedReadbacks(); err == nil || !strings.Contains(err.Error(), "STAGED_READBACK_CORRUPT") {
		t.Fatalf("staged readback err=%v, want STAGED_READBACK_CORRUPT", err)
	}
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.req("GET", "/tasks", nil, nil)
	requireStatus(t, w, 503)
	if !strings.Contains(w.Body.String(), "UPGRADE_SNAPSHOT_UNAVAILABLE") {
		t.Fatal("page did not refuse an undecodable staged readback")
	}
}

// TestStagedReadbackIsTheNewestHealthyStage pins that an older healthy stage
// cannot shadow the newest one after a later stage succeeds.
func TestStagedReadbackIsTheNewestHealthyStage(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "two-stages", 8443, 2222)
	requireStatus(t, pairJSON(t, app, created.ID, "edge", code), 200)
	first := markStagedAndActive(t, app, created.ID)
	task, err := store.NewFixedTask(created.ID, protocol.KindConfigStage, json.RawMessage(`{"revision":1}`), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.store.EnqueueTaskAt(task, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err = app.store.ReportResultAudited(created.ID, protocol.TaskResult{OperationID: task.OperationID, Status: "healthy"}, app.now()); err != nil {
		t.Fatal(err)
	}
	staged, err := app.store.StagedReadbacks()
	if err != nil {
		t.Fatal(err)
	}
	if got := staged[created.ID]; got.Revision != first || got.OperationID != task.OperationID {
		t.Fatalf("staged readback = %+v, want the newest healthy stage", got)
	}
}

// TestUpgradePolicyRevisionsReadLiveLayers pins that the page's live policy
// revisions come from the store's active rows, not from the manifest.
func TestUpgradePolicyRevisionsReadLiveLayers(t *testing.T) {
	app, _ := testApp(t)
	view, err := app.upgradeView(app.now())
	if err != nil {
		t.Fatal(err)
	}
	if view.LivePolicyRevisions["client"] != 0 || view.LivePolicyRevisions["server"] != 0 {
		t.Fatalf("live policy revisions = %v, want zero before any active policy", view.LivePolicyRevisions)
	}
	if len(view.Manifest.RoutePolicyRevisions) != 0 {
		t.Fatalf("manifest claimed published policy revisions: %v", view.Manifest.RoutePolicyRevisions)
	}
}
