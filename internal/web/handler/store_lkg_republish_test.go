package handler

// LKG republish (#11c-3 Task 4, spec §4.11).
//
// A failed upgrade's explicit rollback target is the Agent's last-known-good
// candidate revision. The Hub republishes that exact revision as a new
// immutable candidate through the existing four-task chain (U5 exemption: the
// rollback target may be behind the current revision). Nothing is stamped on
// the stage row: running == target keeps the plain-stage semantics, so the
// Agent never mistakes the rollback for another upgrade.

import (
	"fmt"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/node"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// lkgFixture creates one paired node whose candidate 1 is the last-known-good
// revision and whose candidate 2 is the current (later) revision. The observed
// revision is the Agent's own readback, which is the LKG source.
func lkgFixture(t *testing.T) (*Server, store.Node) {
	t.Helper()
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "lkg-rollback", 8443, 2222)
	requireStatus(t, pairJSON(t, app, created.ID, "edge", code), 200)
	clearNodeTasks(t, app, created.ID)

	// Publish a later candidate revision, then let its chain finish so the
	// rollback republish has an idle node.
	candidate, err := app.Store.Candidate(created.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := app.Store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	next := candidate.Document.Candidate()
	next.Revision = 2
	if err := store.InsertCandidateTx(tx, next, app.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET observed_revision=1, observed_at=? WHERE id=?`,
		app.Now().Unix(), created.ID); err != nil {
		t.Fatal(err)
	}
	return app, created
}

func pendingTasksForNode(t *testing.T, app *Server, nodeID string) []protocol.Task {
	t.Helper()
	rows, err := app.Store.DB.Query(`SELECT operation_id, revision, kind FROM agent_tasks
 WHERE node_id=? AND status='pending' ORDER BY revision`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tasks []protocol.Task
	for rows.Next() {
		task := protocol.Task{NodeID: nodeID}
		if err := rows.Scan(&task.OperationID, &task.Revision, &task.Kind); err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	return tasks
}

// TestLkgRepublish is the publish property: the observed LKG revision is
// republished as a new immutable revision through the fixed four-task chain,
// carries the same compiled configuration, and leaves the stage row unstamped.
func TestLkgRepublish(t *testing.T) {
	app, created := lkgFixture(t)
	lkg, err := app.Store.Candidate(created.ID, 1)
	if err != nil {
		t.Fatal(err)
	}

	republished, tasks, err := app.Store.RepublishLKG(created.ID, app.Now())
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	if republished.Revision != 3 {
		t.Fatalf("revision = %d, want 3", republished.Revision)
	}
	// The immutable revision advances (the compiled config embeds the revision
	// tag), so the restored CONTENT is what must match: users, REALITY, route,
	// ports, role and kernel. Comparing the compiled digest would demand the
	// impossible (two revisions with one revision tag).
	got, want := republished.Document.Candidate(), lkg.Document.Candidate()
	got.Revision, want.Revision = 0, 0
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("republished candidate = %+v, want the LKG content %+v", got, want)
	}
	if len(tasks) != len(protocol.PublicationKinds) {
		t.Fatalf("tasks = %+v, want the fixed four-task chain", tasks)
	}
	for i, kind := range protocol.PublicationKinds {
		if tasks[i].Kind != kind {
			t.Fatalf("task %d = %q, want %q", i, tasks[i].Kind, kind)
		}
	}
	stage := tasks[0]
	for _, task := range tasks {
		if task.Kind == protocol.KindConfigStage {
			stage = task
		}
	}
	// U5 exemption pins the plain-stage semantics: no upgrade target is
	// stamped, so Agent state.Revision == target is an ordinary local stage.
	if stamped, ok, err := app.Store.StampedStageTarget(created.ID, stage.OperationID); err != nil || ok {
		t.Fatalf("rollback stage carries an upgrade target: %+v, %v", stamped, err)
	}
}

// TestLkgRepublishNoOpIsStillPlainStage pins the explicit no-op case: when the
// LKG revision IS the latest revision, the operator's explicit republish still
// creates a new plain-stage chain instead of silently doing nothing or
// inventing an upgrade target.
func TestLkgRepublishNoOpIsStillPlainStage(t *testing.T) {
	app, created := lkgFixture(t)
	if _, err := app.Store.DB.Exec(`UPDATE nodes SET observed_revision=2 WHERE id=?`, created.ID); err != nil {
		t.Fatal(err)
	}
	republished, tasks, err := app.Store.RepublishLKG(created.ID, app.Now())
	if err != nil {
		t.Fatalf("no-op republish: %v", err)
	}
	if republished.Revision != 3 || len(tasks) != len(protocol.PublicationKinds) {
		t.Fatalf("republished = revision %d, tasks %d", republished.Revision, len(tasks))
	}
	for _, task := range tasks {
		if task.Kind == protocol.KindConfigStage {
			if _, ok, err := app.Store.StampedStageTarget(created.ID, task.OperationID); err != nil || ok {
				t.Fatalf("no-op republish stamped a target: %+v, %v", ok, err)
			}
		}
	}
}

// TestLkgRepublishRefusals pins the fail-closed edges: no observed revision,
// an unknown revision and an unfinished chain are refusals, not a guessed
// target.
func requireRepublishError(t *testing.T, err error, prefix string) {
	t.Helper()
	if err == nil {
		t.Fatalf("republish succeeded, want %s", prefix)
	}
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("error = %v, want %s", err, prefix)
	}
}

func TestLkgRepublishRefusals(t *testing.T) {
	t.Run("no observed revision", func(t *testing.T) {
		app, created := lkgFixture(t)
		if _, err := app.Store.DB.Exec(`UPDATE nodes SET observed_revision=0 WHERE id=?`, created.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err := app.Store.RepublishLKG(created.ID, app.Now())
		requireRepublishError(t, err, "LKG_UNAVAILABLE")
	})
	t.Run("unknown observed revision", func(t *testing.T) {
		app, created := lkgFixture(t)
		if _, err := app.Store.DB.Exec(`UPDATE nodes SET observed_revision=9 WHERE id=?`, created.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err := app.Store.RepublishLKG(created.ID, app.Now())
		requireRepublishError(t, err, "LKG_UNAVAILABLE")
	})
	t.Run("unfinished chain", func(t *testing.T) {
		app, created := lkgFixture(t)
		now := app.Now()
		if _, err := app.Store.DB.Exec(`INSERT INTO agent_tasks(operation_id, node_id, revision, idempotency_key, kind, params, status, created_at, updated_at)
 VALUES(?,?,?,?,?,?, 'pending', ?, ?)`, strings.Repeat("f", 32), created.ID, 99,
			strings.Repeat("f", 32), protocol.KindConfigCheck, `{"revision":1}`, now.Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
		_, _, err := app.Store.RepublishLKG(created.ID, now)
		requireRepublishError(t, err, "TASKS_IN_PROGRESS")
	})
}

// TestLkgRollbackFailureMessages pins the post-commit distinction: a readback
// failure after the chain was committed never says "not published", while
// every pre-commit refusal does.
func TestLkgRollbackFailureMessages(t *testing.T) {
	committed := node.LKGRollbackFailure(fmt.Errorf("LKG_ROLLBACK_READBACK_FAILED: DATABASE_UNAVAILABLE"))
	if committed.Code != "LKG_ROLLBACK_READBACK_FAILED" || committed.Status != 503 {
		t.Fatalf("committed failure = %+v", committed)
	}
	if !strings.Contains(committed.Message, "回退已开始") || strings.Contains(committed.Message, "未发布") {
		t.Fatalf("committed message = %q, want a started-but-unconfirmed message", committed.Message)
	}
	for _, tc := range []struct{ err, code string }{
		{"TASKS_IN_PROGRESS: busy", "TASKS_IN_PROGRESS"},
		{"LKG_UNAVAILABLE: none", "LKG_UNAVAILABLE"},
		{"NODE_NOT_FOUND: gone", "NODE_NOT_FOUND"},
		{"DATABASE_UNAVAILABLE", "LKG_ROLLBACK_FAILED"},
	} {
		failure := node.LKGRollbackFailure(fmt.Errorf("%s", tc.err))
		if failure.Code != tc.code || !strings.Contains(failure.Message, "回退未完成") {
			t.Fatalf("%q => %+v, want %s / not-started", tc.err, failure, tc.code)
		}
	}
	if failure := node.LKGRollbackFailure(nil); failure.Code != "LKG_ROLLBACK_FAILED" {
		t.Fatalf("nil error = %+v", failure)
	}
}

// TestRollbackLkgRoute is the narrow Web surface: one authenticated, CSRF
// protected POST queues the plain-stage rollback chain and reports the new
// revision without exposing any caller-chosen revision.
func TestRollbackLkgRoute(t *testing.T) {
	app, created := lkgFixture(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	page := b.post("/nodes/"+created.ID+"/rollback-lkg", url.Values{})
	requireStatus(t, page, 200)
	if !strings.Contains(page.Body.String(), "LKG 回退已排队") {
		t.Fatalf("rollback action did not report the queued chain: %s", page.Body.String())
	}
	tasks := pendingTasksForNode(t, app, created.ID)
	if len(tasks) != len(protocol.PublicationKinds) {
		t.Fatalf("pending tasks = %+v, want the four-task chain", tasks)
	}
}
