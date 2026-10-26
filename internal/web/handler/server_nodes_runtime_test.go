package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/node/protocol"
)

func fixedTasksForRevision(t *testing.T, app *Server, nodeID string, revision int64) []protocol.Task {
	t.Helper()
	rows, err := app.store.DB.Query(`SELECT operation_id, revision, idempotency_key, kind, params
 FROM agent_tasks WHERE node_id=? AND status='pending' ORDER BY revision`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tasks []protocol.Task
	for rows.Next() {
		task := protocol.Task{Schema: protocol.Schema, Version: protocol.Version, NodeID: nodeID}
		var params string
		if err := rows.Scan(&task.OperationID, &task.Revision, &task.IdempotencyKey, &task.Kind, &params); err != nil {
			t.Fatal(err)
		}
		task.Params = json.RawMessage(params)
		var p struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal(task.Params, &p) == nil && p.Revision == revision {
			tasks = append(tasks, task)
		}
	}
	return tasks
}

func TestReissuePairingSeedsCurrentCandidateTasks(t *testing.T) {
	app, _ := testApp(t)
	created, firstCode := createPendingNode(t, app, "edge", "repair-edge", 8443, 2222)
	w := pairJSON(t, app, created.ID, "edge", firstCode)
	requireStatus(t, w, 200)
	var firstPair map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &firstPair)
	firstToken := firstPair["identity_token"]

	code, err := app.store.ReissuePairing(created.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var replaced int
	if err = app.store.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status='failed' AND error_code='IDENTITY_REPLACED'`, created.ID).Scan(&replaced); err != nil || replaced != 4 {
		t.Fatalf("replaced tasks=%d err=%v", replaced, err)
	}
	if w = bearerReq(app, "GET", "/api/agent/tasks", firstToken, nil); w.Code != 401 {
		t.Fatalf("old identity status=%d, want 401", w.Code)
	}
	w = pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, w, 200)
	var secondPair map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &secondPair)
	if secondPair["identity_token"] == "" || secondPair["identity_token"] == firstToken {
		t.Fatal("reissue did not replace the identity")
	}
	latest, err := app.store.LatestCandidate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	tasks := fixedTasksForRevision(t, app, created.ID, latest.Revision)
	if len(tasks) != 4 {
		t.Fatalf("new identity seeded %d fixed tasks, want 4", len(tasks))
	}
	for i, kind := range []string{protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback} {
		if tasks[i].Kind != kind {
			t.Fatalf("task %d kind=%s, want %s", i, tasks[i].Kind, kind)
		}
		if i > 0 && tasks[i].Revision <= tasks[i-1].Revision {
			t.Fatal("seeded task revisions are not increasing")
		}
	}
}

func TestLateReadbackCannotRegressObservedRevision(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "out", "late-readback", 8443, 2222)
	w := pairJSON(t, app, created.ID, "out", code)
	requireStatus(t, w, 200)
	var paired map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &paired)
	token := paired["identity_token"]
	latest, err := app.store.LatestCandidate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	apply, readback := fixedTasksForRevision(t, app, created.ID, latest.Revision)[2], fixedTasksForRevision(t, app, created.ID, latest.Revision)[3]
	release, _ := node.KernelReleaseFor("amd64")
	evidence := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion(),
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: release.Version,
		KernelSHA256: release.BinarySHA256, ActiveRevision: latest.Revision,
		ConfigSHA256: latest.ConfigSHA256, LocalActive: true, OutDefaultDeny: true,
	}
	detail, _ := json.Marshal(evidence)
	for _, task := range []protocol.Task{apply, readback} {
		w = reportJSON(t, app, token, protocol.TaskResult{OperationID: task.OperationID, Status: "healthy", Detail: string(detail)})
		requireStatus(t, w, 200)
	}
	firstObserved, err := app.store.GetNodeAt(created.ID, app.now())
	if err != nil || firstObserved.ObservedRevision != latest.Revision || firstObserved.ObservedTaskRevision != readback.Revision {
		t.Fatalf("observed after readback: %+v err=%v", firstObserved, err)
	}
	if !firstObserved.LocalVerified || !firstObserved.NativeReady ||
		firstObserved.PublicReachabilityVerified || firstObserved.ProtocolVerified || firstObserved.ClientVerified {
		t.Fatalf("readback evidence labels are wrong: %+v", firstObserved)
	}
	if _, err = app.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, created.ID); err != nil {
		t.Fatal(err)
	}
	offline, err := app.store.GetNodeAt(created.ID, app.now())
	if err != nil || !offline.Offline || offline.NativeReady || offline.ObservedRevision != latest.Revision {
		t.Fatalf("offline history was conflated with current readiness: %+v err=%v", offline, err)
	}

	olderID, _ := protocol.NewID()
	if _, err = app.store.DB.Exec(`INSERT INTO agent_tasks(operation_id,node_id,kind,revision,idempotency_key,status,params,created_at,updated_at)
 VALUES(?,?,?,?,?, 'pending', ?,?,?)`, olderID, created.ID, protocol.KindConfigReadback, readback.Revision-10,
		olderID, `{"revision":1}`, time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: olderID, Status: "healthy", Detail: string(detail)})
	requireStatus(t, w, 200)
	after, err := app.store.GetNodeAt(created.ID, app.now())
	if err != nil || after.ObservedRevision != firstObserved.ObservedRevision || after.ObservedTaskRevision != firstObserved.ObservedTaskRevision {
		t.Fatalf("late readback regressed observation: before=%+v after=%+v err=%v", firstObserved, after, err)
	}
}

func TestHealthyReadbackRejectsExtraFields(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "strict-readback", 8443, 2222)
	w := pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, w, 200)
	var paired map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &paired)
	token := paired["identity_token"]
	latest, err := app.store.LatestCandidate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	readback := fixedTasksForRevision(t, app, created.ID, latest.Revision)[3]
	release, _ := node.KernelReleaseFor("amd64")
	evidence := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion(),
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: release.Version,
		KernelSHA256: release.BinarySHA256, ActiveRevision: latest.Revision,
		ConfigSHA256: latest.ConfigSHA256, LocalActive: true, OutDefaultDeny: false,
	}
	body, _ := json.Marshal(evidence)
	body = append(body[:len(body)-1], []byte(`,"extra":true}`)...)
	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: readback.OperationID, Status: "healthy", Detail: string(body)})
	requireStatus(t, w, 400)
	var status string
	if err := app.store.DB.QueryRow(`SELECT status FROM agent_tasks WHERE operation_id=?`, readback.OperationID).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("invalid readback changed task status=%q err=%v", status, err)
	}

	w = reportJSON(t, app, token, protocol.TaskResult{OperationID: readback.OperationID, Status: "healthy", Detail: string(body[:len(body)-1])})
	requireStatus(t, w, 400)
}

func TestIdentityRevokeFailsUnfinishedTasksWithoutDeletingCandidate(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "revoke-edge", 8443, 2222)
	w := pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, w, 200)
	var paired map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &paired)
	token := paired["identity_token"]
	if err := app.store.RevokeIdentity(created.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if w = bearerReq(app, "GET", "/api/agent/tasks", token, nil); w.Code != 401 {
		t.Fatalf("revoked identity status=%d, want 401", w.Code)
	}
	var failed int
	if err := app.store.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status='failed' AND error_code='IDENTITY_REVOKED'`, created.ID).Scan(&failed); err != nil || failed != 4 {
		t.Fatalf("revoked unfinished tasks=%d err=%v", failed, err)
	}
	if latest, err := app.store.LatestCandidate(created.ID); err != nil || latest.Revision != 1 {
		t.Fatalf("candidate was deleted or changed: %+v err=%v", latest, err)
	}
}

func TestStaleNodeDoesNotReceiveStateChangingTasks(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "offline-edge", 8443, 2222)
	w := pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, w, 200)
	var paired map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &paired)
	if _, err := app.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, created.ID); err != nil {
		t.Fatal(err)
	}
	w = bearerReq(app, "GET", "/api/agent/tasks", paired["identity_token"], nil)
	requireStatus(t, w, 200)
	var body struct {
		Tasks []protocol.Task `json:"tasks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Tasks) != 0 {
		t.Fatalf("offline node received tasks: %+v err=%v", body.Tasks, err)
	}
}

func TestReconcilePublicationRollsBackCandidateOnTaskFailure(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "atomic-reconcile", 8443, 2222)
	w := pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, w, 200)
	if _, err := app.store.DB.Exec(`UPDATE agent_tasks SET status='failed' WHERE node_id=?`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.DB.Exec(`CREATE TRIGGER reject_stage_task BEFORE INSERT ON agent_tasks
 WHEN NEW.kind='config.stage' BEGIN SELECT RAISE(ABORT, 'TEST_TASK_FAILURE'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.store.ReconcileNode(created.ID, time.Now()); err == nil {
		t.Fatal("reconcile unexpectedly succeeded")
	}
	if latest, err := app.store.LatestCandidate(created.ID); err != nil || latest.Revision != 1 {
		t.Fatalf("candidate publication was not rolled back: %+v err=%v", latest, err)
	}
	var pending int
	if err := app.store.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status='pending'`, created.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("partial task chain persisted: pending=%d err=%v", pending, err)
	}
}

func TestInstallArtifactBoundariesAndShellQuote(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.req("GET", "/api/nodes/cli", nil, nil)
	requireStatus(t, w, 404)
	if !strings.Contains(w.Body.String(), "INSTALL_ARTIFACT_UNAVAILABLE") {
		t.Fatal("missing artifact did not fail explicitly")
	}
	page := b.req("GET", "/nodes", nil, nil)
	if strings.Contains(page.Body.String(), "./meshmux install") {
		t.Fatal("development preview rendered an executable install command")
	}
	if got := view.ShellQuote("https://hub.example.invalid/'quoted"); got != `'https://hub.example.invalid/'"'"'quoted'` {
		t.Fatalf("shellQuote=%q", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "meshmux")
	body := []byte("fixed-test-cli")
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	app.cfg.InstallArtifact = &InstallArtifact{
		Path: path, Version: node.CurrentAgentVersion(), Architecture: "amd64", SHA256: hex.EncodeToString(sum[:]),
	}
	w = b.req("GET", "/api/nodes/cli", nil, nil)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Header().Get("Content-Disposition"), "meshmux") || w.Body.String() != string(body) {
		t.Fatal("artifact bytes were not bound to the download")
	}
}

func TestNodeCreateAndReissueFormsRequireOriginAndCSRF(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	node, _ := createPendingNode(t, app, "edge", "form-security", 8443, 2222)
	for _, path := range []string{"/nodes/reconcile", "/nodes/reissue"} {
		w := b.req("POST", path, url.Values{"node_id": {node.ID}, "csrf": {b.csrf}}, http.Header{"Origin": {}})
		requireStatus(t, w, 403)
		if !strings.Contains(w.Body.String(), "ORIGIN_REJECTED") {
			t.Fatalf("%s missing origin rejection", path)
		}
	}
}
