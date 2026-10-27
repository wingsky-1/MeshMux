package handler

import (
	"bytes"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// pairedWebOutSyncApp builds one Hub with a paired Out, a paired Line with a
// literal address and one subscriber, through the real HTTP endpoints so the
// heartbeat and result path is exercised end to end.
type pairedWebOutSyncApp struct {
	app       *Server
	logs      *bytes.Buffer
	outToken  string
	lineToken string
	outID     string
	lineID    string
}

// logsForTest returns the audit log buffer of the fixture app, so a test can
// assert which fields an event emitted.
func (f pairedWebOutSyncApp) logsForTest() string {
	if f.logs == nil {
		return ""
	}
	return f.logs.String()
}

func newPairedWebOutSyncApp(t *testing.T) pairedWebOutSyncApp {
	t.Helper()
	return newPairedWebOutSyncAppWithLevel(t, slog.LevelInfo)
}

// newPairedWebOutSyncAppWithLevel builds the same fixture with an explicit log
// level. The heartbeat's readback audit is Debug (it repeats every poll), so a
// test that reads that line from a heartbeat asks for Debug here.
func newPairedWebOutSyncAppWithLevel(t *testing.T, level slog.Level) pairedWebOutSyncApp {
	t.Helper()
	app, logs := testAppWithLevel(t, level)
	now := time.Now()
	out := createPairedWebNode(t, app, "out", "out-sync", 9443, 2223)
	line := createPairedWebNode(t, app, "edge", "line-sync", 8443, 2222)
	lineSettings := testLine(line.ID, "line-sync")
	lineSettings.Server = "203.0.113.7"
	lineSettings.ServerName = "line.example.invalid"
	if _, err := app.Store.SetLine(lineSettings, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.Store.CreateSubscriber("alice", []string{line.ID}, now); err != nil {
		t.Fatal(err)
	}
	// The fixture Out always carries its dial address, so enabling a binding
	// in a test exercises the egress path instead of the transport refusal.
	configureOut(t, app.Store, out.ID, now)
	// The tokens are issued after the roles are known. A reissue resets the
	// node to pending, so both are marked online again afterwards and their
	// seeded chains are settled, which lets the test attribute every later chain
	// to its own action.
	result := pairedWebOutSyncApp{
		app: app, logs: logs, outID: out.ID, lineID: line.ID,
		outToken: agentToken(t, app, out.ID), lineToken: agentToken(t, app, line.ID),
	}
	for _, nodeID := range []string{out.ID, line.ID} {
		markLineOnline(t, app.Store, nodeID, now)
		settleTasks(t, app.Store, nodeID)
		confirmChain(t, app.Store, nodeID, now)
	}
	return result
}

// agentToken returns the identity token of a paired node. The test app never
// stores the plaintext token, so it is re-issued through the pairing endpoint
// with the node's own immutable role.
func agentToken(t *testing.T, app *Server, nodeID string) string {
	t.Helper()
	var role string
	if err := app.Store.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	code, err := app.Store.ReissuePairing(nodeID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := pairJSON(t, app, nodeID, role, code)
	if w.Code != 200 {
		t.Fatalf("re-pair status=%d body=%.200s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["identity_token"] == "" {
		t.Fatalf("re-pair body: %v %.200s", err, w.Body.String())
	}
	return body["identity_token"]
}

func heartbeatJSON(t *testing.T, app *Server, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(protocol.HeartbeatRequest{AgentVersion: "meshmux-agent test", KernelVersion: node.KernelVersion})
	return bearerReq(app, "POST", "/api/agent/heartbeat", token, body)
}

// TestHeartbeatSuccessStaysOutOfTheDefaultJournal pins the log contract of the
// Agent heartbeat at its 1s cadence. One tick must not write anything at the
// default Warn floor: the per-tick AGENT_HEARTBEAT event and the coordination
// readback are Debug. The failure path is unchanged and must still reach the
// operator at Warn.
func TestHeartbeatSuccessStaysOutOfTheDefaultJournal(t *testing.T) {
	f := newPairedWebOutSyncApp(t)
	app := f.app

	// Success: nothing at all at the production floor.
	before := f.logsForTest()
	requireStatus(t, heartbeatJSON(t, app, f.lineToken), 200)
	after := f.logsForTest()
	if after != before {
		t.Fatalf("a successful heartbeat wrote to the default journal: %.600s", after[len(before):])
	}
	if strings.Contains(after, "AGENT_HEARTBEAT") || strings.Contains(after, `"msg":"out_readback"`) {
		t.Fatalf("a successful heartbeat wrote its audit event at the default level: %.600s", after)
	}

	// Failure: the same event still reaches the operator, unchanged.
	w := bearerReq(app, "POST", "/api/agent/heartbeat", f.lineToken, []byte(`{"agent_version":""}`))
	requireStatus(t, w, 400)
	failure := f.logsForTest()
	if !strings.Contains(failure, `"error_code":"HEARTBEAT_INVALID"`) {
		t.Fatalf("the refused heartbeat lost its stable code: %.600s", failure)
	}
	if !strings.Contains(failure, `"level":"WARN"`) {
		t.Fatalf("the refused heartbeat is not a Warn line: %.600s", failure)
	}

	// The Debug level still carries both success events, so the audit is
	// reachable when an operator raises the level on purpose.
	debug := newPairedWebOutSyncAppWithLevel(t, slog.LevelDebug)
	requireStatus(t, heartbeatJSON(t, debug.app, debug.lineToken), 200)
	logs := debug.logsForTest()
	for _, needle := range []string{"AGENT_HEARTBEAT", `"msg":"out_readback"`} {
		if _, ok := logLineAt(logs, slog.LevelDebug, needle); !ok {
			t.Fatalf("%s is not a Debug line: %.600s", needle, logs)
		}
	}
}

// logLineAt returns the first log line written at level that mentions needle.
func logLineAt(logs string, level slog.Level, needle string) (string, bool) {
	want := `"level":"` + level.String() + `"`
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, want) && strings.Contains(line, needle) {
			return line, true
		}
	}
	return "", false
}

// TestOutSyncHeartbeatAndResultReadback drives the real Agent endpoints: a
// heartbeat and a healthy result are the readback events that reconcile the
// pair, and the hub logs each fact with a stable code only.
func TestOutSyncHeartbeatAndResultReadback(t *testing.T) {
	f := newPairedWebOutSyncApp(t)
	app, now := f.app, time.Now()

	// Change the link key so the next Out event has a real revision to publish;
	// an unchanged chain is deliberately not repeated.
	key, err := node.NewOutLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.DB.Exec(`UPDATE out_settings SET link_key=? WHERE node_id=?`, key, f.outID); err != nil {
		t.Fatal(err)
	}
	w := heartbeatJSON(t, app, f.outToken)
	requireStatus(t, w, 200)
	settled := candidateCount(t, app.Store, f.outID)
	if settled < 1 {
		t.Fatalf("out has no published chain: %d", settled)
	}

	// Report the Out chain healthy: the result event confirms the Out's own
	// revision and must not republish a Line.
	lineBefore := candidateCount(t, app.Store, f.lineID)
	latest, err := app.Store.LatestCandidate(f.outID)
	if err != nil {
		t.Fatal(err)
	}
	outReadback := fixedTasksForRevision(t, app, f.outID, latest.Revision)
	if len(outReadback) != 4 {
		t.Fatalf("out chain = %d tasks, want 4", len(outReadback))
	}
	release, _ := node.KernelReleaseFor("amd64")
	evidence := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion(),
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: release.Version,
		KernelSHA256: release.BinarySHA256, ActiveRevision: latest.Revision,
		ConfigSHA256: latest.ConfigSHA256, LocalActive: true, OutDefaultDeny: true,
	}
	detail, _ := json.Marshal(evidence)
	for _, task := range outReadback {
		w = reportJSON(t, app, f.outToken, protocol.TaskResult{OperationID: task.OperationID, Status: "healthy", Detail: string(detail)})
		requireStatus(t, w, 200)
	}
	// The Out is healthy and the Line is untouched: the two chains are
	// independent after the client-chain rebuild.
	if got := candidateCount(t, app.Store, f.lineID); got != lineBefore {
		t.Fatalf("out confirmation republished the line: %d -> %d", lineBefore, got)
	}
	state, code, err := outSyncStatusForTest(t, app.Store, f.outID, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncHealthy || code != "" {
		t.Fatalf("out status after confirmation = %s/%s, want healthy", state, code)
	}

	// The Line's own chain is published and confirmed independently of the
	// Out event; its readback is the second half of the pair.
	if err := prepareSubscriberSyncForLine(app.Store, f.lineID, now); err != nil {
		t.Fatal(err)
	}
	settleTasks(t, app.Store, f.lineID)
	confirmChain(t, app.Store, f.lineID, now)
	lineCandidate, err := app.Store.LatestCandidate(f.lineID)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := app.Store.NodeCoordinationReadback(f.lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	// No subscription selects the Out, so the Line itself egresses directly.
	// The dual readback must still prove the Line half, and must not claim an
	// Out path it does not have.
	if readback.Allowlist != store.LineEgressDirect || readback.Inbound != store.SubscriberSyncHealthy ||
		readback.FinalEgress != store.SubscriberSyncHealthy || !readback.Reality ||
		readback.ConfirmedRevision != lineCandidate.Revision {
		t.Fatalf("dual readback after both confirmations = %+v, want a healthy direct pair", readback)
	}

	// A further heartbeat after convergence changes nothing: the drain is
	// idempotent and never repeats a confirmed chain.
	before := candidateCount(t, app.Store, f.outID)
	requireStatus(t, heartbeatJSON(t, app, f.outToken), 200)
	if got := candidateCount(t, app.Store, f.outID); got != before {
		t.Fatalf("converged heartbeat republished: %d -> %d", before, got)
	}
	_ = subscription.StateActive
}

// TestOutSyncRevokeLeavesTheOutChainAlone pins the decoupling: revoking a Line
// identity is not an Out authorization change any more. The Out admits by link
// key, so its own chain must not gain a revision from the revocation.
func TestOutSyncRevokeLeavesTheOutChainAlone(t *testing.T) {
	f := newPairedWebOutSyncApp(t)
	app, now := f.app, time.Now()

	enableOutForLine(t, app.Store, f.outID, f.lineID, now)
	settleTasks(t, app.Store, f.outID)
	confirmChain(t, app.Store, f.outID, now)
	before, err := app.Store.LatestCandidate(f.outID)
	if err != nil {
		t.Fatal(err)
	}

	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.post("/nodes/"+f.lineID+"/revoke", nil)
	requireStatus(t, w, 200)

	after, err := app.Store.LatestCandidate(f.outID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision || after.ConfigSHA256 != before.ConfigSHA256 {
		t.Fatalf("revoking a Line republished the out chain: %d/%s -> %d/%s",
			before.Revision, before.ConfigSHA256, after.Revision, after.ConfigSHA256)
	}
}

// TestOutSyncIdempotencyConflictIsUnchanged pins that the coordination layer did
// not soften the frozen idempotency contract: the same operation_id with
// different content is still a conflict.
func TestOutSyncIdempotencyConflictIsUnchanged(t *testing.T) {
	app, _ := testApp(t)
	// A freshly created node carries no task yet, so revision 1 is free.
	node, _ := createPendingNode(t, app, "out", "out-idem", 9443, 2223)
	task := protocol.Task{
		Schema: protocol.Schema, Version: protocol.Version,
		OperationID: strings.Repeat("e", 32), IdempotencyKey: strings.Repeat("e", 32),
		NodeID: node.ID, Kind: protocol.KindHealthStatus, Params: []byte(`{}`), Revision: 1,
	}
	if err := app.Store.EnqueueTaskAt(task, time.Now()); err != nil {
		t.Fatal(err)
	}
	changed := task
	changed.Params = []byte(`{}`)
	changed.Kind = protocol.KindHealthStatus
	changed.Revision = 2
	if err := app.Store.EnqueueTaskAt(changed, time.Now()); err == nil || !hasErrorCode(err, "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("changed envelope error = %v, want IDEMPOTENCY_CONFLICT", err)
	}
	// An identical replay stays a success.
	if err := app.Store.EnqueueTaskAt(task, time.Now()); err != nil {
		t.Fatalf("identical replay failed: %v", err)
	}
}
