package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"

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
	app, logs := testApp(t)
	now := time.Now()
	out := createPairedWebNode(t, app, "out", "out-sync", 9443, 2223)
	line := createPairedWebNode(t, app, "edge", "line-sync", 8443, 2222)
	lineSettings := storetest.TestLine(line.ID, "line-sync")
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
	storetest.ConfigureOut(t, app.Store, out.ID, now)
	// The tokens are issued after the roles are known. A reissue resets the
	// node to pending, so both are marked online again afterwards and their
	// seeded chains are settled, which lets the test attribute every later chain
	// to its own action.
	result := pairedWebOutSyncApp{
		app: app, logs: logs, outID: out.ID, lineID: line.ID,
		outToken: agentToken(t, app, out.ID), lineToken: agentToken(t, app, line.ID),
	}
	for _, nodeID := range []string{out.ID, line.ID} {
		storetest.MarkLineOnline(t, app.Store, nodeID, now)
		storetest.SettleTasks(t, app.Store, nodeID)
		storetest.ConfirmChain(t, app.Store, nodeID, now)
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

// TestOutSyncHeartbeatAndResultReadback drives the real Agent endpoints: a
// heartbeat and a healthy result are the readback events that reconcile the
// pair, and the hub logs each fact with a stable code only.
func TestOutSyncHeartbeatAndResultReadback(t *testing.T) {
	f := newPairedWebOutSyncApp(t)
	app, now := f.app, time.Now()

	// The Out's authorization is node membership (Ruling R10), so the heartbeat
	// reconciles the pair rather than a subscription edit: it republishes the Out when
	// the membership list is not yet the published one.
	w := heartbeatJSON(t, app, f.outToken)
	requireStatus(t, w, 200)
	settled := storetest.CandidateCount(t, app.Store, f.outID)
	if settled < 1 {
		t.Fatalf("out has no published chain: %d", settled)
	}

	// Report the Out chain healthy: the result event must release the Line.
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
	// The Out is healthy and its own confirmation released the Line: the Line
	// chain is now queued by the result event, not by a manual action.
	if got := storetest.CandidateCount(t, app.Store, f.lineID); got != 2 {
		t.Fatalf("line revisions after out confirmation = %d, want 2", got)
	}
	state, code, err := storetest.OutSyncStatusForTest(t, app.Store, f.outID, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncHealthy || code != "" {
		t.Fatalf("out status after confirmation = %s/%s, want healthy", state, code)
	}

	// The Line reports its own chain healthy, which is the second half of the
	// dual readback.
	lineCandidate, err := app.Store.LatestCandidate(f.lineID)
	if err != nil {
		t.Fatal(err)
	}
	lineEvidence := evidence
	lineEvidence.ActiveRevision = lineCandidate.Revision
	lineEvidence.ConfigSHA256 = lineCandidate.ConfigSHA256
	lineEvidence.OutDefaultDeny = false
	lineDetail, _ := json.Marshal(lineEvidence)
	for _, task := range fixedTasksForRevision(t, app, f.lineID, lineCandidate.Revision) {
		w = reportJSON(t, app, f.lineToken, protocol.TaskResult{OperationID: task.OperationID, Status: "healthy", Detail: string(lineDetail)})
		requireStatus(t, w, 200)
	}
	readback, err := app.Store.NodeCoordinationReadback(f.lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	// No subscription selects the Out, so the Line itself egresses directly
	// (Ruling R10: the ACL is membership, the route is the selection). The dual
	// readback must still prove the Line half, and must not claim an Out path it does
	// not have.
	if readback.Allowlist != store.LineEgressDirect || readback.Inbound != store.SubscriberSyncHealthy ||
		readback.FinalEgress != store.SubscriberSyncHealthy || !readback.Reality ||
		readback.ConfirmedRevision != lineCandidate.Revision {
		t.Fatalf("dual readback after both confirmations = %+v, want a healthy direct pair", readback)
	}

	// A further heartbeat after convergence changes nothing: the drain is
	// idempotent and never repeats a confirmed chain.
	before := storetest.CandidateCount(t, app.Store, f.outID)
	requireStatus(t, heartbeatJSON(t, app, f.outToken), 200)
	if got := storetest.CandidateCount(t, app.Store, f.outID); got != before {
		t.Fatalf("converged heartbeat republished: %d -> %d", before, got)
	}
	_ = subscription.StateActive
}

// TestOutSyncRetireThroughRevokeEndpoint proves the retire path is reachable
// through the real revocation endpoint and reclaims the allowlist.
func TestOutSyncRetireThroughRevokeEndpoint(t *testing.T) {
	f := newPairedWebOutSyncApp(t)
	app, now := f.app, time.Now()

	storetest.EnableOutForLine(t, app.Store, f.outID, f.lineID, now)
	storetest.SettleTasks(t, app.Store, f.outID)
	storetest.ConfirmChain(t, app.Store, f.outID, now)
	allowed, err := app.Store.DeriveOutAllowlist(f.outID)
	if err != nil || len(allowed) != 1 {
		t.Fatalf("derivation before revoke = %v err=%v", allowed, err)
	}

	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	w := b.Post("/nodes/"+f.lineID+"/revoke", nil)
	requireStatus(t, w, 200)

	allowed, err = app.Store.DeriveOutAllowlist(f.outID)
	if err != nil || len(allowed) != 0 {
		t.Fatalf("derivation after revoke = %v err=%v, want empty", allowed, err)
	}
	latest, err := app.Store.LatestCandidate(f.outID)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := storetest.OutReadbackAllowlist(app.Store, f.outID, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("reclaimed chain = %v present=%v, want an explicit empty list", revoked, present)
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
	if err := app.Store.EnqueueTaskAt(changed, time.Now()); err == nil || !storetest.HasErrorCode(err, "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("changed envelope error = %v, want IDEMPOTENCY_CONFLICT", err)
	}
	// An identical replay stays a success.
	if err := app.Store.EnqueueTaskAt(task, time.Now()); err != nil {
		t.Fatalf("identical replay failed: %v", err)
	}
}
