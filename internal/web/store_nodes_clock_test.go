package web

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/agent"
	"github.com/wingsky-1/MeshMux/internal/node"
)

// fixedTaskStamp reads created_at/updated_at of one task row.
func fixedTaskStamp(t *testing.T, s *store, operationID string) (created, updated int64) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT created_at, updated_at FROM agent_tasks WHERE operation_id=?`, operationID).
		Scan(&created, &updated); err != nil {
		t.Fatal(err)
	}
	return created, updated
}

// latestTaskOfKind returns the newest task row of one kind, including its
// candidate revision params.
func latestTaskOfKind(t *testing.T, s *store, nodeID, kind string) (operationID string, revision int64) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT operation_id, revision FROM agent_tasks
 WHERE node_id=? AND kind=? ORDER BY revision DESC LIMIT 1`, nodeID, kind).
		Scan(&operationID, &revision); err != nil {
		t.Fatal(err)
	}
	return operationID, revision
}

// TestNodeClockOfflineWindowAgreesWithSubscriberDrain pins the offline flag and
// the drain delivery window to the same caller clock. The rows were stamped with
// the fixture clock, so a wall-clock projection would report them offline.
func TestNodeClockOfflineWindowAgreesWithSubscriberDrain(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	markLineOnline(t, s, edge, now)

	cases := []struct {
		name    string
		at      time.Time
		offline bool
	}{
		{"inside window", now.Add(offlineAfter - time.Second), false},
		{"exact boundary", now.Add(offlineAfter), false},
		{"past boundary", now.Add(offlineAfter + time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			projected, err := s.getNodeAt(edge, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := s.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			drainOffline, drainErr := subscriberLineNodeOfflineTx(tx, edge, tc.at)
			tx.Rollback()
			if drainErr != nil {
				t.Fatal(drainErr)
			}
			if projected.Offline != tc.offline {
				t.Fatalf("getNodeAt offline=%v, want %v", projected.Offline, tc.offline)
			}
			if drainOffline != projected.Offline {
				t.Fatalf("drain offline=%v, projection offline=%v at the same instant", drainOffline, projected.Offline)
			}
		})
	}

	// The fixed clock must also drive the list projection, not the wall clock.
	listed, err := s.listNodesAt(now.Add(offlineAfter))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Offline {
		t.Fatalf("listNodesAt at the boundary = %+v, want one online node", listed)
	}

	// A pending node has never contacted the Hub, so both windows agree there.
	second, _, err := s.createNode("edge", "pending-line", 8444, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.getNodeAt(second.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	pendingOffline, err := subscriberLineNodeOfflineTx(tx, second.ID, now)
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Offline || !pendingOffline {
		t.Fatalf("pending node offline flags = projection:%v drain:%v, want both true", pending.Offline, pendingOffline)
	}
}

// TestEnqueueAndPublishUseInjectedClock covers both the explicit enqueue path
// and the candidate publication path: every created task row carries the
// caller's clock, not the wall clock.
func TestEnqueueAndPublishUseInjectedClock(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)

	operationID, err := agent.NewID()
	if err != nil {
		t.Fatal(err)
	}
	task := agent.Task{
		Schema: agent.Schema, Version: agent.Version,
		OperationID: operationID, Revision: 1, IdempotencyKey: operationID,
		NodeID: edge, Kind: agent.KindHealthStatus, Params: []byte(`{}`),
	}
	if err := s.enqueueTaskAt(task, now); err != nil {
		t.Fatal(err)
	}
	if created, updated := fixedTaskStamp(t, s, operationID); created != now.Unix() || updated != now.Unix() {
		t.Fatalf("enqueueTaskAt stamps = %d/%d, want %d", created, updated, now.Unix())
	}
	// The drain never publishes over in-flight work. Finish the health task
	// above, exactly as a delivered result would, so the publication below
	// really stores a new revision instead of returning a silent no-op.
	if _, err := s.db.Exec(`UPDATE agent_tasks SET status='healthy' WHERE operation_id=?`, operationID); err != nil {
		t.Fatal(err)
	}

	// Publication stamps the candidate and the fixed four-task chain together.
	configureLine(t, s, edge, "line-a", now)
	markLineOnline(t, s, edge, now)
	alice, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	publishedAt := now.Add(30 * time.Second)
	before, err := s.latestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareSubscriberSync(alice.ID, publishedAt); err != nil {
		t.Fatal(err)
	}
	latest, err := s.latestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	// The caller clock can only be proven on a real publication, so the
	// snapshot change must have produced a new revision.
	if latest.Revision <= before.Revision {
		t.Fatalf("candidate revision = %d, want a new revision after %d", latest.Revision, before.Revision)
	}
	var candidateCreated int64
	if err := s.db.QueryRow(`SELECT created_at FROM node_candidates WHERE node_id=? AND revision=?`, edge, latest.Revision).
		Scan(&candidateCreated); err != nil {
		t.Fatal(err)
	}
	if candidateCreated != publishedAt.Unix() {
		t.Fatalf("candidate created_at = %d, want %d", candidateCreated, publishedAt.Unix())
	}
	chain := chainTasksForRevision(t, s, edge, latest.Revision)
	if len(chain) != len(subscriberChainKinds) {
		t.Fatalf("published chain has %d tasks, want %d", len(chain), len(subscriberChainKinds))
	}
	for _, task := range chain {
		created, updated := fixedTaskStamp(t, s, task.OperationID)
		if created != publishedAt.Unix() || updated != publishedAt.Unix() {
			t.Fatalf("%s stamps = %d/%d, want %d", task.Kind, created, updated, publishedAt.Unix())
		}
	}
}

// TestReportResultUsesInjectedClock verifies that one request clock stamps the
// task update, the node success and the observation together.
func TestReportResultUsesInjectedClock(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	markLineOnline(t, s, edge, now)
	alice, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	latest, err := s.latestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	readbackID, _ := latestTaskOfKind(t, s, edge, agent.KindConfigReadback)

	release, ok := node.KernelReleaseFor("amd64")
	if !ok {
		t.Fatal("missing amd64 kernel release")
	}
	evidence := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion,
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: release.Version,
		KernelSHA256: release.BinarySHA256, ActiveRevision: latest.Revision,
		ConfigSHA256: latest.ConfigSHA256, LocalActive: true,
	}
	detail, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	resultAt := now.Add(30 * time.Second)
	changed, err := s.reportResultAudited(edge, agent.TaskResult{
		OperationID: readbackID, Status: "healthy", Detail: string(detail),
	}, resultAt)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("readback result did not change the row")
	}
	if _, updated := fixedTaskStamp(t, s, readbackID); updated != resultAt.Unix() {
		t.Fatalf("agent_tasks.updated_at = %d, want %d", updated, resultAt.Unix())
	}
	var lastSuccessAt, observedAt int64
	if err := s.db.QueryRow(`SELECT last_success_at, observed_at FROM nodes WHERE id=?`, edge).
		Scan(&lastSuccessAt, &observedAt); err != nil {
		t.Fatal(err)
	}
	if lastSuccessAt != resultAt.Unix() {
		t.Fatalf("nodes.last_success_at = %d, want %d", lastSuccessAt, resultAt.Unix())
	}
	if observedAt != resultAt.Unix() {
		t.Fatalf("nodes.observed_at = %d, want %d", observedAt, resultAt.Unix())
	}
	projected, err := s.getNodeAt(edge, resultAt)
	if err != nil {
		t.Fatal(err)
	}
	if projected.ObservedAt != resultAt.Unix() || projected.LastSuccessAt != resultAt.Unix() {
		t.Fatalf("projected observed/last_success = %d/%d, want %d", projected.ObservedAt, projected.LastSuccessAt, resultAt.Unix())
	}
}
