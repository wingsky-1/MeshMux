package handler

import (
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// markLineOnline puts one Line inside the task delivery window.
func markLineOnline(t *testing.T, s *store.Store, nodeID string, now time.Time) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired', last_heartbeat=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
}

// drainLineNow runs the Line drain in the caller's transaction.
func drainLineNow(t *testing.T, s *store.Store, nodeID string, now time.Time) error {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := s.DrainSubscriberNodeTx(tx, nodeID, now); err != nil {
		return err
	}
	if err := store.FinalizeDeletingSubscribersTx(tx, nodeID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return nil
}

// candidateCount returns the number of immutable revisions of one Line.
func candidateCount(t *testing.T, s *store.Store, nodeID string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// taskCount returns the number of tasks of one Line.
func taskCount(t *testing.T, s *store.Store, nodeID string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// settleTasks marks the whole current chain of one Line as successfully
// finished. The result is only used to make the next drain see no in-flight
// chain; the exact readback evidence is simulated separately.
func settleTasks(t *testing.T, s *store.Store, nodeID string) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='healthy' WHERE node_id=? AND status<>'healthy'`, nodeID); err != nil {
		t.Fatal(err)
	}
}

// confirmLatest simulates the exact local readback a Line reports after it
// applied its latest candidate.
func confirmLatest(t *testing.T, s *store.Store, nodeID string, now time.Time) {
	t.Helper()
	latest, err := s.LatestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_revision=?, observed_config_sha256=?,
 observed_at=?, observed_task_revision=?, observed_task_operation_id=?
 WHERE id=?`, latest.Revision, latest.ConfigSHA256, now.Unix(), latest.Revision, "0123456789abcdef0123456789abcdef", nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='healthy' WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	// The latest config.readback task must point at the confirmed revision.
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET params=? WHERE node_id=? AND kind='config.readback'
 AND revision=(SELECT MAX(revision) FROM agent_tasks WHERE node_id=? AND kind='config.readback')`,
		`{"revision":`+store.Itoa(int(latest.Revision))+`}`, nodeID, nodeID); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriberSyncOfflineKeepsIntentAndPublishesAfterReconnect(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}

	// The Line never contacted the Hub: the desired snapshot stays durable,
	// but no state-changing task is enqueued.
	err = s.PrepareSubscriberSync(alice.ID, now)
	if err == nil {
		t.Fatal("offline line reported a successful publication")
	}
	if !hasErrorCode(err, "LINE_OFFLINE") {
		t.Fatalf("error %q does not carry LINE_OFFLINE", err)
	}
	if got := candidateCount(t, s, edge); got != 1 {
		t.Fatalf("candidate revisions after offline prepare = %d, want the initial revision only", got)
	}
	if got := taskCount(t, s, edge); got != 0 {
		t.Fatalf("offline prepare enqueued %d tasks", got)
	}
	status, code, err := s.SubscriberSyncStatus(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != store.SubscriberSyncPartial || code != "NODE_OFFLINE" {
		t.Fatalf("offline status = %s/%s, want partial/NODE_OFFLINE", status, code)
	}

	// The Line connects again: the persisted intent is published without a
	// second subscriber action.
	markLineOnline(t, s, edge, now)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, edge); got != 2 {
		t.Fatalf("candidate revisions after reconnect = %d, want 2", got)
	}
	if got := taskCount(t, s, edge); got != 4 {
		t.Fatalf("tasks after reconnect = %d, want the fixed chain of 4", got)
	}
	latest, err := s.LatestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest.Document.Users) != 1 {
		t.Fatalf("published users = %d, want 1", len(latest.Document.Users))
	}
	status, code, err = s.SubscriberSyncStatus(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != store.SubscriberSyncPending || code != "SYNC_IN_PROGRESS" {
		t.Fatalf("in-flight status = %s/%s, want pending/SYNC_IN_PROGRESS", status, code)
	}
}

func TestSubscriberSyncWaitsForInFlightChainThenPublishesChangedSnapshot(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	markLineOnline(t, s, edge, now)
	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := s.CreateSubscriber("bob", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	first, err := s.LatestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Document.Users) != 2 {
		t.Fatalf("first snapshot users = %d, want 2", len(first.Document.Users))
	}
	bobCredentials, err := s.ListSubscriberCredentials(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	aliceCredentials, err := s.ListSubscriberCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}

	// The desired snapshot changes while the first chain is still pending.
	if _, err := s.SetSubscriberState(bob.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, edge); got != 2 {
		t.Fatalf("drain replaced the in-flight chain: revisions = %d, want 2", got)
	}

	// Once the chain finished, the next drain publishes the changed snapshot.
	settleTasks(t, s, edge)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, edge); got != 3 {
		t.Fatalf("revisions after the chain settled = %d, want 3", got)
	}
	latest, err := s.LatestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest.Document.Users) != 1 {
		t.Fatalf("second snapshot users = %d, want 1", len(latest.Document.Users))
	}
	if latest.Document.Users[0].CredentialID != aliceCredentials[0].ID ||
		latest.Document.Users[0].UUID != aliceCredentials[0].UUID {
		t.Fatal("the remaining subscriber's credential was not preserved")
	}
	for _, user := range latest.Document.Users {
		if user.UUID == bobCredentials[0].UUID {
			t.Fatal("the paused subscriber's uuid is still published")
		}
	}
	// Alice is untouched by Bob's pause.
	if _, err := s.GetSubscriber(alice.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriberSyncAutomaticPollDoesNotRepeatFailedSnapshotAndRetryUsesNewIDs(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	markLineOnline(t, s, edge, now)
	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	first, err := s.LatestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	var firstOperations []string
	rows, err := s.DB.Query(`SELECT operation_id FROM agent_tasks WHERE node_id=? ORDER BY revision`, edge)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		firstOperations = append(firstOperations, id)
	}
	rows.Close()

	// The chain fails on the same desired snapshot.
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='CONFIG_CHECK_FAILED' WHERE node_id=?`, edge); err != nil {
		t.Fatal(err)
	}
	status, code, err := s.SubscriberSyncStatus(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != store.SubscriberSyncPartial || code != "CONFIG_CHECK_FAILED" {
		t.Fatalf("failed status = %s/%s, want partial/CONFIG_CHECK_FAILED", status, code)
	}

	// Automatic reconciliation must not retry the unchanged snapshot.
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, edge); got != 2 {
		t.Fatalf("automatic poll republished a failed snapshot: revisions = %d, want 2", got)
	}

	// An explicit retry publishes a fresh revision and a fresh chain.
	if err := s.RetrySubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, edge); got != 3 {
		t.Fatalf("revisions after explicit retry = %d, want 3", got)
	}
	second, err := s.LatestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	if second.ConfigSHA256 != first.ConfigSHA256 {
		// The compiled bytes of an Edge candidate are revision-independent,
		// so an unchanged user set must keep the same digest.
		t.Fatal("unchanged snapshot changed its compiled digest")
	}
	var secondOperations []string
	rows, err = s.DB.Query(`SELECT operation_id FROM agent_tasks WHERE node_id=? AND status='pending' ORDER BY revision`, edge)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		secondOperations = append(secondOperations, id)
	}
	rows.Close()
	if len(secondOperations) != 4 {
		t.Fatalf("pending tasks after retry = %d, want 4", len(secondOperations))
	}
	firstSet := map[string]bool{}
	for _, id := range firstOperations {
		firstSet[id] = true
	}
	for _, id := range secondOperations {
		if firstSet[id] {
			t.Fatal("retry reused the operation id of the failed chain")
		}
	}
}

func TestSubscriberSyncDeletionWaitsForExactReadbackAndKeepsOtherUser(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	markLineOnline(t, s, edge, now)
	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := s.CreateSubscriber("bob", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	confirmLatest(t, s, edge, now)
	status, code, err := s.SubscriberSyncStatus(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != store.SubscriberSyncHealthy || code != "" {
		t.Fatalf("confirmed status = %s/%s, want healthy", status, code)
	}

	// Bob is deleted: his UUID must disappear, Alice must stay.
	if _, err := s.SetSubscriberState(bob.ID, subscription.StateDeleting, now); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(bob.ID, now); err != nil {
		t.Fatal(err)
	}
	// Without a readback the tombstone stays: deletion is not claimed early.
	stored, err := s.GetSubscriber(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != subscription.StateDeleting {
		t.Fatalf("state before readback = %s, want deleting", stored.State)
	}
	confirmLatest(t, s, edge, now)

	// The next recovery hook finalizes Bob after the exact readback.
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	stored, err = s.GetSubscriber(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != subscription.StateDeleted {
		t.Fatalf("state after exact readback = %s, want deleted", stored.State)
	}
	// Alice and her credential are untouched.
	storedAlice, err := s.GetSubscriber(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedAlice.State != subscription.StateActive {
		t.Fatalf("other subscriber state = %s, want active", storedAlice.State)
	}
	latest, err := s.LatestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	aliceCredentials, err := s.ListSubscriberCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, user := range latest.Document.Users {
		if user.UUID == aliceCredentials[0].UUID {
			found = true
		}
	}
	if !found {
		t.Fatal("deleting one subscriber removed another subscriber's credential")
	}
	// A deleted subscriber is terminal and is not listed any more.
	if list, err := s.ListSubscribers(); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range list {
			if entry.ID == bob.ID {
				t.Fatal("deleted subscriber still listed")
			}
		}
	}
	if !strings.Contains(string(stored.State), "deleted") {
		t.Fatal("unreachable")
	}
}
