package web

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/agent"
)

// chainFixtureTask is one agent_tasks row narrowed to a candidate revision
// chain. Tests read and settle task rows directly because the store never
// rewrites an already delivered chain.
type chainFixtureTask struct {
	OperationID string
	Kind        string
	Revision    int64
	Status      string
	ErrorCode   string
}

// chainTasksForRevision returns every fixed-chain task whose params point at
// exactly one candidate revision. An older chain of another revision is never
// included, so a test can keep it failed while a newer revision settles.
func chainTasksForRevision(t *testing.T, s *store, nodeID string, revision int64) []chainFixtureTask {
	t.Helper()
	rows, err := s.db.Query(`SELECT operation_id, kind, revision, status, error_code, params
 FROM agent_tasks WHERE node_id=? ORDER BY revision`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tasks []chainFixtureTask
	for rows.Next() {
		var task chainFixtureTask
		var params string
		if err := rows.Scan(&task.OperationID, &task.Kind, &task.Revision, &task.Status, &task.ErrorCode, &params); err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal([]byte(params), &decoded) != nil || decoded.Revision != revision {
			continue
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return tasks
}

// chainTaskStatus reads one task of a candidate revision chain.
func chainTaskStatus(t *testing.T, s *store, nodeID string, revision int64, kind string) (string, string) {
	t.Helper()
	for _, task := range chainTasksForRevision(t, s, nodeID, revision) {
		if task.Kind == kind {
			return task.Status, task.ErrorCode
		}
	}
	t.Fatalf("chain of revision %d has no %s task", revision, kind)
	return "", ""
}

// settleChainForRevision marks every fixed-chain task of one candidate revision
// healthy and records the matching local readback evidence. Chains of other
// revisions are untouched.
func settleChainForRevision(t *testing.T, s *store, nodeID string, revision int64, now time.Time) {
	t.Helper()
	stored, err := s.candidate(nodeID, revision)
	if err != nil {
		t.Fatal(err)
	}
	tasks := chainTasksForRevision(t, s, nodeID, revision)
	if len(tasks) != len(subscriberChainKinds) {
		t.Fatalf("chain of revision %d has %d tasks, want %d", revision, len(tasks), len(subscriberChainKinds))
	}
	byKind := make(map[string]chainFixtureTask, len(tasks))
	for _, task := range tasks {
		byKind[task.Kind] = task
	}
	for _, kind := range subscriberChainKinds {
		task, ok := byKind[kind]
		if !ok {
			t.Fatalf("chain of revision %d has no %s task", revision, kind)
		}
		if _, err := s.db.Exec(`UPDATE agent_tasks SET status='healthy', error_code='', updated_at=? WHERE operation_id=?`,
			now.Unix(), task.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	readback := byKind[agent.KindConfigReadback]
	if _, err := s.db.Exec(`UPDATE nodes SET observed_revision=?, observed_config_sha256=?,
 observed_at=?, observed_task_revision=?, observed_task_operation_id=? WHERE id=?`,
		stored.Revision, stored.ConfigSHA256, now.Unix(), readback.Revision, readback.OperationID, nodeID); err != nil {
		t.Fatal(err)
	}
}

// partialChainFailure flips exactly one kind of one candidate revision chain to
// failed while every later step of that chain, including the readback, stays
// healthy. It models the regression where a healthy readback row alone used to
// be accepted as confirmation.
func partialChainFailure(t *testing.T, s *store, nodeID string, revision int64, kind, code string) {
	t.Helper()
	for _, task := range chainTasksForRevision(t, s, nodeID, revision) {
		if task.Kind != kind {
			continue
		}
		result, err := s.db.Exec(`UPDATE agent_tasks SET status='failed', error_code=? WHERE operation_id=?`, code, task.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			t.Fatalf("failed to fail chain task %s: affected=%d err=%v", kind, affected, err)
		}
		return
	}
	t.Fatalf("chain of revision %d has no %s task", revision, kind)
}

// desiredPublishedRevision asserts that the desired snapshot of one Line is
// exactly the latest published candidate and returns that candidate revision.
func desiredPublishedRevision(t *testing.T, s *store, nodeID string) int64 {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	desired, err := desiredLineDigestTx(tx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	revision, digest, _, found, err := latestPublishedCandidateTx(tx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("line has no published candidate")
	}
	if digest != desired {
		t.Fatalf("published digest %s does not match the desired snapshot", digest)
	}
	return revision
}

// TestSubscriberSyncPriorChainFailureIsNotConfirmed is the regression for a
// readback row that stays healthy while an earlier step of the same revision
// chain failed. A partial chain must stay partial, and automatic reconciliation
// must neither republish nor rewrite it.
func TestSubscriberSyncPriorChainFailureIsNotConfirmed(t *testing.T) {
	for _, failedKind := range []string{agent.KindConfigCheck, agent.KindConfigStage, agent.KindConfigApply} {
		t.Run(failedKind, func(t *testing.T) {
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
			revision := desiredPublishedRevision(t, s, edge)
			settleChainForRevision(t, s, edge, revision, now)
			if status, code, err := s.subscriberSyncStatus(alice.ID, now); err != nil || status != subscriberSyncHealthy || code != "" {
				t.Fatalf("confirmed status = %s/%s err=%v, want healthy", status, code, err)
			}

			const failureCode = "CONFIG_STEP_FAILED"
			partialChainFailure(t, s, edge, revision, failedKind, failureCode)
			if status, code := chainTaskStatus(t, s, edge, revision, agent.KindConfigReadback); status != "healthy" || code != "" {
				t.Fatalf("readback after %s failure = %s/%s, want healthy", failedKind, status, code)
			}

			tx, err := s.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			status, code, viewErr := subscriberLineSyncViewTx(tx, edge, now)
			latestStatus, latestCode, terminal, latestErr := subscriberLineLatestTaskTx(tx, edge)
			tx.Rollback()
			if viewErr != nil {
				t.Fatal(viewErr)
			}
			if latestErr != nil {
				t.Fatal(latestErr)
			}
			if status != subscriberSyncPartial || code != failureCode {
				t.Fatalf("%s failure view = %s/%s, want partial/%s", failedKind, status, code, failureCode)
			}
			if latestStatus != "failed" || latestCode != failureCode || !terminal {
				t.Fatalf("latest task = %s/%s terminal=%v, want failed/%s", latestStatus, latestCode, terminal, failureCode)
			}

			candidates := candidateCount(t, s, edge)
			tasks := taskCount(t, s, edge)
			if err := drainLineNow(t, s, edge, now); err != nil {
				t.Fatal(err)
			}
			if got := candidateCount(t, s, edge); got != candidates {
				t.Fatalf("automatic drain republished after a partial chain: revisions = %d, want %d", got, candidates)
			}
			if got := taskCount(t, s, edge); got != tasks {
				t.Fatalf("automatic drain appended tasks after a partial chain: tasks = %d, want %d", got, tasks)
			}
			if status, code := chainTaskStatus(t, s, edge, revision, failedKind); status != "failed" || code != failureCode {
				t.Fatalf("drain rewrote the failed %s task: %s/%s", failedKind, status, code)
			}
			if status, code, err := s.subscriberSyncStatus(alice.ID, now); err != nil || status != subscriberSyncPartial || code != failureCode {
				t.Fatalf("status after drain = %s/%s err=%v, want partial/%s", status, code, err, failureCode)
			}
		})
	}
}

// TestSubscriberSyncNewerRevisionHealthyChainOverridesOlderFailure proves that
// the newest revision decides: an older failed chain stays failed and visible
// in the task history, but it never downgrades a fully healthy newer chain.
func TestSubscriberSyncNewerRevisionHealthyChainOverridesOlderFailure(t *testing.T) {
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
	first := desiredPublishedRevision(t, s, edge)
	settleChainForRevision(t, s, edge, first, now)
	partialChainFailure(t, s, edge, first, agent.KindConfigCheck, "CONFIG_CHECK_FAILED")

	if _, _, err := s.createSubscriber("bob", []string{edge}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	second := desiredPublishedRevision(t, s, edge)
	if second <= first {
		t.Fatalf("newer publication revision = %d, want > %d", second, first)
	}
	settleChainForRevision(t, s, edge, second, now)

	status, code, err := s.subscriberSyncStatus(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != subscriberSyncHealthy || code != "" {
		t.Fatalf("newer healthy chain status = %s/%s, want healthy despite the older failure", status, code)
	}

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	olderHealthy, err := subscriberLineChainHealthyTx(tx, edge, first)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	newerHealthy, err := subscriberLineChainHealthyTx(tx, edge, second)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	latestStatus, latestCode, terminal, err := subscriberLineLatestTaskTx(tx, edge)
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if olderHealthy {
		t.Fatal("the older failed chain reported healthy")
	}
	if !newerHealthy {
		t.Fatal("the newer settled chain did not report healthy")
	}
	if latestStatus != "healthy" || latestCode != "" || terminal {
		t.Fatalf("latest chain = %s/%s terminal=%v, want healthy", latestStatus, latestCode, terminal)
	}
	if status, code := chainTaskStatus(t, s, edge, first, agent.KindConfigCheck); status != "failed" || code != "CONFIG_CHECK_FAILED" {
		t.Fatalf("older chain was rewritten: %s/%s", status, code)
	}

	candidates := candidateCount(t, s, edge)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, edge); got != candidates {
		t.Fatalf("drain republished a confirmed newer chain: revisions = %d, want %d", got, candidates)
	}
}

// TestSubscriberSyncDeletingSubscriberWithPriorChainFailureStaysDeleting
// ensures a deleting subscriber is finalized only by a complete healthy chain
// of the exact snapshot without its UUIDs, not by its healthy readback row.
func TestSubscriberSyncDeletingSubscriberWithPriorChainFailureStaysDeleting(t *testing.T) {
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
	first := desiredPublishedRevision(t, s, edge)
	settleChainForRevision(t, s, edge, first, now)

	if _, err := s.setSubscriberState(alice.ID, "deleting", now); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	second := desiredPublishedRevision(t, s, edge)
	if second <= first {
		t.Fatalf("deletion publication revision = %d, want > %d", second, first)
	}
	settleChainForRevision(t, s, edge, second, now)
	partialChainFailure(t, s, edge, second, agent.KindConfigCheck, "CONFIG_CHECK_FAILED")
	if status, code := chainTaskStatus(t, s, edge, second, agent.KindConfigReadback); status != "healthy" {
		t.Fatalf("readback = %s/%s, want healthy", status, code)
	}
	status, code, err := s.subscriberSyncStatus(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != subscriberSyncPartial || code != "CONFIG_CHECK_FAILED" {
		t.Fatalf("deleting status = %s/%s, want partial/CONFIG_CHECK_FAILED", status, code)
	}

	candidates := candidateCount(t, s, edge)
	tasks := taskCount(t, s, edge)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	stored, err := s.getSubscriber(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "deleting" {
		t.Fatalf("state after a partial chain = %s, want deleting", stored.State)
	}
	if got := candidateCount(t, s, edge); got != candidates {
		t.Fatalf("drain republished during deletion: revisions = %d, want %d", got, candidates)
	}
	if got := taskCount(t, s, edge); got != tasks {
		t.Fatalf("drain appended tasks during deletion: tasks = %d, want %d", got, tasks)
	}

	// Positive control: only the repaired complete chain finalizes the
	// subscriber, so the negative assertion above is not vacuous.
	settleChainForRevision(t, s, edge, second, now)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	stored, err = s.getSubscriber(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "deleted" {
		t.Fatalf("state after a complete chain = %s, want deleted", stored.State)
	}
	if got := candidateCount(t, s, edge); got != candidates {
		t.Fatalf("finalizing republished a converged snapshot: revisions = %d, want %d", got, candidates)
	}
}
