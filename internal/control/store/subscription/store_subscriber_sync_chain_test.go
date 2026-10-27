package subscription_test

import (
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// chainTaskStatus reads one task of a candidate revision chain.
func chainTaskStatus(t *testing.T, s *store.Store, nodeID string, revision int64, kind string) (string, string) {
	t.Helper()
	for _, task := range storetest.ChainTasksForRevision(t, s, nodeID, revision) {
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
func settleChainForRevision(t *testing.T, s *store.Store, nodeID string, revision int64, now time.Time) {
	t.Helper()
	stored, err := s.Candidate(nodeID, revision)
	if err != nil {
		t.Fatal(err)
	}
	tasks := storetest.ChainTasksForRevision(t, s, nodeID, revision)
	if len(tasks) != len(store.SubscriberChainKinds) {
		t.Fatalf("chain of revision %d has %d tasks, want %d", revision, len(tasks), len(store.SubscriberChainKinds))
	}
	byKind := make(map[string]storetest.ChainFixtureTask, len(tasks))
	for _, task := range tasks {
		byKind[task.Kind] = task
	}
	for _, kind := range store.SubscriberChainKinds {
		task, ok := byKind[kind]
		if !ok {
			t.Fatalf("chain of revision %d has no %s task", revision, kind)
		}
		if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='healthy', error_code='', updated_at=? WHERE operation_id=?`,
			now.Unix(), task.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	readback := byKind[protocol.KindConfigReadback]
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_revision=?, observed_config_sha256=?,
 observed_at=?, observed_task_revision=?, observed_task_operation_id=? WHERE id=?`,
		stored.Revision, stored.ConfigSHA256, now.Unix(), readback.Revision, readback.OperationID, nodeID); err != nil {
		t.Fatal(err)
	}
}

// partialChainFailure flips exactly one kind of one candidate revision chain to
// failed while every later step of that chain, including the readback, stays
// healthy. It models the regression where a healthy readback row alone used to
// be accepted as confirmation.
func partialChainFailure(t *testing.T, s *store.Store, nodeID string, revision int64, kind, code string) {
	t.Helper()
	for _, task := range storetest.ChainTasksForRevision(t, s, nodeID, revision) {
		if task.Kind != kind {
			continue
		}
		result, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code=? WHERE operation_id=?`, code, task.OperationID)
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
func desiredPublishedRevision(t *testing.T, s *store.Store, nodeID string, now time.Time) int64 {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	desired, err := store.DesiredLineDigestTx(tx, nodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	revision, digest, _, found, err := store.LatestPublishedCandidateTx(tx, nodeID)
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
	for _, failedKind := range []string{protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply} {
		t.Run(failedKind, func(t *testing.T) {
			s, now := storetest.SubscriberStore(t)
			edge := storetest.CreateEdgeNode(t, s, now)
			storetest.ConfigureLine(t, s, edge, "line-a", now)
			storetest.MarkLineOnline(t, s, edge, now)
			alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
				t.Fatal(err)
			}
			revision := desiredPublishedRevision(t, s, edge, now)
			settleChainForRevision(t, s, edge, revision, now)
			if status, code, err := subscriberSyncStatusForTest(t, s, alice.ID, now); err != nil || status != store.SubscriberSyncHealthy || code != "" {
				t.Fatalf("confirmed status = %s/%s err=%v, want healthy", status, code, err)
			}

			const failureCode = "CONFIG_STEP_FAILED"
			partialChainFailure(t, s, edge, revision, failedKind, failureCode)
			if status, code := chainTaskStatus(t, s, edge, revision, protocol.KindConfigReadback); status != "healthy" || code != "" {
				t.Fatalf("readback after %s failure = %s/%s, want healthy", failedKind, status, code)
			}

			tx, err := s.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			status, code, viewErr := store.SubscriberLineSyncViewTx(tx, edge, now)
			latestStatus, latestCode, terminal, latestErr := store.SubscriberLineLatestTaskTx(tx, edge)
			tx.Rollback()
			if viewErr != nil {
				t.Fatal(viewErr)
			}
			if latestErr != nil {
				t.Fatal(latestErr)
			}
			if status != store.SubscriberSyncPartial || code != failureCode {
				t.Fatalf("%s failure view = %s/%s, want partial/%s", failedKind, status, code, failureCode)
			}
			if latestStatus != "failed" || latestCode != failureCode || !terminal {
				t.Fatalf("latest task = %s/%s terminal=%v, want failed/%s", latestStatus, latestCode, terminal, failureCode)
			}

			candidates := storetest.CandidateCount(t, s, edge)
			tasks := storetest.TaskCount(t, s, edge)
			if err := drainLineNow(t, s, edge, now); err != nil {
				t.Fatal(err)
			}
			if got := storetest.CandidateCount(t, s, edge); got != candidates {
				t.Fatalf("automatic drain republished after a partial chain: revisions = %d, want %d", got, candidates)
			}
			if got := storetest.TaskCount(t, s, edge); got != tasks {
				t.Fatalf("automatic drain appended tasks after a partial chain: tasks = %d, want %d", got, tasks)
			}
			if status, code := chainTaskStatus(t, s, edge, revision, failedKind); status != "failed" || code != failureCode {
				t.Fatalf("drain rewrote the failed %s task: %s/%s", failedKind, status, code)
			}
			if status, code, err := subscriberSyncStatusForTest(t, s, alice.ID, now); err != nil || status != store.SubscriberSyncPartial || code != failureCode {
				t.Fatalf("status after drain = %s/%s err=%v, want partial/%s", status, code, err, failureCode)
			}
		})
	}
}

// TestSubscriberSyncNewerRevisionHealthyChainOverridesOlderFailure proves that
// the newest revision decides: an older failed chain stays failed and visible
// in the task history, but it never downgrades a fully healthy newer chain.
func TestSubscriberSyncNewerRevisionHealthyChainOverridesOlderFailure(t *testing.T) {
	s, now := storetest.SubscriberStore(t)
	edge := storetest.CreateEdgeNode(t, s, now)
	storetest.ConfigureLine(t, s, edge, "line-a", now)
	storetest.MarkLineOnline(t, s, edge, now)
	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	first := desiredPublishedRevision(t, s, edge, now)
	settleChainForRevision(t, s, edge, first, now)
	partialChainFailure(t, s, edge, first, protocol.KindConfigCheck, "CONFIG_CHECK_FAILED")

	if _, _, err := s.CreateSubscriber("bob", []string{edge}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	second := desiredPublishedRevision(t, s, edge, now)
	if second <= first {
		t.Fatalf("newer publication revision = %d, want > %d", second, first)
	}
	settleChainForRevision(t, s, edge, second, now)

	status, code, err := subscriberSyncStatusForTest(t, s, alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != store.SubscriberSyncHealthy || code != "" {
		t.Fatalf("newer healthy chain status = %s/%s, want healthy despite the older failure", status, code)
	}

	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	olderHealthy, err := store.SubscriberLineChainHealthyTx(tx, edge, first)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	newerHealthy, err := store.SubscriberLineChainHealthyTx(tx, edge, second)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	latestStatus, latestCode, terminal, err := store.SubscriberLineLatestTaskTx(tx, edge)
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
	if status, code := chainTaskStatus(t, s, edge, first, protocol.KindConfigCheck); status != "failed" || code != "CONFIG_CHECK_FAILED" {
		t.Fatalf("older chain was rewritten: %s/%s", status, code)
	}

	candidates := storetest.CandidateCount(t, s, edge)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	if got := storetest.CandidateCount(t, s, edge); got != candidates {
		t.Fatalf("drain republished a confirmed newer chain: revisions = %d, want %d", got, candidates)
	}
}

// TestSubscriberSyncDeletingSubscriberWithPriorChainFailureStaysDeleting
// ensures a deleting subscriber is finalized only by a complete healthy chain
// of the exact snapshot without its UUIDs, not by its healthy readback row.
func TestSubscriberSyncDeletingSubscriberWithPriorChainFailureStaysDeleting(t *testing.T) {
	s, now := storetest.SubscriberStore(t)
	edge := storetest.CreateEdgeNode(t, s, now)
	storetest.ConfigureLine(t, s, edge, "line-a", now)
	storetest.MarkLineOnline(t, s, edge, now)
	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	first := desiredPublishedRevision(t, s, edge, now)
	settleChainForRevision(t, s, edge, first, now)

	if _, err := s.SetSubscriberState(alice.ID, "deleting", now); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(alice.ID, now); err != nil {
		t.Fatal(err)
	}
	second := desiredPublishedRevision(t, s, edge, now)
	if second <= first {
		t.Fatalf("deletion publication revision = %d, want > %d", second, first)
	}
	settleChainForRevision(t, s, edge, second, now)
	partialChainFailure(t, s, edge, second, protocol.KindConfigCheck, "CONFIG_CHECK_FAILED")
	if status, code := chainTaskStatus(t, s, edge, second, protocol.KindConfigReadback); status != "healthy" {
		t.Fatalf("readback = %s/%s, want healthy", status, code)
	}
	status, code, err := subscriberSyncStatusForTest(t, s, alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if status != store.SubscriberSyncPartial || code != "CONFIG_CHECK_FAILED" {
		t.Fatalf("deleting status = %s/%s, want partial/CONFIG_CHECK_FAILED", status, code)
	}

	candidates := storetest.CandidateCount(t, s, edge)
	tasks := storetest.TaskCount(t, s, edge)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetSubscriber(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "deleting" {
		t.Fatalf("state after a partial chain = %s, want deleting", stored.State)
	}
	if got := storetest.CandidateCount(t, s, edge); got != candidates {
		t.Fatalf("drain republished during deletion: revisions = %d, want %d", got, candidates)
	}
	if got := storetest.TaskCount(t, s, edge); got != tasks {
		t.Fatalf("drain appended tasks during deletion: tasks = %d, want %d", got, tasks)
	}

	// Positive control: only the repaired complete chain finalizes the
	// subscriber, so the negative assertion above is not vacuous.
	settleChainForRevision(t, s, edge, second, now)
	if err := drainLineNow(t, s, edge, now); err != nil {
		t.Fatal(err)
	}
	stored, err = s.GetSubscriber(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "deleted" {
		t.Fatalf("state after a complete chain = %s, want deleted", stored.State)
	}
	if got := storetest.CandidateCount(t, s, edge); got != candidates {
		t.Fatalf("finalizing republished a converged snapshot: revisions = %d, want %d", got, candidates)
	}
}
