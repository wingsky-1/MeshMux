package storetest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

// MarkLineOnline puts one Line inside the task delivery window.
func MarkLineOnline(t *testing.T, s *store.Store, nodeID string, now time.Time) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired', last_heartbeat=? WHERE id=?`, now.Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
}

// CandidateCount returns the number of immutable revisions of one Line.
func CandidateCount(t *testing.T, s *store.Store, nodeID string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// TaskCount returns the number of tasks of one Line.
func TaskCount(t *testing.T, s *store.Store, nodeID string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// SettleTasks marks the whole current chain of one Line as successfully
// finished. The result is only used to make the next drain see no in-flight
// chain; the exact readback evidence is simulated separately.
func SettleTasks(t *testing.T, s *store.Store, nodeID string) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='healthy' WHERE node_id=? AND status<>'healthy'`, nodeID); err != nil {
		t.Fatal(err)
	}
}

// ChainFixtureTask is one agent_tasks row narrowed to a candidate revision
// chain. Tests read and settle task rows directly because the store never
// rewrites an already delivered chain.
type ChainFixtureTask struct {
	OperationID string
	Kind        string
	Revision    int64
	Status      string
	ErrorCode   string
}

// ChainTasksForRevision returns every fixed-chain task whose params point at
// exactly one candidate revision. An older chain of another revision is never
// included, so a test can keep it failed while a newer revision settles.
func ChainTasksForRevision(t *testing.T, s *store.Store, nodeID string, revision int64) []ChainFixtureTask {
	t.Helper()
	rows, err := s.DB.Query(`SELECT operation_id, kind, revision, status, error_code, params
 FROM agent_tasks WHERE node_id=? ORDER BY revision`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tasks []ChainFixtureTask
	for rows.Next() {
		var task ChainFixtureTask
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
