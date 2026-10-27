package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// outSyncFixture is one Hub with a paired Out, a paired Line with a literal
// transport address and one subscriber. After the client-chain rebuild the
// subscription selects the client's egress; it does not authorize a source at
// the Out, so the fixture also exercises the "nobody selected it" state.
type outSyncFixture struct {
	store      *store.Store
	now        time.Time
	out        string
	line       string
	lineServer string
}

// outSyncStatusForTest reads the Out projection through the production
// NodeCoordinationReadback entry point.
func outSyncStatusForTest(t *testing.T, s *store.Store, outID string, now time.Time) (string, string, error) {
	t.Helper()
	readback, err := s.NodeCoordinationReadback(outID, now)
	if err != nil {
		return "", "", err
	}
	return readback.Allowlist, readback.AllowlistCode, nil
}

func newOutSyncFixture(t *testing.T) outSyncFixture {
	t.Helper()
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)
	lineSettings := testLine(line, "line-a")
	lineSettings.Server = "203.0.113.7"
	lineSettings.ServerName = "line.example.invalid"
	if _, err := s.SetLine(lineSettings, now); err != nil {
		t.Fatal(err)
	}
	// The fixture Out always carries its dial address, so a later selection
	// exercises the egress path instead of the transport refusal.
	configureOut(t, s, out, now)
	markLineOnline(t, s, line, now)
	markLineOnline(t, s, out, now)
	if _, _, err := s.CreateSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	// The Out was enrolled before its dial address existed, so publish the v4
	// chain now (the real enrollment event does the same). The Line is then
	// published through the ordinary drain.
	s.RepublishOutAuthorizations(now)
	settleTasks(t, s, out)
	confirmChain(t, s, out, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("publish the fixture line: %v", err)
	}
	settleTasks(t, s, line)
	confirmChain(t, s, line, now)
	return outSyncFixture{store: s, now: now, out: out, line: line, lineServer: "203.0.113.7"}
}

// seedInitialChain reproduces the chain that pairing seeds for the current
// candidate, without driving the pairing endpoint.
func seedInitialChain(t *testing.T, s *store.Store, nodeID string, now time.Time) {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := store.SeedInitialTasksTx(tx, nodeID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// chainRevisionParams reads the params of every task of one revision chain.
func chainRevisionParams(t *testing.T, s *store.Store, nodeID string, revision int64) []struct {
	Kind    string
	Allowed *[]string
} {
	t.Helper()
	rows, err := s.DB.Query(`SELECT kind, params FROM agent_tasks WHERE node_id=? ORDER BY revision ASC`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []struct {
		Kind    string
		Allowed *[]string
	}
	for rows.Next() {
		var kind, raw string
		if err := rows.Scan(&kind, &raw); err != nil {
			t.Fatal(err)
		}
		var params struct {
			Revision       int64     `json:"revision"`
			AllowedSources *[]string `json:"allowed_sources"`
		}
		if json.Unmarshal([]byte(raw), &params) != nil || params.Revision != revision {
			continue
		}
		out = append(out, struct {
			Kind    string
			Allowed *[]string
		}{Kind: kind, Allowed: params.AllowedSources})
	}
	return out
}

// prepareSubscriberSyncForLine runs the Line half of the drain for one Line, so
// the publication path can be exercised without a subscriber action.
func prepareSubscriberSyncForLine(s *store.Store, lineID string, now time.Time) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := store.DrainSubscriberNodeIntentTx(tx, lineID, now, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// confirmChain simulates the exact readback the Agent reports: the latest
// candidate revision and digest observed, plus a healthy fixed chain.
func confirmChain(t *testing.T, s *store.Store, nodeID string, now time.Time) {
	t.Helper()
	latest, err := s.LatestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='healthy' WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_revision=?, observed_config_sha256=?,
 observed_at=?, observed_task_revision=?, observed_task_operation_id=?
 WHERE id=?`, latest.Revision, latest.ConfigSHA256, now.Unix(), latest.Revision, "0123456789abcdef0123456789abcdef", nodeID); err != nil {
		t.Fatal(err)
	}
}

// drainOut runs the automatic Out drain for one node.
func drainOut(t *testing.T, s *store.Store, outID string, now time.Time) {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := store.DrainOutNodeIntentTx(tx, outID, now, false); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// drainOutAllowError runs the automatic Out drain and returns its error so a
// test can assert the explicit offline refusal.
func drainOutAllowError(s *store.Store, outID string, now time.Time) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = store.DrainOutNodeIntentTx(tx, outID, now, false)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// lineEgressState is a test helper around the read-only projection.
func lineEgressState(s *store.Store, lineID string, now time.Time) (string, string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	return store.LineOutEgressStatusTx(tx, lineID, now)
}

// TestOutChainUnchangedFailureNeedsExplicitRetry keeps the bounded-retry rule:
// a terminal failure is not republished by an automatic poll, only by the
// explicit retry.
func TestOutChainUnchangedFailureNeedsExplicitRetry(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out := f.store, f.now, f.out

	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_SYNC_FAILED' WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	state, code, err := outSyncStatusForTest(t, s, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncPartial || code != "OUT_SYNC_FAILED" {
		t.Fatalf("failure status = %s/%s, want partial/OUT_SYNC_FAILED", state, code)
	}
	before := candidateCount(t, s, out)
	drainOut(t, s, out, now)
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("automatic drain retried an unchanged failure: %d -> %d", before, got)
	}
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("explicit retry failed: %v", err)
	}
	if got := candidateCount(t, s, out); got != before+1 {
		t.Fatalf("explicit retry revisions = %d, want %d", got, before+1)
	}
}

// TestOutChainOfflineDefersItsOwnPublish proves an offline Out receives no
// state-changing task and the caller sees the explicit deferral.
func TestOutChainOfflineDefersItsOwnPublish(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out := f.store, f.now, f.out

	before := candidateCount(t, s, out)
	// Change the link key, which is the one value the Out's own candidate
	// renders; a changed dial address alone is deliberately candidate-neutral.
	key, err := node.NewOutLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE out_settings SET link_key=? WHERE node_id=?`, key, out); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	if err := drainOutAllowError(s, out, now); err == nil || !hasErrorCode(err, "OUT_OFFLINE") {
		t.Fatalf("automatic offline drain = %v, want OUT_OFFLINE", err)
	}
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("offline out received %d revisions, want %d", got-before, 0)
	}
	err = s.RetryOutSync(out, now)
	if err == nil || !hasErrorCode(err, "OUT_OFFLINE") {
		t.Fatalf("offline retry error = %v, want OUT_OFFLINE", err)
	}
}

// TestOutChainInFlightIsNeverRaced proves a publish request defers while
// another chain of the same Out is unfinished.
func TestOutChainInFlightIsNeverRaced(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out := f.store, f.now, f.out

	before := candidateCount(t, s, out)
	tasks, err := s.DB.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=? AND status='healthy'`, out)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := tasks.RowsAffected(); n == 0 {
		t.Fatal("the fixture out has no settled chain to re-open")
	}
	// A new link key changes the Out candidate; the unfinished chain must keep
	// it from being published on top of the apply already in flight.
	key, err := node.NewOutLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE out_settings SET link_key=? WHERE node_id=?`, key, out); err != nil {
		t.Fatal(err)
	}
	drainOut(t, s, out, now)
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("in-flight out published a competing chain: %d -> %d", before, got)
	}
	settleTasks(t, s, out)
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("retry after settle failed: %v", err)
	}
	if got := candidateCount(t, s, out); got != before+1 {
		t.Fatalf("republish after settle = %d revisions, want %d", got, before+1)
	}
}

// TestOutChainReadbackUsesOnlyStableCodes proves the readback never leaks a
// stored value or a raw error.
func TestOutChainReadbackUsesOnlyStableCodes(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	enableOutForLine(t, s, out, line, now)
	readback, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(readback)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.lineServer, "line.example.invalid", "alice"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("readback leaked %q: %s", secret, body)
		}
	}
	for _, field := range []string{readback.AllowlistCode, readback.InboundCode, readback.FinalEgressCode} {
		if field == "" {
			continue
		}
		if !store.SyncErrorCodePattern.MatchString(field) {
			t.Fatalf("readback code %q is not a stable code", field)
		}
	}
}

// TestOutChainSchemaIsUnchanged keeps the coordination layer free of new tables
// and kinds: the egress is a subscription selection and the Out chain carries
// only its own credential document.
func TestOutChainSchemaIsUnchanged(t *testing.T) {
	f := newOutSyncFixture(t)
	s := f.store
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("user_version = %d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	if len(protocol.PublicationKinds) != 4 {
		t.Fatalf("publication kinds = %v, want the frozen four", protocol.PublicationKinds)
	}
	candidate, err := s.LatestCandidate(f.out)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Document.Role != node.RoleOut || candidate.Document.Reality != nil ||
		len(candidate.Document.Users) != 0 {
		t.Fatalf("out candidate is not the credential-free baseline: %+v", candidate.Document)
	}
	if _, err := s.DB.Exec(`UPDATE node_candidates SET config_sha256='x' WHERE node_id=? AND revision=?`,
		f.out, candidate.Revision); err == nil || !strings.Contains(err.Error(), "CANDIDATE_IMMUTABLE") {
		t.Fatalf("candidate immutability lost: %v", err)
	}
	_ = subscription.StateActive
}

// TestOutPreviewFollowsSelection pins the read-only preview after the ACL
// removal: it reports which subscriptions select the Out, never a source set.
func TestOutPreviewFollowsSelection(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	direct, err := s.PreviewOutAuthorizationAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Mode != store.OutPoolLineDirect || len(direct.LineIDs) != 0 || len(direct.Sources) != 0 {
		t.Fatalf("unselected preview = %+v, want line-direct with no source", direct)
	}

	enableOutForLine(t, s, out, line, now)
	selected, err := s.PreviewOutAuthorizationAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Mode != store.OutPoolBound || len(selected.LineIDs) != 1 || selected.LineIDs[0] != line {
		t.Fatalf("selected preview = %+v, want out-selected with the line", selected)
	}
	if selected.EgressState != store.LineEgressHealthy || selected.EgressCode != "" {
		t.Fatalf("selected preview state = %s/%s, want healthy", selected.EgressState, selected.EgressCode)
	}
	if len(selected.Sources) != 0 {
		t.Fatalf("selected preview still names sources: %v", selected.Sources)
	}
	if len(selected.Subscribers) != 1 || selected.Subscribers[0] != "alice" {
		t.Fatalf("selected preview subscribers = %v, want alice", selected.Subscribers)
	}
}

// TestLinePublishIsNotGatedByOutChain pins the decoupling: once an Out has a
// dial address, a Line that selects it publishes without waiting for the Out's
// own chain confirmation.
func TestLinePublishIsNotGatedByOutChain(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	enableOutForLine(t, s, out, line, now)
	// Clear the Out evidence: under the client-chain model this no longer
	// blocks the Line, because the Line candidate carries no Out route.
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0, observed_revision=0, observed_config_sha256='' WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	before := candidateCount(t, s, line)
	if _, _, err := s.CreateSubscriber("bob", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("a line publication waited for the out chain: %v", err)
	}
	if got := candidateCount(t, s, line); got != before+1 {
		t.Fatalf("line revisions = %d, want one more than %d", got, before+1)
	}
}

// TestLineReadbackIsIndependentOfTheOutChain pins the two projections: the Out's
// own failure is retryable on the Out, while the Line's final egress follows its
// own inbound and is healthy without the Out's confirmation.
func TestLineReadbackIsIndependentOfTheOutChain(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	enableOutForLine(t, s, out, line, now)
	confirmChain(t, s, out, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	healthy, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.Allowlist != store.LineEgressHealthy || healthy.Inbound != store.SubscriberSyncHealthy ||
		healthy.FinalEgress != store.LineEgressHealthy {
		t.Fatalf("confirmed readback = %+v, want a healthy pair", healthy)
	}

	// The Out chain fails: the Out projection is partial and retryable, but the
	// Line does not regress because it carries no Out route.
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_SYNC_FAILED' WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	outReadback, err := s.NodeCoordinationReadback(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if outReadback.FinalEgress != store.OutSyncPartial || !outReadback.RetryPending {
		t.Fatalf("out readback = %+v, want partial and retry-pending", outReadback)
	}
	stillHealthy, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if stillHealthy.FinalEgress != store.LineEgressHealthy {
		t.Fatalf("line followed the out failure: %+v", stillHealthy)
	}

	// The Line's own inbound is the fact that still matters.
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0 WHERE id=?`, line); err != nil {
		t.Fatal(err)
	}
	lineRegressed, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if lineRegressed.FinalEgress == store.LineEgressHealthy {
		t.Fatalf("readback reported healthy without the line inbound: %+v", lineRegressed)
	}
}

// TestLineRevokeLeavesOutChainAlone pins that retiring a Line identity is not an
// Out authorization change: the Out's link key and chain are independent.
func TestLineRevokeLeavesOutChainAlone(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	before := candidateCount(t, s, out)
	beforeLatest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	afterLatest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("revoking a line republished the out chain: %d -> %d", before, got)
	}
	if afterLatest.Revision != beforeLatest.Revision || afterLatest.ConfigSHA256 != beforeLatest.ConfigSHA256 {
		t.Fatalf("out chain changed after the revoke: %d/%s -> %d/%s",
			beforeLatest.Revision, beforeLatest.ConfigSHA256, afterLatest.Revision, afterLatest.ConfigSHA256)
	}
}
