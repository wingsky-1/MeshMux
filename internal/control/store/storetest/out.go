package storetest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

// TestSubscriberForLine returns the active subscriber that serves one Line,
// creating one when the fixture has none. The newest subscriber wins so a fixture
// that created several keeps a deterministic owner.
func TestSubscriberForLine(t *testing.T, s *store.Store, lineID string, now time.Time) string {
	t.Helper()
	var subscriberID string
	err := s.DB.QueryRow(`SELECT l.subscriber_id FROM subscription_lines l
	  JOIN subscribers s ON s.id=l.subscriber_id
	 WHERE l.node_id=? AND s.state='active' ORDER BY l.subscriber_id LIMIT 1`, lineID).Scan(&subscriberID)
	if err == nil {
		return subscriberID
	}
	sub, _, err := s.CreateSubscriber("owner-"+ShortID(lineID), []string{lineID}, now)
	if err != nil {
		t.Fatalf("create the owning subscriber: %v", err)
	}
	return sub.ID
}

// ShortID is a readable test suffix for a node id.
func ShortID(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}

// TableExists reports whether a table is present in the store's schema. It is how
// a test asserts that a migration dropped a table, instead of trusting a version
// number.
func TableExists(t *testing.T, s *store.Store, name string) bool {
	t.Helper()
	var tables int
	if err := s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&tables); err != nil {
		t.Fatalf("schema probe for %s: %v", name, err)
	}
	return tables != 0
}

// PairedStoreNode creates one node plus the non-revoked identity that a real
// pairing would issue, so a store-level test has a node the derivation can treat
// as current. The display name stays role-scoped and short.
func PairedStoreNode(t *testing.T, s *store.Store, role string, now time.Time) string {
	t.Helper()
	node, _, err := s.CreateNode(role, role+"-node", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`,
		node.ID, []byte{0x01}, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired' WHERE id=?`, node.ID); err != nil {
		t.Fatal(err)
	}
	return node.ID
}

// SelectOutForLine writes the subscription edge that authorizes an Out for one
// Line. It is the single replacement of the deleted SetOutBindingAt.
func SelectOutForLine(t *testing.T, s *store.Store, outID, lineID string, now time.Time) {
	t.Helper()
	subscriberID := TestSubscriberForLine(t, s, lineID, now)
	if _, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{lineID}, OutID: outID,
	}, now); err != nil {
		t.Fatalf("select out %s for line %s: %v", outID, lineID, err)
	}
}

// ClearOutForLine removes the Out choice of the subscription that serves one Line,
// keeping the Line selected. It is the replacement of a disabled binding and of
// ClearOutBindingAt: the Line is a direct egress again.
func ClearOutForLine(t *testing.T, s *store.Store, lineID string, now time.Time) {
	t.Helper()
	subscriberID := TestSubscriberForLine(t, s, lineID, now)
	if _, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{lineID},
	}, now); err != nil {
		t.Fatalf("clear the out selection of line %s: %v", lineID, err)
	}
}

// EnableOutForLine is the readable alias of SelectOutForLine.
func EnableOutForLine(t *testing.T, s *store.Store, outID, lineID string, now time.Time) {
	t.Helper()
	SelectOutForLine(t, s, outID, lineID, now)
}

// DisableOutForLine is the readable alias of ClearOutForLine.
func DisableOutForLine(t *testing.T, s *store.Store, outID, lineID string, now time.Time) {
	t.Helper()
	// The Out id is checked so a test typo cannot silently pass on the wrong
	// fixture, even though the selection write is keyed by the Line.
	if _, err := s.GetNodeAt(outID, now); err != nil {
		t.Fatalf("disable an unknown out %s: %v", outID, err)
	}
	ClearOutForLine(t, s, lineID, now)
}

// NodeSubscriberID returns the active subscriber that serves one Line, so a test can
// drive the subscriber publication without guessing the id.
func NodeSubscriberID(t *testing.T, s *store.Store, lineID string) string {
	t.Helper()
	var id string
	if err := s.DB.QueryRow(`SELECT l.subscriber_id FROM subscription_lines l
	  JOIN subscribers sub ON sub.id=l.subscriber_id AND sub.state='active'
	 WHERE l.node_id=? ORDER BY l.subscriber_id LIMIT 1`, lineID).Scan(&id); err != nil {
		t.Fatalf("read the subscriber of line %s: %v", lineID, err)
	}
	return id
}

// OutSyncFixture is one Hub with a paired Out, a paired Line with a literal
// transport address and one subscriber, so the allowlist derivation has a real
// source to authorize.
type OutSyncFixture struct {
	Store      *store.Store
	Now        time.Time
	Out        string
	Line       string
	LineServer string
}

// NewOutSyncFixture builds the fixture. The Line transport address is a
// documentation IPv4 literal because a host name would be explicitly
// unauthorized by the Hub.
//
// Both nodes start with their initial publication chain already settled, so a
// test only has to reason about the chain its own action creates.
// OutSyncStatusForTest reads the Out projection through the production
// NodeCoordinationReadback entry point; the former OutSyncStatus convenience
// wrapper was removed in Task 6.
func OutSyncStatusForTest(t *testing.T, s *store.Store, outID string, now time.Time) (string, string, error) {
	t.Helper()
	readback, err := s.NodeCoordinationReadback(outID, now)
	if err != nil {
		return "", "", err
	}
	return readback.Allowlist, readback.AllowlistCode, nil
}

func NewOutSyncFixture(t *testing.T) OutSyncFixture {
	t.Helper()
	s, now := SubscriberStore(t)
	out := PairedStoreNode(t, s, "out", now)
	line := PairedStoreNode(t, s, "edge", now)
	lineSettings := TestLine(line, "line-a")
	lineSettings.Server = "203.0.113.7"
	lineSettings.ServerName = "line.example.invalid"
	if _, err := s.SetLine(lineSettings, now); err != nil {
		t.Fatal(err)
	}
	// The fixture Out always carries its dial address, so enabling a binding
	// in a test exercises the egress path instead of the transport refusal.
	ConfigureOut(t, s, out, now)
	MarkLineOnline(t, s, line, now)
	MarkLineOnline(t, s, out, now)
	if _, _, err := s.CreateSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	// The fixture starts from a converged pair instead of a seeded chain: the Out was
	// enrolled before its dial address existed, so its stored candidate is still the
	// credential-free v1 baseline. Publishing it now is what the real enrollment
	// event does (Ruling R10), and it is the only way the chain carries the SS guard
	// and the membership allowlist. The Line is then published through the ordinary
	// gate, which the Out has just been confirmed for.
	s.RepublishOutAuthorizations(now)
	SettleTasks(t, s, out)
	ConfirmChain(t, s, out, now)
	if err := PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("publish the fixture line: %v", err)
	}
	SettleTasks(t, s, line)
	ConfirmChain(t, s, line, now)
	return OutSyncFixture{Store: s, Now: now, Out: out, Line: line, LineServer: "203.0.113.7"}
}

// SeedInitialChain reproduces the chain that pairing seeds for the current
// candidate, without driving the pairing endpoint.
func SeedInitialChain(t *testing.T, s *store.Store, nodeID string, now time.Time) {
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

// ChainRevisionParams reads the params of every task of one revision chain.
func ChainRevisionParams(t *testing.T, s *store.Store, nodeID string, revision int64) []struct {
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

// LineEgressState is a test helper around the read-only projection.
func LineEgressState(s *store.Store, lineID string, now time.Time) (string, string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	return store.LineOutEgressStatusTx(tx, lineID, now)
}

// OutReadbackAllowlist is a test helper around the chain lookup.
func OutReadbackAllowlist(s *store.Store, outID string, revision int64) ([]string, bool, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	return store.OutReadbackAllowlistTx(tx, outID, revision)
}

// PrepareSubscriberSyncForLine runs the Line half of the drain for one Line, so
// the gate can be exercised without a subscriber action.
func PrepareSubscriberSyncForLine(s *store.Store, lineID string, now time.Time) error {
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

// ConfirmChain simulates the exact readback the Agent reports: the latest
// candidate revision and digest observed, plus a healthy fixed chain.
func ConfirmChain(t *testing.T, s *store.Store, nodeID string, now time.Time) {
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

// SubscriberSyncStatusForLine exposes the per-Line projection for tests.
func SubscriberSyncStatusForLine(s *store.Store, lineID string, now time.Time) (string, string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	return store.SubscriberLineSyncViewTx(tx, lineID, now)
}

// ConfigureOut stores the dial address of one Out node for tests. The port
// always matches the node's VLESS port, mirroring the production port-match
// rule, and the server is a documentation address.
func ConfigureOut(t *testing.T, s *store.Store, outID string, now time.Time) store.OutTransport {
	t.Helper()
	node, err := s.GetNodeAt(outID, now)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := s.SetOutTransport(outID, "out.example.invalid", node.VlessPort, now)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

// DropOutSelection keeps the subscriber's Lines but removes its Out choice.
func DropOutSelection(t *testing.T, s *store.Store, subscriberID string, lineIDs []string, now time.Time) {
	t.Helper()
	SelectOut(t, s, subscriberID, "", lineIDs, now)
}

// selectOut writes the subscription-side edge that carries an Out selection. Under
// Ruling R10 this is a routing choice for the client document, not an ACL write, so
// tests use it only where they are exercising the published client/route behavior.
func SelectOut(t *testing.T, s *store.Store, subscriberID, outID string, lineIDs []string, now time.Time) {
	t.Helper()
	if _, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{LineIDs: lineIDs, OutID: outID}, now); err != nil {
		t.Fatalf("select out %s for %s: %v", outID, subscriberID, err)
	}
}

func DrainOut(t *testing.T, s *store.Store, outID string, now time.Time) {
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
