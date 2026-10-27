package handler

// Subscription-side replacements for the deleted Out binding helpers.
//
// Before Task 5 these tests enabled an Out with store.SetOutBindingAt, which wrote
// the out_bindings row the ACL derivation read. That row is gone: the authorization
// now comes from the subscription edges, so a test that used to bind an Out selects
// it in the subscription that already serves the Line. Using the real wizard save
// keeps the fixtures honest — the same-Line consistency rule, the credential reuse
// and the drain side effects all run exactly as they do in production.

import (
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

// testSubscriberForLine returns the active subscriber that serves one Line,
// creating one when the fixture has none. The newest subscriber wins so a fixture
// that created several keeps a deterministic owner.
func testSubscriberForLine(t *testing.T, s *store.Store, lineID string, now time.Time) string {
	t.Helper()
	var subscriberID string
	err := s.DB.QueryRow(`SELECT l.subscriber_id FROM subscription_lines l
	  JOIN subscribers s ON s.id=l.subscriber_id
	 WHERE l.node_id=? AND s.state='active' ORDER BY l.subscriber_id LIMIT 1`, lineID).Scan(&subscriberID)
	if err == nil {
		return subscriberID
	}
	sub, _, err := s.CreateSubscriber("owner-"+shortID(lineID), []string{lineID}, now)
	if err != nil {
		t.Fatalf("create the owning subscriber: %v", err)
	}
	return sub.ID
}

// shortID is a readable test suffix for a node id.
func shortID(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}

// tableExists reports whether a table is present in the store's schema. It is how
// a test asserts that a migration dropped a table, instead of trusting a version
// number.
func tableExists(t *testing.T, s *store.Store, name string) bool {
	t.Helper()
	var tables int
	if err := s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&tables); err != nil {
		t.Fatalf("schema probe for %s: %v", name, err)
	}
	return tables != 0
}

// pairedStoreNode creates one node plus the non-revoked identity that a real
// pairing would issue, so a store-level test has a node the derivation can treat
// as current. The display name stays role-scoped and short.
func pairedStoreNode(t *testing.T, s *store.Store, role string, now time.Time) string {
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

// selectOutForLine writes the subscription edge that authorizes an Out for one
// Line. It is the single replacement of the deleted SetOutBindingAt.
func selectOutForLine(t *testing.T, s *store.Store, outID, lineID string, now time.Time) {
	t.Helper()
	subscriberID := testSubscriberForLine(t, s, lineID, now)
	if _, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{lineID}, OutID: outID,
	}, now); err != nil {
		t.Fatalf("select out %s for line %s: %v", outID, lineID, err)
	}
}

// clearOutForLine removes the Out choice of the subscription that serves one Line,
// keeping the Line selected. It is the replacement of a disabled binding and of
// ClearOutBindingAt: the Line is a direct egress again.
func clearOutForLine(t *testing.T, s *store.Store, lineID string, now time.Time) {
	t.Helper()
	subscriberID := testSubscriberForLine(t, s, lineID, now)
	if _, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{lineID},
	}, now); err != nil {
		t.Fatalf("clear the out selection of line %s: %v", lineID, err)
	}
}

// enableOutForLine is the readable alias of selectOutForLine.
func enableOutForLine(t *testing.T, s *store.Store, outID, lineID string, now time.Time) {
	t.Helper()
	selectOutForLine(t, s, outID, lineID, now)
}

// subscriberIDForTest returns the single subscriber a fixture created, so a test can
// drive the subscriber publication without guessing the id.
func (f pairedWebOutSyncApp) subscriberIDForTest(t *testing.T) string {
	t.Helper()
	var id string
	if err := f.app.Store.DB.QueryRow(`SELECT id FROM subscribers ORDER BY created_at ASC, id ASC LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("read the fixture subscriber: %v", err)
	}
	return id
}
