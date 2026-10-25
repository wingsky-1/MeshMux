package handler

// Legacy client-policy fixtures for the Task 6 read-only client layer.
//
// The client layer is closed to writes at the store boundary, so a test that
// needs an active legacy revision (to prove the preview/read path still works)
// inserts it directly. This is deliberately the only writer left: it stands for
// a row written by a release before schema 17, not for a supported operator
// action.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/web/store"
)

// seedLegacyClientPolicyStore inserts one active client revision for a legacy
// read/preview fixture and returns its id. A previous active client row is
// superseded first, mirroring the layer's one-active invariant.
func seedLegacyClientPolicyStore(t *testing.T, s *store.Store, payload json.RawMessage, now time.Time) string {
	t.Helper()
	id, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	stamp := now.Unix()
	if _, err := s.DB.Exec(`UPDATE route_policies SET status='superseded', updated_at=? WHERE layer='client' AND status='active'`, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO route_policies(id, revision, layer, name, payload, pins, status, operation_id, created_at, updated_at)
		VALUES(?,1,'client','legacy-client',?,'{}','active','legacy-client',?,?)`,
		id, string(payload), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO route_policy_events(policy_id, revision, kind, from_status, to_status, operation_id, created_at)
		VALUES(?,1,'create','','active','legacy-client',?)`, id, stamp); err != nil {
		t.Fatal(err)
	}
	return id
}

// seedLegacyClientPolicy is the browser-fixture form used by the publish and
// page tests.
func seedLegacyClientPolicy(t *testing.T, b *browser, payload string) string {
	t.Helper()
	return seedLegacyClientPolicyStore(t, b.app.store, json.RawMessage(payload), b.app.now())
}
