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

	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
)

// seedLegacyClientPolicy is the browser-fixture form used by the publish and
// page tests.
func seedLegacyClientPolicy(t *testing.T, b *browser, payload string) string {
	t.Helper()
	return storetest.SeedLegacyClientPolicyStore(t, b.app.Store, json.RawMessage(payload), b.app.Now())
}
