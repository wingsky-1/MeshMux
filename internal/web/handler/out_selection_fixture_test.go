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
)

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
