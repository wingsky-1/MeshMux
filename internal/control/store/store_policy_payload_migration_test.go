package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestSchema17StripsRetiredPolicyFields proves the only data change of Task 6:
// a legacy client revision keeps default/rules/note, loses the two keys that
// never reached a rendered document, and the row stays readable through the
// (now strict) active-intent decoder.
func TestSchema17StripsRetiredPolicyFields(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}],"exceptions":["news.example.invalid"],"ssids":["home-wifi"],"note":"legacy"}`
	clean := `{"default":"direct","rules":[]}`
	insert := func(id, layer, payload string) {
		t.Helper()
		if _, err := s.DB.Exec(`INSERT INTO route_policies(id, revision, layer, name, payload, pins, status, operation_id, created_at, updated_at)
			VALUES(?,1,?,?,?,'{}','active','legacy',1,1)`, id, layer, "legacy-"+layer, payload); err != nil {
			t.Fatal(err)
		}
	}
	clientID := strings.Repeat("a", 32)
	serverID := strings.Repeat("b", 32)
	insert(clientID, string(PolicyLayerClient), legacy)
	insert(serverID, string(PolicyLayerServer), clean)
	if _, err := s.DB.Exec(`PRAGMA user_version=16`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = OpenStore(dir)
	if err != nil {
		t.Fatalf("schema 16 -> 17 migration: %v", err)
	}
	defer s.Close()
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != DatabaseSchemaVersion {
		t.Fatalf("user_version = %d err=%v, want %d", version, err, DatabaseSchemaVersion)
	}
	var migrated, untouched []byte
	if err := s.DB.QueryRow(`SELECT payload FROM route_policies WHERE id=? AND revision=1`, clientID).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT payload FROM route_policies WHERE id=? AND revision=1`, serverID).Scan(&untouched); err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(migrated, &object); err != nil {
		t.Fatalf("migrated payload is not JSON: %v", err)
	}
	for _, retired := range []string{"exceptions", "ssids"} {
		if _, present := object[retired]; present {
			t.Fatalf("schema 17 kept %q: %s", retired, migrated)
		}
	}
	for _, kept := range []string{"default", "rules", "note"} {
		if _, present := object[kept]; !present {
			t.Fatalf("schema 17 dropped %q: %s", kept, migrated)
		}
	}
	if string(untouched) != clean {
		t.Fatalf("a clean payload changed: %s -> %s", clean, untouched)
	}
	// The strict reader accepts the migrated row: the legacy keys are gone.
	record, intent, err := s.ActivePolicyIntent(PolicyLayerClient)
	if err != nil || record.ID != clientID || intent.Default != "proxy" || len(intent.Rules) != 1 {
		t.Fatalf("legacy active read = %+v %+v err=%v", record, intent, err)
	}
	// A hand-written legacy key after the migration is refused, never ignored.
	if _, err := s.DB.Exec(`UPDATE route_policies SET payload=? WHERE id=? AND revision=1`, legacy, clientID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ActivePolicyIntent(PolicyLayerClient); err == nil || !strings.HasPrefix(err.Error(), "POLICY_CORRUPT") {
		t.Fatalf("strict decoder accepted a retired key: %v", err)
	}
	// Replaying the migration leg is a no-op: version 17 does not rewrite again.
	if err := s.Migrate(); err != nil {
		t.Fatalf("replay: %v", err)
	}
	var replayed []byte
	if err := s.DB.QueryRow(`SELECT payload FROM route_policies WHERE id=? AND revision=1`, serverID).Scan(&replayed); err != nil {
		t.Fatal(err)
	}
	if string(replayed) != clean {
		t.Fatalf("replay rewrote a clean payload: %s", replayed)
	}
}
