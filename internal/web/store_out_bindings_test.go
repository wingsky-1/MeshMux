package web

import (
	"strings"
	"testing"
	"time"
)

// pairedStoreNode creates one node plus the non-revoked identity that a real
// pairing would issue, so enabling a binding can be tested without the HTTP
// pairing flow. The display name stays role-scoped and short.
func pairedStoreNode(t *testing.T, s *store, role string, now time.Time) string {
	t.Helper()
	node, _, err := s.createNode(role, role+"-node", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`,
		node.ID, []byte{0x01}, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE nodes SET status='paired' WHERE id=?`, node.ID); err != nil {
		t.Fatal(err)
	}
	return node.ID
}

// TestOutBindingCRUD_PreviewUnaffectedWithoutOut proves the two baseline
// guarantees of PR #8-A: an empty Hub has no binding and previews
// no-out-direct, and storing a binding never changes the subscription input
// that keeps the direct Line egress working.
func TestOutBindingCRUD_PreviewUnaffectedWithoutOut(t *testing.T) {
	s, now := subscriberStoreFixture(t)

	bindings, err := s.ListOutBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("empty store lists %d bindings", len(bindings))
	}
	preview, err := s.PreviewOutBinding("", "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "no-out-direct" || preview.Enabled || preview.AffectedLines != 0 || preview.AffectedPolicies != 0 {
		t.Fatalf("empty preview wrong: %+v", preview)
	}

	line := pairedStoreNode(t, s, "edge", now)
	out := pairedStoreNode(t, s, "out", now)
	configureLine(t, s, line, "line-a", now)
	subscriber, _, err := s.createSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Without a binding the proposed egress is direct and no policy is moved.
	preview, err = s.PreviewOutBinding(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "line-direct" || preview.AffectedLines != 0 || preview.AffectedPolicies != 0 {
		t.Fatalf("unbound preview wrong: %+v", preview)
	}

	if err = s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetOutBinding(out)
	if err != nil {
		t.Fatal(err)
	}
	if stored.OutID != out || stored.LineID != line || !stored.Enabled || stored.UpdatedAt <= 0 {
		t.Fatalf("stored binding wrong: %+v", stored)
	}
	bindings, err = s.ListOutBindings()
	if err != nil || len(bindings) != 1 || bindings[0] != stored {
		t.Fatalf("list after bind wrong: %+v err=%v", bindings, err)
	}

	preview, err = s.PreviewOutBinding(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "out-bound" || !preview.Enabled || preview.AffectedLines != 1 ||
		preview.AffectedPolicies != 1 || preview.AffectedSubscribers != 1 {
		t.Fatalf("bound preview wrong: %+v", preview)
	}

	// The binding layer never rewrites the subscription input: the Subscriber
	// still owns exactly one active credential on its Line.
	var credentials int
	if err = s.db.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND node_id=? AND active=1`,
		subscriber.ID, line).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if credentials != 1 {
		t.Fatalf("subscription credentials changed by binding: %d", credentials)
	}

	// A disabled binding is a real state: the record survives but egress is
	// direct again.
	if err = s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	preview, err = s.PreviewOutBinding(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "out-disabled" || preview.Enabled || preview.LineID != line {
		t.Fatalf("disabled preview wrong: %+v", preview)
	}

	// Unbind preserves the audit row with an empty LineID.
	if err = s.ClearOutBinding(out); err != nil {
		t.Fatal(err)
	}
	stored, err = s.GetOutBinding(out)
	if err != nil {
		t.Fatal(err)
	}
	if stored.OutID != out || stored.LineID != "" || stored.Enabled || stored.UpdatedAt <= 0 {
		t.Fatalf("unbound row wrong: %+v", stored)
	}
	preview, err = s.PreviewOutBinding(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "line-direct" || preview.Enabled || preview.AffectedLines != 0 {
		t.Fatalf("unbound preview wrong: %+v", preview)
	}
	// The Hub as a whole returns to direct egress because no binding is
	// enabled; the preserved audit row is not an egress.
	preview, err = s.PreviewOutBinding("", "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "line-direct" || preview.Enabled {
		t.Fatalf("hub preview after unbind wrong: %+v", preview)
	}
}

// TestOutBindingValidationAndAuthorization covers both ends of the immutable
// role contract and the paired-identity gate that protects enabling.
func TestOutBindingValidationAndAuthorization(t *testing.T) {
	s, now := subscriberStoreFixture(t)

	edgePaired := pairedStoreNode(t, s, "edge", now)
	outPaired := pairedStoreNode(t, s, "out", now)
	outUnpaired, _, err := s.createNode("out", "out-unpaired", 9443, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	edgeUnpaired, _, err := s.createNode("edge", "line-unpaired", 9444, 2224, now)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		binding OutBinding
		code    string
	}{
		{"out role", OutBinding{OutID: edgePaired, LineID: edgePaired, Enabled: false}, "OUT_ROLE_INVALID"},
		{"line role", OutBinding{OutID: outPaired, LineID: outPaired, Enabled: false}, "LINE_ROLE_INVALID"},
		{"unknown out", OutBinding{OutID: strings.Repeat("a", 32), LineID: edgePaired, Enabled: false}, "OUT_NOT_FOUND"},
		{"unknown line", OutBinding{OutID: outPaired, LineID: strings.Repeat("b", 32), Enabled: false}, "LINE_NOT_FOUND"},
		{"out unpaired", OutBinding{OutID: outUnpaired.ID, LineID: edgePaired, Enabled: true}, "OUT_NOT_AUTHORIZED"},
		{"line unpaired", OutBinding{OutID: outPaired, LineID: edgeUnpaired.ID, Enabled: true}, "OUT_NOT_AUTHORIZED"},
		{"bad out id", OutBinding{OutID: "out", LineID: edgePaired, Enabled: false}, "OUT_BINDING_INVALID"},
		{"empty line", OutBinding{OutID: outPaired, LineID: "", Enabled: false}, "OUT_BINDING_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.SetOutBinding(tc.binding); err == nil || !hasErrorCode(err, tc.code) {
				t.Fatalf("error = %v, want code %s", err, tc.code)
			}
		})
	}
	// None of the rejected writes left a rebound egress behind.
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM out_bindings WHERE enabled=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rejected bindings created %d enabled rows", count)
	}

	// A disabled binding needs only the roles, never a live identity.
	if err := s.SetOutBinding(OutBinding{OutID: outUnpaired.ID, LineID: edgePaired, Enabled: false}); err != nil {
		t.Fatalf("disabled binding rejected: %v", err)
	}

	// Unknown or wrongly typed nodes cannot be read or unbound either.
	if _, err := s.GetOutBinding(strings.Repeat("c", 32)); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("unknown get error = %v", err)
	}
	if err := s.ClearOutBinding(strings.Repeat("c", 32)); err == nil || !hasErrorCode(err, "OUT_NOT_FOUND") {
		t.Fatalf("unknown clear error = %v", err)
	}
	if err := s.ClearOutBinding(edgePaired); err == nil || !hasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("edge clear error = %v", err)
	}

	// Preview validates roles but never requires a paired identity.
	preview, err := s.PreviewOutBinding(outUnpaired.ID, edgePaired)
	if err != nil {
		t.Fatalf("read-only preview rejected an unpaired proposal: %v", err)
	}
	if preview.Mode != "out-bound" || preview.LineID != edgePaired || preview.AffectedLines != 1 {
		t.Fatalf("proposal preview wrong: %+v", preview)
	}
	if _, err := s.PreviewOutBinding(edgePaired, ""); err == nil || !hasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("edge preview error = %v", err)
	}
	if _, err := s.PreviewOutBinding(outPaired, outPaired); err == nil || !hasErrorCode(err, "LINE_ROLE_INVALID") {
		t.Fatalf("out-as-line preview error = %v", err)
	}
}

// TestSchemaV5MigrationCreatesOutBindingsAndPreservesV4 simulates a schema-4
// database, upgrades it, checks the additive table and verifies that the
// future-schema guard now rejects v6.
func TestSchemaV5MigrationCreatesOutBindingsAndPreservesV4(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)
	out := pairedStoreNode(t, s, "out", now)
	configureLine(t, s, line, "line-a", now)
	subscriber, _, err := s.createSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the database in its schema-4 shape: the Out binding table does
	// not exist yet and the version is 4.
	if _, err = s.db.Exec(`DROP TABLE out_bindings; PRAGMA user_version=4;`); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 4 {
		t.Fatalf("user_version=%d err=%v, want 4", version, err)
	}
	if err = s.migrate(); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("user_version=%d err=%v, want 5", version, err)
	}
	var tables int
	if err = s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='out_bindings'`).Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("out_bindings table missing: %d err=%v", tables, err)
	}

	// Schema-4 data and the new binding path survive the upgrade.
	if _, err = s.getSubscriber(subscriber.ID); err != nil {
		t.Fatalf("subscriber lost by migration: %v", err)
	}
	if err = s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
		t.Fatalf("binding after migration failed: %v", err)
	}

	// The schema guard moved with the migration.
	if _, err = s.db.Exec(`PRAGMA user_version=6`); err != nil {
		t.Fatal(err)
	}
	if err = s.migrate(); err == nil || !hasErrorCode(err, "SCHEMA_TOO_NEW") {
		t.Fatalf("future schema accepted: %v", err)
	}
}
