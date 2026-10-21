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
	edgeUnpaired, _, err := s.createNode("edge", "line-unpaired", 8443, 2224, now)
	if err != nil {
		t.Fatal(err)
	}
	// Both edge nodes carry a stored transport, so the enable gate reaches the
	// identity check instead of stopping at LINE_NOT_CONFIGURED.
	configureLine(t, s, edgePaired, "line-paired", now)
	configureLine(t, s, edgeUnpaired.ID, "line-unpaired", now)

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

// TestOutBindingEnableRequiresConfiguredLine closes the gap where a binding
// could point at an edge node that never stored a Line transport, which could
// never serve a client configuration.
func TestOutBindingEnableRequiresConfiguredLine(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)

	// Enabled binding to an unconfigured Line is rejected with the same code
	// the subscriber selection path uses.
	err := s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: true})
	if err == nil || !hasErrorCode(err, "LINE_NOT_CONFIGURED") {
		t.Fatalf("enabled unconfigured line error = %v, want LINE_NOT_CONFIGURED", err)
	}
	if _, err := s.GetOutBinding(out); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("rejected enable left a row: %v", err)
	}
	// A read-only proposal preview refuses the same impossible egress instead
	// of promising it.
	if _, err := s.PreviewOutBinding(out, line); err == nil || !hasErrorCode(err, "LINE_NOT_CONFIGURED") {
		t.Fatalf("proposal preview error = %v, want LINE_NOT_CONFIGURED", err)
	}
	// Disabled bindings stay allowed: they describe no egress yet.
	if err := s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: false}); err != nil {
		t.Fatalf("disabled binding rejected: %v", err)
	}
	// Once the transport exists, enabling succeeds.
	configureLine(t, s, line, "line-configured", now)
	if err := s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
		t.Fatalf("configured line still rejected: %v", err)
	}
}

// TestOutBindingStoreOwnsClock proves the audit timestamp cannot be chosen by
// the caller: a zero, past or future UpdatedAt is always replaced by the
// store clock of the request.
func TestOutBindingStoreOwnsClock(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-clock", now)

	for _, supplied := range []int64{0, 1, 1 << 40} {
		if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true, UpdatedAt: supplied}, now); err != nil {
			t.Fatalf("set with UpdatedAt=%d failed: %v", supplied, err)
		}
		stored, err := s.GetOutBinding(out)
		if err != nil {
			t.Fatal(err)
		}
		if stored.UpdatedAt != now.Unix() {
			t.Fatalf("UpdatedAt=%d stored as %d, want store clock %d", supplied, stored.UpdatedAt, now.Unix())
		}
	}

	// The unbound audit row also uses the store clock.
	later := now.Add(time.Hour)
	if err := s.clearOutBindingAt(out, later); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetOutBinding(out)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UpdatedAt != later.Unix() {
		t.Fatalf("clear UpdatedAt=%d, want %d", stored.UpdatedAt, later.Unix())
	}
}

// TestOutBindingClearUnboundOutIsNoop keeps a never-configured Hub at
// no-out-direct: unbinding an Out that has no row must not fabricate an audit
// row that would read as a deliberate direct egress.
func TestOutBindingClearUnboundOutIsNoop(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)

	if err := s.ClearOutBinding(out); err != nil {
		t.Fatalf("clear of unbound out failed: %v", err)
	}
	bindings, err := s.ListOutBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("clear fabricated %d binding rows", len(bindings))
	}
	preview, err := s.PreviewOutBinding("", "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "no-out-direct" {
		t.Fatalf("hub preview after no-op clear = %s, want no-out-direct", preview.Mode)
	}

	// An existing row still becomes a preserved unbind audit row, and a
	// repeated clear stays idempotent.
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-noop", now)
	if err := s.SetOutBinding(OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearOutBinding(out); err != nil {
		t.Fatal(err)
	}
	first, err := s.GetOutBinding(out)
	if err != nil {
		t.Fatal(err)
	}
	if first.LineID != "" || first.Enabled {
		t.Fatalf("clear did not unbind: %+v", first)
	}
	if err := s.ClearOutBinding(out); err != nil {
		t.Fatalf("repeated clear failed: %v", err)
	}
	second, err := s.GetOutBinding(out)
	if err != nil {
		t.Fatal(err)
	}
	if second.LineID != "" || second.Enabled {
		t.Fatalf("repeated clear changed the row: %+v", second)
	}
	// The Hub now reports line-direct because a real audit row exists.
	preview, err = s.PreviewOutBinding("", "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "line-direct" || preview.Enabled {
		t.Fatalf("hub preview after real unbind = %+v", preview)
	}
}

// TestOutBindingPreviewFanOutCountsOnce is the I1 regression: two Out rows may
// point at the same Line, and the credentials join then fans out. The Hub
// aggregate must count each policy once and match the single-binding preview.
func TestOutBindingPreviewFanOutCountsOnce(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)
	outA := pairedStoreNode(t, s, "out", now)
	outB := pairedStoreNode(t, s, "out", now)
	configureLine(t, s, line, "line-fanout", now)
	for _, name := range []string{"alice", "bob"} {
		if _, _, err := s.createSubscriber(name, []string{line}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetOutBinding(OutBinding{OutID: outA, LineID: line, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOutBinding(OutBinding{OutID: outB, LineID: line, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	single, err := s.PreviewOutBinding(outA, "")
	if err != nil {
		t.Fatal(err)
	}
	if single.AffectedLines != 1 || single.AffectedPolicies != 2 || single.AffectedSubscribers != 2 {
		t.Fatalf("single preview wrong: %+v", single)
	}
	hub, err := s.PreviewOutBinding("", "")
	if err != nil {
		t.Fatal(err)
	}
	if hub.Mode != "out-bound" || !hub.Enabled {
		t.Fatalf("hub preview mode wrong: %+v", hub)
	}
	// Two Out rows, one Line, two policies: the fan-out must not double count.
	if hub.AffectedLines != single.AffectedLines {
		t.Fatalf("affected lines %d != single %d", hub.AffectedLines, single.AffectedLines)
	}
	if hub.AffectedPolicies != single.AffectedPolicies {
		t.Fatalf("affected policies %d != single %d (fan-out double counted)", hub.AffectedPolicies, single.AffectedPolicies)
	}
	if hub.AffectedSubscribers != single.AffectedSubscribers {
		t.Fatalf("affected subscribers %d != single %d", hub.AffectedSubscribers, single.AffectedSubscribers)
	}
	if hub.AffectedPolicies != 2 {
		t.Fatalf("affected policies = %d, want 2", hub.AffectedPolicies)
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
