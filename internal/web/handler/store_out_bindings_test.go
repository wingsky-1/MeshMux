package handler

import (
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
	"time"
)

// pairedStoreNode creates one node plus the non-revoked identity that a real
// pairing would issue, so enabling a binding can be tested without the HTTP
// pairing flow. The display name stays role-scoped and short.
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
	configureOut(t, s, out, now)
	subscriber, _, err := s.CreateSubscriber("alice", []string{line}, now)
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

	if err = s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
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
	if err = s.DB.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND node_id=? AND active=1`,
		subscriber.ID, line).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if credentials != 1 {
		t.Fatalf("subscription credentials changed by binding: %d", credentials)
	}

	// A disabled binding is a real state: the record survives but egress is
	// direct again.
	if err = s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: false}); err != nil {
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
	outUnpaired, _, err := s.CreateNode("out", "out-unpaired", 9443, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	edgeUnpaired, _, err := s.CreateNode("edge", "line-unpaired", 8443, 2224, now)
	if err != nil {
		t.Fatal(err)
	}
	// Both edge nodes carry a stored transport, so the enable gate reaches the
	// identity check instead of stopping at LINE_NOT_CONFIGURED.
	configureLine(t, s, edgePaired, "line-paired", now)
	configureLine(t, s, edgeUnpaired.ID, "line-unpaired", now)

	cases := []struct {
		name    string
		binding store.OutBinding
		code    string
	}{
		{"out role", store.OutBinding{OutID: edgePaired, LineID: edgePaired, Enabled: false}, "OUT_ROLE_INVALID"},
		{"line role", store.OutBinding{OutID: outPaired, LineID: outPaired, Enabled: false}, "LINE_ROLE_INVALID"},
		{"unknown out", store.OutBinding{OutID: strings.Repeat("a", 32), LineID: edgePaired, Enabled: false}, "OUT_NOT_FOUND"},
		{"unknown line", store.OutBinding{OutID: outPaired, LineID: strings.Repeat("b", 32), Enabled: false}, "LINE_NOT_FOUND"},
		{"out unpaired", store.OutBinding{OutID: outUnpaired.ID, LineID: edgePaired, Enabled: true}, "OUT_NOT_AUTHORIZED"},
		{"line unpaired", store.OutBinding{OutID: outPaired, LineID: edgeUnpaired.ID, Enabled: true}, "OUT_NOT_AUTHORIZED"},
		{"bad out id", store.OutBinding{OutID: "out", LineID: edgePaired, Enabled: false}, "OUT_BINDING_INVALID"},
		{"empty line", store.OutBinding{OutID: outPaired, LineID: "", Enabled: false}, "OUT_BINDING_INVALID"},
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
	if err := s.DB.QueryRow(`SELECT count(*) FROM out_bindings WHERE enabled=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rejected bindings created %d enabled rows", count)
	}

	// A disabled binding needs only the roles, never a live identity.
	if err := s.SetOutBinding(store.OutBinding{OutID: outUnpaired.ID, LineID: edgePaired, Enabled: false}); err != nil {
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

	// Preview validates roles but never requires a paired identity. The Out
	// carries its dial address so the proposal can describe a real egress.
	configureOut(t, s, outUnpaired.ID, now)
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
	err := s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true})
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
	if err := s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: false}); err != nil {
		t.Fatalf("disabled binding rejected: %v", err)
	}
	// A configured Line with an unconfigured Out is refused too: the Line
	// would otherwise render a block stub while the gate reports healthy.
	configureLine(t, s, line, "line-configured", now)
	err = s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true})
	if err == nil || !hasErrorCode(err, "OUT_NOT_CONFIGURED") {
		t.Fatalf("enabled unconfigured out error = %v, want OUT_NOT_CONFIGURED", err)
	}
	if _, err := s.PreviewOutBinding(out, line); err == nil || !hasErrorCode(err, "OUT_NOT_CONFIGURED") {
		t.Fatalf("proposal preview error = %v, want OUT_NOT_CONFIGURED", err)
	}
	// Once both transports exist, enabling succeeds.
	configureOut(t, s, out, now)
	if err := s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
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
	configureOut(t, s, out, now)

	for _, supplied := range []int64{0, 1, 1 << 40} {
		if err := s.SetOutBindingAt(store.OutBinding{OutID: out, LineID: line, Enabled: true, UpdatedAt: supplied}, now); err != nil {
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
	if err := s.ClearOutBindingAt(out, later); err != nil {
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
	configureOut(t, s, out, now)
	if err := s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
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

// TestDeleteOut_CleansRoutesAndACL is the brief case: deleting an Out must
// leave no dangling route and no extra ACL line, and the cleanup is published
// as an explicit empty authorization that the Hub reads back before returning.
func TestDeleteOut_CleansRoutesAndACL(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.SetOutBindingAt(store.OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, out, now)
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil || len(allowed) != 1 {
		t.Fatalf("authorization before delete = %v err=%v", allowed, err)
	}

	if err := s.DeleteOutAt(out, now); err != nil {
		t.Fatalf("delete out failed: %v", err)
	}

	// No route row survives, so "never configured" is the Hub-level state and
	// no preserved unbind row can read as a deliberate egress.
	bindings, err := s.ListOutBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("delete left %d binding rows", len(bindings))
	}
	if _, err := s.GetOutBinding(out); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("binding after delete = %v, want OUT_BINDING_NOT_FOUND", err)
	}
	preview, err := s.PreviewOutBinding("", "")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "no-out-direct" || preview.Enabled {
		t.Fatalf("hub preview after delete = %+v, want no-out-direct", preview)
	}

	// The ACL cleanup is the host-visible half: the newest chain names an
	// explicit empty list, never an omitted key.
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, present, err := outReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(reclaimed) != 0 {
		t.Fatalf("cleanup chain = %v present=%v, want an explicit empty allowlist", reclaimed, present)
	}
	for _, task := range chainRevisionParams(t, s, out, latest.Revision) {
		if task.Allowed == nil {
			t.Fatalf("%s task omitted the cleaned allowlist", task.Kind)
		}
		if len(*task.Allowed) != 0 {
			t.Fatalf("%s task still authorizes %v after delete", task.Kind, *task.Allowed)
		}
	}
	// The Out still has to prove the reclaimed guard, so it is not healthy yet.
	state, code, err := s.OutSyncStatus(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state == store.OutSyncHealthy {
		t.Fatalf("out status after delete = %s/%s, want a non-healthy transition", state, code)
	}

	// The Line is released from the Out gate: it is a direct Line again, and
	// its own publication no longer depends on a deleted Out.
	egress, _, err := lineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if egress != store.LineEgressDirect {
		t.Fatalf("line egress after delete = %s, want direct", egress)
	}
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("line publish after delete failed: %v", err)
	}

	// Once the Out proved the cleaned guard, deleting again is an idempotent
	// no-op: there is no route left and nothing to republish.
	settleTasks(t, s, out)
	if err := s.DeleteOutAt(out, now); err != nil {
		t.Fatalf("repeated delete after cleanup = %v, want a no-op success", err)
	}
	if bindings, err := s.ListOutBindings(); err != nil || len(bindings) != 0 {
		t.Fatalf("repeated delete left rows = %v err=%v", bindings, err)
	}
}

// TestDeleteOut_DefersCleanupForUnreachableOut keeps the partial-failure
// contract: the routing model is cleaned and fail-closed, but the host cleanup
// that could not be delivered is reported as pending instead of success.
func TestDeleteOut_DefersCleanupForUnreachableOut(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.SetOutBindingAt(store.OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, out, now)
	// The Out goes offline after its chain settled: the cleanup task cannot be
	// delivered, and the host may still carry the last authorized guard.
	if _, err := s.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	err := s.DeleteOutAt(out, now)
	if err == nil || !hasErrorCode(err, store.CodeOutSyncPending) || !hasErrorCode(err, "OUT_OFFLINE") {
		t.Fatalf("delete of an offline out = %v, want OUT_SYNC_PENDING and OUT_OFFLINE", err)
	}
	// The route is gone even though the host cleanup is pending: the Hub is
	// fail-closed from now on and never authorizes the deleted Line again.
	if _, err := s.GetOutBinding(out); err == nil || !hasErrorCode(err, "OUT_BINDING_NOT_FOUND") {
		t.Fatalf("binding after deferred delete = %v, want none", err)
	}
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil || len(allowed) != 0 {
		t.Fatalf("derivation after deferred delete = %v err=%v, want empty", allowed, err)
	}
	// The durable intent is complete: once the Out returns, its own event
	// publishes the empty authorization without another operator action.
	markLineOnline(t, s, out, now)
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("retry after the out returned failed: %v", err)
	}
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, present, err := outReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(reclaimed) != 0 {
		t.Fatalf("deferred cleanup chain = %v present=%v, want an explicit empty allowlist", reclaimed, present)
	}
}

// TestDeleteOut_RefusesWrongRoleAndUnknownNode pins the validation of the
// delete: only an existing Out node can be deleted, and a Line is never
// silently accepted.
func TestDeleteOut_RefusesWrongRoleAndUnknownNode(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)

	if err := s.DeleteOut(line); err == nil || !hasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("delete of an edge = %v, want OUT_ROLE_INVALID", err)
	}
	if err := s.DeleteOut(strings.Repeat("d", 32)); err == nil || !hasErrorCode(err, "OUT_NOT_FOUND") {
		t.Fatalf("delete of an unknown node = %v, want OUT_NOT_FOUND", err)
	}
	if err := s.DeleteOut("nope"); err == nil || !hasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("delete of a malformed id = %v, want OUT_BINDING_INVALID", err)
	}
	// The rejected calls changed nothing.
	if _, err := s.GetNodeAt(line, now); err != nil {
		t.Fatalf("rejected delete removed a node: %v", err)
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
	configureOut(t, s, outA, now)
	configureOut(t, s, outB, now)
	for _, name := range []string{"alice", "bob"} {
		if _, _, err := s.CreateSubscriber(name, []string{line}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetOutBinding(store.OutBinding{OutID: outA, LineID: line, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOutBinding(store.OutBinding{OutID: outB, LineID: line, Enabled: true}); err != nil {
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
// future-schema guard now rejects v8.
func TestSchemaV5MigrationCreatesOutBindingsAndPreservesV4(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)
	out := pairedStoreNode(t, s, "out", now)
	configureLine(t, s, line, "line-a", now)
	subscriber, _, err := s.CreateSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the database in its schema-4 shape: the Out binding and mesh
	// tables do not exist yet and the version is 4.
	if _, err = s.DB.Exec(`DROP TABLE route_policy_events; DROP TABLE route_policies; DROP TABLE mesh_route_events; DROP TABLE mesh_routes; DROP TABLE mesh_enrollment_keys; DROP TABLE mesh_devices; DROP TABLE out_bindings; PRAGMA user_version=4;`); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 4 {
		t.Fatalf("user_version=%d err=%v, want 4", version, err)
	}
	if err = s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("user_version=%d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	var tables int
	if err = s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='out_bindings'`).Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("out_bindings table missing: %d err=%v", tables, err)
	}
	// The Task 2 dial-parameter table is ensured on every open without a
	// version step, so it survives the same upgrade.
	if err = s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='out_settings'`).Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("out_settings table missing: %d err=%v", tables, err)
	}

	// Schema-4 data and the new binding path survive the upgrade.
	if _, err = s.GetSubscriber(subscriber.ID); err != nil {
		t.Fatalf("subscriber lost by migration: %v", err)
	}
	configureOut(t, s, out, now)
	if err = s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
		t.Fatalf("binding after migration failed: %v", err)
	}

	// The schema guard moved with the migration.
	if _, err = s.DB.Exec(`PRAGMA user_version=13`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(); err == nil || !hasErrorCode(err, "SCHEMA_TOO_NEW") {
		t.Fatalf("future schema accepted: %v", err)
	}
}
