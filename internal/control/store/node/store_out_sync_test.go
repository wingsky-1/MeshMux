package node_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// TestOutAllowlist_LineRetireRevokes is the brief regression under Ruling R10: the
// Line is authorized at the Out by enrollment, and revoking its identity reclaims
// that authorization and republishes the Out with an explicit empty allowlist.
func TestOutAllowlist_LineRetireRevokes(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// Membership, not a subscription, authorizes the Line, so no selection is needed.
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 1 || allowed[0] != "203.0.113.7/32" {
		t.Fatalf("derived allowlist = %v, want the line address as a host prefix", allowed)
	}
	before := storetest.CandidateCount(t, s, out)
	if before < 1 {
		t.Fatalf("out has no published chain: %d", before)
	}
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	chain := storetest.ChainRevisionParams(t, s, out, latest.Revision)
	if len(chain) != len(protocol.PublicationKinds) {
		t.Fatalf("out chain length = %d, want %d", len(chain), len(protocol.PublicationKinds))
	}
	for _, task := range chain {
		if task.Allowed == nil {
			t.Fatalf("%s task omitted allowed_sources", task.Kind)
		}
		if len(*task.Allowed) != 1 || (*task.Allowed)[0] != "203.0.113.7/32" {
			t.Fatalf("%s task allowlist = %v, want the line address", task.Kind, *task.Allowed)
		}
	}
	// The fixture starts from a confirmed pair, so the Out is healthy for the
	// membership authorization the chain carries.
	state, code, err := storetest.OutSyncStatusForTest(t, s, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncHealthy || code != "" {
		t.Fatalf("out status after enrollment = %s/%s, want healthy", state, code)
	}

	// Retiring is an identity revocation: it reclaims the authorization at
	// every Out that ever bound the Line.
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	allowed, err = s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("derived allowlist after retire = %v, want empty", allowed)
	}
	if got := storetest.CandidateCount(t, s, out); got != before+1 {
		t.Fatalf("out revisions after retire = %d, want exactly one more than %d", got, before)
	}
	latest, err = s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range storetest.ChainRevisionParams(t, s, out, latest.Revision) {
		if task.Allowed == nil {
			t.Fatalf("%s task omitted the reclaimed allowlist", task.Kind)
		}
		if len(*task.Allowed) != 0 {
			t.Fatalf("%s task still authorizes %v after retire", task.Kind, *task.Allowed)
		}
	}
	// The published chain carries the revoked set. A revocation lands while the
	// previous chain is still in flight, so the republish is deferred and the Out is
	// never reported healthy on the stale guard; once the chain settles the empty
	// authorization is published and confirmed.
	state, _, err = storetest.OutSyncStatusForTest(t, s, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state == store.OutSyncHealthy {
		t.Fatal("out reported healthy while its guard still carried the revoked source")
	}
	storetest.SettleTasks(t, s, out)
	storetest.ConfirmChain(t, s, out, now)
	state, code, err = storetest.OutSyncStatusForTest(t, s, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncHealthy || code != "" {
		t.Fatalf("out status after the reclaimed guard settled = %s/%s, want healthy", state, code)
	}

	// The revoked Line has no egress selection, so the pair reports the direct state
	// (nothing to gate), while the Out no longer accepts it as a source at all: the
	// revocation is carried by the empty allowlist asserted above, not by pretending
	// the Line still uses the Out.
	egress, _, err := storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if egress != store.LineEgressDirect {
		t.Fatalf("line egress after retire = %s, want direct (the selection is gone)", egress)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("the retired line is still an authorized source: %v err=%v", allowed, err)
	}
}

// TestOutAllowlist_DerivationStates pins the two "no authorization" states of the
// membership model and the canonical spelling of the authorized one.
//
// Ruling R10 removed the subscription from the ACL, so "never selected" and
// "selection dropped" are no longer authorization states at all: they are the
// ordinary case of an enrolled Line. What can still empty the list is a Hub with no
// Line, or a Line whose identity/transport is gone.
func TestOutAllowlist_DerivationStates(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// Enrolled Line: authorized by membership, with no subscription involved.
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 1 ||
		allowed[0] != "203.0.113.7/32" {
		t.Fatalf("membership derivation = %v err=%v, want the line address", allowed, err)
	}
	// Dropping the subscription changes nothing: it is not an ACL input.
	storetest.DisableOutForLine(t, s, out, line, now)
	storetest.SettleTasks(t, s, out)
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 1 {
		t.Fatalf("derivation after dropping the selection = %v err=%v, want membership unchanged", allowed, err)
	}
	// Revoking the identity does empty it, and the Out republishes an explicit empty
	// list instead of dropping the key.
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	storetest.SettleTasks(t, s, out)
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("revoked derivation = %v err=%v, want empty", allowed, err)
	}
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := storetest.OutReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("revoked chain = %v present=%v, want an explicit empty list", revoked, present)
	}

	// Unknown and wrong-role nodes are refused instead of being reported as
	// "authorized for nothing".
	if _, err := s.DeriveOutAllowlist(strings.Repeat("a", 32)); err == nil || !storetest.HasErrorCode(err, "OUT_NOT_FOUND") {
		t.Fatalf("unknown out derivation error = %v", err)
	}
	if _, err := s.DeriveOutAllowlist(line); err == nil || !storetest.HasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("edge derivation error = %v", err)
	}
	if _, err := s.DeriveOutAllowlist("out"); err == nil || !storetest.HasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("malformed out derivation error = %v", err)
	}
	_ = now
	_ = line
}

// TestOutAllowlist_RejectsUnverifiableLine keeps the "only verified Line egress"
// rule explicit: a DNS-named Line cannot be authorized, and an unpaired Line is
// simply not a source yet.
func TestOutAllowlist_RejectsUnverifiableLine(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// A host name has no Hub-verifiable egress address.
	named := storetest.TestLine(line, "line-a")
	named.Server = "line.example.invalid"
	named.ServerName = "line.example.invalid"
	if _, err := s.SetLine(named, now); err != nil {
		t.Fatal(err)
	}
	// The derivation is a hard refusal, not a silent empty set: the Hub will not guess
	// an address for a DNS-named Line (Ruling R10 keeps this rule).
	if allowed, err := s.DeriveOutAllowlist(out); err == nil {
		t.Fatalf("host-named line derived %v, want LINE_EGRESS_UNVERIFIED", allowed)
	} else if !storetest.HasErrorCode(err, store.CodeLineEgressUnverified) {
		t.Fatalf("host-named derivation error = %v, want LINE_EGRESS_UNVERIFIED", err)
	}
	// Selecting the Out makes the Line's own egress projection report the refusal.
	storetest.EnableOutForLine(t, s, out, line, now)
	state, code, err := storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressPartial || code != store.CodeLineEgressUnverified {
		t.Fatalf("host-named line egress = %s/%s, want partial/LINE_EGRESS_UNVERIFIED", state, code)
	}
	// A changed snapshot reaches the gate: adding a subscriber gives the Line
	// something new to publish, and the refusal must stop it.
	if _, _, err := s.CreateSubscriber("bob", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err == nil || !storetest.HasErrorCode(err, "OUT_NOT_AUTHORIZED") {
		t.Fatalf("host-named line publish error = %v, want OUT_NOT_AUTHORIZED", err)
	}

	// No Out chain was published with the host name in it: the derivation refused, so
	// the guard keeps whatever membership set it already had (a Line the Hub cannot
	// vouch for never widens it).
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := storetest.OutReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("the published chain omitted allowed_sources")
	}
	for _, entry := range revoked {
		if strings.Contains(entry, "line.example.invalid") {
			t.Fatalf("a host name reached the allowlist: %v", revoked)
		}
	}

	// Without a current identity the Line is simply not a source any more, and the
	// projection reports that instead of silently publishing.
	if _, err := s.DB.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, line); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("unpaired line derived %v err=%v, want empty", allowed, err)
	}
	state, code, err = storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressPartial || code != store.CodeLineNotAuthorized {
		t.Fatalf("unpaired line egress = %s/%s, want partial/LINE_NOT_AUTHORIZED", state, code)
	}
}

// TestOutAllowlist_SourceCanonicalization pins the derivation contract that keeps
// the Node side from silently widening a prefix: only a bare address or an
// aligned CIDR survives, and an unmasked prefix is rejected.
func TestOutAllowlist_SourceCanonicalization(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{"ipv4 host", "203.0.113.7", "203.0.113.7/32", true},
		{"ipv6 host", "2001:db8::7", "2001:db8::7/128", true},
		{"aligned ipv4 cidr", "198.51.100.0/24", "198.51.100.0/24", true},
		{"aligned ipv6 cidr", "2001:db8::/32", "2001:db8::/32", true},
		{"unaligned ipv4 cidr", "198.51.100.99/24", "", false},
		{"unaligned ipv6 cidr", "2001:db8::7/32", "", false},
		{"default route v4", "0.0.0.0/0", "", false},
		{"default route v6", "::/0", "", false},
		{"host name", "line.example.invalid", "", false},
		{"host with zone", "fe80::1%eth0", "", false},
		{"v4 in v6", "::ffff:203.0.113.7", "", false},
		{"empty", "", "", false},
		{"whitespace", " 203.0.113.7", "", false},
		{"injection", "203.0.113.7; reboot", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.OutAllowlistSource(tc.input)
			if tc.ok {
				if err != nil || got != tc.want {
					t.Fatalf("outAllowlistSource(%q) = %q err=%v, want %q", tc.input, got, err, tc.want)
				}
				return
			}
			if err == nil || !storetest.HasErrorCode(err, "OUT_ALLOWLIST_INVALID") {
				t.Fatalf("outAllowlistSource(%q) = %q err=%v, want OUT_ALLOWLIST_INVALID", tc.input, got, err)
			}
		})
	}
}

// TestOutAllowlist_PublishGateBlocksUnauthorizedEgress is the publish gate: the
// Line is not published while the Out has not confirmed the authorization, and
// the projection says so instead of reporting a healthy snapshot.
func TestOutAllowlist_PublishGateBlocksUnauthorizedEgress(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// No subscription selects an Out, so the Line has no Out path and the gate is a
	// no-op: a membership Hub must not block a direct Line on an unrelated Out.
	// A confirmed direct Line needs no republication: the gate is a no-op, so the
	// desired snapshot already matches the published one.
	before := storetest.CandidateCount(t, s, line)
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("a direct line publish must not be gated: %v", err)
	}
	if got := storetest.CandidateCount(t, s, line); got != before {
		t.Fatalf("an unchanged direct line was republished: %d -> %d", before, got)
	}

	// Selecting the Out puts that Line behind the Out gate. The selection alone does
	// not republish the Out (Ruling R10: it is not an ACL input), so the gate passes
	// immediately and the Line publishes the double hop.
	storetest.EnableOutForLine(t, s, out, line, now)
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("publish after selecting the out failed: %v", err)
	}
	selected := storetest.CandidateCount(t, s, line)
	if selected < before {
		t.Fatalf("line revisions regressed: %d -> %d", before, selected)
	}

	// The gate bites when the Out's own authorization is not proven: an Out that has
	// not confirmed its chain must not release the Line, or the Line would publish an
	// egress the guard still drops.
	//
	// The gate is asserted through the projection it reads (LineOutEgressStatusTx) and
	// through a changed Line snapshot, because an unchanged confirmed Line is a
	// deliberate no-op that never reaches the gate.
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0, observed_revision=0, observed_config_sha256='' WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	if state, _, statusErr := storetest.LineEgressState(s, line, now); statusErr != nil || state == store.LineEgressHealthy {
		t.Fatalf("line egress after the out evidence was cleared = %s err=%v, want a refusal", state, statusErr)
	}
	if _, _, err := s.CreateSubscriber("bob", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	err := storetest.PrepareSubscriberSyncForLine(s, line, now)
	if err == nil || !storetest.HasErrorCode(err, "OUT_NOT_AUTHORIZED") {
		t.Fatalf("publish before out confirmation error = %v, want OUT_NOT_AUTHORIZED", err)
	}
	if got := storetest.CandidateCount(t, s, line); got != selected {
		t.Fatalf("a gated line published: %d -> %d", selected, got)
	}
	storetest.ConfirmChain(t, s, out, now)
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("publish after out confirmation failed: %v", err)
	}
	if got := storetest.CandidateCount(t, s, line); got != selected+1 {
		t.Fatalf("line revisions after gate opens = %d, want one more than %d", got, selected)
	}
}

// TestOutAllowlist_RetireReclaimsEvenWhenDisabled keeps the "no dangling allow"
// guarantee: an Out that carries the ACL of a formerly enabled binding is
// republished even when the binding was disabled in the meantime.
func TestOutAllowlist_RetireReclaimsEvenWhenDisabled(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	storetest.EnableOutForLine(t, s, out, line, now)
	storetest.ConfirmChain(t, s, out, now)
	storetest.DisableOutForLine(t, s, out, line, now)
	before, err := storetest.CandidateCount(t, s, out), error(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	// The disabled binding still names the Line, so the retire path reads the
	// row and republishes the (already empty) authorization. An idempotent no-op
	// would be acceptable, a stale allowlist is not.
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := storetest.OutReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("disabled-then-retired chain = %v present=%v, want explicit empty", revoked, present)
	}
	if got := storetest.CandidateCount(t, s, out); got < before {
		t.Fatalf("out revisions = %d, want at least %d", got, before)
	}
}

// TestOutAllowlist_MismatchIsAnExpectedTransition pins the OUT_ACL_SOURCE_MISMATCH
// handling: the superseded chain is not a terminal failure and the identical
// snapshot is not retried automatically.
func TestOutAllowlist_MismatchIsAnExpectedTransition(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	storetest.EnableOutForLine(t, s, out, line, now)
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code=? WHERE node_id=?`, store.OutAclSourceMismatchCode, out); err != nil {
		t.Fatal(err)
	}
	state, code, err := storetest.OutSyncStatusForTest(t, s, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncVerifying || code != store.OutAclSourceMismatchCode {
		t.Fatalf("mismatch status = %s/%s, want verifying/OUT_ACL_SOURCE_MISMATCH", state, code)
	}
	before := storetest.CandidateCount(t, s, out)
	// An automatic drain never republishes the identical snapshot.
	storetest.DrainOut(t, s, out, now)
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("automatic drain repeated a superseded chain: %d -> %d", before, got)
	}
	// The explicit retry is the rollback pointer that publishes it again.
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("explicit retry failed: %v", err)
	}
	if got := storetest.CandidateCount(t, s, out); got != before+1 {
		t.Fatalf("explicit retry published %d revisions, want one more than %d", got, before)
	}
}

// drainOut runs the automatic Out drain for one node.
// TestOutAllowlist_UnchangedFailureNeedsExplicitRetry keeps the bounded-retry
// rule: a terminal failure is not republished by an automatic poll, only by the
// explicit retry.
func TestOutAllowlist_UnchangedFailureNeedsExplicitRetry(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	storetest.EnableOutForLine(t, s, out, line, now)
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_ACL_RULE_INVALID' WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	state, code, err := storetest.OutSyncStatusForTest(t, s, out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.OutSyncPartial || code != "OUT_ACL_RULE_INVALID" {
		t.Fatalf("failure status = %s/%s, want partial/OUT_ACL_RULE_INVALID", state, code)
	}
	before := storetest.CandidateCount(t, s, out)
	storetest.DrainOut(t, s, out, now)
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("automatic drain retried an unchanged failure: %d -> %d", before, got)
	}
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("explicit retry failed: %v", err)
	}
	if got := storetest.CandidateCount(t, s, out); got != before+1 {
		t.Fatalf("explicit retry revisions = %d, want %d", got, before+1)
	}
}

// TestOutAllowlist_OfflineOutKeepsIntent proves an offline Out receives no
// state-changing task and the caller sees the explicit deferral.
func TestOutAllowlist_OfflineOutKeepsIntent(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// The Out goes offline after its membership authorization settled, so the next
	// change cannot be delivered and the durable intent has to wait.
	before := storetest.CandidateCount(t, s, out)
	if _, err := s.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatalf("revoke the line: %v", err)
	}
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("offline out received %d revisions, want %d", got, before)
	}
	err := s.RetryOutSync(out, now)
	if err == nil || !storetest.HasErrorCode(err, "OUT_OFFLINE") {
		t.Fatalf("offline retry error = %v, want OUT_OFFLINE", err)
	}
}

// TestOutAllowlist_InFlightChainIsNeverRaced proves a publish request defers
// while another chain of the same Out is unfinished.
func TestOutAllowlist_InFlightChainIsNeverRaced(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	before := storetest.CandidateCount(t, s, out)
	// An unfinished chain of the Out defers the event that would republish it, so a
	// retire cannot leave two apply steps racing on one host.
	tasks, err := s.DB.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=? AND status='healthy'`, out)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := tasks.RowsAffected(); n == 0 {
		t.Fatal("the fixture out has no settled chain to re-open")
	}
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("retire published a competing chain: %d -> %d", before, got)
	}
	// The published chain still names the retired Line, which is exactly why
	// the caller sees an explicit pending state instead of a false success.
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := storetest.OutReadbackAllowlist(s, out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 1 {
		t.Fatalf("in-flight published chain = %v present=%v, want the previous authorization", revoked, present)
	}
	// Once the in-flight chain settles the reclaim is published.
	storetest.SettleTasks(t, s, out)
	if err := s.RetryOutSync(out, now); err != nil {
		t.Fatalf("retry after settle failed: %v", err)
	}
	if got := storetest.CandidateCount(t, s, out); got != before+1 {
		t.Fatalf("reclaim after settle = %d revisions, want %d", got, before+1)
	}
}

// TestOutAllowlist_DualReadbackReportsEachFact pins the four-way readback: a
// plain Out allowlist alone never makes the final egress healthy.
func TestOutAllowlist_DualReadbackReportsEachFact(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// Direct egress: the final egress follows the Line snapshot alone.
	direct, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Allowlist != store.LineEgressDirect {
		t.Fatalf("direct allowlist = %s, want direct", direct.Allowlist)
	}

	// The membership authorization is confirmed, so selecting the Out makes the pair
	// healthy rather than transitional; the four facts are then asserted one by one.
	storetest.EnableOutForLine(t, s, out, line, now)
	pending, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Allowlist == store.LineEgressDirect || pending.FinalEgress == store.LineEgressHealthy && pending.AllowlistCode != "" {
		t.Fatalf("unconfirmed readback = %+v, want a non-healthy transition", pending)
	}

	// Confirm both sides: the Out allowlist and the Line snapshot.
	storetest.ConfirmChain(t, s, out, now)
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	storetest.ConfirmChain(t, s, line, now)
	healthy, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.Allowlist != store.LineEgressHealthy || healthy.Inbound != store.SubscriberSyncHealthy ||
		healthy.FinalEgress != store.LineEgressHealthy || !healthy.Reality {
		t.Fatalf("confirmed readback = %+v, want a healthy pair with REALITY", healthy)
	}

	// A reclaimed allowlist while the Line is unchanged drops the final egress
	// back to a transition: the pair is never healthy on one side alone.
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=? AND status='healthy'`, out); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	regressed, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if regressed.FinalEgress == store.LineEgressHealthy {
		t.Fatalf("readback reported healthy after the out evidence was cleared: %+v", regressed)
	}

	// The other direction is equally decisive: a healthy Out allowlist must not
	// carry the pair when the Line itself lost its inbound evidence. Otherwise
	// "allowlist healthy" alone would be treated as an egress proof.
	storetest.ConfirmChain(t, s, out, now)
	if _, err := s.DB.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=? AND status='healthy'`, line); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0 WHERE id=?`, line); err != nil {
		t.Fatal(err)
	}
	lineRegressed, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if lineRegressed.Allowlist != store.LineEgressHealthy {
		t.Fatalf("setup: out allowlist should still be healthy, got %+v", lineRegressed)
	}
	if lineRegressed.FinalEgress == store.LineEgressHealthy {
		t.Fatalf("readback reported healthy on the allowlist alone: %+v", lineRegressed)
	}
}

// TestOutAllowlist_ReadbackUsesOnlyStableCodes proves the readback never leaks a
// stored value or a raw error.
func TestOutAllowlist_ReadbackUsesOnlyStableCodes(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	storetest.EnableOutForLine(t, s, out, line, now)
	readback, err := s.NodeCoordinationReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(readback)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.LineServer, "line.example.invalid", "alice"} {
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

// TestOutAllowlist_SchemaIsUnchanged keeps the coordination layer free of new
// tables and kinds: the authorization lives in the frozen chain params. The
// schema version itself is 8 only because the mesh device, route and policy tables
// exist; this slice adds nothing to it.
func TestOutAllowlist_SchemaIsUnchanged(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s := f.Store
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("user_version = %d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	// The four kinds are still exactly the frozen publication chain.
	if len(protocol.PublicationKinds) != 4 {
		t.Fatalf("publication kinds = %v, want the frozen four", protocol.PublicationKinds)
	}
	// An Out candidate never carries users or REALITY.
	candidate, err := s.LatestCandidate(f.Out)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Document.Role != node.RoleOut || candidate.Document.Reality != nil ||
		len(candidate.Document.Users) != 0 {
		t.Fatalf("out candidate is not the credential-free baseline: %+v", candidate.Document)
	}
	// The immutable candidate is still immutable.
	if _, err := s.DB.Exec(`UPDATE node_candidates SET config_sha256='x' WHERE node_id=? AND revision=?`,
		f.Out, candidate.Revision); err == nil || !strings.Contains(err.Error(), "CANDIDATE_IMMUTABLE") {
		t.Fatalf("candidate immutability lost: %v", err)
	}
	_ = subscription.StateActive
}

// TestOutAllowlist_PreviewReportsEgressState pins the brief's "preview refuses a
// policy that depends on an unauthorized Out": a proposal is never reported as
// an established path, and an enabled binding reports the real Hub state.
func TestOutAllowlist_PreviewReportsEgressState(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// Membership preview: the Out accepts the enrolled Line and names it as its source,
	// whether or not any subscription selects it (Ruling R10).
	direct, err := s.PreviewOutAuthorizationAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Mode != store.OutPoolBound || direct.EgressState != store.LineEgressHealthy ||
		direct.EgressCode != "" || len(direct.Sources) != 1 || direct.Sources[0] != "203.0.113.7/32" {
		t.Fatalf("membership preview = %+v, want out-selected/healthy with the line address", direct)
	}
	if len(direct.LineIDs) != 1 || direct.LineIDs[0] != line {
		t.Fatalf("membership preview lines = %v, want the enrolled line", direct.LineIDs)
	}
	// A proposal is pending, with the same refusal code the gate uses.
	proposal, err := s.PreviewOutAuthorizationAt(out, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.EgressState != store.LineEgressPendingPreview || proposal.EgressCode != store.CodeOutNotAuthorized {
		t.Fatalf("proposal preview = %+v, want pending/OUT_NOT_AUTHORIZED", proposal)
	}
	// An established, confirmed selection reports healthy and names its source.
	storetest.EnableOutForLine(t, s, out, line, now)
	storetest.ConfirmChain(t, s, out, now)
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	storetest.ConfirmChain(t, s, line, now)
	established, err := s.PreviewOutAuthorizationAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if established.EgressState != store.LineEgressHealthy || established.Mode != store.OutPoolBound {
		t.Fatalf("established preview = %+v, want out-selected/healthy", established)
	}
	if len(established.Sources) != 1 || established.Sources[0] != "203.0.113.7/32" {
		t.Fatalf("established preview sources = %v", established.Sources)
	}
	// Dropping the selection changes nothing about membership: the Out still accepts
	// the Line and still reports the same derived source (Ruling R10). The selection is
	// a routing choice, not an authorization one.
	storetest.DisableOutForLine(t, s, out, line, now)
	released, err := s.PreviewOutAuthorizationAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if released.Mode != store.OutPoolBound || released.EgressState != store.LineEgressHealthy {
		t.Fatalf("released preview = %+v, want out-selected/healthy (membership unchanged)", released)
	}
	if len(released.Sources) != 1 || released.Sources[0] != "203.0.113.7/32" {
		t.Fatalf("released preview sources = %v, want the membership source", released.Sources)
	}
	if len(released.Subscribers) != 0 {
		t.Fatalf("released preview still reports a selecting subscriber: %v", released.Subscribers)
	}
}
