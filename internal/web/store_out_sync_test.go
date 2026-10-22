package web

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// outSyncFixture is one Hub with a paired Out, a paired Line with a literal
// transport address and one subscriber, so the allowlist derivation has a real
// source to authorize.
type outSyncFixture struct {
	store      *store
	now        time.Time
	out        string
	line       string
	lineServer string
}

// newOutSyncFixture builds the fixture. The Line transport address is a
// documentation IPv4 literal because a host name would be explicitly
// unauthorized by the Hub.
//
// Both nodes start with their initial publication chain already settled, so a
// test only has to reason about the chain its own action creates.
func newOutSyncFixture(t *testing.T) outSyncFixture {
	t.Helper()
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)
	lineSettings := testLine(line, "line-a")
	lineSettings.Server = "203.0.113.7"
	lineSettings.ServerName = "line.example.invalid"
	if _, err := s.setLine(lineSettings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, s, line, now)
	markLineOnline(t, s, out, now)
	if _, _, err := s.createSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{out, line} {
		seedInitialChain(t, s, nodeID, now)
		confirmChain(t, s, nodeID, now)
	}
	return outSyncFixture{store: s, now: now, out: out, line: line, lineServer: "203.0.113.7"}
}

// seedInitialChain reproduces the chain that pairing seeds for the current
// candidate, without driving the pairing endpoint.
func seedInitialChain(t *testing.T, s *store, nodeID string, now time.Time) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := seedInitialTasksTx(tx, nodeID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// chainRevisionParams reads the params of every task of one revision chain.
func chainRevisionParams(t *testing.T, s *store, nodeID string, revision int64) []struct {
	Kind    string
	Allowed *[]string
} {
	t.Helper()
	rows, err := s.db.Query(`SELECT kind, params FROM agent_tasks WHERE node_id=? ORDER BY revision ASC`, nodeID)
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

// TestOutAllowlist_LineRetireRevokes is the brief regression: an enabled binding
// authorizes the Line at the Out, and retiring the Line reclaims that
// authorization and republishes the Out with an explicit empty allowlist.
func TestOutAllowlist_LineRetireRevokes(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	// Enabling the binding publishes the authorization immediately, in the
	// frozen four-task chain, without the caller doing anything else.
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 1 || allowed[0] != "203.0.113.7/32" {
		t.Fatalf("derived allowlist = %v, want the line address as a host prefix", allowed)
	}
	if got, want := candidateCount(t, s, out), 2; got != want {
		t.Fatalf("out revisions after enable = %d, want %d", got, want)
	}
	latest, err := s.latestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	chain := chainRevisionParams(t, s, out, latest.Revision)
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
	state, code, err := s.outSyncStatus(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != outSyncVerifying || code != codeOutSyncInProgress {
		t.Fatalf("out status after publish = %s/%s, want verifying in progress", state, code)
	}
	// The Agent applies and confirms the authorization before the Line can
	// retire: a retire during the in-flight chain is an explicit deferral.
	settleTasks(t, s, out)

	// Retiring is an identity revocation: it reclaims the authorization at
	// every Out that ever bound the Line.
	if err := s.revokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	allowed, err = s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("derived allowlist after retire = %v, want empty", allowed)
	}
	if got, want := candidateCount(t, s, out), 3; got != want {
		t.Fatalf("out revisions after retire = %d, want %d", got, want)
	}
	latest, err = s.latestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range chainRevisionParams(t, s, out, latest.Revision) {
		if task.Allowed == nil {
			t.Fatalf("%s task omitted the reclaimed allowlist", task.Kind)
		}
		if len(*task.Allowed) != 0 {
			t.Fatalf("%s task still authorizes %v after retire", task.Kind, *task.Allowed)
		}
	}
	// The published chain carries the revoked set, so the Out is waiting for
	// the Agent to prove the reclaimed guard rather than reporting healthy.
	state, code, err = s.outSyncStatus(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != outSyncVerifying || code != codeOutSyncInProgress {
		t.Fatalf("out status after retire = %s/%s, want verifying in progress", state, code)
	}

	// A retired Line has no enabled egress left, so its subscriber sync is no
	// longer gated by the Out. The Line itself is not a verifiable source any
	// more, which is exactly the revoked state.
	egress, _, err := s.lineEgressState(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if egress != lineEgressPartial {
		t.Fatalf("line egress after retire = %s, want partial", egress)
	}
}

// lineEgressState is a test helper around the read-only projection.
func (s *store) lineEgressState(lineID string, now time.Time) (string, string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	return lineOutEgressStatusTx(tx, lineID, now)
}

// TestOutAllowlist_DerivationStates pins the three "no authorization" states and
// the canonical spelling of the one authorized state.
func TestOutAllowlist_DerivationStates(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	// Never configured: an empty list, not an error.
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("unbound derivation = %v err=%v, want empty", allowed, err)
	}
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: false}, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("disabled derivation = %v err=%v, want empty", allowed, err)
	}
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 1 {
		t.Fatalf("enabled derivation = %v err=%v, want one source", allowed, err)
	}
	// Settle the authorized chain before unbinding, so the reclaim is not
	// deferred behind an in-flight apply. That deferral is pinned separately.
	settleTasks(t, s, out)
	// Unbinding republishes the Out with an explicit empty list instead of
	// dropping the key.
	if err := s.clearOutBindingAt(out, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("unbound derivation = %v err=%v, want empty", allowed, err)
	}
	latest, err := s.latestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := s.outReadbackAllowlist(out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("unbound chain = %v present=%v, want an explicit empty list", revoked, present)
	}

	// Unknown and wrong-role nodes are refused instead of being reported as
	// "authorized for nothing".
	if _, err := s.DeriveOutAllowlist(strings.Repeat("a", 32)); err == nil || !hasErrorCode(err, "OUT_NOT_FOUND") {
		t.Fatalf("unknown out derivation error = %v", err)
	}
	if _, err := s.DeriveOutAllowlist(line); err == nil || !hasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("edge derivation error = %v", err)
	}
	if _, err := s.DeriveOutAllowlist("out"); err == nil || !hasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("malformed out derivation error = %v", err)
	}
	_ = now
}

// outReadbackAllowlist is a test helper around the chain lookup.
func (s *store) outReadbackAllowlist(outID string, revision int64) ([]string, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	return outReadbackAllowlistTx(tx, outID, revision)
}

// TestOutAllowlist_RejectsUnverifiableLine keeps the "only verified Line egress"
// rule explicit: a DNS-named Line cannot be authorized, and an unpaired Line is
// simply not a source yet.
func TestOutAllowlist_RejectsUnverifiableLine(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	// A host name has no Hub-verifiable egress address.
	named := testLine(line, "line-a")
	named.Server = "line.example.invalid"
	named.ServerName = "line.example.invalid"
	if _, err := s.setLine(named, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("host-named line derived %v err=%v, want empty", allowed, err)
	}
	// The binding itself is allowed (T1 only checks configuration), but the
	// gate refuses to publish the Line: the Hub cannot prove its source.
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	state, code, err := s.lineEgressState(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != lineEgressPartial || code != codeLineEgressUnverified {
		t.Fatalf("host-named line egress = %s/%s, want partial/LINE_EGRESS_UNVERIFIED", state, code)
	}
	if err := s.prepareSubscriberSyncForLine(line, now); err == nil || !hasErrorCode(err, "OUT_NOT_AUTHORIZED") {
		t.Fatalf("host-named line publish error = %v, want OUT_NOT_AUTHORIZED", err)
	}

	// The published Out chain carries an explicit empty list: fail-closed.
	latest, err := s.latestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := s.outReadbackAllowlist(out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("unverifiable line chain = %v present=%v, want explicit empty", revoked, present)
	}

	// Without a current identity the Line is not a source either, and the
	// gate reports that instead of silently publishing.
	if _, err := s.db.Exec(`UPDATE node_identities SET revoked=1 WHERE node_id=?`, line); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("unpaired line derived %v err=%v, want empty", allowed, err)
	}
	state, code, err = s.lineEgressState(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != lineEgressPartial || code != codeLineNotAuthorized {
		t.Fatalf("unpaired line egress = %s/%s, want partial/LINE_NOT_AUTHORIZED", state, code)
	}
}

// prepareSubscriberSyncForLine runs the Line half of the drain for one Line, so
// the gate can be exercised without a subscriber action.
func (s *store) prepareSubscriberSyncForLine(lineID string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := drainSubscriberNodeIntentTx(tx, lineID, now, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
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
			got, err := outAllowlistSource(tc.input)
			if tc.ok {
				if err != nil || got != tc.want {
					t.Fatalf("outAllowlistSource(%q) = %q err=%v, want %q", tc.input, got, err, tc.want)
				}
				return
			}
			if err == nil || !hasErrorCode(err, "OUT_ALLOWLIST_INVALID") {
				t.Fatalf("outAllowlistSource(%q) = %q err=%v, want OUT_ALLOWLIST_INVALID", tc.input, got, err)
			}
		})
	}
}

// TestOutAllowlist_PublishGateBlocksUnauthorizedEgress is the publish gate: the
// Line is not published while the Out has not confirmed the authorization, and
// the projection says so instead of reporting a healthy snapshot.
func TestOutAllowlist_PublishGateBlocksUnauthorizedEgress(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	// The Out chain is in flight (pending), so the pair is not proven.
	err := s.prepareSubscriberSyncForLine(line, now)
	if err == nil || !hasErrorCode(err, "OUT_NOT_AUTHORIZED") {
		t.Fatalf("publish before out confirmation error = %v, want OUT_NOT_AUTHORIZED", err)
	}
	if got := candidateCount(t, s, line); got != 1 {
		t.Fatalf("gated line publishes = %d revisions, want the initial one only", got)
	}

	// Confirm the Out chain: the exact revision, digest and healthy chain are
	// what the Agent reports.
	confirmChain(t, s, out, now)
	legacy, code, err := s.subscriberSyncStatusForLine(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != subscriberSyncPending || code != "SYNC_PENDING" {
		t.Fatalf("line sync after out confirmation = %s/%s, want pending/SYNC_PENDING", legacy, code)
	}
	if err := s.prepareSubscriberSyncForLine(line, now); err != nil {
		t.Fatalf("publish after out confirmation failed: %v", err)
	}
	if got := candidateCount(t, s, line); got != 2 {
		t.Fatalf("line revisions after gate opens = %d, want 2", got)
	}
}

// confirmChain simulates the exact readback the Agent reports: the latest
// candidate revision and digest observed, plus a healthy fixed chain.
func confirmChain(t *testing.T, s *store, nodeID string, now time.Time) {
	t.Helper()
	latest, err := s.latestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE agent_tasks SET status='healthy' WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE nodes SET observed_revision=?, observed_config_sha256=?,
 observed_at=?, observed_task_revision=?, observed_task_operation_id=?
 WHERE id=?`, latest.Revision, latest.ConfigSHA256, now.Unix(), latest.Revision, "0123456789abcdef0123456789abcdef", nodeID); err != nil {
		t.Fatal(err)
	}
}

// subscriberSyncStatusForLine exposes the per-Line projection for tests.
func (s *store) subscriberSyncStatusForLine(lineID string, now time.Time) (string, string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	return subscriberLineSyncViewTx(tx, lineID, now)
}

// TestOutAllowlist_RetireReclaimsEvenWhenDisabled keeps the "no dangling allow"
// guarantee: an Out that carries the ACL of a formerly enabled binding is
// republished even when the binding was disabled in the meantime.
func TestOutAllowlist_RetireReclaimsEvenWhenDisabled(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, out, now)
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: false}, now); err != nil {
		t.Fatal(err)
	}
	before, err := candidateCount(t, s, out), error(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.revokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	// The disabled binding still names the Line, so the retire path reads the
	// row and republishes the (already empty) authorization. An idempotent no-op
	// would be acceptable, a stale allowlist is not.
	latest, err := s.latestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := s.outReadbackAllowlist(out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 0 {
		t.Fatalf("disabled-then-retired chain = %v present=%v, want explicit empty", revoked, present)
	}
	if got := candidateCount(t, s, out); got < before {
		t.Fatalf("out revisions = %d, want at least %d", got, before)
	}
}

// TestOutAllowlist_OnLineRetiredRefusesLiveLine proves the retire call is not a
// silent de-authorization: a Line that is still a verifiable source must be
// revoked first.
func TestOutAllowlist_OnLineRetiredRefusesLiveLine(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	before := candidateCount(t, s, out)
	err := s.OnLineRetired(line)
	if err == nil || !hasErrorCode(err, "LINE_NOT_RETIRED") {
		t.Fatalf("retire of a live line error = %v, want LINE_NOT_RETIRED", err)
	}
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("refused retire published a chain: %d -> %d", before, got)
	}
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil || len(allowed) != 1 {
		t.Fatalf("refused retire changed the authorization: %v err=%v", allowed, err)
	}
	_ = now

	// Retiring an unknown or non-edge node is refused too.
	if err := s.OnLineRetired(strings.Repeat("d", 32)); err == nil || !hasErrorCode(err, "LINE_NOT_FOUND") {
		t.Fatalf("unknown line retire error = %v", err)
	}
	if err := s.OnLineRetired(out); err == nil || !hasErrorCode(err, "LINE_ROLE_INVALID") {
		t.Fatalf("out retire error = %v", err)
	}
	if err := s.OnLineRetired("line"); err == nil || !hasErrorCode(err, "LINE_ID_INVALID") {
		t.Fatalf("malformed line retire error = %v", err)
	}
}

// TestOutAllowlist_MismatchIsAnExpectedTransition pins the OUT_ACL_SOURCE_MISMATCH
// handling: the superseded chain is not a terminal failure and the identical
// snapshot is not retried automatically.
func TestOutAllowlist_MismatchIsAnExpectedTransition(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE agent_tasks SET status='failed', error_code=? WHERE node_id=?`, outAclSourceMismatchCode, out); err != nil {
		t.Fatal(err)
	}
	state, code, err := s.outSyncStatus(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != outSyncVerifying || code != outAclSourceMismatchCode {
		t.Fatalf("mismatch status = %s/%s, want verifying/OUT_ACL_SOURCE_MISMATCH", state, code)
	}
	before := candidateCount(t, s, out)
	// An automatic drain never republishes the identical snapshot.
	drainOut(t, s, out, now)
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("automatic drain repeated a superseded chain: %d -> %d", before, got)
	}
	// The explicit retry is the rollback pointer that publishes it again.
	if err := s.retryOutSync(out, now); err != nil {
		t.Fatalf("explicit retry failed: %v", err)
	}
	if got := candidateCount(t, s, out); got != before+1 {
		t.Fatalf("explicit retry published %d revisions, want one more than %d", got, before)
	}
}

// drainOut runs the automatic Out drain for one node.
func drainOut(t *testing.T, s *store, outID string, now time.Time) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := drainOutNodeIntentTx(tx, outID, now, false); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestOutAllowlist_UnchangedFailureNeedsExplicitRetry keeps the bounded-retry
// rule: a terminal failure is not republished by an automatic poll, only by the
// explicit retry.
func TestOutAllowlist_UnchangedFailureNeedsExplicitRetry(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE agent_tasks SET status='failed', error_code='OUT_ACL_RULE_INVALID' WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	state, code, err := s.outSyncStatus(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != outSyncPartial || code != "OUT_ACL_RULE_INVALID" {
		t.Fatalf("failure status = %s/%s, want partial/OUT_ACL_RULE_INVALID", state, code)
	}
	before := candidateCount(t, s, out)
	drainOut(t, s, out, now)
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("automatic drain retried an unchanged failure: %d -> %d", before, got)
	}
	if err := s.retryOutSync(out, now); err != nil {
		t.Fatalf("explicit retry failed: %v", err)
	}
	if got := candidateCount(t, s, out); got != before+1 {
		t.Fatalf("explicit retry revisions = %d, want %d", got, before+1)
	}
}

// TestOutAllowlist_OfflineOutKeepsIntent proves an offline Out receives no
// state-changing task and the caller sees the explicit deferral.
func TestOutAllowlist_OfflineOutKeepsIntent(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if _, err := s.db.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, out); got != 1 {
		t.Fatalf("offline out received %d revisions, want the initial one only", got)
	}
	err := s.retryOutSync(out, now)
	if err == nil || !hasErrorCode(err, "OUT_OFFLINE") {
		t.Fatalf("offline retry error = %v, want OUT_OFFLINE", err)
	}
}

// TestOutAllowlist_InFlightChainIsNeverRaced proves a publish request defers
// while another chain of the same Out is unfinished.
func TestOutAllowlist_InFlightChainIsNeverRaced(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	before := candidateCount(t, s, out)
	// The seeded chain of the Out is still pending, so a retire defers.
	if err := s.revokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	if got := candidateCount(t, s, out); got != before {
		t.Fatalf("retire published a competing chain: %d -> %d", before, got)
	}
	// The published chain still names the retired Line, which is exactly why
	// the caller sees an explicit pending state instead of a false success.
	latest, err := s.latestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	revoked, present, err := s.outReadbackAllowlist(out, latest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !present || len(revoked) != 1 {
		t.Fatalf("in-flight published chain = %v present=%v, want the previous authorization", revoked, present)
	}
	// Once the in-flight chain settles the reclaim is published.
	settleTasks(t, s, out)
	if err := s.retryOutSync(out, now); err != nil {
		t.Fatalf("retry after settle failed: %v", err)
	}
	if got := candidateCount(t, s, out); got != before+1 {
		t.Fatalf("reclaim after settle = %d revisions, want %d", got, before+1)
	}
}

// TestOutAllowlist_DualReadbackReportsEachFact pins the four-way readback: a
// plain Out allowlist alone never makes the final egress healthy.
func TestOutAllowlist_DualReadbackReportsEachFact(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	// Direct egress: the final egress follows the Line snapshot alone.
	direct, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Allowlist != lineEgressDirect {
		t.Fatalf("direct allowlist = %s, want direct", direct.Allowlist)
	}

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	pending, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Allowlist != lineEgressVerifying || pending.FinalEgress == lineEgressHealthy {
		t.Fatalf("unconfirmed readback = %+v, want a non-healthy transition", pending)
	}

	// Confirm both sides: the Out allowlist and the Line snapshot.
	confirmChain(t, s, out, now)
	if err := s.prepareSubscriberSyncForLine(line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	healthy, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.Allowlist != lineEgressHealthy || healthy.Inbound != subscriberSyncHealthy ||
		healthy.FinalEgress != lineEgressHealthy || !healthy.Reality {
		t.Fatalf("confirmed readback = %+v, want a healthy pair with REALITY", healthy)
	}

	// A reclaimed allowlist while the Line is unchanged drops the final egress
	// back to a transition: the pair is never healthy on one side alone.
	if _, err := s.db.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=? AND status='healthy'`, out); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE nodes SET observed_at=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	regressed, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if regressed.FinalEgress == lineEgressHealthy {
		t.Fatalf("readback reported healthy after the out evidence was cleared: %+v", regressed)
	}

	// The other direction is equally decisive: a healthy Out allowlist must not
	// carry the pair when the Line itself lost its inbound evidence. Otherwise
	// "allowlist healthy" alone would be treated as an egress proof.
	confirmChain(t, s, out, now)
	if _, err := s.db.Exec(`UPDATE agent_tasks SET status='pending' WHERE node_id=? AND status='healthy'`, line); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE nodes SET observed_at=0 WHERE id=?`, line); err != nil {
		t.Fatal(err)
	}
	lineRegressed, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if lineRegressed.Allowlist != lineEgressHealthy {
		t.Fatalf("setup: out allowlist should still be healthy, got %+v", lineRegressed)
	}
	if lineRegressed.FinalEgress == lineEgressHealthy {
		t.Fatalf("readback reported healthy on the allowlist alone: %+v", lineRegressed)
	}
}

// TestOutAllowlist_ReadbackUsesOnlyStableCodes proves the readback never leaks a
// stored value or a raw error.
func TestOutAllowlist_ReadbackUsesOnlyStableCodes(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	readback, err := s.OutEgressReadback(line, now)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(readback)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.lineServer, "line.example.invalid", "alice"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("readback leaked %q: %s", secret, body)
		}
	}
	for _, field := range []string{readback.AllowlistCode, readback.InboundCode, readback.FinalEgressCode} {
		if field == "" {
			continue
		}
		if !syncErrorCodePattern.MatchString(field) {
			t.Fatalf("readback code %q is not a stable code", field)
		}
	}
}

// TestOutAllowlist_SchemaIsUnchanged keeps the coordination layer free of new
// tables and kinds: the authorization lives in the frozen chain params. The
// schema version itself is 8 only because the mesh device, route and policy tables
// exist; this slice adds nothing to it.
func TestOutAllowlist_SchemaIsUnchanged(t *testing.T) {
	f := newOutSyncFixture(t)
	s := f.store
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 8 {
		t.Fatalf("user_version = %d err=%v, want 8", version, err)
	}
	// The four kinds are still exactly the frozen publication chain.
	if len(protocol.PublicationKinds) != 4 {
		t.Fatalf("publication kinds = %v, want the frozen four", protocol.PublicationKinds)
	}
	// An Out candidate never carries users or REALITY.
	candidate, err := s.latestCandidate(f.out)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Document.Role != node.RoleOut || candidate.Document.Reality != nil ||
		len(candidate.Document.Users) != 0 {
		t.Fatalf("out candidate is not the credential-free baseline: %+v", candidate.Document)
	}
	// The immutable candidate is still immutable.
	if _, err := s.db.Exec(`UPDATE node_candidates SET config_sha256='x' WHERE node_id=? AND revision=?`,
		f.out, candidate.Revision); err == nil || !strings.Contains(err.Error(), "CANDIDATE_IMMUTABLE") {
		t.Fatalf("candidate immutability lost: %v", err)
	}
	_ = subscription.StateActive
}

// TestOutAllowlist_PreviewReportsEgressState pins the brief's "preview refuses a
// policy that depends on an unauthorized Out": a proposal is never reported as
// an established path, and an enabled binding reports the real Hub state.
func TestOutAllowlist_PreviewReportsEgressState(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, out, line := f.store, f.now, f.out, f.line

	// Direct egress: an Out that never bound anything previews a direct Line
	// and no egress dependency.
	direct, err := s.previewOutBindingAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Mode != "line-direct" || direct.EgressState != "" || direct.EgressCode != "" {
		t.Fatalf("direct preview = %+v, want an empty egress state", direct)
	}
	// A proposal is pending, with the same refusal code the gate uses.
	proposal, err := s.previewOutBindingAt(out, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.EgressState != lineEgressPendingPreview || proposal.EgressCode != codeOutNotAuthorized {
		t.Fatalf("proposal preview = %+v, want pending/OUT_NOT_AUTHORIZED", proposal)
	}
	// An established, confirmed binding reports healthy.
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, out, now)
	if err := s.prepareSubscriberSyncForLine(line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	established, err := s.previewOutBindingAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if established.EgressState != lineEgressHealthy {
		t.Fatalf("established preview = %+v, want healthy", established)
	}
	// A disabled binding is a direct egress again, not a broken Out.
	if err := s.setOutBindingAt(OutBinding{OutID: out, LineID: line, Enabled: false}, now); err != nil {
		t.Fatal(err)
	}
	disabled, err := s.previewOutBindingAt(out, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Mode != "out-disabled" || disabled.EgressState != lineEgressDirect {
		t.Fatalf("disabled preview = %+v, want out-disabled/direct", disabled)
	}
}
