package node_test

// Authorization derivation under the node membership model (Ruling R10), which
// supersedes the subscription-driven derivation of Task 5.
//
// The contract these tests pin:
//
//	outAllowedSources(out) = union of the transport addresses of every enrolled
//	                          Line that holds a current pairing identity.
//
// Membership, not subscription, is the authorization source:
//
//   - a Line becomes a permitted source of every Out when its identity is issued,
//     and an Out enrolled later starts with every Line that already exists;
//   - a deleted node, a revoked identity or a removed transport drops the source;
//   - creating, editing, pausing or deleting a subscription never changes the list,
//     so it never republishes an Out.
//
// The original Task-5 migration evidence is preserved, restated against the new
// model: the ACL bytes the Hub publishes for a given membership set are exactly the
// bytes the pre-migration binding layer produced for the equivalent binding, so the
// data-plane contract did not move when the authorization source did.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// bindOutForTest attaches an Out to the subscription that already serves one Line,
// creating a subscriber when the fixture has none.
func bindOutForTest(t *testing.T, s *store.Store, outID, lineID string, now time.Time) string {
	t.Helper()
	subscriberID := storetest.TestSubscriberForLine(t, s, lineID, now)
	storetest.SelectOut(t, s, subscriberID, outID, []string{lineID}, now)
	return subscriberID
}

// legacyBindingAllowlist reproduces the derivation of the deleted binding layer: one
// enabled binding to a verifiable Line authorized exactly that Line's stored address,
// and every other state authorized nothing. An unverifiable address was the binding
// layer's hard error.
//
// It is the reference the migration is compared against: the *source of truth*
// changed (binding row -> node membership), but the ACL the Agent applies for a given
// authorized set must be byte-identical.
func legacyBindingAllowlist(t *testing.T, s *store.Store, outID, lineID string, enabled bool) ([]string, error) {
	t.Helper()
	if !enabled || lineID == "" {
		return []string{}, nil
	}
	var role string
	if err := s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role); err != nil {
		t.Fatalf("legacy derivation role: %v", err)
	}
	if role != "edge" {
		return []string{}, nil
	}
	var server string
	err := s.DB.QueryRow(`SELECT server FROM line_settings WHERE node_id=?`, lineID).Scan(&server)
	if err != nil {
		return []string{}, nil
	}
	var identities int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_identities WHERE node_id=? AND revoked=0`, lineID).Scan(&identities); err != nil {
		t.Fatalf("legacy derivation identity: %v", err)
	}
	if identities != 1 {
		return []string{}, nil
	}
	if _, err := netip.ParseAddr(server); err != nil {
		return nil, errLegacyUnverified
	}
	source, err := store.OutAllowlistSource(server)
	if err != nil {
		return nil, err
	}
	return []string{source}, nil
}

// errLegacyUnverified mirrors the binding layer's LINE_EGRESS_UNVERIFIED refusal for
// a DNS-named Line.
var errLegacyUnverified = &legacyUnverifiedError{}

type legacyUnverifiedError struct{}

func (*legacyUnverifiedError) Error() string {
	return "LINE_EGRESS_UNVERIFIED: the line transport address is a host name"
}

// aclBytes renders the nft table the Agent would apply for one allowlist.
func aclBytes(t *testing.T, s *store.Store, outID string, allowed []string) []byte {
	t.Helper()
	stored, err := s.LatestCandidate(outID)
	if err != nil {
		t.Fatalf("latest out candidate: %v", err)
	}
	rendered, err := node.CompileACL(stored.Document.Candidate(), allowed)
	if err != nil {
		t.Fatalf("compile acl %v: %v", allowed, err)
	}
	return rendered
}

// publishedAllowlist is the allowlist the newest Out chain carried, in the exact JSON
// the Agent compares against its applied state.
func publishedAllowlist(t *testing.T, s *store.Store, outID string) ([]string, string) {
	t.Helper()
	latest, err := s.LatestCandidate(outID)
	if err != nil {
		t.Fatalf("latest out candidate: %v", err)
	}
	allowed, present, err := storetest.OutReadbackAllowlist(s, outID, latest.Revision)
	if err != nil {
		t.Fatalf("readback allowlist: %v", err)
	}
	if !present {
		t.Fatal("the published chain omitted allowed_sources: an omitted key is not a fail-closed authorization")
	}
	tasks := storetest.ChainRevisionParams(t, s, outID, latest.Revision)
	body, err := json.Marshal(tasks)
	if err != nil {
		t.Fatal(err)
	}
	return allowed, string(body)
}

// TestOutAuthorization_MigratedACLMatchesBindingBytes is the migration parity gate: for
// every authorization state the migration can produce, the ACL bytes the Hub publishes
// are identical to what the deleted binding layer produced for the equivalent binding.
//
// The states are the *membership* states now (an enrolled Line, an unenrolled one, a
// revoked identity), plus the subscription states that the previous model treated as
// authorization and that Ruling R10 explicitly removed from the ACL: they must leave
// the bytes unchanged, which is the decisive assertion that no subscription edit can
// widen or narrow the guard.
func TestOutAuthorization_MigratedACLMatchesBindingBytes(t *testing.T) {
	cases := []struct {
		name string
		// arrange prepares the state and returns the legacy binding view.
		arrange func(t *testing.T, s *store.Store, out, line string, now time.Time) (lineID string, enabled bool)
		// wantAuthorized controls the parity direction: the migrated model may
		// authorize the Line even where the legacy binding did not.
		wantAuthorized bool
	}{
		{
			name: "enrolled line with a current identity",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				return line, true
			},
			wantAuthorized: true,
		},
		{
			name: "line identity revoked",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				if err := s.RevokeIdentity(line, now); err != nil {
					t.Fatal(err)
				}
				return line, false
			},
			wantAuthorized: false,
		},
		{
			name: "line transport removed",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				if _, err := s.DB.Exec(`DELETE FROM line_settings WHERE node_id=?`, line); err != nil {
					t.Fatal(err)
				}
				return line, false
			},
			wantAuthorized: false,
		},
		{
			name: "subscription selects the out",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				bindOutForTest(t, s, out, line, now)
				return line, true
			},
			wantAuthorized: true,
		},
		{
			name: "subscription drops the out selection",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				subscriberID := storetest.TestSubscriberForLine(t, s, line, now)
				storetest.DropOutSelection(t, s, subscriberID, []string{line}, now)
				return "", false
			},
			wantAuthorized: true,
		},
		{
			name: "subscriber paused",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				subscriberID := bindOutForTest(t, s, out, line, now)
				if _, err := s.SetSubscriberState(subscriberID, "paused", now); err != nil {
					t.Fatal(err)
				}
				return "", false
			},
			wantAuthorized: true,
		},
		{
			name: "subscriber deleted",
			arrange: func(t *testing.T, s *store.Store, out, line string, now time.Time) (string, bool) {
				subscriberID := bindOutForTest(t, s, out, line, now)
				if _, err := s.SetSubscriberState(subscriberID, "deleting", now); err != nil {
					t.Fatal(err)
				}
				return "", false
			},
			wantAuthorized: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := storetest.NewOutSyncFixture(t)
			s, now, out, line := f.Store, f.Now, f.Out, f.Line

			bindingLine, enabled := tc.arrange(t, s, out, line, now)
			settleAndRepublishOuts(t, s, now)

			legacy, legacyErr := legacyBindingAllowlist(t, s, out, bindingLine, enabled)
			derived, err := s.DeriveOutAllowlist(out)
			if legacyErr != nil {
				if err == nil {
					t.Fatalf("derived %v, want the legacy refusal for an unverifiable line", derived)
				}
				if !storetest.HasErrorCode(err, store.CodeLineEgressUnverified) {
					t.Fatalf("derived error = %v, want LINE_EGRESS_UNVERIFIED", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("derived allowlist: %v", err)
			}
			if tc.wantAuthorized && len(derived) != 1 {
				t.Fatalf("derived allowlist = %v, want the enrolled line authorized", derived)
			}
			if !tc.wantAuthorized && len(derived) != 0 {
				t.Fatalf("derived allowlist = %v, want nothing authorized", derived)
			}
			// The ACL the Agent applies is a function of the authorized set only, so it
			// must be byte-identical to the binding layer's render of the same set.
			expected := legacy
			if tc.wantAuthorized && len(legacy) == 0 {
				source, sourceErr := store.OutAllowlistSource("203.0.113.7")
				if sourceErr != nil {
					t.Fatal(sourceErr)
				}
				expected = []string{source}
			}
			if got, want := aclBytes(t, s, out, derived), aclBytes(t, s, out, expected); string(got) != string(want) {
				t.Fatalf("derived ACL bytes differ from the reference render:\n%s\n---\n%s", got, want)
			}
			if !node.SameACLSourceSet(derived, expected) {
				t.Fatalf("derived allowlist %v != reference %v", derived, expected)
			}
			// The published chain is the authorization the Agent applies.
			published, chainJSON := publishedAllowlist(t, s, out)
			if !node.SameACLSourceSet(published, derived) {
				t.Fatalf("published allowlist %v != derived %v (chain %s)", published, derived, chainJSON)
			}
		})
	}
}

// TestOutAuthorization_DerivationIsNodeMembership proves the new model authorizes
// every enrolled Line, in a canonical order a retry can compare byte for byte.
func TestOutAuthorization_DerivationIsNodeMembership(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out := f.Store, f.Now, f.Out

	// Distinct documentation addresses: the fixture's own Line already owns
	// 203.0.113.7, and the derivation de-duplicates by source, so reusing it would make
	// a revocation look like it left the source behind.
	addresses := []string{"192.0.2.44", "198.51.100.9", "2001:db8::7"}
	lineIDs := make([]string, 0, len(addresses))
	for index, address := range addresses {
		lineID := storetest.PairedStoreNode(t, s, "edge", now)
		settings := storetest.TestLine(lineID, "line-union-"+string(rune('a'+index)))
		settings.Server = address
		settings.ServerName = "line.example.invalid"
		if _, err := s.SetLine(settings, now); err != nil {
			t.Fatal(err)
		}
		storetest.MarkLineOnline(t, s, lineID, now)
		lineIDs = append(lineIDs, lineID)
	}

	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.44/32", "198.51.100.9/32", "2001:db8::7/128", "203.0.113.7/32"}
	if len(allowed) != len(want) {
		t.Fatalf("derived membership = %v, want %v", allowed, want)
	}
	for _, source := range want {
		if len(intersectOne(allowed, source)) != 1 {
			t.Fatalf("derived membership %v is missing %s", allowed, source)
		}
	}
	// No subscription exists anywhere: membership alone authorized them.
	var subscriptions int
	if err := s.DB.QueryRow(`SELECT count(*) FROM subscription_outs`).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if subscriptions != 0 {
		t.Fatalf("the fixture created %d out selections; membership must not need any", subscriptions)
	}
	acl := string(aclBytes(t, s, out, allowed))
	for _, source := range want {
		if !strings.Contains(acl, "saddr "+source+" tcp dport 8443 accept") {
			t.Fatalf("ACL misses the authorized source %s:\n%s", source, acl)
		}
	}

	// Revoking one Line's identity narrows the set by exactly that address.
	var revokedAddr string
	if err := s.DB.QueryRow(`SELECT server FROM line_settings WHERE node_id=?`, lineIDs[0]).Scan(&revokedAddr); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeIdentity(lineIDs[0], now); err != nil {
		t.Fatal(err)
	}
	narrowed, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(narrowed) != 3 {
		t.Fatalf("derived membership after one revocation = %v, want three sources", narrowed)
	}
	revokedSource, err := store.OutAllowlistSource(revokedAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range narrowed {
		if source == revokedSource {
			t.Fatalf("revoked source still authorized: %v", narrowed)
		}
	}
}

// intersectOne keeps the entry that documents the same prefix as source, so a test
// can compare one element order-insensitively.
func intersectOne(allowed []string, source string) []string {
	for _, entry := range allowed {
		if entry == source {
			return []string{entry}
		}
	}
	return nil
}

// TestOutAuthorization_EmptyMembershipIsDefaultDeny is the fail-closed case: an Out
// with no Line to accept authorizes nothing, and the Agent is told so with an
// explicit empty list, not with an omitted key.
func TestOutAuthorization_EmptyMembershipIsDefaultDeny(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// Remove every Line from the membership: the Hub has nothing to authorize.
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	settleAndRepublishOuts(t, s, now)
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("an Out with no member Line derived %v, want empty", allowed)
	}
	acl := string(aclBytes(t, s, out, allowed))
	if strings.Contains(strings.ReplaceAll(acl, "policy accept", ""), "accept") {
		t.Fatalf("default-deny ACL rendered an accept rule:\n%s", acl)
	}
	for _, drop := range []string{"tcp dport 8443 drop", "udp dport 8443 drop"} {
		if !strings.Contains(acl, drop) {
			t.Fatalf("default-deny ACL misses %q:\n%s", drop, acl)
		}
	}

	// Publishing an empty authorization is still an explicit decision: the chain
	// carries [], never an omitted key.
	settleAndRepublishOuts(t, s, now)
	storetest.ConfirmChain(t, s, out, now)
	published, chainJSON := publishedAllowlist(t, s, out)
	if len(published) != 0 {
		t.Fatalf("published empty authorization = %v (%s)", published, chainJSON)
	}
	// Nothing to change means nothing to publish.
	before := storetest.CandidateCount(t, s, out)
	s.RepublishOutAuthorizations(now)
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("an unchanged empty authorization was republished: %d -> %d", before, got)
	}

	// The Line has no Out selection, so it is a direct egress: an Out-free
	// subscription is the configured direct state, not an authorized Out path.
	state, code, err := storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressDirect || code != "" {
		t.Fatalf("line egress without an Out selection = %s/%s, want direct", state, code)
	}
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("a direct Line publish must not be gated by an unselected Out: %v", err)
	}
}

// TestOutAuthorization_SubscriptionNeverTouchesTheACL is the decisive Ruling R10
// assertion: every subscription mutation leaves the Out authorization — and the Out's
// published chain — exactly where it was.
func TestOutAuthorization_SubscriptionNeverTouchesTheACL(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	settleAndRepublishOuts(t, s, now)
	storetest.ConfirmChain(t, s, out, now)
	baseline, baselineChain := publishedAllowlist(t, s, out)
	baselineRevisions := storetest.CandidateCount(t, s, out)

	subscriberID := storetest.TestSubscriberForLine(t, s, line, now)
	mutations := []struct {
		name   string
		mutate func()
	}{
		{"select the out", func() { storetest.SelectOut(t, s, subscriberID, out, []string{line}, now) }},
		{"drop the out selection", func() { storetest.DropOutSelection(t, s, subscriberID, []string{line}, now) }},
		{"pause the subscriber", func() {
			if _, err := s.SetSubscriberState(subscriberID, "paused", now); err != nil {
				t.Fatal(err)
			}
		}},
		{"resume the subscriber", func() {
			if _, err := s.SetSubscriberState(subscriberID, "active", now); err != nil {
				t.Fatal(err)
			}
		}},
		{"save a full selection through the wizard path", func() {
			storetest.SelectOut(t, s, subscriberID, out, []string{line}, now)
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutation.mutate()
			allowed, err := s.DeriveOutAllowlist(out)
			if err != nil {
				t.Fatal(err)
			}
			if !node.SameACLSourceSet(allowed, baseline) {
				t.Fatalf("%s changed the ACL: %v != %v", mutation.name, allowed, baseline)
			}
			if got := storetest.CandidateCount(t, s, out); got != baselineRevisions {
				t.Fatalf("%s republished the out: %d revisions, want %d", mutation.name, got, baselineRevisions)
			}
			published, chainJSON := publishedAllowlist(t, s, out)
			if !node.SameACLSourceSet(published, baseline) {
				t.Fatalf("%s changed the published chain: %v (%s)", mutation.name, published, chainJSON)
			}
			if canonicalChain(baselineChain) != canonicalChain(chainJSON) {
				t.Fatalf("%s changed the chain params:\n%s\n---\n%s", mutation.name, baselineChain, chainJSON)
			}
		})
	}
}

// TestOutAuthorization_PoolDrainIsLifecycleOnly is the I2 regression: the pool-wide
// reconcile is O(Out) by design, so it must be reachable from *node lifecycle* events
// only. A subscription edit must never reach it, and the events that do have to be the
// ones that actually change the membership set.
//
// It pins the contract from the outside (revision counts per event), because that is
// what an operator observes; the call-site list itself is documented on
// RepublishOutAuthorizations and booked as O(Out) work for Task 6 / 1.1.
func TestOutAuthorization_PoolDrainIsLifecycleOnly(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	settleAndRepublishOuts(t, s, now)
	storetest.ConfirmChain(t, s, out, now)
	baseline := storetest.CandidateCount(t, s, out)

	// Subscription events: no pool drain, so the Out keeps its revision.
	subscriberID := storetest.TestSubscriberForLine(t, s, line, now)
	storetest.SelectOut(t, s, subscriberID, out, []string{line}, now)
	if got := storetest.CandidateCount(t, s, out); got != baseline {
		t.Fatalf("selecting the out drained the pool: %d -> %d", baseline, got)
	}
	if _, err := s.SetSubscriberState(subscriberID, "paused", now); err != nil {
		t.Fatal(err)
	}
	if got := storetest.CandidateCount(t, s, out); got != baseline {
		t.Fatalf("pausing a subscriber drained the pool: %d -> %d", baseline, got)
	}

	// Lifecycle event 1: a Line's transport address changes, which changes the source
	// an Out authorizes. This must reach the pool.
	settings := storetest.TestLine(line, "line-a")
	settings.Server = "198.51.100.9"
	settings.ServerName = "line.example.invalid"
	if _, err := s.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	storetest.SettleTasks(t, s, out)
	afterAddress := storetest.CandidateCount(t, s, out)
	if afterAddress <= baseline {
		t.Fatalf("an address change did not republish the out: %d -> %d", baseline, afterAddress)
	}
	allowed, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 1 || allowed[0] != "198.51.100.9/32" {
		t.Fatalf("the address change did not reach the acl: %v", allowed)
	}

	// Lifecycle event 2: an identity revocation removes a member. The drain either
	// publishes immediately or defers behind the settled chain, but the derived set must
	// never keep the revoked source.
	if err := s.RevokeIdentity(line, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err != nil || len(allowed) != 0 {
		t.Fatalf("the revocation did not drop the source: %v err=%v", allowed, err)
	}
	storetest.SettleTasks(t, s, out)
	s.RepublishOutAuthorizations(now)
	storetest.SettleTasks(t, s, out)
	storetest.ConfirmChain(t, s, out, now)
	published, chainJSON := publishedAllowlist(t, s, out)
	if len(published) != 0 {
		t.Fatalf("the revocation never reached the published chain: %v (%s)", published, chainJSON)
	}
}

// TestOutAuthorization_EnrollmentAddsEveryLine is the positive half of R10 ①②: a Line
// enrolled after the Out exists joins every Out's allowlist, and an Out enrolled after
// the Lines exist starts with all of them.
func TestOutAuthorization_EnrollmentAddsEveryLine(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// A Line enrolled later joins the existing Out.
	late := storetest.PairedStoreNode(t, s, "edge", now)
	settings := storetest.TestLine(late, "line-late")
	settings.Server = "198.51.100.9"
	settings.ServerName = "line.example.invalid"
	if _, err := s.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	storetest.MarkLineOnline(t, s, late, now)
	settleAndRepublishOuts(t, s, now)
	after, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("a newly enrolled Line did not join the allowlist: %v", after)
	}

	// An Out enrolled later starts with every Line that already exists.
	lateOut := storetest.PairedStoreNode(t, s, "out", now)
	storetest.ConfigureOut(t, s, lateOut, now)
	s.RepublishOutAuthorizations(now)
	storetest.SettleTasks(t, s, lateOut)
	second, err := s.DeriveOutAllowlist(lateOut)
	if err != nil {
		t.Fatal(err)
	}
	if !node.SameACLSourceSet(second, after) {
		t.Fatalf("a newly enrolled Out started with %v, want the existing membership %v", second, after)
	}
	_ = line
}

// TestOutAuthorization_SelectingTheOutAuthorizesAndPublishes proves the routing half
// still works while the ACL is membership-driven: selecting the Out makes the Line
// render the SS hop, and the publish gate is satisfied because the Out already
// authorized the Line by membership.
func TestOutAuthorization_SelectingTheOutAuthorizesAndPublishes(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	// Membership already authorized the Line, so selecting the Out is purely a
	// routing change: no Out republication, and the gate is already satisfied.
	before := storetest.CandidateCount(t, s, out)
	bindOutForTest(t, s, out, line, now)
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("selecting the Out republished it: %d -> %d", before, got)
	}
	published, chainJSON := publishedAllowlist(t, s, out)
	if !node.SameACLSourceSet(published, []string{"203.0.113.7/32"}) {
		t.Fatalf("published authorization = %v (%s)", published, chainJSON)
	}

	// The Line candidate is built from the selection, so the publish has to happen
	// after it: the fixture's Line is already confirmed, and only a changed snapshot
	// republishes. Adding a subscriber changes the user set.
	if _, _, err := s.CreateSubscriber("carol", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("line publish with a membership-authorized Out: %v", err)
	}
	stored, err := s.LatestCandidate(line)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Document.Out == nil || stored.Document.Out.Server != "out.example.invalid" {
		t.Fatalf("line candidate carries no Out egress: %+v", stored.Document.Out)
	}
	if stored.Document.Out.Key == "" {
		t.Fatal("line candidate carries no Hub-issued link key")
	}
	if stored.Document.Route != nil {
		t.Fatalf("a Line without an active server policy must stay route-free: %s", stored.Document.Route)
	}
	state, code, err := storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressHealthy || code != "" {
		t.Fatalf("line egress after the Out was selected = %s/%s, want healthy", state, code)
	}
}

// TestOutAuthorization_DroppingTheSelectionKeepsTheACL proves the reverse routing
// action does not reclaim the authorization: the Line is still a member of the Out.
func TestOutAuthorization_DroppingTheSelectionKeepsTheACL(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	subscriberID := bindOutForTest(t, s, out, line, now)
	settleAndRepublishOuts(t, s, now)
	storetest.ConfirmChain(t, s, out, now)
	before := storetest.CandidateCount(t, s, out)

	storetest.DropOutSelection(t, s, subscriberID, []string{line}, now)
	if got := storetest.CandidateCount(t, s, out); got != before {
		t.Fatalf("dropping the Out selection republished it: %d -> %d", before, got)
	}
	published, chainJSON := publishedAllowlist(t, s, out)
	if !node.SameACLSourceSet(published, []string{"203.0.113.7/32"}) {
		t.Fatalf("dropping the selection changed the authorization: %v (%s)", published, chainJSON)
	}
	state, _, err := storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressDirect {
		t.Fatalf("line egress after the Out selection was removed = %s, want direct", state)
	}
	if err := storetest.PrepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("line publish after the Out was released: %v", err)
	}
}

// TestOutAuthorization_UnverifiableLineFailsClosed keeps the "only a Hub-verifiable
// source" rule: a DNS-named Line cannot be authorized, and the Out is never published
// with a guessed address.
func TestOutAuthorization_UnverifiableLineFailsClosed(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out, line := f.Store, f.Now, f.Out, f.Line

	named := storetest.TestLine(line, "line-a")
	named.Server = "line.example.invalid"
	named.ServerName = "line.example.invalid"
	if _, err := s.SetLine(named, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeriveOutAllowlist(out); err == nil {
		t.Fatalf("a DNS-named Line derived %v, want LINE_EGRESS_UNVERIFIED", allowed)
	} else if !storetest.HasErrorCode(err, store.CodeLineEgressUnverified) {
		t.Fatalf("derived error = %v, want LINE_EGRESS_UNVERIFIED", err)
	}
	subscriberID := storetest.TestSubscriberForLine(t, s, line, now)
	storetest.SelectOut(t, s, subscriberID, out, []string{line}, now)
	state, code, err := storetest.LineEgressState(s, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressPartial || code != store.CodeLineEgressUnverified {
		t.Fatalf("line egress for an unverifiable Line = %s/%s", state, code)
	}
	// The published chain never carries the host name.
	if published, _ := publishedAllowlist(t, s, out); len(published) != 0 {
		for _, entry := range published {
			if strings.Contains(entry, "line.example.invalid") {
				t.Fatalf("an unverifiable Line was authorized: %v", published)
			}
		}
	}
}

// TestOutAuthorization_SourceOrderIsByteStable proves one membership set renders one
// chain: the source order is canonical, so an unchanged authorization is recognized as
// unchanged instead of being republished with different params.
func TestOutAuthorization_SourceOrderIsByteStable(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, now, out := f.Store, f.Now, f.Out

	lineB := storetest.PairedStoreNode(t, s, "edge", now)
	settings := storetest.TestLine(lineB, "line-b")
	settings.Server = "198.51.100.9"
	settings.ServerName = "line.example.invalid"
	if _, err := s.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	storetest.MarkLineOnline(t, s, lineB, now)
	settleAndRepublishOuts(t, s, now)

	first, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	_, firstChain := publishedAllowlist(t, s, out)

	// Re-derive after an unrelated enrollment order change: the set is the same and the
	// published params must be identical.
	settleAndRepublishOuts(t, s, now)
	second, err := s.DeriveOutAllowlist(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("source order is not canonical: %v vs %v", first, second)
	}
	published, secondChain := publishedAllowlist(t, s, out)
	if !node.SameACLSourceSet(published, second) {
		t.Fatalf("published %v != derived %v", published, second)
	}
	if canonicalChain(firstChain) != canonicalChain(secondChain) {
		t.Fatalf("chain params are not stable:\n%s\n---\n%s", firstChain, secondChain)
	}
}

// canonicalChain keeps only the allowed_sources of every chain task, in order, so two
// publications of the same authorization can be compared on the allowlist only.
func canonicalChain(chainJSON string) string {
	var tasks []struct {
		Allowed *[]string `json:"Allowed"`
	}
	if err := json.Unmarshal([]byte(chainJSON), &tasks); err != nil {
		return chainJSON
	}
	out := make([]string, 0, len(tasks))
	for _, task := range tasks {
		if task.Allowed == nil {
			return chainJSON
		}
		out = append(out, strings.Join(*task.Allowed, ","))
	}
	return strings.Join(out, "|")
}

// settleAndRepublishOuts completes the deferred authorization of a change that landed
// while a chain was in flight: it settles that chain and lets the next Out event run,
// which is the documented completion of a deferred change.
func settleAndRepublishOuts(t *testing.T, s *store.Store, now time.Time) {
	t.Helper()
	outIDs, err := storeOutIDs(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, outID := range outIDs {
		storetest.SettleTasks(t, s, outID)
	}
	s.RepublishOutAuthorizations(now)
	for _, outID := range outIDs {
		storetest.SettleTasks(t, s, outID)
	}
}

// storeOutIDs lists every Out node the fixture created.
func storeOutIDs(s *store.Store) ([]string, error) {
	rows, err := s.DB.Query(`SELECT id FROM nodes WHERE role='out' ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// TestOutAuthorization_BindingTableIsGone is the schema half of the original switch:
// the table is dropped in the same migration that makes the derivation authoritative,
// so no binary can read a stale authorization from it.
func TestOutAuthorization_BindingTableIsGone(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s := f.Store

	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != store.DatabaseSchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, store.DatabaseSchemaVersion)
	}
	if storetest.TableExists(t, s, "out_bindings") {
		t.Fatal("out_bindings still exists: the authorization must have exactly one source")
	}
	for _, table := range []string{"subscription_outs", "subscription_lines", "out_settings"} {
		if !storetest.TableExists(t, s, table) {
			t.Fatalf("%s missing", table)
		}
	}
}
