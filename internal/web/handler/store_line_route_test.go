package handler

// Route carry-forward drift (issue #113 Phase 1-4).
//
// A published route is rendered output, not intent. Both implicit publishers
// (subscriber synchronization and upgrade approval) used to copy the newest
// candidate's route into the next revision, which froze whatever Out binding
// and policy revision happened to exist at that moment. These tests pin the
// replacement rule: the route is re-derived from the live server policy and the
// current Out facts, and an Out that was unbound, deleted or went offline
// invalidates the old route instead of being republished.

import (
	"context"
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// outServerPolicy selects the Out for one documentation domain.
const outServerPolicy = `{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`

// staleOutRoute is the fragment the old carry-forward left behind after the Out
// stopped justifying it.
const staleOutRoute = `{"rules":[{"domain":["ai.example.invalid"],"outbound":"out"}],"final":"out"}`

// activateServerPolicy creates and activates one server revision on a fixture.
func activateServerPolicy(t *testing.T, f outSyncFixture, payload string) {
	t.Helper()
	created, err := f.store.CreateRoutePolicy(store.PolicyLayerServer, "服务端策略",
		json.RawMessage(payload), nil, "op-policy", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ActivateRoutePolicy(created.ID, created.Revision, "op-activate", f.now); err != nil {
		t.Fatal(err)
	}
}

// latestStoredRoute reads the newest candidate's route of one node.
func latestStoredRoute(t *testing.T, s *store.Store, nodeID string) string {
	t.Helper()
	stored, err := s.LatestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return string(stored.Document.Route)
}

// routeFragment is a decoded server route: only the fields the drift assertions
// read, so a compacted or indented spelling is judged the same.
type routeFragment struct {
	Rules []struct {
		Outbound string `json:"outbound"`
	} `json:"rules"`
	Final string `json:"final"`
}

// decodeRoute decodes one stored route fragment.
func decodeRoute(t *testing.T, raw string) routeFragment {
	t.Helper()
	if raw == "" {
		return routeFragment{}
	}
	var fragment routeFragment
	if err := json.Unmarshal([]byte(raw), &fragment); err != nil {
		t.Fatalf("route %q is not a server route: %v", raw, err)
	}
	return fragment
}

// routeSelectsOut reports whether the route names the "out" tag anywhere.
func routeSelectsOut(raw string) bool {
	var fragment routeFragment
	if raw == "" || json.Unmarshal([]byte(raw), &fragment) != nil {
		return strings.Contains(raw, `"out"`)
	}
	if fragment.Final == "out" {
		return true
	}
	for _, rule := range fragment.Rules {
		if rule.Outbound == "out" {
			return true
		}
	}
	return false
}

// TestLineRouteDerivationFollowsLiveIntent pins the derivation itself: the route
// is a function of the active policy revision and the Out facts, so removing the
// Out, changing the policy or revoking it changes the next route instead of
// preserving an old one.
func TestLineRouteDerivationFollowsLiveIntent(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, line, out := f.store, f.now, f.line, f.out

	deriveRoute := func() (string, error) {
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		fragment, err := store.LineServerRouteTx(tx, line, now)
		if err != nil {
			return "", err
		}
		return string(fragment), nil
	}

	// No active server revision: the Hub holds no route intent.
	if got, err := deriveRoute(); err != nil || got != "" {
		t.Fatalf("route without an active policy = %q err=%v, want none", got, err)
	}

	// The policy selects the Out and the Out is authorized: the route names it.
	activateServerPolicy(t, f, outServerPolicy)
	enableOutForLine(t, s, out, line, now)
	confirmChain(t, s, out, now)
	got, err := deriveRoute()
	if err != nil {
		t.Fatalf("route with a healthy Out: %v", err)
	}
	if !routeSelectsOut(got) {
		t.Fatalf("route does not select the bound Out: %s", got)
	}

	// The Out is unbound while the policy still selects it: fail-closed, never a
	// stale "out" reference and never a silent direct render.
	disableOutForLine(t, s, out, line, now)
	if _, err := deriveRoute(); err == nil || !hasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("route without the Out = %v, want OUT_BINDING_INVALID", err)
	}

	// The operator moves the policy back to direct: the route no longer names an
	// Out, so an unbound Out is not an error either.
	activateServerPolicy(t, f, publishServerDirect)
	got, err = deriveRoute()
	if err != nil {
		t.Fatalf("direct route: %v", err)
	}
	if routeSelectsOut(got) {
		t.Fatalf("direct policy rendered an Out reference: %s", got)
	}

	// Revoking the active revision removes the route intent entirely.
	active, err := s.ActiveRoutePolicy(store.PolicyLayerServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeRoutePolicy(active.ID, active.Revision, "op-revoke", now); err != nil {
		t.Fatal(err)
	}
	if got, err := deriveRoute(); err != nil || got != "" {
		t.Fatalf("route after revoke = %q err=%v, want none", got, err)
	}
}

// TestSubscriberSyncRedrivesRouteInsteadOfCarryingTheOldOne is the drift
// regression: a credential change publishes the route the active revision
// resolves now, so a stale "out" route cannot ride into the next revision.
func TestSubscriberSyncRedrivesRouteInsteadOfCarryingTheOldOne(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, line, out := f.store, f.now, f.line, f.out

	activateServerPolicy(t, f, outServerPolicy)
	enableOutForLine(t, s, out, line, now)
	confirmChain(t, s, out, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	if got := latestStoredRoute(t, s, line); !routeSelectsOut(got) {
		t.Fatalf("published route does not select the Out: %s", got)
	}
	confirmChain(t, s, line, now)
	// The derived route is the same bytes the publication stored: an unchanged
	// snapshot is confirmed, so a subscriber event does not republish it.
	revisions := candidateCount(t, s, line)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("unchanged publication after the out policy: %v", err)
	}
	if got := candidateCount(t, s, line); got != revisions {
		t.Fatalf("an unchanged confirmed snapshot was republished: %d -> %d", revisions, got)
	}
	tasks := taskCount(t, s, line)

	// The Out is unbound while the policy still selects it: the publication fails
	// closed, stores nothing and names the conflict, so the stale "out" route is
	// not refreshed under a new revision either.
	disableOutForLine(t, s, out, line, now)
	err := prepareSubscriberSyncForLine(s, line, now)
	if err == nil || !hasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("publication while the policy still selects the unbound Out = %v, want OUT_BINDING_INVALID", err)
	}
	if got := candidateCount(t, s, line); got != revisions {
		t.Fatalf("fail-closed publication stored %d revisions, want %d", got, revisions)
	}
	if got := taskCount(t, s, line); got != tasks {
		t.Fatalf("fail-closed publication enqueued %d tasks, want %d", got, tasks)
	}
	// The subscriber projection reports the conflict instead of a stale healthy.
	if status, code, err := subscriberSyncStatusForLine(s, line, now); err != nil {
		t.Fatal(err)
	} else if status != store.SubscriberSyncPartial || code != "OUT_BINDING_INVALID" {
		t.Fatalf("line status = %s/%s, want partial/OUT_BINDING_INVALID", status, code)
	}
	activateServerPolicy(t, f, publishServerDirect)

	subscribers, err := s.ListSubscribers()
	if err != nil || len(subscribers) != 1 {
		t.Fatalf("subscribers = %v err=%v", subscribers, err)
	}
	if _, err := s.SetSubscriberState(subscribers[0].ID, "paused", now); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareSubscriberSync(subscribers[0].ID, now); err != nil {
		t.Fatalf("subscriber publication after the policy change: %v", err)
	}
	rederived := latestStoredRoute(t, s, line)
	if routeSelectsOut(rederived) {
		t.Fatalf("a new candidate carried the stale Out route: %s", rederived)
	}
	if fragment := decodeRoute(t, rederived); fragment.Final != "direct" || len(fragment.Rules) != 0 {
		t.Fatalf("rederived route = %s, want the live direct intent", rederived)
	}
}

// TestSubscriberSyncFailsClosedWhenTheOutIsDeleted covers the delete path: the
// subscription selection is what authorizes the Out, so a deleted Out with no
// selection left cannot render the policy that names it and no revision is stored.
//
// The delete itself is refused while the selection exists (a live subscription is a
// live egress), so the fixture releases the selection first — the same migration the
// refusal asks the operator for — and then deletes the Out.
func TestSubscriberSyncFailsClosedWhenTheOutIsDeleted(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, line, out := f.store, f.now, f.line, f.out

	activateServerPolicy(t, f, outServerPolicy)
	enableOutForLine(t, s, out, line, now)
	confirmChain(t, s, out, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	revisions := candidateCount(t, s, line)

	// A live reference refuses the delete and changes nothing: the Out is still the
	// authorized egress, so this is not the fail-closed state yet.
	if err := s.DeleteOutAt(out, now); err == nil || !hasErrorCode(err, store.CodeOutReferenced) {
		t.Fatalf("delete of a selected out = %v, want %s", err, store.CodeOutReferenced)
	}
	clearOutForLine(t, s, line, now)
	settleTasks(t, s, out)
	if err := s.DeleteOutAt(out, now); err != nil {
		t.Fatalf("delete out: %v", err)
	}
	err := prepareSubscriberSyncForLine(s, line, now)
	if err == nil || !hasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("publication after the Out was deleted = %v, want OUT_BINDING_INVALID", err)
	}
	if got := candidateCount(t, s, line); got != revisions {
		t.Fatalf("fail-closed publication after delete stored %d revisions, want %d", got, revisions)
	}
}

// TestSubscriberSyncFailsClosedWhenTheOutIsOffline is the offline half: the
// binding still exists, but the Out cannot carry the traffic, so an
// Out-selecting policy refuses with the compiler's own code.
func TestSubscriberSyncFailsClosedWhenTheOutIsOffline(t *testing.T) {
	f := newOutSyncFixture(t)
	s, now, line, out := f.store, f.now, f.line, f.out

	activateServerPolicy(t, f, outServerPolicy)
	enableOutForLine(t, s, out, line, now)
	confirmChain(t, s, out, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatal(err)
	}
	confirmChain(t, s, line, now)
	revisions := candidateCount(t, s, line)

	if _, err := s.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, s, line, now)
	err := prepareSubscriberSyncForLine(s, line, now)
	if err == nil || !hasErrorCode(err, compiler.CodeOutOfflineFailClosed) {
		t.Fatalf("publication with an offline Out = %v, want %s", err, compiler.CodeOutOfflineFailClosed)
	}
	if got := candidateCount(t, s, line); got != revisions {
		t.Fatalf("offline fail-closed publication stored %d revisions, want %d", got, revisions)
	}
}

// seedStoredRouteCandidate stores one v3 candidate with an explicit route,
// exactly what the old carry-forward produced and left behind.
func seedStoredRouteCandidate(t *testing.T, app *Server, nodeID, fragment string) {
	t.Helper()
	now := app.now()
	tx, err := app.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	revision, err := store.NextCandidateRevisionTx(tx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.BuildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Route = json.RawMessage(fragment)
	if err := store.InsertCandidateTx(tx, candidate, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// upgradeManifestVersion is the one release this Hub can pin.
func upgradeManifestVersion(t *testing.T) string {
	t.Helper()
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return manifest.Version
}

// TestUpgradeApprovalInvalidatesAStaleRoute is the approval half of the drift
// regression: with no active server revision the Hub holds no route intent, so a
// lagging node's approval stores a route-free candidate instead of republishing
// the stale "out" fragment a removed policy left behind.
func TestUpgradeApprovalInvalidatesAStaleRoute(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	if _, err := app.store.SetLine(testLine(nodeID, "upgrade-line"), app.now()); err != nil {
		t.Fatal(err)
	}
	seedStoredRouteCandidate(t, app, nodeID, staleOutRoute)
	before := latestRevision(t, app, nodeID)

	receipt := decodeApprove(t, approveUpgrade(t, b, nodeID, upgradeManifestVersion(t)), 200)
	if !receipt.OK || receipt.Revision <= before {
		t.Fatalf("approval receipt = %+v", receipt)
	}
	if got := latestStoredRoute(t, app.store, nodeID); got != "" {
		t.Fatalf("approval carried the stale Out route: %s", got)
	}
}

// TestUpgradeApprovalRefusesAnUnboundOut keeps the approval fail-closed: the
// live policy still selects an Out the Line no longer has, so no revision is
// stored and the receipt names the stable compiler code.
func TestUpgradeApprovalRefusesAnUnboundOut(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	now := app.now()
	settings := testLine(nodeID, "upgrade-line")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	created, err := app.store.CreateRoutePolicy(store.PolicyLayerServer, "升级服务端策略",
		json.RawMessage(outServerPolicy), nil, "op-upgrade-policy", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.ActivateRoutePolicy(created.ID, created.Revision, "op-upgrade-activate", now); err != nil {
		t.Fatal(err)
	}
	before := latestRevision(t, app, nodeID)
	refusal := decodeApprove(t, approveUpgrade(t, b, nodeID, upgradeManifestVersion(t)), 409)
	if refusal.OK || refusal.ErrorCode != "OUT_BINDING_INVALID" {
		t.Fatalf("approval without the Out = %+v, want OUT_BINDING_INVALID", refusal)
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("refused approval advanced the revision: %d -> %d", before, got)
	}
	if got := countStamped(t, app, nodeID); got != 0 {
		t.Fatalf("refused approval wrote %d upgrade records", got)
	}
}

// TestUpgradeApprovalRefusesAnOfflineOut is the offline half of the approval
// refusal: the binding is still there, the Out just cannot prove it.
func TestUpgradeApprovalRefusesAnOfflineOut(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	now := app.now()
	settings := testLine(nodeID, "upgrade-line")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	out := pairedStoreNode(t, app.store, "out", now)
	markLineOnline(t, app.store, out, now)
	configureOut(t, app.store, out, now)
	// Enrollment publishes the Out guard (Ruling R10); the fixture settles and confirms
	// it so the offline state below is the only reason for the refusal.
	app.store.RepublishOutAuthorizations(now)
	settleTasks(t, app.store, out)
	confirmChain(t, app.store, out, now)
	enableOutForLine(t, app.store, out, nodeID, now)
	// Selecting the Out makes the Line route through it; the Line's own chain has to
	// settle before the approval can be judged on the Out state alone.
	if err := app.store.PrepareSubscriberSync(nodeSubscriberID(t, app.store, nodeID), now); err != nil {
		t.Fatalf("publish the line: %v", err)
	}
	settleTasks(t, app.store, nodeID)
	confirmChain(t, app.store, nodeID, now)
	created, err := app.store.CreateRoutePolicy(store.PolicyLayerServer, "升级服务端策略",
		json.RawMessage(outServerPolicy), nil, "op-upgrade-policy", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.ActivateRoutePolicy(created.ID, created.Revision, "op-upgrade-activate", now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	before := latestRevision(t, app, nodeID)
	refusal := decodeApprove(t, approveUpgrade(t, b, nodeID, upgradeManifestVersion(t)), 409)
	if refusal.OK || refusal.ErrorCode != compiler.CodeOutOfflineFailClosed {
		t.Fatalf("approval with an offline Out = %+v, want %s", refusal, compiler.CodeOutOfflineFailClosed)
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("refused approval advanced the revision: %d -> %d", before, got)
	}
}

// TestSubscriberSyncEndpointReportsTheOutRefusal drives the real sync endpoint:
// the re-derived route can refuse on the Out contract, and the operator sees the
// compiler's code instead of a generic SUBSCRIBER_SYNC_FAILED. Nothing is stored
// and the previous revision stays live.
func TestSubscriberSyncEndpointReportsTheOutRefusal(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	now := app.now()
	line := createPairedWebNode(t, app, "edge", "line-sync-out", 8443, 2222)
	settings := testLine(line.ID, "line-sync-out")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, app.store, line.ID, now)
	subscriber, _, err := app.store.CreateSubscriber("alice", []string{line.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	created, err := app.store.CreateRoutePolicy(store.PolicyLayerServer, "服务端策略",
		json.RawMessage(outServerPolicy), nil, "op-policy", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.ActivateRoutePolicy(created.ID, created.Revision, "op-activate", now); err != nil {
		t.Fatal(err)
	}
	before := latestRevision(t, app, line.ID)

	w := b.post("/subscribers/sync", url.Values{"subscriber_id": {subscriber.ID}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "OUT_BINDING_INVALID") {
		t.Fatalf("sync refusal does not name the Out conflict: %.400s", w.Body.String())
	}
	if got := latestRevision(t, app, line.ID); got != before {
		t.Fatalf("refused sync advanced the revision: %d -> %d", before, got)
	}
	if got := countStamped(t, app, line.ID); got != 0 {
		t.Fatalf("refused sync wrote %d upgrade records", got)
	}
}

// TestPublishAssemblyStillUsesTheSameOutFacts proves the shared derivation did
// not change the publication path: an Out-free direct policy still assembles,
// and the route it stores is exactly what the implicit derivation produces.
func TestPublishAssemblyStillUsesTheSameOutFacts(t *testing.T) {
	f := newPublishFixture(t)
	f.activatePolicy(t, store.PolicyLayerServer, publishServerDirect, "")
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(`{"operation_id":"op-publish"}`))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := f.store.AssemblePolicyPublication(context.Background(), &fixturePublishVerifier{}, request, f.now)
	if err != nil {
		t.Fatalf("direct assembly: %v", err)
	}
	if assembly.EgressState != compiler.AIEgressLine || len(assembly.Targets) != 1 {
		t.Fatalf("assembly = %s/%+v", assembly.EgressState, assembly.Targets)
	}
	if _, err := f.store.PublishPolicyAssembly(assembly, f.now); err != nil {
		t.Fatalf("store publication: %v", err)
	}
	tx, err := f.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	live, err := store.LineServerRouteTx(tx, f.line, f.now)
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if stored := latestStoredRoute(t, f.store, f.line); !sameJSON(t, string(live), stored) {
		t.Fatalf("implicit route %q disagrees with the published route %q", live, stored)
	}
}

// sameJSON compares two JSON documents by value: the store compacts a raw route
// while the renderer emits indented bytes, and the drift is about content.
func sameJSON(t *testing.T, left, right string) bool {
	t.Helper()
	var a, b any
	if err := json.Unmarshal([]byte(left), &a); err != nil {
		t.Fatalf("route %q is not JSON: %v", left, err)
	}
	if err := json.Unmarshal([]byte(right), &b); err != nil {
		t.Fatalf("route %q is not JSON: %v", right, err)
	}
	first, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(first) == string(second)
}

// TestLineRouteSkipsNonEdgeNodes keeps the derivation scoped to a Line: an Out
// node and an unconfigured Edge carry no server route.
func TestLineRouteSkipsNonEdgeNodes(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	unconfigured := pairedStoreNode(t, s, "edge", now)
	created, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端策略",
		json.RawMessage(outServerPolicy), nil, "op-policy", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateRoutePolicy(created.ID, created.Revision, "op-activate", now); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{out, unconfigured} {
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		fragment, err := store.LineServerRouteTx(tx, nodeID, now)
		tx.Rollback()
		if err != nil {
			t.Fatalf("%s route derivation: %v", nodeID, err)
		}
		if len(fragment) != 0 {
			t.Fatalf("%s derived a route: %s", nodeID, fragment)
		}
	}
}
