package handler

import (
	"context"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/meshnet"
)

// refuseMeshRouteIntentUpdates makes the local intent write of a route action
// fail while every read and every Headscale call still succeeds. It is the
// "remote accepted, local failed" injection: a trigger refuses only the UPDATE
// of mesh_routes.desired, so the handler reaches its compensation path instead
// of failing before the mutation.
func refuseMeshRouteIntentUpdates(t *testing.T, app *Server) {
	t.Helper()
	if _, err := app.store.DB.Exec(`CREATE TRIGGER mesh_route_desired_refused
 BEFORE UPDATE OF desired ON mesh_routes
 BEGIN
   SELECT RAISE(ABORT, 'MESH_ROUTE_TEST_REFUSED');
 END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := app.store.DB.Exec(`DROP TRIGGER IF EXISTS mesh_route_desired_refused`); err != nil {
			t.Errorf("drop trigger: %v", err)
		}
	})
}

// routeCompensationRefusingHeadscale accepts the first mutation and refuses the
// compensation, so the handler can only report a partial outcome.
type routeCompensationRefusingHeadscale struct {
	*fakeHeadscale
	failOn int
	seen   int
}

func (f *routeCompensationRefusingHeadscale) refuse() bool {
	f.seen++
	return f.seen == f.failOn
}

func (f *routeCompensationRefusingHeadscale) SetApprovedRoutes(ctx context.Context, id uint64, prefixes []string) (meshnet.Node, error) {
	if f.refuse() {
		f.mu.Lock()
		_ = f.record("nodes.approve-routes")
		f.mu.Unlock()
		return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeUnavailable}
	}
	return f.fakeHeadscale.SetApprovedRoutes(ctx, id, prefixes)
}

func (f *routeCompensationRefusingHeadscale) ClearApprovedRoutes(ctx context.Context, id uint64) (meshnet.Node, error) {
	if f.refuse() {
		f.mu.Lock()
		_ = f.record("nodes.clear-routes")
		f.mu.Unlock()
		return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeUnavailable}
	}
	return f.fakeHeadscale.ClearApprovedRoutes(ctx, id)
}

// TestMeshRouteApproveLocalFailureRevertsHeadscale pins the compensated failure:
// Headscale accepted the approval, the Hub could not record it, and the handler
// put the approved set back to what the request found. The page therefore still
// reports a failure, but one that is true: nothing changed on either side.
func TestMeshRouteApproveLocalFailureRevertsHeadscale(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
		ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"10.5.0.0/16"},
		AvailableRoutes: []string{"10.5.0.0/16", "192.168.1.0/24"},
	}}
	refuseMeshRouteIntentUpdates(t, app)
	fake.resetCalls()

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), store.CodeDatabaseUnavailable) {
		t.Fatalf("compensated failure lost its code: %.500s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), codeMeshRouteApprovalPartial) {
		t.Fatalf("a reverted mutation was reported as partial: %.500s", w.Body.String())
	}
	// The revert is the readback the handler reports on: the prefix the request
	// approved is no longer approved, and the untracked one is untouched.
	approved := fake.nodes[0].ApprovedRoutes
	if len(approved) != 1 || approved[0] != "10.5.0.0/16" {
		t.Fatalf("approved set after compensation = %v, want the pre-request set", approved)
	}
	if got := fake.callsOf("nodes.approve-routes"); got != 2 {
		t.Fatalf("approve-routes calls = %d, want the mutation and its revert (%v)", got, fake.calls)
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("failed local write changed the stored intent: %+v", stored)
	}
	if !strings.Contains(logs.String(), codeMeshRouteCompensated) {
		t.Fatalf("the confirmed revert was not audited: %.800s", logs.String())
	}
}

// TestMeshRouteApprovePartialWhenRevertFails covers the other half: Headscale
// accepted the approval and the Hub could not record it, and the revert was
// refused too. Only then does the page claim a partial outcome, with its own
// code and a reconcile action, because the two sides really disagree.
func TestMeshRouteApprovePartialWhenRevertFails(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
		ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"10.5.0.0/16"},
		AvailableRoutes: []string{"10.5.0.0/16", "192.168.1.0/24"},
	}}
	refusing := &routeCompensationRefusingHeadscale{fakeHeadscale: fake, failOn: 2}
	app.mesh = refusing
	refuseMeshRouteIntentUpdates(t, app)
	fake.resetCalls()

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusInternalServerError)
	body := w.Body.String()
	if !strings.Contains(body, codeMeshRouteApprovalPartial) {
		t.Fatalf("partial approval lost its code: %.500s", body)
	}
	if !strings.Contains(body, "重新核对") {
		t.Fatalf("partial approval has no recovery action: %.500s", body)
	}
	if !strings.Contains(logs.String(), codeMeshRouteApprovalPartial) {
		t.Fatalf("partial approval was not audited: %.800s", logs.String())
	}
	if !strings.Contains(logs.String(), meshnet.CodeUnavailable) {
		t.Fatalf("the refused revert lost its code: %.800s", logs.String())
	}
	// The control plane really is ahead of the Hub, which is what "partial"
	// claims: the prefix stays approved remotely and the intent stays advertised.
	if !meshRoutePrefixIn(fake.nodes[0].ApprovedRoutes, "192.168.1.0/24") {
		t.Fatalf("partial was reported without the remote change: %v", fake.nodes[0].ApprovedRoutes)
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("failed local write changed the stored intent: %+v", stored)
	}
}

// TestMeshRouteRevokeLocalFailureRestoresApproval is the withdrawal half of the
// compensation: the prefix is approved again because the Hub could not record
// the withdrawal, and the other approved prefixes are still approved once.
func TestMeshRouteRevokeLocalFailureRestoresApproval(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	now := app.now()
	if _, err := app.store.RecordMeshObservation(router.ID, 7, now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", now); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24", "10.5.0.0/16"},
		AvailableRoutes: []string{"192.168.1.0/24", "10.5.0.0/16"}}}
	refuseMeshRouteIntentUpdates(t, app)
	fake.resetCalls()

	w := b.post("/mesh/routes/revoke", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), store.CodeDatabaseUnavailable) {
		t.Fatalf("compensated withdrawal lost its code: %.500s", w.Body.String())
	}
	if !meshRoutePrefixIn(fake.nodes[0].ApprovedRoutes, "192.168.1.0/24") {
		t.Fatalf("withdrawal was not reverted: %v", fake.nodes[0].ApprovedRoutes)
	}
	if len(fake.nodes[0].ApprovedRoutes) != 2 {
		t.Fatalf("reverted set = %v, want both pre-request prefixes", fake.nodes[0].ApprovedRoutes)
	}
	if got := fake.callsOf("nodes.approve-routes"); got != 2 {
		t.Fatalf("approve-routes calls = %d, want the mutation and its revert (%v)", got, fake.calls)
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredApproved {
		t.Fatalf("failed withdrawal changed intent: %+v", stored)
	}
	if !strings.Contains(logs.String(), codeMeshRouteCompensated) {
		t.Fatalf("the confirmed revert was not audited: %.800s", logs.String())
	}
}

// TestMeshRouteRevokePartialWhenClearRevertFails pins the clear path: the
// withdrawal emptied the approved set, and the revert that had to approve the
// prefix again was refused, so the outcome is partial and not a plain failure.
func TestMeshRouteRevokePartialWhenClearRevertFails(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	now := app.now()
	if _, err := app.store.RecordMeshObservation(router.ID, 7, now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", now); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24"},
		AvailableRoutes: []string{"192.168.1.0/24"}}}
	refusing := &routeCompensationRefusingHeadscale{fakeHeadscale: fake, failOn: 2}
	app.mesh = refusing
	refuseMeshRouteIntentUpdates(t, app)
	fake.resetCalls()

	w := b.post("/mesh/routes/revoke", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusInternalServerError)
	if !strings.Contains(w.Body.String(), codeMeshRouteWithdrawPartial) {
		t.Fatalf("partial withdrawal lost its code: %.500s", w.Body.String())
	}
	if !strings.Contains(logs.String(), codeMeshRouteWithdrawPartial) {
		t.Fatalf("partial withdrawal was not audited: %.800s", logs.String())
	}
	// The request found the prefix approved, so the revert is a set operation,
	// not a clear: it must approve exactly that prefix again.
	if fake.callsOf("nodes.clear-routes") != 1 || fake.callsOf("nodes.approve-routes") != 1 {
		t.Fatalf("withdrawal calls = %v, want a clear and its refused set revert", fake.calls)
	}
}

// TestMeshRoutePartialWhenTheHubRecordCannotBeRead pins the other unprovable
// case: the local readback fails outright, so the handler can neither confirm
// nor exclude a committed write. It must not revert on an unknown local state -
// that could undo a commit - and must report the mismatch as partial.
func TestMeshRoutePartialWhenTheHubRecordCannotBeRead(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	now := app.now()
	if _, err := app.store.RecordMeshObservation(router.ID, 7, now); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24"},
		AvailableRoutes: []string{"192.168.1.0/24"}}}
	if _, err := app.store.DB.Exec(`DROP TABLE mesh_routes`); err != nil {
		t.Fatal(err)
	}
	fake.resetCalls()

	w := httptest.NewRecorder()
	app.meshRouteLocalFail(w, httptest.NewRequest(http.MethodPost, testOrigin+"/mesh/routes/revoke", nil), session{},
		errors.New("DATABASE_UNAVAILABLE"), meshRouteLocalFailure{
			Fallback: codeMeshRouteWithdraw,
			Partial:  codeMeshRouteWithdrawPartial,
			Applied:  "Headscale 已撤销该前缀的批准",
			Intended: mesh.RouteDesiredAdvertised,
			DeviceID: router.ID,
			Prefix:   "192.168.1.0/24",
			NodeID:   7,
			Previous: []string{"192.168.1.0/24"},
		})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unreadable-record status = %d, want 500", w.Code)
	}
	if !strings.Contains(w.Body.String(), codeMeshRouteWithdrawPartial) {
		t.Fatalf("unreadable record lost the partial code: %.500s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), store.CodeDatabaseUnavailable) {
		t.Fatalf("the unreadable-record cause was not named: %.500s", w.Body.String())
	}
	// An unknown local state is never compensated: the remote set is untouched.
	if len(fake.calls) != 0 {
		t.Fatalf("an unknown local state was compensated: %v", fake.calls)
	}
	if !strings.Contains(logs.String(), codeMeshRouteWithdrawPartial) {
		t.Fatalf("the partial outcome was not audited: %.800s", logs.String())
	}
}

// TestMeshRouteLocalFailureDoesNotRevertACommittedWrite pins the readback before
// compensation: when the stored intent already carries the requested state, the
// local write did commit and only its response failed. Reverting Headscale then
// would create the disagreement the handler exists to prevent.
func TestMeshRouteLocalFailureDoesNotRevertACommittedWrite(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	now := app.now()
	if _, err := app.store.RecordMeshObservation(router.ID, 7, now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", now); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24"},
		AvailableRoutes: []string{"192.168.1.0/24"}}}
	fake.resetCalls()

	w := httptest.NewRecorder()
	app.meshRouteLocalFail(w, httptest.NewRequest(http.MethodPost, testOrigin+"/mesh/routes/approve", nil), session{},
		errors.New("DATABASE_UNAVAILABLE"), meshRouteLocalFailure{
			Fallback: codeMeshRouteApproval,
			Partial:  codeMeshRouteApprovalPartial,
			Applied:  "Headscale 已批准该前缀",
			Intended: mesh.RouteDesiredApproved,
			DeviceID: router.ID,
			Prefix:   "192.168.1.0/24",
			NodeID:   7,
			Previous: []string{},
		})
	if w.Code != http.StatusOK {
		t.Fatalf("committed-write readback status = %d, want the page to render", w.Code)
	}
	if strings.Contains(w.Body.String(), codeMeshRouteApprovalPartial) {
		t.Fatalf("a committed write was reported as partial: %.500s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Hub 也已记录该状态") {
		t.Fatalf("committed write was not reported honestly: %.500s", w.Body.String())
	}
	if got := fake.callsOf("nodes.clear-routes") + fake.callsOf("nodes.approve-routes"); got != 0 {
		t.Fatalf("a committed write was reverted: %v", fake.calls)
	}
}
