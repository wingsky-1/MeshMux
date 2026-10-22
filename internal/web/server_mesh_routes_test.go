package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/headscale"
	"github.com/wingsky-1/MeshMux/internal/mesh"
)

// meshCreateRouter creates a subnet_router through the page form, including the
// prefixes the form now requires.
func meshCreateRouter(t *testing.T, b *browser, displayName string, prefixes ...string) MeshDeviceRecord {
	t.Helper()
	w := b.post("/mesh", url.Values{
		"display_name":      {displayName},
		"purpose":           {"subnet_router"},
		"platform":          {"nas"},
		"subscriber_id":     {""},
		"declared_prefixes": {strings.Join(prefixes, "\n")},
	})
	requireStatus(t, w, http.StatusOK)
	devices, err := b.app.store.listMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.DisplayName == displayName {
			return device
		}
	}
	t.Fatalf("no subnet_router named %q was created", displayName)
	return MeshDeviceRecord{}
}

// routeCallIndex returns the position of one call in the recorded sequence.
func routeCallIndex(calls []string, name string) int {
	for i, call := range calls {
		if call == name {
			return i
		}
	}
	return -1
}

func TestMeshCreateSubnetRouterRequiresPrefix(t *testing.T) {
	_, b, _, _ := meshTestApp(t)
	w := b.post("/mesh", url.Values{
		"display_name": {"nas"}, "purpose": {"subnet_router"},
		"platform": {"nas"}, "subscriber_id": {""}, "declared_prefixes": {""},
	})
	requireStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), mesh.CodeRouteDeclarationInvalid) {
		t.Fatalf("missing declaration lost its code: %.300s", w.Body.String())
	}
	if devices, err := b.app.store.listMeshDevices(); err != nil || len(devices) != 0 {
		t.Fatalf("a refused router stored %d devices (err=%v)", len(devices), err)
	}
}

// TestMeshRouteApproveSendsFullSetAndPreservesUntracked pins the set contract:
// the approval sends the observed approved set plus the new prefix, keeps an
// approved prefix the Hub never declared, and records it as untracked rather
// than silently clearing it.
func TestMeshRouteApproveSendsFullSetAndPreservesUntracked(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.recordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []headscale.Node{{
		ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"10.5.0.0/16"},
		AvailableRoutes: []string{"10.5.0.0/16", "192.168.1.0/24"},
	}}
	fake.resetCalls()

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.list") != 2 { // one pre-read, one page render
		t.Fatalf("approval calls = %v", fake.calls)
	}
	if fake.callsOf("nodes.approve-routes") != 1 {
		t.Fatalf("approval did not set the approved routes: %v", fake.calls)
	}
	got := map[string]bool{}
	for _, prefix := range fake.nodes[0].ApprovedRoutes {
		got[prefix] = true
	}
	if !got["192.168.1.0/24"] || !got["10.5.0.0/16"] {
		t.Fatalf("approved set = %v, want the new prefix and the untracked one", fake.nodes[0].ApprovedRoutes)
	}
	stored, err := app.store.getMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredApproved || stored.Observed != mesh.RouteObservedApproved {
		t.Fatalf("stored route = %+v", stored)
	}
	if got := routeEventKinds(t, app.store, router.ID, "10.5.0.0/16"); len(got) != 1 || got[0] != codeMeshRouteUntracked {
		t.Fatalf("untracked approval events = %v", got)
	}
	body := w.Body.String()
	for _, want := range []string{"已批准", stored.OperationID, "approved", "available", "served"} {
		if !strings.Contains(body, want) {
			t.Fatalf("approval page lost %q", want)
		}
	}

	// Repeating the approval is a no-op: the first transition owns the audit key
	// and no second Headscale mutation is sent.
	fake.resetCalls()
	w = b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.approve-routes") != 0 {
		t.Fatalf("repeat approval called Headscale again: %v", fake.calls)
	}
}

// routeReadbackLosingHeadscale accepts the set command but reports a node whose
// approved list does not contain the new prefix, simulating a readback that
// cannot confirm the change.
type routeReadbackLosingHeadscale struct{ *fakeHeadscale }

func (f *routeReadbackLosingHeadscale) SetApprovedRoutes(_ context.Context, id uint64, _ []string) (headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("nodes.approve-routes"); err != nil {
		return headscale.Node{}, err
	}
	for _, node := range f.nodes {
		if node.ID == id {
			return node, nil
		}
	}
	return headscale.Node{}, &headscale.Error{Code: headscale.CodeNotFound}
}

func TestMeshRouteApproveReadbackMismatchLeavesAdvertised(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.recordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []headscale.Node{{ID: 7, Name: router.NodeName, AvailableRoutes: []string{"192.168.1.0/24"}}}
	app.mesh = &routeReadbackLosingHeadscale{fake}

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), codeMeshRouteApprovalUnconfirmed) {
		t.Fatalf("unconfirmed readback lost its code: %.400s", w.Body.String())
	}
	stored, err := app.store.getMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("unconfirmed approval changed intent: %+v", stored)
	}
}

func TestMeshRouteRevokeSendsDifference(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.recordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.setMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []headscale.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24", "10.5.0.0/16"},
		AvailableRoutes: []string{"192.168.1.0/24", "10.5.0.0/16"}}}
	fake.resetCalls()

	w := b.post("/mesh/routes/revoke", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.approve-routes") != 1 || fake.callsOf("nodes.clear-routes") != 0 {
		t.Fatalf("withdrawal calls = %v, want one set operation", fake.calls)
	}
	if len(fake.nodes[0].ApprovedRoutes) != 1 || fake.nodes[0].ApprovedRoutes[0] != "10.5.0.0/16" {
		t.Fatalf("withdrawal did not send the difference set: %v", fake.nodes[0].ApprovedRoutes)
	}
	stored, err := app.store.getMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("withdrawal did not return the prefix to advertised: %+v", stored)
	}
}

func TestMeshRouteRevokeClearsWhenNothingRemains(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.recordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.setMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []headscale.Node{{ID: 7, Name: router.NodeName, ApprovedRoutes: []string{"192.168.1.0/24"}}}
	fake.resetCalls()

	w := b.post("/mesh/routes/revoke", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.clear-routes") != 1 || fake.callsOf("nodes.approve-routes") != 0 {
		t.Fatalf("empty remaining set calls = %v, want clear", fake.calls)
	}
}

// TestMeshReconcileRecordsRouteEvidence covers the reconcile half: the same
// nodes list read records the three lists as one observation, an untracked
// advertisement becomes an event only, and no prefix is approved by the pass.
func TestMeshReconcileRecordsRouteEvidence(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.recordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []headscale.Node{{
		ID: 7, Name: router.NodeName,
		AvailableRoutes: []string{"192.168.1.0/24", "10.5.0.0/16"},
		ApprovedRoutes:  []string{"192.168.1.0/24"},
		SubnetRoutes:    []string{"192.168.1.0/24"},
	}}
	w := b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, http.StatusOK)
	stored, err := app.store.getMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Observed != mesh.RouteObservedServed {
		t.Fatalf("observed = %q, want served", stored.Observed)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("reconcile approved a prefix: %+v", stored)
	}
	if got := routeEventKinds(t, app.store, router.ID, "10.5.0.0/16"); len(got) != 1 || got[0] != codeMeshRouteUntracked {
		t.Fatalf("untracked advertisement events = %v", got)
	}
}

// TestMeshRevokeClearsApprovedRoutesBeforeDelete pins the deletion order for a
// routing device: approval is withdrawn before the node is expired and removed.
func TestMeshRevokeClearsApprovedRoutesBeforeDelete(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.recordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.setMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []headscale.Node{{ID: 7, Name: router.NodeName, ApprovedRoutes: []string{"192.168.1.0/24"}}}
	fake.resetCalls()

	w := b.post("/mesh/revoke", url.Values{"device_id": {router.ID}})
	requireStatus(t, w, http.StatusOK)
	calls := fake.resetCalls()
	clearAt := routeCallIndex(calls, "nodes.clear-routes")
	deleteAt := routeCallIndex(calls, "nodes.delete")
	if clearAt < 0 || deleteAt < 0 || clearAt > deleteAt {
		t.Fatalf("remote calls = %v, want clear-routes before nodes.delete", calls)
	}
	revoked, err := app.store.getMeshDevice(router.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != mesh.StatusRevoked {
		t.Fatalf("device did not settle: %+v", revoked)
	}
}
