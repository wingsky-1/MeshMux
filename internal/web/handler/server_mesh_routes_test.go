package handler

import (
	"context"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
)

// meshCreateRouter creates a subnet_router through the page form, including the
// prefixes the form now requires.
func meshCreateRouter(t *testing.T, b *browser, displayName string, prefixes ...string) store.MeshDeviceRecord {
	t.Helper()
	w := b.post("/mesh", url.Values{
		"display_name":      {displayName},
		"purpose":           {"subnet_router"},
		"platform":          {"nas"},
		"subscriber_id":     {""},
		"declared_prefixes": {strings.Join(prefixes, "\n")},
	})
	requireStatus(t, w, http.StatusOK)
	devices, err := b.app.store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.DisplayName == displayName {
			return device
		}
	}
	t.Fatalf("no subnet_router named %q was created", displayName)
	return store.MeshDeviceRecord{}
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

// TestMeshSubnetRouterKeepsTheStockClient pins #113 2-5 for the purpose that
// actually advertises LAN prefixes. A subnet_router never receives the
// device-scoped sing-box document: that document is proxy_mesh-only and pins
// accept_routes=false, so it could not reach an advertised prefix anyway. The
// page keeps the stock Tailscale client and its join command with the declared
// prefixes; that client owns its own --accept-routes choice, which the Hub does
// not set. The exporter's own purpose table is pinned in internal/subscription.
func TestMeshSubnetRouterKeepsTheStockClient(t *testing.T) {
	app, b, fake, _ := meshEndpointTestApp(t, testHeadscaleOrigin)
	now := app.now()
	line := createEdgeNode(t, app.store, now)
	configureLine(t, app.store, line, "line-a", now)
	// A subnet_router may be bound to a subscriber; the binding must not turn
	// it into a proxy+mesh device.
	sub, _, err := app.store.CreateSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}
	fake.resetCalls()
	w := b.post("/mesh", url.Values{
		"display_name": {"nas"}, "purpose": {"subnet_router"}, "platform": {"nas"},
		"subscriber_id": {sub.ID}, "declared_prefixes": {"192.168.1.0/24"},
	})
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if strings.Contains(body, `"accept_routes"`) || strings.Contains(body, "meshmux-ts") {
		t.Fatalf("subnet_router received the proxy_mesh document: %.600s", body)
	}
	if !strings.Contains(body, "--advertise-routes=192.168.1.0/24") {
		t.Fatalf("subnet_router lost its stock advertise command: %.600s", body)
	}
	if fake.callsOf("preauthkeys.create") != 0 {
		t.Fatalf("subnet_router minted a Headscale pre-auth key: %v", fake.calls)
	}
	// The config endpoint refuses the same purpose with a stable code, so an
	// explicit POST cannot reach the renderer either.
	devices, err := app.store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d", len(devices))
	}
	fake.resetCalls()
	w = b.post("/mesh/config", url.Values{"device_id": {devices[0].ID}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), codeMeshEndpointPurposeUnsupported) {
		t.Fatalf("config refusal lost its code: %.400s", w.Body.String())
	}
	if fake.callsOf("preauthkeys.create") != 0 {
		t.Fatalf("config refusal minted a pre-auth key: %v", fake.calls)
	}
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
	if devices, err := b.app.store.ListMeshDevices(); err != nil || len(devices) != 0 {
		t.Fatalf("a refused router stored %d devices (err=%v)", len(devices), err)
	}
}

// TestMeshRouteApprovalSetDropsUnsendableEntries pins the set builder directly:
// sendable approved prefixes are canonicalised, deduplicated and kept; entries
// the Headscale adapter refuses are returned as dropped rather than sent back,
// so one stale exit route cannot block the whole set. A value the mesh domain
// cannot parse but the adapter accepts is still sent unchanged: the adapter's
// rule is the only rule that decides what may travel in the CSV value.
func TestMeshRouteApprovalSetDropsUnsendableEntries(t *testing.T) {
	cases := []struct {
		name        string
		existing    []string
		add, remove string
		want        []string
		dropped     []string
	}{
		{
			name:     "sendable entries are kept and canonicalised",
			existing: []string{"10.5.0.0/16", " 10.5.0.0/16 ", "192.168.2.0/24"},
			want:     []string{"10.5.0.0/16", "192.168.2.0/24"},
		},
		{
			name:     "exit routes are dropped for the add path",
			existing: []string{"0.0.0.0/0", "::/0", "10.5.0.0/16"},
			add:      "192.168.1.0/24",
			want:     []string{"10.5.0.0/16", "192.168.1.0/24"},
			dropped:  []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:     "host bits and non-prefixes are dropped",
			existing: []string{"10.0.0.1/8", "lan", "10.5.0.0/16"},
			remove:   "10.5.0.0/16",
			want:     []string{},
			dropped:  []string{"10.0.0.1/8", "lan"},
		},
		{
			name: "an empty existing set leaves only the addition",
			add:  "192.168.1.0/24",
			want: []string{"192.168.1.0/24"},
		},
		{
			name:     "the removed prefix is not reported as dropped",
			existing: []string{"192.168.1.0/24", "0.0.0.0/0"},
			remove:   "192.168.1.0/24",
			want:     []string{},
			dropped:  []string{"0.0.0.0/0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, dropped := meshRouteApprovalSet(tc.existing, tc.add, tc.remove)
			if strings.Join(set, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("set = %v, want %v", set, tc.want)
			}
			if strings.Join(dropped, ",") != strings.Join(tc.dropped, ",") {
				t.Fatalf("dropped = %v, want %v", dropped, tc.dropped)
			}
			// Whatever the builder returns must survive the adapter's own
			// refusal, which is the property that ends the deadlock.
			for _, prefix := range set {
				if !meshnet.ApprovableRoutePrefix(prefix) {
					t.Fatalf("set carries an unsendable prefix %q", prefix)
				}
			}
		})
	}
}

// TestMeshRouteApproveSendsFullSetAndPreservesUntracked pins the set contract:
// the approval sends the observed approved set plus the new prefix, keeps an
// approved prefix the Hub never declared, and records it as untracked rather
// than silently clearing it.
func TestMeshRouteApproveSendsFullSetAndPreservesUntracked(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
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
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredApproved || stored.Observed != mesh.RouteObservedApproved {
		t.Fatalf("stored route = %+v", stored)
	}
	if got := routeEventKinds(t, app.store, router.ID, "10.5.0.0/16"); len(got) != 1 || got[0] != store.CodeMeshRouteUntracked {
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

func (f *routeReadbackLosingHeadscale) SetApprovedRoutes(_ context.Context, id uint64, _ []string) (meshnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("nodes.approve-routes"); err != nil {
		return meshnet.Node{}, err
	}
	for _, node := range f.nodes {
		if node.ID == id {
			return node, nil
		}
	}
	return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeNotFound}
}

// routeRefusingSendableOnlyHeadscale behaves like the production adapter: it
// refuses the whole set when any entry would not survive ApprovableRoutePrefix,
// which is exactly the failure a stale exit route used to trigger.
type routeRefusingSendableOnlyHeadscale struct{ *fakeHeadscale }

func (f *routeRefusingSendableOnlyHeadscale) SetApprovedRoutes(ctx context.Context, id uint64, prefixes []string) (meshnet.Node, error) {
	for _, prefix := range prefixes {
		if !meshnet.ApprovableRoutePrefix(prefix) {
			f.mu.Lock()
			_ = f.record("nodes.approve-routes")
			f.mu.Unlock()
			return meshnet.Node{}, &meshnet.Error{Code: meshnet.CodeRouteInvalid}
		}
	}
	return f.fakeHeadscale.SetApprovedRoutes(ctx, id, prefixes)
}

// TestMeshRouteApproveSurvivesAnUnsendableApprovedPrefix drives the whole path
// through an adapter that refuses the complete set the way the real one does. The
// exit route already in Headscale's approved list used to turn every approval of
// a legitimate prefix into a 503; the prefix now goes through and the drop is
// audited.
func TestMeshRouteApproveSurvivesAnUnsendableApprovedPrefix(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	app.mesh = &routeRefusingSendableOnlyHeadscale{fake}
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
		ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"0.0.0.0/0"},
		AvailableRoutes: []string{"192.168.1.0/24"},
	}}
	fake.resetCalls()

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.approve-routes") != 1 {
		t.Fatalf("approval calls = %v", fake.calls)
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredApproved {
		t.Fatalf("an exit route in the approved set still blocks approval: %+v", stored)
	}
}

func TestMeshRouteApproveReadbackMismatchLeavesAdvertised(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName, AvailableRoutes: []string{"192.168.1.0/24"}}}
	app.mesh = &routeReadbackLosingHeadscale{fake}

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), codeMeshRouteApprovalUnconfirmed) {
		t.Fatalf("unconfirmed readback lost its code: %.400s", w.Body.String())
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
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
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
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
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
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
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName, ApprovedRoutes: []string{"192.168.1.0/24"}}}
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
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
		ID: 7, Name: router.NodeName,
		AvailableRoutes: []string{"192.168.1.0/24", "10.5.0.0/16"},
		ApprovedRoutes:  []string{"192.168.1.0/24"},
		SubnetRoutes:    []string{"192.168.1.0/24"},
	}}
	w := b.post("/mesh/reconcile", url.Values{})
	requireStatus(t, w, http.StatusOK)
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Observed != mesh.RouteObservedServed {
		t.Fatalf("observed = %q, want served", stored.Observed)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("reconcile approved a prefix: %+v", stored)
	}
	if got := routeEventKinds(t, app.store, router.ID, "10.5.0.0/16"); len(got) != 1 || got[0] != store.CodeMeshRouteUntracked {
		t.Fatalf("untracked advertisement events = %v", got)
	}
}

// TestMeshRevokeClearsApprovedRoutesBeforeDelete pins the deletion order for a
// routing device: approval is withdrawn before the node is expired and removed.
func TestMeshRevokeClearsApprovedRoutesBeforeDelete(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName, ApprovedRoutes: []string{"192.168.1.0/24"}}}
	fake.resetCalls()

	w := b.post("/mesh/revoke", url.Values{"device_id": {router.ID}})
	requireStatus(t, w, http.StatusOK)
	calls := fake.resetCalls()
	clearAt := routeCallIndex(calls, "nodes.clear-routes")
	deleteAt := routeCallIndex(calls, "nodes.delete")
	if clearAt < 0 || deleteAt < 0 || clearAt > deleteAt {
		t.Fatalf("remote calls = %v, want clear-routes before nodes.delete", calls)
	}
	revoked, err := app.store.GetMeshDevice(router.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != mesh.StatusRevoked {
		t.Fatalf("device did not settle: %+v", revoked)
	}
}

// TestMeshRouteApproveDropsUnsendableApprovedPrefix is the deadlock regression.
// `nodes approve-routes` replaces the whole approved list in one value, so an
// exit route already sitting in Headscale's approved set used to make the adapter
// refuse every approval of a legitimate prefix, forever. The un-sendable entries
// are now left out, the sendable ones still go, and each drop is audited.
func TestMeshRouteApproveDropsUnsendableApprovedPrefix(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
		ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"10.5.0.0/16", "0.0.0.0/0", "::/0", "10.0.0.1/8"},
		AvailableRoutes: []string{"10.5.0.0/16", "192.168.1.0/24"},
	}}
	fake.resetCalls()
	logs.Reset()

	w := b.post("/mesh/routes/approve", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.approve-routes") != 1 {
		t.Fatalf("approval never reached Headscale: %v", fake.calls)
	}
	if got := fake.nodes[0].ApprovedRoutes; len(got) != 2 || got[0] != "10.5.0.0/16" || got[1] != "192.168.1.0/24" {
		t.Fatalf("approved set = %v, want the sendable prefixes only", got)
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredApproved {
		t.Fatalf("dropping an un-sendable prefix blocked the approval: %+v", stored)
	}
	log := logs.String()
	if got := strings.Count(log, codeMeshRouteUntrackedDropped); got != 3 {
		t.Fatalf("dropped-prefix events = %d, want 3: %s", got, log)
	}
	for _, leak := range []string{"0.0.0.0/0", "::/0", "10.0.0.1/8"} {
		if strings.Contains(log, leak) {
			t.Fatalf("log quoted the dropped prefix %q: %s", leak, log)
		}
	}
	body := w.Body.String()
	if !strings.Contains(body, codeMeshRouteUntrackedDropped) || !strings.Contains(body, "3 条") {
		t.Fatalf("approval page did not disclose the drop: %.600s", body)
	}
}

// TestMeshRouteWithdrawDropsUnsendableApprovedPrefix covers the other set
// operation: withdrawing a declared prefix keeps the sendable untracked ones and
// leaves an exit route out of the difference set, so the withdrawal itself is not
// refused by the adapter.
func TestMeshRouteWithdrawDropsUnsendableApprovedPrefix(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24", "10.5.0.0/16", "0.0.0.0/0"},
		AvailableRoutes: []string{"192.168.1.0/24", "10.5.0.0/16"}}}
	fake.resetCalls()
	logs.Reset()

	w := b.post("/mesh/routes/revoke", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.approve-routes") != 1 || fake.callsOf("nodes.clear-routes") != 0 {
		t.Fatalf("withdrawal calls = %v, want one set operation", fake.calls)
	}
	if got := fake.nodes[0].ApprovedRoutes; len(got) != 1 || got[0] != "10.5.0.0/16" {
		t.Fatalf("withdrawal sent %v, want the sendable difference set", got)
	}
	stored, err := app.store.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("withdrawal did not return the prefix to advertised: %+v", stored)
	}
	if got := strings.Count(logs.String(), codeMeshRouteUntrackedDropped); got != 1 {
		t.Fatalf("dropped-prefix events = %d, want 1: %s", got, logs.String())
	}
	if body := w.Body.String(); !strings.Contains(body, codeMeshRouteUntrackedDropped) {
		t.Fatalf("withdrawal page did not disclose the drop: %.600s", body)
	}
}

// TestMeshRouteWithdrawClearsWhenOnlyUnsendableRemains pins the clear path: when
// nothing sendable is left, the withdrawal clears the set, which also removes the
// prefix the adapter would refuse to send back.
func TestMeshRouteWithdrawClearsWhenOnlyUnsendableRemains(t *testing.T) {
	app, b, fake, logs := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas", "192.168.1.0/24")
	if _, err := app.store.RecordMeshObservation(router.ID, 7, app.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-seed", app.now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{ID: 7, Name: router.NodeName,
		ApprovedRoutes:  []string{"192.168.1.0/24", "0.0.0.0/0"},
		AvailableRoutes: []string{"192.168.1.0/24"}}}
	fake.resetCalls()
	logs.Reset()

	w := b.post("/mesh/routes/revoke", url.Values{"device_id": {router.ID}, "prefix": {"192.168.1.0/24"}})
	requireStatus(t, w, http.StatusOK)
	if fake.callsOf("nodes.clear-routes") != 1 || fake.callsOf("nodes.approve-routes") != 0 {
		t.Fatalf("calls = %v, want one clear", fake.calls)
	}
	if got := strings.Count(logs.String(), codeMeshRouteUntrackedDropped); got != 1 {
		t.Fatalf("dropped-prefix events = %d, want 1: %s", got, logs.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "一并撤销") {
		t.Fatalf("clear notice did not say the dropped prefix was withdrawn: %.600s", body)
	}
}
