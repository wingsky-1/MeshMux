package mesh_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
	meshh "github.com/wingsky-1/MeshMux/internal/web/handler/mesh"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

func TestMeshExportTailnetPrefixesMatchDomain(t *testing.T) {
	if subscription.MeshTailnetIPv4Prefix != mesh.TailnetIPv4Prefix ||
		subscription.MeshTailnetIPv6Prefix != mesh.TailnetIPv6Prefix {
		t.Fatalf("subscription tailnet prefixes = %q/%q, domain = %q/%q",
			subscription.MeshTailnetIPv4Prefix, subscription.MeshTailnetIPv6Prefix,
			mesh.TailnetIPv4Prefix, mesh.TailnetIPv6Prefix)
	}
	// server_mesh_config.go converts the stored purpose to the exporter's own
	// type, so the two spellings must stay identical.
	for _, purpose := range []mesh.Purpose{mesh.PurposeProxyMesh, mesh.PurposeMeshOnly, mesh.PurposeSubnetRouter} {
		if got := subscription.MeshPurpose(purpose); string(got) != string(purpose) {
			t.Fatalf("subscription purpose %q does not match domain purpose %q", got, purpose)
		}
	}
}

func TestMeshCreateProxyDeviceShowsConfigOnceAndNeverReplaysIt(t *testing.T) {
	app, b, fake, logs := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	sub, _ := handlertest.MeshConvergedSubscriber(t, app, now)

	w := b.Post("/mesh", url.Values{
		"display_name": {"alice-iphone"}, "purpose": {"proxy_mesh"},
		"platform": {"ios"}, "subscriber_id": {sub.ID},
	})
	handlertest.RequireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !strings.Contains(body, "meshmux-ts") || !strings.Contains(body, "auth_key") || !strings.Contains(body, "control_url") {
		t.Fatalf("combined config is missing: %.600s", body)
	}
	if !strings.Contains(body, handlertest.TestHeadscaleOrigin) {
		t.Fatalf("config does not use the configured Headscale origin: %.600s", body)
	}
	if got := strings.Count(body, "headscale-preauth-example-once"); got != 1 {
		t.Fatalf("the one-shot Headscale key appears %d times, want 1", got)
	}
	if fake.CallsOf("preauthkeys.create") != 1 {
		t.Fatalf("preauth key calls = %v", fake.Calls)
	}
	if !strings.Contains(logs.String(), "MESH_DEVICE_CONFIG_ISSUED") {
		t.Fatal("config issue audit event missing")
	}
	// The next page is a plain GET: it must not replay the config or key.
	next := b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, next, 200)
	if strings.Contains(next.Body.String(), "headscale-preauth-example-once") || strings.Contains(next.Body.String(), "meshmux-ts") {
		t.Fatal("a page render replayed the one-shot config")
	}
	// There is deliberately no GET route for config generation.
	get := b.Req("GET", "/mesh/config", nil, nil)
	if get.Code == http.StatusOK {
		t.Fatalf("GET /mesh/config answered 200: %.300s", get.Body.String())
	}
	if strings.Contains(get.Body.String(), "headscale-preauth-example-once") {
		t.Fatal("GET /mesh/config exposed a key")
	}
	// The Headscale key is not persisted. Only the Hub key digest exists.
	var plaintext int
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM mesh_enrollment_keys WHERE secret_hash=?`, []byte("headscale-preauth-example-once")).Scan(&plaintext); err != nil {
		t.Fatal(err)
	}
	if plaintext != 0 {
		t.Fatal("the Headscale pre-auth key was written to the database")
	}
}

func TestMeshConfigRegeneratesForAPendingProxyDevice(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	sub, _ := handlertest.MeshConvergedSubscriber(t, app, now)
	w := b.Post("/mesh", url.Values{
		"display_name": {"alice-iphone"}, "purpose": {"proxy_mesh"},
		"platform": {"ios"}, "subscriber_id": {sub.ID},
	})
	handlertest.RequireStatus(t, w, http.StatusOK)
	devices, err := app.Store.ListMeshDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d", len(devices))
	}
	fake.ResetCalls()
	w = b.Post("/mesh/config", url.Values{"device_id": {devices[0].ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "meshmux-ts") {
		t.Fatalf("regenerated config missing: %.400s", w.Body.String())
	}
	if fake.CallsOf("preauthkeys.create") != 1 {
		t.Fatalf("regeneration calls = %v", fake.Calls)
	}
	keys, err := app.Store.ListMeshEnrollmentKeys(devices[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var issued, revoked int
	for _, key := range keys {
		switch key.State {
		case mesh.KeyIssued:
			issued++
		case mesh.KeyRevoked:
			revoked++
		}
	}
	if issued != 1 || revoked != 1 {
		t.Fatalf("after regeneration: issued=%d revoked=%d, want 1/1", issued, revoked)
	}
}

func TestMeshConfigRefusesPurposeWithoutMintingKey(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := app.Now()
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("phone", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	fake.ResetCalls()
	w := b.Post("/mesh/config", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), meshh.CodeMeshEndpointPurposeUnsupported) {
		t.Fatalf("purpose refusal lost its code: %.400s", w.Body.String())
	}
	if fake.CallsOf("preauthkeys.create") != 0 {
		t.Fatalf("purpose refusal minted a pre-auth key: %v", fake.Calls)
	}
}

// TestMeshConfigPurposeReachesTheExporter proves the stored purpose travels
// into the pure renderer instead of the exporter assuming proxy_mesh (#113
// 2-5). The 9c document is proxy_mesh-only and states accept_routes=false; a
// subnet_router keeps the stock Tailscale client, so the same field set with
// that purpose is refused by the exporter rather than rendered.
func TestMeshConfigPurposeReachesTheExporter(t *testing.T) {
	app, _, _, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := app.Now()
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("nas", mesh.PurposeSubnetRouter, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	input := subscription.MeshDeviceInput{
		DeviceID:   device.ID,
		Hostname:   device.NodeName,
		Purpose:    subscription.MeshPurpose(device.Purpose),
		ControlURL: handlertest.TestHeadscaleOrigin,
		AuthKey:    "hskey-auth-example-once",
	}
	if _, err = subscription.NewMeshConfigModel(input); err == nil ||
		!strings.Contains(err.Error(), subscription.CodeMeshPurposeUnsupported) {
		t.Fatalf("subnet_router reached the renderer as a proxy document: %v", err)
	}
	// The missing-purpose case is the fail-closed counterpart: a caller that
	// forgets the field cannot silently get the proxy_mesh document.
	input.Purpose = ""
	if _, err = subscription.ExportMeshDevice(input); err == nil ||
		!strings.Contains(err.Error(), subscription.CodeMeshPurposeUnsupported) {
		t.Fatalf("an input without a purpose rendered a document: %v", err)
	}
}

func TestMeshConfigRefusesMissingControlURLBeforeKeys(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, "")
	now := app.Now()
	subID := storetest.MeshSubscriberFixture(t, app.Store, now)
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("phone", mesh.PurposeProxyMesh, subID), now)
	if err != nil {
		t.Fatal(err)
	}
	fake.ResetCalls()
	w := b.Post("/mesh/config", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), meshh.CodeMeshEndpointControlURLUnavailable) {
		t.Fatalf("control URL refusal lost its code: %.400s", w.Body.String())
	}
	if fake.CallsOf("preauthkeys.create") != 0 {
		t.Fatalf("missing control URL minted a pre-auth key: %v", fake.Calls)
	}
}

func TestMeshConfigRefusesInactiveSubscriberBeforeKeys(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := app.Now()
	subID := storetest.MeshSubscriberFixture(t, app.Store, now)
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("phone", mesh.PurposeProxyMesh, subID), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Store.SetSubscriberState(subID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	fake.ResetCalls()
	w := b.Post("/mesh/config", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), meshh.CodeMeshEndpointSubscriberUnavailable) {
		t.Fatalf("subscriber refusal lost its code: %.400s", w.Body.String())
	}
	if fake.CallsOf("preauthkeys.create") != 0 {
		t.Fatalf("inactive subscriber minted a pre-auth key: %v", fake.Calls)
	}
}

func TestMeshConfigCompensatesBothKeysOnRenderFailure(t *testing.T) {
	app, _, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := app.Now()
	sub, _ := handlertest.MeshConvergedSubscriber(t, app, now)
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("phone", mesh.PurposeProxyMesh, sub.ID), now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.MeshDomainForTest().MeshConfigPreflight(device, now)
	if err != nil {
		t.Fatal(err)
	}
	// The plan was built from a valid Line. Corrupt only the immutable Lines
	// copy passed to the renderer, so the pure export fails after both keys
	// exist and the compensation path is exercised.
	plan.Lines = append([]subscription.Line(nil), plan.Lines...)
	plan.Lines[0].Server = "100.64.0.1"
	fake.ResetCalls()
	_, err = app.MeshDomainForTest().MeshConfig(context.Background(), plan, meshnet.User{ID: 1, Name: mesh.DefaultHeadscaleUser}, now)
	if err == nil || !strings.Contains(err.Error(), "EXPORT_MESH_LINE_IN_TAILNET") {
		t.Fatalf("render failure = %v", err)
	}
	if fake.CallsOf("preauthkeys.create") != 1 || fake.CallsOf("preauthkeys.expire") != 1 {
		t.Fatalf("compensation calls = %v", fake.Calls)
	}
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].State != mesh.KeyRevoked {
		t.Fatalf("Hub key was not revoked after render failure: %+v", keys)
	}
}

func TestMeshClaimBindsUnclaimedSameNameNodeExplicitly(t *testing.T) {
	app, b, fake, logs := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := app.Now()
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("phone", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	fake.Nodes = []meshnet.Node{{ID: 77, Name: device.NodeName, UserName: mesh.DefaultHeadscaleUser, Online: true}}
	if _, _, err = app.Store.IssueMeshEnrollmentKey(device.ID, app.Now()); err != nil {
		t.Fatalf("fixture key: %v", err)
	}

	page := b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, page, 200)
	if !strings.Contains(page.Body.String(), "待认领") || !strings.Contains(page.Body.String(), "77") {
		t.Fatalf("unclaimed same-name node was not offered: %.800s", page.Body.String())
	}
	// A plain page render must not claim anything.
	before, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Status != mesh.StatusPending || before.HeadscaleNodeID != 0 {
		t.Fatalf("page render changed the device: %+v", before)
	}

	w := b.Post("/mesh/claim", url.Values{"device_id": {device.ID}, "node_id": {"77"}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	after, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != mesh.StatusRegistered || after.HeadscaleNodeID != 77 {
		t.Fatalf("claim did not record the observation: %+v", after)
	}
	// Claim is the production path that proves registration, so it spends the
	// device's one-time key in the same transaction: the row is consumed and its
	// digest is gone, which is what makes the key one-time.
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].State != mesh.KeyConsumed || keys[0].ConsumedAt == 0 {
		t.Fatalf("claim left the key history %+v, want one consumed key", keys)
	}
	var digests int
	if err = app.Store.DB.QueryRow(`SELECT count(*) FROM mesh_enrollment_keys WHERE secret_hash IS NOT NULL`).Scan(&digests); err != nil {
		t.Fatal(err)
	}
	if digests != 0 {
		t.Fatalf("a spent key kept its digest: %d non-NULL digests", digests)
	}
	if !strings.Contains(logs.String(), "MESH_DEVICE_CLAIMED") {
		t.Fatal("claim audit event missing")
	}
	page = b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, page, 200)
	if strings.Contains(page.Body.String(), "待认领") {
		t.Fatal("claimed node is still offered as unclaimed")
	}
	// Repeating the same explicit claim is an idempotent success.
	w = b.Post("/mesh/claim", url.Values{"device_id": {device.ID}, "node_id": {"77"}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "无需再次认领") {
		t.Fatalf("repeat claim was not idempotent: %.300s", w.Body.String())
	}
}

func TestMeshClaimRefusesNodeNameMismatch(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := app.Now()
	device, err := app.Store.CreateMeshDevice(storetest.MeshSpec("phone", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	fake.Nodes = []meshnet.Node{{ID: 88, Name: "another-node", UserName: mesh.DefaultHeadscaleUser}}
	w := b.Post("/mesh/claim", url.Values{"device_id": {device.ID}, "node_id": {"88"}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), meshh.CodeMeshClaimNodeMismatch) {
		t.Fatalf("mismatch refusal lost its code: %.400s", w.Body.String())
	}
	after, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != mesh.StatusPending {
		t.Fatalf("mismatched claim changed the device: %+v", after)
	}
}
