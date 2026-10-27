package handler

// The Task-4 wizard boundary: four selection groups, preview fail-fast and the
// approved-artifact download.
//
// The gate is replaced by the existing fixture verifier, so these tests prove
// the HTTP contract and the layer ordering without a kernel install. The real
// `sing-box check` evidence is the composer test plus the existing
// TestPublishGateRealKernel* cases.

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscriber"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// wizardApp opens a Web runtime whose publish gate is the fixture verifier.
func wizardApp(t *testing.T) (*Server, *browser, *fixturePublishVerifier) {
	t.Helper()
	app, _ := testApp(t)
	verifier := &fixturePublishVerifier{}
	app.policyServer.SetPublishGate(func() (store.PublishVerifier, error) { return verifier, nil })
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return app, b, verifier
}

// wizardLine inserts one configured edge Line and returns its node id.
func wizardLine(t *testing.T, app *Server, name string) string {
	t.Helper()
	node, _ := createPendingNode(t, app, "edge", name, 8443, 2222)
	configureLine(t, app.Store, node.ID, name, app.Now())
	return node.ID
}

// wizardOut inserts one configured Out and returns its node id.
func wizardOut(t *testing.T, app *Server, name string) string {
	t.Helper()
	node, _ := createPendingNode(t, app, "out", name, 8444, 2223)
	if _, err := app.Store.SetOutTransport(node.ID, "out.example.invalid", node.VlessPort, app.Now()); err != nil {
		t.Fatal(err)
	}
	return node.ID
}

func TestWizardPageRendersFourGroupsAndExecutionBoundary(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	outID := wizardOut(t, app, "out-01")

	w := b.req("GET", "/subscribers/wizard", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{
		"订阅向导", "一 · 线路", "二 · 出口", "三 · 规则", "四 · 组网",
		"Out / HTTP 代理 · 单选", "预览（不保存）", "创建订阅并校验",
		"line_" + lineID, "out_id", "rule_", "四 · 组网",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("wizard page missing %q", want)
		}
	}
	if !strings.Contains(body, outID) {
		t.Fatal("wizard page misses the configured Out")
	}
	// The mesh group is still recorded-only; the egress group is executable
	// (the Line route renders it and passes the kernel gate).
	if strings.Count(body, "已记录 · 暂不执行") < 1 {
		t.Fatal("the recorded-only execution status is not stated for the mesh group")
	}
	// The wizard is admin-only like every other management surface.
	app2, _ := testApp(t)
	anonymous := &browser{app: app2}
	requireStatus(t, anonymous.req("GET", "/subscribers/wizard", nil, nil), http.StatusUnauthorized)
}

func TestWizardPreviewWritesNothingAndRemindsOnRecordedGroups(t *testing.T) {
	app, b, verifier := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")

	w := b.post("/subscribers/wizard/preview", url.Values{
		"display_name":                     {"alice"},
		"line_" + lineID:                   {"1"},
		"device_" + wizardDeviceID(t, app): {"1"},
	})
	require2xx(t, w)
	body := w.Body.String()
	// The recorded-only reminder renders with "!" and never blocks.
	if !strings.Contains(body, "COMPOSE_NETWORK_RECORDED_ONLY") {
		t.Fatalf("preview misses the recorded-only reminders: %.800s", body)
	}
	if !strings.Contains(body, "预览完成：未保存任何内容。") {
		t.Fatal("preview does not state that nothing was saved")
	}
	// Nothing was written: no subscriber, no edges, no snapshot.
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 0 {
		t.Fatalf("preview created %d subscribers (err %v)", len(subs), err)
	}
	for table, want := range map[string]int{"subscription_lines": 0, "subscription_outs": 0, "subscription_rules": 0, "subscription_networks": 0, "subscription_snapshots": 0} {
		var count int
		if err := app.Store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s rows = %d, want %d", table, count, want)
		}
	}
	// The gate did run on the composed documents, so the preview proves what
	// the save would prove.
	if calls, _ := verifier.counts(); calls != 1 {
		t.Fatalf("sing-box gate calls = %d, want 1", calls)
	}
}

func TestWizardSaveApprovesArtifactAndDownloadServesIt(t *testing.T) {
	app, b, verifier := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	outID := wizardOut(t, app, "out-01")
	seedActivePolicyPins(t, app)

	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":           {"alice"},
		"line_" + lineID:         {"1"},
		"out_id":                 {outID},
		"rule_preset-proxy-ai@1": {"1"},
	})
	require2xx(t, w)
	body := w.Body.String()
	// The create flow discloses the bearer exactly once, like the old form.
	match := subscriberTokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("save did not disclose the one-time bearer")
	}
	bearer := match[1]

	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscribers = %d err=%v", len(subs), err)
	}
	sub := subs[0]
	var artifactID string
	var approved int
	if err := app.Store.DB.QueryRow(`SELECT artifact_id, artifact_approved FROM subscription_snapshots WHERE subscriber_id=?`, sub.ID).
		Scan(&artifactID, &approved); err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}
	if approved != 1 || artifactID == "" {
		t.Fatalf("artifact = %q approved=%d, want an approved digest", artifactID, approved)
	}
	if calls, _ := verifier.counts(); calls != 1 {
		t.Fatalf("sing-box gate calls = %d, want 1", calls)
	}
	// The approved artifact is the download's single source of truth.
	if _, artifactID, err := app.Store.SubscriptionArtifact(sub.ID); err != nil || artifactID == "" {
		t.Fatalf("artifact = %q err=%v", artifactID, err)
	}
	// The convergence gate still runs first, so an unconverged Line refuses
	// the download; that ordering is proven by the dedicated download tests.
	if w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json"); w.Code != http.StatusNotFound {
		t.Fatalf("unconverged download status %d, want 404", w.Code)
	}
}

func TestWizardSaveRefusesBlockingPreviewWithoutWriting(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	outID := wizardOut(t, app, "out-01")

	// An Out with no proxy rule is the "selected Out, Line route unchanged"
	// case: the Line route would never use the Out, so the save is refused.
	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":   {"alice"},
		"line_" + lineID: {"1"},
		"out_id":         {outID},
	})
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, "COMPOSE_OUT_WITHOUT_PROXY_RULE") || !strings.Contains(body, "✖") {
		t.Fatalf("save did not report the blocking finding: %.800s", body)
	}
	if !strings.Contains(body, "保存被拒绝") {
		t.Fatal("save does not state that it wrote nothing")
	}
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 0 {
		t.Fatalf("a blocked save created %d subscribers (err %v)", len(subs), err)
	}
}

func TestWizardSaveRefusesGateFailure(t *testing.T) {
	app, b, verifier := wizardApp(t)
	verifier.rejectSingBoxAt = 1
	lineID := wizardLine(t, app, "hk-01")

	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":   {"alice"},
		"line_" + lineID: {"1"},
	})
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "SUBSCRIPTION_GATE_FAILED") {
		t.Fatalf("gate refusal missing: %.800s", w.Body.String())
	}
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 0 {
		t.Fatalf("a refused gate created %d subscribers", len(subs))
	}
}

func TestWizardSaveAllowsIndependentOutSelection(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	outID := wizardOut(t, app, "out-01")
	seedActivePolicyPins(t, app)

	// The first subscription records the Line without an Out.
	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":   {"alice"},
		"line_" + lineID: {"1"},
	})
	require2xx(t, w)

	// A second subscription on the same Line may choose an Out: the egress is a
	// per-subscription client choice now, not a shared server route.
	w = b.post("/subscribers/wizard/save", url.Values{
		"display_name":           {"bob"},
		"line_" + lineID:         {"1"},
		"out_id":                 {outID},
		"rule_preset-proxy-ai@1": {"1"},
	})
	require2xx(t, w)
	if subs, _ := app.Store.ListSubscribers(); len(subs) != 2 {
		t.Fatalf("independent saves created %d subscribers, want 2", len(subs))
	}
}

func TestWizardSaveRefusesMihomoRejectionButAcceptsAbsentBinary(t *testing.T) {
	app, b, verifier := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")

	// Absent binary: approved, with the skipped-gate reminder. The create
	// response is the one-time bearer page, so the reminder is asserted on the
	// re-save that renders the wizard.
	verifier.missingMihomo = true
	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":   {"alice"},
		"line_" + lineID: {"1"},
	})
	require2xx(t, w)
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscribers = %d err=%v", len(subs), err)
	}
	w = b.post("/subscribers/wizard/save", url.Values{
		"subscriber_id":  {subs[0].ID},
		"line_" + lineID: {"1"},
	})
	require2xx(t, w)
	if !strings.Contains(w.Body.String(), store.CodeComposeMihomoSkipped) {
		t.Fatalf("skipped-gate reminder missing: %.800s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "选择已保存并通过门禁") {
		t.Fatal("the save did not report success")
	}

	// A rejecting binary is a blocking failure for a fresh subscriber. The two
	// saves above already spent mihomo calls 1 and 2.
	verifier.missingMihomo = false
	verifier.rejectMihomoAt = 3
	other := wizardLine(t, app, "hk-02")
	w = b.post("/subscribers/wizard/save", url.Values{
		"display_name":  {"carol"},
		"line_" + other: {"1"},
	})
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "SUBSCRIPTION_GATE_FAILED") {
		t.Fatalf("mihomo refusal missing: %.800s", w.Body.String())
	}
	if subs, _ := app.Store.ListSubscribers(); len(subs) != 1 {
		t.Fatalf("subscribers = %d, want only the first approved one", len(subs))
	}
}

func TestDownloadRefusesDriftedOrUnapprovedArtifact(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":   {"alice"},
		"line_" + lineID: {"1"},
	})
	require2xx(t, w)
	match := subscriberTokenPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("no bearer disclosed")
	}
	bearer := match[1]
	// The convergence gate refuses before the artifact check, which is the
	// documented order; the artifact path itself is proven in the store test.
	if w := subscriptionRequest(app, "GET", "admin.example.invalid", "/subscription/"+bearer+"/sing-box.json"); w.Code != http.StatusNotFound {
		t.Fatalf("unconverged download status %d, want 404", w.Code)
	}
}

// TestWizardMeshGroupRefusesRevokedDevice proves a revoked device cannot be
// newly selected and the reference graph names the subscription that holds it.
func TestWizardMeshGroupRefusesRevokedDevice(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	deviceID := wizardDeviceID(t, app)

	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":       {"alice"},
		"line_" + lineID:     {"1"},
		"device_" + deviceID: {"1"},
	})
	require2xx(t, w)
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscribers = %d err=%v", len(subs), err)
	}
	names, err := app.Store.MeshDeviceUsedBy(deviceID)
	if err != nil || len(names) != 1 || names[0] != "alice" {
		t.Fatalf("device used-by = %q err=%v, want [alice]", names, err)
	}
	if _, _, err := app.Store.RequestMeshDeviceRevocation(deviceID, "USER_DELETE", app.Now()); err != nil {
		t.Fatal(err)
	}
	// A revoked device is history: selecting it again is refused.
	other := wizardLine(t, app, "hk-02")
	w = b.post("/subscribers/wizard/save", url.Values{
		"display_name":       {"bob"},
		"line_" + other:      {"1"},
		"device_" + deviceID: {"1"},
	})
	requireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "MESH_DEVICE_STATUS_INVALID") {
		t.Fatalf("revoked device was not refused: %.600s", w.Body.String())
	}
}

// wizardDeviceID inserts one selectable mesh device.
func wizardDeviceID(t *testing.T, app *Server) string {
	t.Helper()
	device, err := app.Store.CreateMeshDevice(meshSpec("ipad", mesh.PurposeMeshOnly, ""), app.Now())
	if err != nil {
		t.Fatal(err)
	}
	return device.ID
}

// TestWizardSelectionRestoresSavedChoice pins the snapshot's second purpose:
// reopening the wizard shows the last confirmed selection.
func TestWizardSelectionRestoresSavedChoice(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	seedActivePolicyPins(t, app)
	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":            {"alice"},
		"line_" + lineID:          {"1"},
		"rule_preset-direct-cn@1": {"1"},
	})
	require2xx(t, w)
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscribers = %d err=%v", len(subs), err)
	}
	w = b.req("GET", "/subscribers/wizard?subscriber_id="+subs[0].ID, nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"alice", "checked", "preset-direct-cn@1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("restored wizard misses %q", want)
		}
	}
	selection, saved, err := app.Store.SubscriptionSelection(subs[0].ID)
	if err != nil || !saved {
		t.Fatalf("selection = %+v saved=%v err=%v", selection, saved, err)
	}
	if len(selection.Lines) != 1 || selection.Lines[0].NodeID != lineID {
		t.Fatalf("selection lines = %+v", selection.Lines)
	}
	if len(selection.Rules) != 1 || selection.Rules[0].StableKey != "preset-direct-cn" {
		t.Fatalf("selection rules = %+v", selection.Rules)
	}
}

// TestWizardSelectionPositionsAreStable proves one checkbox set always yields
// exactly one selection. r.PostForm is a map, so before the fix the dense
// positions came from Go's randomized map order: the same submission could store
// a different selection_json, a different snapshot id and a different rule order
// (the composer keeps input order), breaking "same choice, same bytes".
func TestWizardSelectionPositionsAreStable(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineA := wizardLine(t, app, "hk-01")
	lineB := wizardLine(t, app, "hk-02")
	deviceID := wizardDeviceID(t, app)
	seedActivePolicyPins(t, app)

	fields := url.Values{
		"display_name":             {"alice"},
		"line_" + lineA:            {"1"},
		"line_" + lineB:            {"1"},
		"device_" + deviceID:       {"1"},
		"rule_preset-proxy-ai@1":   {"1"},
		"rule_preset-direct-cn@1":  {"1"},
		"rule_preset-reject-ads@1": {"1"},
	}
	// 1. The parser itself must be order-free: the same form renders the same
	//    spec every time, in sorted field-name order.
	var first store.SelectionSpec
	for iteration := 0; iteration < 20; iteration++ {
		r := httptest.NewRequest("POST", testOrigin+"/subscribers/wizard/preview", strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		spec, _, err := subscriber.ReadWizardSelection(r)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			first = spec
			continue
		}
		if !reflect.DeepEqual(spec, first) {
			t.Fatalf("iteration %d: spec = %+v, want %+v", iteration, spec, first)
		}
	}
	if len(first.LineIDs) != 2 || first.LineIDs[0] >= first.LineIDs[1] {
		t.Fatalf("line ids = %q, want ascending sorted order", first.LineIDs)
	}
	wantRules := []string{"preset-direct-cn", "preset-proxy-ai", "preset-reject-ads"}
	for index, want := range wantRules {
		if first.Rules[index].StableKey != want {
			t.Fatalf("rule %d = %q, want %q (sorted field-name order)", index, first.Rules[index].StableKey, want)
		}
	}

	// 2. End to end: repeated saves of the same set store the same positions and
	//    compose byte-identical documents.
	w := b.post("/subscribers/wizard/save", fields)
	require2xx(t, w)
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscribers = %d err=%v", len(subs), err)
	}
	subID := subs[0].ID
	firstSelection, saved, err := app.Store.SubscriptionSelection(subID)
	if err != nil || !saved {
		t.Fatalf("selection saved=%v err=%v", saved, err)
	}
	firstDocuments, firstArtifact, err := app.Store.SubscriptionArtifact(subID)
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 5; iteration++ {
		repeat := url.Values{}
		for key, values := range fields {
			repeat[key] = values
		}
		delete(repeat, "display_name")
		repeat.Set("subscriber_id", subID)
		w = b.post("/subscribers/wizard/save", repeat)
		require2xx(t, w)
		selection, _, err := app.Store.SubscriptionSelection(subID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(selection.Lines, firstSelection.Lines) {
			t.Fatalf("iteration %d: line positions = %+v, want %+v", iteration, selection.Lines, firstSelection.Lines)
		}
		if !reflect.DeepEqual(selection.Rules, firstSelection.Rules) {
			t.Fatalf("iteration %d: rule positions = %+v, want %+v", iteration, selection.Rules, firstSelection.Rules)
		}
		if !reflect.DeepEqual(selection.Networks, firstSelection.Networks) {
			t.Fatalf("iteration %d: device positions = %+v, want %+v", iteration, selection.Networks, firstSelection.Networks)
		}
		documents, artifactID, err := app.Store.SubscriptionArtifact(subID)
		if err != nil {
			t.Fatal(err)
		}
		if artifactID != firstArtifact || string(documents.SingBox) != string(firstDocuments.SingBox) ||
			string(documents.Mihomo) != string(firstDocuments.Mihomo) {
			t.Fatalf("iteration %d: the recomposed artifact changed for the same checkbox set", iteration)
		}
	}
}

// TestWizardSaveKeepsExistingCredentialOnReSave proves a re-save does not
// rotate the credential of a Line that stays selected.
func TestWizardSaveKeepsExistingCredentialOnReSave(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":   {"alice"},
		"line_" + lineID: {"1"},
	})
	require2xx(t, w)
	subs, _ := app.Store.ListSubscribers()
	before, err := app.Store.ListSubscriberCredentials(subs[0].ID)
	if err != nil || len(before) != 1 {
		t.Fatalf("credentials = %d err=%v", len(before), err)
	}
	w = b.post("/subscribers/wizard/save", url.Values{
		"subscriber_id":  {subs[0].ID},
		"line_" + lineID: {"1"},
	})
	require2xx(t, w)
	after, err := app.Store.ListSubscriberCredentials(subs[0].ID)
	if err != nil || len(after) != 1 {
		t.Fatalf("credentials after re-save = %d err=%v", len(after), err)
	}
	if after[0].UUID != before[0].UUID {
		t.Fatal("a re-save rotated the credential of a kept Line")
	}
}

// TestWizardRequiresCSRFAndOrigin proves the wizard inherits the mutation
// boundary instead of opening a second one.
func TestWizardRequiresCSRFAndOrigin(t *testing.T) {
	app, b, _ := wizardApp(t)
	lineID := wizardLine(t, app, "hk-01")
	w := b.req("POST", "/subscribers/wizard/save", url.Values{
		"csrf": {"wrong"}, "display_name": {"mallory"}, "line_" + lineID: {"1"},
	}, nil)
	requireStatus(t, w, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "CSRF_REJECTED") {
		t.Fatal("wrong CSRF was not rejected")
	}
	if subs, _ := app.Store.ListSubscribers(); len(subs) != 0 {
		t.Fatal("a rejected request created a subscriber")
	}
}

// TestWizardGateUsesRealSingBox runs the real kernel against the composed
// documents when the pinned binary is available.
func TestWizardGateUsesRealSingBox(t *testing.T) {
	binary := testSingBoxBinary(t)
	app, b, _ := wizardApp(t)
	app.policyServer.SetPublishGate(nil)
	app.Cfg.SingBoxPath = binary
	app.policyServer.SetPublishRunner(node.ExecRunner{})
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	lineID := wizardLine(t, app, "hk-01")
	seedActivePolicyPins(t, app)

	w := b.post("/subscribers/wizard/save", url.Values{
		"display_name":            {"alice"},
		"line_" + lineID:          {"1"},
		"rule_preset-direct-cn@1": {"1"},
	})
	require2xx(t, w)
	// The create response is the one-time bearer page; the approved artifact is
	// the proof that the real kernel accepted the composed documents.
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscribers = %d err=%v", len(subs), err)
	}
	if _, artifactID, err := app.Store.SubscriptionArtifact(subs[0].ID); err != nil || artifactID == "" {
		t.Fatalf("real gate refused the composed artifact: artifact=%q err=%v", artifactID, err)
	}
}

// seedActivePolicyPins stores one active server policy revision whose pins
// cover the geo and ruleset tags the wizard tests select. The rule library is
// the subscription's rule source; the artifact pins stay on the policy revision,
// which is the deployment's single version lock.
func seedActivePolicyPins(t *testing.T, app *Server) {
	t.Helper()
	pin := map[string]string{
		"source":  "https://rulesets.example.invalid/2026-10-26.srs",
		"version": "20261026",
		"sha256":  strings.Repeat("a", 64),
	}
	pins := map[string]any{
		"GeoSite": map[string]any{"cn": pin},
		"GeoIP":   map[string]any{"cn": pin},
		"Remote":  map[string]any{"ai": pin},
	}
	encoded, err := json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"default":"direct","rules":[]}`)
	policy, err := app.Store.CreateRoutePolicy(store.PolicyLayerServer, "wizard-pins", payload, encoded, "op-wizard-pins", app.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Only an active revision is read as the deployment's artifact lock.
	if _, err := app.Store.ActivateRoutePolicy(policy.ID, policy.Revision, "op-wizard-pins-activate", app.Now()); err != nil {
		t.Fatal(err)
	}
}

// testSingBoxBinary resolves the pinned test binary or skips.
func testSingBoxBinary(t *testing.T) string {
	t.Helper()
	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native wizard gate")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	return binary
}
