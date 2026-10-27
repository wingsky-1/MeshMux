package handler

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
)

// meshRowSlice returns the article slice of one device row, so row assertions
// stay scoped to that device instead of matching the whole page.
func meshRowSlice(t *testing.T, body, deviceID string) string {
	t.Helper()
	start := strings.Index(body, `data-device-id="`+deviceID+`"`)
	if start < 0 {
		t.Fatalf("device row %s missing", deviceID)
	}
	tail := body[start:]
	end := strings.Index(tail, "</article>")
	if end < 0 {
		t.Fatalf("device row %s not closed", deviceID)
	}
	return tail[:end]
}

// TestMeshDeviceRowActions pins the Task 1 device-list UI contract (pure
// presentation, flow unchanged):
//
//   - every device renders one horizontal row carrying status dot, name,
//     purpose, online state, subnet-route summary and actions;
//   - the add-device form lives in a modal with name/purpose/subnet fields;
//   - the one-time enrollment key renders in its own disclosure block exactly
//     once, without dialog semantics;
//   - a pending device without an observed Headscale node id renders its
//     approve control disabled instead of an actionable form;
//   - the remove/revoke control goes through a confirmation step.
func TestMeshDeviceRowActions(t *testing.T) {
	_, b, _, _ := meshTestApp(t)

	// Add-device modal with the three required fields, reusing the existing
	// create flow (no new endpoint).
	w := b.Req("GET", "/mesh", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, `id="mesh-add-modal"`) {
		t.Fatalf("add-device modal missing: %.600s", body)
	}
	for _, field := range []string{`name="display_name"`, `name="purpose"`, `name="declared_prefixes"`} {
		if !strings.Contains(body, field) {
			t.Fatalf("add-device modal lost field %s: %.600s", field, body)
		}
	}

	// One pending subnet_router with no observed node: approval must be
	// present but greyed out, never an actionable approve form.
	router := meshCreateRouter(t, b, "nas-row", "192.168.10.0/24")
	page := b.Req("GET", "/mesh", nil, nil)
	requireStatus(t, page, http.StatusOK)
	row := meshRowSlice(t, page.Body.String(), router.ID)
	for _, want := range []string{"nas-row", "子网路由", "192.168.10.0/24"} {
		if !strings.Contains(row, want) {
			t.Fatalf("device row lost %q: %.800s", want, row)
		}
	}
	// C1: the status dot uses an independent tone class, never a badge class
	// (badge padding/min-height would stretch the 10px dot into an ellipse).
	if !strings.Contains(row, `class="status-dot"`) {
		t.Fatalf("device row lost its independent status dot: %.800s", row)
	}
	if strings.Contains(row, "status-dot badge") {
		t.Fatalf("status dot reuses a badge class: %.800s", row)
	}
	if !strings.Contains(row, "disabled") || !strings.Contains(row, "批准") {
		t.Fatalf("unobserved device must render a disabled approve control: %.800s", row)
	}
	if strings.Contains(row, `action="/mesh/routes/approve"`) {
		// The row for a device with no observed node must not offer an
		// actionable approve form; approval lives behind the confirm modal
		// once the node is observed.
		t.Fatalf("unobserved device offered an actionable approve form: %.800s", row)
	}

	// Remove/revoke goes through a confirmation step, still posting to the
	// existing revoke endpoint.
	if !strings.Contains(row, `id="mesh-remove-modal-`+router.ID+`"`) {
		t.Fatalf("remove control has no confirmation step: %.800s", row)
	}
	if !strings.Contains(row, `action="/mesh/revoke"`) {
		t.Fatalf("remove confirmation lost the existing revoke flow: %.800s", row)
	}
	if !strings.Contains(row, ">移除</a>") {
		t.Fatalf("row action must read 移除, not a bare 操作: %.800s", row)
	}

	// Key disclosure appears exactly once in the create response and never
	// again; it is a plain section, not a dialog.
	created := b.Post("/mesh", url.Values{
		"display_name": {"key-row"}, "purpose": {"mesh_only"},
		"platform": {"ios"}, "subscriber_id": {""},
	})
	requireStatus(t, created, http.StatusOK)
	disclosed := created.Body.String()
	if !strings.Contains(disclosed, `id="mesh-key-modal"`) {
		t.Fatalf("key one-time disclosure missing: %.600s", disclosed)
	}
	match := meshKeyPattern.FindStringSubmatch(disclosed)
	if len(match) != 2 {
		t.Fatalf("key disclosure did not show the one-time secret: %.600s", disclosed)
	}
	if got := strings.Count(disclosed, match[1]); got != 1 {
		t.Fatalf("one-time secret appears %d times, want 1", got)
	}
	again := b.Req("GET", "/mesh", nil, nil)
	requireStatus(t, again, http.StatusOK)
	if strings.Contains(again.Body.String(), match[1]) {
		t.Fatal("one-time secret replayed on a later render")
	}
}

// TestMeshApproveModalRendersForObservedDevice covers the approval confirm
// dialog: once a node is observed, the page renders one top-level
// #mesh-approve-modal-{id}-{i} carrying the existing approve flow (action plus
// device and prefix hidden fields) behind a 确认批准 submit.
func TestMeshApproveModalRendersForObservedDevice(t *testing.T) {
	app, b, fake, _ := meshTestApp(t)
	router := meshCreateRouter(t, b, "nas-approve", "192.168.20.0/24")
	if _, err := app.Store.RecordMeshObservation(router.ID, 7, app.Now()); err != nil {
		t.Fatal(err)
	}
	fake.nodes = []meshnet.Node{{
		ID: 7, Name: router.NodeName,
		AvailableRoutes: []string{"192.168.20.0/24"},
	}}

	w := b.Req("GET", "/mesh", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	modalID := `id="mesh-approve-modal-` + router.ID + `-0"`
	at := strings.Index(body, modalID)
	if at < 0 {
		t.Fatalf("approve confirm modal missing: %.800s", body)
	}
	// The dialog lives at page top level (outside the device article), so it
	// never inherits the route table's white-space:nowrap.
	rowEnd := strings.Index(body, "</article>")
	if rowEnd < 0 || at < rowEnd {
		t.Fatal("approve confirm modal must render outside the device article")
	}
	dlg := body[at:]
	if next := strings.Index(dlg, "</form>"); next > 0 {
		dlg = dlg[:next]
	}
	for _, want := range []string{
		`action="/mesh/routes/approve"`,
		`name="device_id" value="` + router.ID + `"`,
		`name="prefix" value="192.168.20.0/24"`,
		"确认批准",
	} {
		if !strings.Contains(dlg, want) {
			t.Fatalf("approve confirm modal lost %q: %.800s", want, dlg)
		}
	}
	if !strings.Contains(body, `href="#mesh-approve-modal-`+router.ID+`-0"`) {
		t.Fatal("row lost its approve confirm trigger link")
	}
}
