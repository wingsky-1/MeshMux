package handler

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestMeshDeviceRowActions pins the Task 1 device-list UI contract (pure
// presentation, flow unchanged):
//
//   - every device renders one horizontal row carrying status dot, name,
//     purpose, online state, subnet-route summary and actions;
//   - the add-device form lives in a modal with name/purpose/subnet fields;
//   - the one-time enrollment key renders in its own dialog exactly once;
//   - a pending device without an observed Headscale node id renders its
//     approve control disabled instead of an actionable form;
//   - the remove/revoke control goes through a confirmation step.
func TestMeshDeviceRowActions(t *testing.T) {
	_, b, _, _ := meshTestApp(t)

	// Add-device modal with the three required fields, reusing the existing
	// create flow (no new endpoint).
	w := b.req("GET", "/mesh", nil, nil)
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
	page := b.req("GET", "/mesh", nil, nil)
	requireStatus(t, page, http.StatusOK)
	row := page.Body.String()
	if !strings.Contains(row, `data-device-id="`+router.ID+`"`) {
		t.Fatalf("device row missing data-device-id: %.600s", row)
	}
	for _, want := range []string{`status-dot`, "nas-row", "子网路由", "192.168.10.0/24"} {
		if !strings.Contains(row, want) {
			t.Fatalf("device row lost %q: %.800s", want, row)
		}
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
	if !strings.Contains(row, `id="mesh-remove-modal-`+router.ID+`"`) && !strings.Contains(row, "data-confirm") {
		t.Fatalf("remove control has no confirmation step: %.800s", row)
	}
	if !strings.Contains(row, `action="/mesh/revoke"`) {
		t.Fatalf("remove confirmation lost the existing revoke flow: %.800s", row)
	}

	// Key dialog appears exactly once in the create response and never again.
	created := b.post("/mesh", url.Values{
		"display_name": {"key-row"}, "purpose": {"mesh_only"},
		"platform": {"ios"}, "subscriber_id": {""},
	})
	requireStatus(t, created, http.StatusOK)
	disclosed := created.Body.String()
	if !strings.Contains(disclosed, `id="mesh-key-modal"`) {
		t.Fatalf("key one-time dialog missing: %.600s", disclosed)
	}
	match := meshKeyPattern.FindStringSubmatch(disclosed)
	if len(match) != 2 {
		t.Fatalf("key dialog did not disclose the one-time secret: %.600s", disclosed)
	}
	if got := strings.Count(disclosed, match[1]); got != 1 {
		t.Fatalf("one-time secret appears %d times, want 1", got)
	}
	again := b.req("GET", "/mesh", nil, nil)
	requireStatus(t, again, http.StatusOK)
	if strings.Contains(again.Body.String(), match[1]) {
		t.Fatal("one-time secret replayed on a later render")
	}
}
