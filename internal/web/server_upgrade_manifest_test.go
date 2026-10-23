package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"runtime"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// TestAgentManifestRequiresAuth pins that the read-only manifest channel is
// still a node-scoped agent surface: without a bearer identity it returns 401
// and never leaks the document.
func TestAgentManifestRequiresAuth(t *testing.T) {
	app, _ := testApp(t)
	w := bearerReq(app, "GET", "/api/agent/manifest", "", nil)
	requireStatus(t, w, http.StatusUnauthorized)
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("unauthenticated Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error_code"] != "AGENT_UNAUTHORIZED" {
		t.Fatalf("unauthenticated body = %q, want AGENT_UNAUTHORIZED", w.Body.String())
	}
}

// TestAgentManifestReturnsPinnedBytes pins the manifest-to-node channel: an
// authenticated agent receives exactly the canonical JSON of this build's
// pinned manifest (upgrade.ForArch), never a cached or caller-supplied version.
// An unknown agent path still falls through to 404, so the new route does not
// widen the agent surface.
func TestAgentManifestReturnsPinnedBytes(t *testing.T) {
	app, _ := testApp(t)
	created, code := createPendingNode(t, app, "edge", "manifest-line", 8443, 2222)
	pairing := pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, pairing, http.StatusOK)
	var paired struct {
		IdentityToken string `json:"identity_token"`
	}
	if err := json.Unmarshal(pairing.Body.Bytes(), &paired); err != nil || paired.IdentityToken == "" {
		t.Fatalf("pairing did not issue an identity: %.200s", pairing.Body.String())
	}

	w := bearerReq(app, "GET", "/api/agent/manifest", paired.IdentityToken, nil)
	requireStatus(t, w, http.StatusOK)
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("manifest bytes differ from the pinned document:\n got: %s\nwant: %s", w.Body.Bytes(), want)
	}

	if unknown := bearerReq(app, "GET", "/api/agent/manifests", paired.IdentityToken, nil); unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown agent path status=%d, want 404", unknown.Code)
	}
}
