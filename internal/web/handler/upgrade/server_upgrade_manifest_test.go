package upgrade_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
)

// TestAgentManifestRequiresAuth pins that the read-only manifest channel is
// still a node-scoped agent surface: without a bearer identity it returns 401
// and never leaks the document.
func TestAgentManifestRequiresAuth(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	w := handlertest.BearerReq(app, "GET", "/api/agent/manifest", "", nil)
	handlertest.RequireStatus(t, w, http.StatusUnauthorized)
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("unauthenticated Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error_code"] != "AGENT_UNAUTHORIZED" {
		t.Fatalf("unauthenticated body = %q, want AGENT_UNAUTHORIZED", w.Body.String())
	}
}

// TestAgentManifestReturnsPinnedBytes pins the manifest-to-node channel: an
// authenticated agent receives the dual-arch set of this build (U4), and each
// embedded architecture table is byte-identical to upgrade.ForArch(arch), the
// document the approval pins. An unknown agent path still falls through to 404,
// so the new route does not widen the agent surface.
func TestAgentManifestReturnsPinnedBytes(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	created, code := handlertest.CreatePendingNode(t, app, "edge", "manifest-line", 8443, 2222)
	pairing := handlertest.PairJSON(t, app, created.ID, "edge", code)
	handlertest.RequireStatus(t, pairing, http.StatusOK)
	var paired struct {
		IdentityToken string `json:"identity_token"`
	}
	if err := json.Unmarshal(pairing.Body.Bytes(), &paired); err != nil || paired.IdentityToken == "" {
		t.Fatalf("pairing did not issue an identity: %.200s", pairing.Body.String())
	}

	w := handlertest.BearerReq(app, "GET", "/api/agent/manifest", paired.IdentityToken, nil)
	handlertest.RequireStatus(t, w, http.StatusOK)
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	// Read the served envelope without re-encoding it: the projection bytes must
	// be exactly what a per-arch manifest pin covers.
	var envelope struct {
		Schema    string                     `json:"schema"`
		Manifests map[string]json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("manifest set: %v", err)
	}
	if envelope.Schema != upgrade.SetSchema || len(envelope.Manifests) != 2 {
		t.Fatalf("served set header = %q with %d tables, want %q with both", envelope.Schema, len(envelope.Manifests), upgrade.SetSchema)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		manifest, err := upgrade.ForArch(arch)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(envelope.Manifests[arch], want) {
			t.Fatalf("%s projection bytes differ from the pinned document:\n got: %s\nwant: %s", arch, envelope.Manifests[arch], want)
		}
	}
	// The whole body is the Hub build's own valid set, not two loose documents.
	var set upgrade.ManifestSet
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("served set is not this build's pinned release: %v", err)
	}

	if unknown := handlertest.BearerReq(app, "GET", "/api/agent/manifests", paired.IdentityToken, nil); unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown agent path status=%d, want 404", unknown.Code)
	}
}
