package client

// Tests of the stamped-target read of the restricted executor (#11c-1 Task 6).
// The path is fixed, the operation id is validated before any request, a 404 is
// the ordinary "no target" answer of a config chain, and a body that is not
// exactly two pinned fields is refused rather than handed to a subprocess.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func stageTargetHub(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	hub, config := newTestHub(t)
	hub.unknown = handler
	return newTestClient(t, hub, config, validIdentity(config))
}

// TestStageTargetReadsPinnedStamp pins the happy path: the client asks its own
// fixed path with its bearer identity and returns the two validated fields.
func TestStageTargetReadsPinnedStamp(t *testing.T) {
	operationID := strings.Repeat("a", 32)
	var gotPath, gotAuth string
	client := stageTargetHub(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		writeRawJSON(t, w, http.StatusOK,
			`{"target_version":"1.0.1","manifest_sha256":"`+strings.Repeat("b", 64)+`"}`)
	})
	target, ok, err := client.StageTarget(context.Background(), operationID)
	if err != nil || !ok {
		t.Fatalf("StageTarget = %+v, %v, %v", target, ok, err)
	}
	if target.Version != "1.0.1" || target.ManifestSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("target = %+v", target)
	}
	if gotPath != agentUpgradeTargetPrefix+operationID {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer "+testIdentity {
		t.Fatalf("auth = %q", gotAuth)
	}
}

// TestStageTargetNotFoundIsNoUpgrade pins that a normal config chain is not
// failed by this read: 404 is (false, nil), not an error.
func TestStageTargetNotFoundIsNoUpgrade(t *testing.T) {
	client := stageTargetHub(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]string{"error_code": "UPGRADE_TARGET_NOT_FOUND", "operation_id": strings.Repeat("c", 22)})
	})
	target, ok, err := client.StageTarget(context.Background(), strings.Repeat("a", 32))
	if err != nil || ok || target != (StageTarget{}) {
		t.Fatalf("StageTarget = %+v, %v, %v, want the zero target and no error", target, ok, err)
	}
}

// TestStageTargetValidatesBeforeRequest pins the local operation-id gate and
// the relaxed response contract: a malformed operation id never reaches the
// Hub, while an extra Hub field is ignored as long as the two pinned fields are
// present.
func TestStageTargetValidatesBeforeRequest(t *testing.T) {
	called := false
	client := stageTargetHub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeRawJSON(t, w, http.StatusOK, `{"target_version":"1.0.1","manifest_sha256":"`+strings.Repeat("b", 64)+`","extra":true}`)
	})
	for _, id := range []string{"", "not-hex", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)} {
		if _, ok, err := client.StageTarget(context.Background(), id); err == nil || ok {
			t.Fatalf("operation id %q was accepted: %v", id, err)
		}
	}
	if called {
		t.Fatal("a malformed operation id reached the Hub")
	}
	// The exact-id call is allowed, and an extra Hub field is ignored.
	target, ok, err := client.StageTarget(context.Background(), strings.Repeat("a", 32))
	if err != nil || !ok || target.Version != "1.0.1" {
		t.Fatalf("an over-specified body was refused: %+v, %v, %v", target, ok, err)
	}
	// A non-SemVer version and a short digest are refused as well.
	for _, body := range []string{
		`{"target_version":"latest","manifest_sha256":"` + strings.Repeat("b", 64) + `"}`,
		`{"target_version":"1.0.1","manifest_sha256":"deadbeef"}`,
	} {
		bad := stageTargetHub(t, func(w http.ResponseWriter, r *http.Request) {
			writeRawJSON(t, w, http.StatusOK, body)
		})
		if _, ok, err := bad.StageTarget(context.Background(), strings.Repeat("a", 32)); err == nil || ok {
			t.Fatalf("body %s was accepted: %v", body, err)
		}
	}
}
