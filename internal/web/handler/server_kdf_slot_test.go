package handler

// #113 3-2: the password-KDF slot covers only the three routes that hash a
// password (login, setup, password change). A publication gates kernels for
// minutes; while it runs, an unrelated node creation must not be refused.
//
// These tests hold each side open explicitly, so the property is observed
// rather than inferred from the routes' registration.

import (
	"context"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// blockingPublishVerifier holds the gate open until release is closed, so a
// test can observe what the Hub still accepts while a publication is in flight.
type blockingPublishVerifier struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingPublishVerifier() *blockingPublishVerifier {
	return &blockingPublishVerifier{entered: make(chan struct{}), release: make(chan struct{})}
}

func (v *blockingPublishVerifier) wait(ctx context.Context) (string, error) {
	v.once.Do(func() { close(v.entered) })
	select {
	case <-v.release:
		return "fixture kernel accepted the assembled document", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (v *blockingPublishVerifier) CheckSingBox(ctx context.Context, _ []byte) (string, error) {
	return v.wait(ctx)
}

func (v *blockingPublishVerifier) CheckMihomo(ctx context.Context, _ []byte) (string, error) {
	return v.wait(ctx)
}

// TestPublishDoesNotHoldThePasswordSlot pins the regression: a publication used
// to keep the global slot for its whole kernel gate, so a node creation in the
// same window answered 429 even though it hashes no password.
func TestPublishDoesNotHoldThePasswordSlot(t *testing.T) {
	app, _ := testApp(t)
	verifier := newBlockingPublishVerifier()
	app.publishGate = func() (store.PublishVerifier, error) { return verifier, nil }
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	seedPublishLine(t, app)
	activateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`)

	// The publication runs on its own browser value so neither goroutine writes
	// the other's cookie/CSRF fields; the copied cookie keeps the same session.
	cookie := *b.cookie
	publisher := &browser{app: app, cookie: &cookie, csrf: b.csrf}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- publisher.post("/policies/publish", url.Values{"publish": {`{"layer":"server","operation_id":"op-publish"}`}})
	}()
	<-verifier.entered

	// The slot itself is free: a publication must not be holding it while its
	// kernel gate waits.
	select {
	case app.kdfSlot <- struct{}{}:
		<-app.kdfSlot
	default:
		t.Fatal("a publication in its kernel gate still holds the password KDF slot")
	}
	// The gate is holding a kernel check, not the password slot: an unrelated
	// management POST must be accepted while it is blocked.
	requireStatus(t, b.post("/nodes", url.Values{"role": {"edge"}, "display_name": {"line-bg-01"}, "vless_port": {"8443"}, "ssh_port": {"2222"}}), 200)
	// The read side is equally unaffected.
	requireStatus(t, b.req("GET", "/api/nodes", nil, nil), 200)

	close(verifier.release)
	requireStatus(t, <-done, 200)
}

// TestPasswordSlotOnlyRefusesPasswordRoutes is the other half of the same
// boundary: while a password hash occupies the slot, login is refused with its
// own code and a retry hint, while a management POST that hashes nothing still
// succeeds.
func TestPasswordSlotOnlyRefusesPasswordRoutes(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	anon := &browser{app: app}
	requireStatus(t, anon.req("GET", "/login", nil, nil), 200)

	app.kdfSlot <- struct{}{}
	busy := anon.post("/login", url.Values{"password": {testPassword}})
	requireStatus(t, busy, 429)
	if !strings.Contains(busy.Body.String(), "AUTH_KDF_BUSY") {
		t.Fatalf("busy login code missing: %.300s", busy.Body.String())
	}
	if got := busy.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
	// A node creation is not a password operation, so the held slot does not
	// refuse it.
	requireStatus(t, b.post("/nodes", url.Values{"role": {"edge"}, "display_name": {"line-slot-01"}, "vless_port": {"8443"}, "ssh_port": {"2222"}}), 200)
	<-app.kdfSlot
	// Once released, the same login form works again.
	requireStatus(t, anon.post("/login", url.Values{"password": {testPassword}}), 303)
}
