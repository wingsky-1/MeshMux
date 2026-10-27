package handler

// HTTP tests for POST /policies/publish. The endpoint is authenticated, CSRF
// protected and form-wrapped like every other management POST; the tests prove
// the receipt shape, the refusal status classes and the "nothing stored" rule.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

// publishApp builds an authenticated browser and installs the fixture gate.
func publishApp(t *testing.T) (*browser, *fixturePublishVerifier) {
	t.Helper()
	app, _ := testApp(t)
	verifier := &fixturePublishVerifier{}
	app.policyServer.SetPublishGate(func() (store.PublishVerifier, error) { return verifier, nil })
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return b, verifier
}

func postPublish(t *testing.T, b *browser, body string) *httptest.ResponseRecorder {
	t.Helper()
	return b.post("/policies/publish", url.Values{"publish": {body}})
}

func publishReceipt(t *testing.T, w *httptest.ResponseRecorder, status int) store.PolicyPublishReceipt {
	t.Helper()
	requireStatus(t, w, status)
	var receipt store.PolicyPublishReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("receipt: %v %.400s", err, w.Body.String())
	}
	if receipt.OperationID == "" {
		t.Fatal("receipt has no operation id")
	}
	return receipt
}

// seedPublishLine stores one Line with transport and a paired identity in the
// running app's store, so a publication has a real target.
func seedPublishLine(t *testing.T, app *Server) string {
	t.Helper()
	now := app.Now()
	line := pairedStoreNode(t, app.Store, "edge", now)
	settings := testLine(line, "line-a")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.Store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	markLineOnline(t, app.Store, line, now)
	if _, _, err := app.Store.CreateSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	seedInitialChain(t, app.Store, line, now)
	confirmChain(t, app.Store, line, now)
	return line
}

// activateViaAPI creates and activates one server policy through the write
// endpoint, so the publish test exercises the same rows an operator would
// produce. The client layer has been read-only since Task 6, so a client call
// seeds a legacy revision directly: that is the only way such a row can exist
// after the upgrade, and it keeps the preview path under test.
func activateViaAPI(t *testing.T, b *browser, layer, payload string) {
	t.Helper()
	if layer == "client" {
		seedLegacyClientPolicy(t, b, payload)
		return
	}
	created := policyReceipt(t, postPolicy(t, b, "/policies",
		fmt.Sprintf(`{"layer":%q,"name":"策略-%s","payload":%s,"operation_id":"op-create"}`, layer, layer, payload)), http.StatusCreated)
	policyReceipt(t, postPolicy(t, b, "/policies/activate",
		fmt.Sprintf(`{"id":%q,"revision":1,"operation_id":"op-activate"}`, created.ID)), http.StatusOK)
}

func TestPublishEndpointGatesServerPolicy(t *testing.T) {
	b, verifier := publishApp(t)
	seedPublishLine(t, b.app)
	activateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`)

	receipt := publishReceipt(t, postPublish(t, b, `{"layer":"server","operation_id":"op-publish"}`), http.StatusOK)
	if !receipt.OK || receipt.Status != "gated" {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.PolicySchema != 8 {
		t.Fatalf("policy_schema = %d, want 8", receipt.PolicySchema)
	}
	if got := receipt.RoutePolicyRevisions; len(got) != 1 || got["server"] != 1 {
		t.Fatalf("route_policy_revisions = %v", got)
	}
	if receipt.EgressState != policy.AIEgressLine {
		t.Fatalf("egress_state = %q, want line", receipt.EgressState)
	}
	// The server layer is a validated record only: no candidate and no Line
	// evidence may be invented for it.
	if receipt.Candidate != nil || len(receipt.Lines) != 0 {
		t.Fatalf("server-only publication invented a candidate: %+v", receipt)
	}
	if len(receipt.Checks) != 0 {
		t.Fatalf("server-only publication ran kernel gates: %+v", receipt.Checks)
	}
	if singBox, mihomo := verifier.counts(); singBox != 0 || mihomo != 0 {
		t.Fatalf("server-only gate calls = %d/%d, want 0/0", singBox, mihomo)
	}
}

func TestPublishEndpointRefusals(t *testing.T) {
	b, _ := publishApp(t)
	seedPublishLine(t, b.app)

	// No active policy for the requested layer.
	refusal := publishReceipt(t, postPublish(t, b, `{"layer":"server","operation_id":"op-publish"}`), http.StatusNotFound)
	if refusal.ErrorCode != store.CodePublishNoPolicy || refusal.OK || refusal.PolicySchema != 8 {
		t.Fatalf("missing policy refusal = %+v", refusal)
	}
	// A missing operation id never reaches a row.
	if got := publishReceipt(t, postPublish(t, b, `{"layer":"server"}`), http.StatusBadRequest); got.ErrorCode != "POLICY_OPERATION_REQUIRED" {
		t.Fatalf("missing operation id = %+v", got)
	}
	if got := publishReceipt(t, postPublish(t, b, `{"layer":"mesh","operation_id":"op"}`), http.StatusBadRequest); got.ErrorCode != "POLICY_LAYER_INVALID" {
		t.Fatalf("illegal layer = %+v", got)
	}
	if got := publishReceipt(t, postPublish(t, b, `not json`), http.StatusBadRequest); got.ErrorCode != "POLICY_PAYLOAD_INVALID" {
		t.Fatalf("malformed body = %+v", got)
	}

}

func TestPublishEndpointClientOnlyIsGatedNotStored(t *testing.T) {
	b, verifier := publishApp(t)
	line := seedPublishLine(t, b.app)
	candidatesBefore := candidateCount(t, b.app.Store, line)
	activateViaAPI(t, b, "client",
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)

	receipt := publishReceipt(t, postPublish(t, b, `{"layer":"client","operation_id":"op-publish"}`), http.StatusOK)
	if !receipt.OK || receipt.Status != "gated" {
		t.Fatalf("client-only receipt = %+v", receipt)
	}
	if receipt.Revision != 1 || receipt.Candidate != nil {
		t.Fatalf("client-only receipt invented a candidate: %+v", receipt)
	}
	if len(receipt.Checks) != 2 || receipt.Checks[0].Kernel != "sing-box" || receipt.Checks[1].Kernel != "mihomo" {
		t.Fatalf("client-only checks = %+v", receipt.Checks)
	}
	if receipt.NextAction == "" {
		t.Fatal("client-only receipt does not explain that no candidate is pushed")
	}
	if got := candidateCount(t, b.app.Store, line); got != candidatesBefore {
		t.Fatalf("client-only publication stored %d candidates", got-candidatesBefore)
	}
	if singBox, mihomo := verifier.counts(); singBox != 1 || mihomo != 1 {
		t.Fatalf("client-only gate calls = %d/%d", singBox, mihomo)
	}
}

func TestPublishEndpointRequiresAdminSession(t *testing.T) {
	app, _ := testApp(t)
	verifier := &fixturePublishVerifier{}
	app.policyServer.SetPublishGate(func() (store.PublishVerifier, error) { return verifier, nil })
	b := &browser{app: app}
	w := b.req("POST", "/policies/publish", url.Values{"publish": {`{"operation_id":"op"}`}}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated publish = %d, want 401", w.Code)
	}
	var candidates int
	if err := app.Store.DB.QueryRow(`SELECT count(*) FROM node_candidates`).Scan(&candidates); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if candidates != 0 {
		t.Fatalf("an unauthenticated publish stored %d candidates", candidates)
	}
	// Without the CSRF token the mutation wrapper refuses the request.
	initialize(t, b)
	loginAs(t, b, testPassword)
	noCSRF := b.req("POST", "/policies/publish", url.Values{"publish": {`{"operation_id":"op"}`}}, nil)
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("CSRF-less publish = %d, want 403", noCSRF.Code)
	}
}

func TestPublishEndpointRefusesMissingKernel(t *testing.T) {
	b, _ := publishApp(t)
	seedPublishLine(t, b.app)
	activateViaAPI(t, b, "client",
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)
	activateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`)
	// The production verifier, pointed at an existing executable for sing-box
	// and no Mihomo binary at all: layer="" must refuse instead of skipping the
	// client kernel. The runner answers the checks, so the stand-in executable
	// is never executed.
	b.app.policyServer.SetPublishGate(nil)
	b.app.policyServer.SetPublishRunner(gateFixtureRunner{})
	b.app.Cfg.SingBoxPath = os.Args[0]
	b.app.Cfg.MihomoPath = ""
	refusal := publishReceipt(t, postPublish(t, b, `{"operation_id":"op-publish"}`), http.StatusServiceUnavailable)
	if refusal.ErrorCode != node.CodePublishMihomoMissing {
		t.Fatalf("missing mihomo = %+v", refusal)
	}

	// The same publication with a Mihomo path that does not exist is also a
	// refusal, named after the missing kernel.
	b.app.Cfg.MihomoPath = filepath.Join(t.TempDir(), "absent-mihomo")
	refusal = publishReceipt(t, postPublish(t, b, `{"operation_id":"op-publish"}`), http.StatusServiceUnavailable)
	if refusal.ErrorCode != node.CodePublishMihomoMissing {
		t.Fatalf("absent mihomo = %+v", refusal)
	}

	// With both kernels present the gate runs and the publication is stored.
	mihomo := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(mihomo, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	b.app.Cfg.MihomoPath = mihomo
	receipt := publishReceipt(t, postPublish(t, b, `{"operation_id":"op-publish"}`), http.StatusOK)
	if !receipt.OK {
		t.Fatalf("publication with both kernels = %+v", receipt)
	}
	// Only the two client documents are gated: the server layer produces no
	// routing artifact. The order is stable, so an operator reads the same
	// evidence every time.
	var kinds []string
	for _, check := range receipt.Checks {
		kinds = append(kinds, check.Stage+"/"+check.Kernel)
	}
	want := "client-document/sing-box,client-document/mihomo"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("gate order = %v, want %s", kinds, want)
	}
}

// gateFixtureRunner answers the version probe and accepts every config check,
// so the verifier itself is exercised without a real kernel.
type gateFixtureRunner struct{}

func (gateFixtureRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	switch {
	case len(args) == 1 && args[0] == "-v":
		return []byte("Mihomo Meta v" + node.MihomoVersion), nil
	case len(args) == 3 && args[0] == "check":
		return nil, nil
	case len(args) == 5 && args[0] == "-t":
		return []byte("configuration test is successful"), nil
	}
	return nil, errors.New("unexpected argv")
}
