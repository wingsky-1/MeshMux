package policy_test

// HTTP tests for POST /policies/publish. The endpoint is authenticated, CSRF
// protected and form-wrapped like every other management POST; the tests prove
// the receipt shape, the refusal status classes and the "nothing stored" rule.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
)

// publishApp builds an authenticated handlertest.Browser and installs the fixture gate.
func TestPublishEndpointStoresCandidate(t *testing.T) {
	b, verifier := handlertest.PublishApp(t)
	line := handlertest.SeedPublishLine(t, b.App)
	handlertest.ActivateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`)

	receipt := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"layer":"server","operation_id":"op-publish"}`), http.StatusOK)
	if !receipt.OK || receipt.Status != "queued" {
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
	if receipt.Candidate == nil || receipt.Candidate.Revision < 1 || receipt.Candidate.Lines != 1 ||
		len(receipt.Candidate.Config) != 64 {
		t.Fatalf("candidate reference = %+v", receipt.Candidate)
	}
	if len(receipt.Checks) != 1 || receipt.Checks[0].Kernel != "sing-box" || receipt.Checks[0].Status != "passed" {
		t.Fatalf("check evidence = %+v", receipt.Checks)
	}
	if len(receipt.Lines) != 1 || receipt.Lines[0].LineID != line || receipt.Lines[0].Status != "queued" {
		t.Fatalf("line evidence = %+v", receipt.Lines)
	}
	// The check evidence is a summary: the document itself never appears.
	body := receipt.Checks[0].Detail
	if strings.Contains(body, "ai.example.invalid") || strings.Contains(body, "outbounds") {
		t.Fatalf("check evidence leaked the document: %q", body)
	}
	if singBox, _ := verifier.Counts(); singBox != 1 {
		t.Fatalf("sing-box gate calls = %d, want 1", singBox)
	}
	// Exactly one new candidate revision carrying the route is stored.
	stored, err := b.App.Store.LatestCandidate(line)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Document.Schema != node.CandidateSchemaV3 || !strings.Contains(string(stored.Document.Route), "ai.example.invalid") {
		t.Fatalf("stored candidate = %s route=%s", stored.Document.Schema, stored.Document.Route)
	}
}

func TestPublishEndpointRefusals(t *testing.T) {
	b, _ := handlertest.PublishApp(t)
	line := handlertest.SeedPublishLine(t, b.App)

	// No active policy for the requested layer.
	refusal := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"layer":"server","operation_id":"op-publish"}`), http.StatusNotFound)
	if refusal.ErrorCode != store.CodePublishNoPolicy || refusal.OK || refusal.PolicySchema != 8 {
		t.Fatalf("missing policy refusal = %+v", refusal)
	}
	// A missing operation id never reaches a row.
	if got := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"layer":"server"}`), http.StatusBadRequest); got.ErrorCode != "POLICY_OPERATION_REQUIRED" {
		t.Fatalf("missing operation id = %+v", got)
	}
	if got := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"layer":"mesh","operation_id":"op"}`), http.StatusBadRequest); got.ErrorCode != "POLICY_LAYER_INVALID" {
		t.Fatalf("illegal layer = %+v", got)
	}
	if got := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `not json`), http.StatusBadRequest); got.ErrorCode != "POLICY_PAYLOAD_INVALID" {
		t.Fatalf("malformed body = %+v", got)
	}

	handlertest.ActivateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"out"}]}`)
	out := storetest.PairedStoreNode(t, b.App.Store, "out", b.App.Now())
	storetest.MarkLineOnline(t, b.App.Store, out, b.App.Now())
	storetest.ConfigureOut(t, b.App.Store, out, b.App.Now())
	storetest.EnableOutForLine(t, b.App.Store, out, line, b.App.Now())
	if _, err := b.App.Store.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	// An unhealthy Out fails closed with 409 and stores nothing.
	refusal = handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"layer":"server","operation_id":"op-publish"}`), http.StatusConflict)
	if refusal.ErrorCode != policy.CodeOutOfflineFailClosed {
		t.Fatalf("unhealthy out = %+v", refusal)
	}
	if refusal.NextAction == "" {
		t.Fatal("a refusal has no next action")
	}
}

func TestPublishEndpointClientOnlyIsGatedNotStored(t *testing.T) {
	b, verifier := handlertest.PublishApp(t)
	line := handlertest.SeedPublishLine(t, b.App)
	candidatesBefore := storetest.CandidateCount(t, b.App.Store, line)
	handlertest.ActivateViaAPI(t, b, "client",
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)

	receipt := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"layer":"client","operation_id":"op-publish"}`), http.StatusOK)
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
	if got := storetest.CandidateCount(t, b.App.Store, line); got != candidatesBefore {
		t.Fatalf("client-only publication stored %d candidates", got-candidatesBefore)
	}
	if singBox, mihomo := verifier.Counts(); singBox != 1 || mihomo != 1 {
		t.Fatalf("client-only gate calls = %d/%d", singBox, mihomo)
	}
}

func TestPublishEndpointRequiresAdminSession(t *testing.T) {
	app, _ := handlertest.TestApp(t)
	verifier := &storetest.FixturePublishVerifier{}
	app.PolicyDomainForTest().SetPublishGate(func() (store.PublishVerifier, error) { return verifier, nil })
	b := &handlertest.Browser{App: app}
	w := b.Req("POST", "/policies/publish", url.Values{"publish": {`{"operation_id":"op"}`}}, nil)
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
	handlertest.Initialize(t, b)
	handlertest.LoginAs(t, b, handlertest.Password)
	noCSRF := b.Req("POST", "/policies/publish", url.Values{"publish": {`{"operation_id":"op"}`}}, nil)
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("CSRF-less publish = %d, want 403", noCSRF.Code)
	}
}

func TestPublishEndpointRefusesMissingKernel(t *testing.T) {
	b, _ := handlertest.PublishApp(t)
	handlertest.SeedPublishLine(t, b.App)
	handlertest.ActivateViaAPI(t, b, "client",
		`{"default":"proxy","rules":[{"priority":100,"match":{"domains":["news.example.invalid"]},"action":"direct"}]}`)
	handlertest.ActivateViaAPI(t, b, "server",
		`{"default":"direct","rules":[{"priority":100,"match":{"domains":["ai.example.invalid"]},"action":"direct"}]}`)
	// The production verifier, pointed at an existing executable for sing-box
	// and no Mihomo binary at all: layer="" must refuse instead of skipping the
	// client kernel. The runner answers the checks, so the stand-in executable
	// is never executed.
	b.App.PolicyDomainForTest().SetPublishGate(nil)
	b.App.PolicyDomainForTest().SetPublishRunner(gateFixtureRunner{})
	b.App.Cfg.SingBoxPath = os.Args[0]
	b.App.Cfg.MihomoPath = ""
	refusal := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"operation_id":"op-publish"}`), http.StatusServiceUnavailable)
	if refusal.ErrorCode != node.CodePublishMihomoMissing {
		t.Fatalf("missing mihomo = %+v", refusal)
	}

	// The same publication with a Mihomo path that does not exist is also a
	// refusal, named after the missing kernel.
	b.App.Cfg.MihomoPath = filepath.Join(t.TempDir(), "absent-mihomo")
	refusal = handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"operation_id":"op-publish"}`), http.StatusServiceUnavailable)
	if refusal.ErrorCode != node.CodePublishMihomoMissing {
		t.Fatalf("absent mihomo = %+v", refusal)
	}

	// With both kernels present the gate runs and the publication is stored.
	mihomo := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(mihomo, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	b.App.Cfg.MihomoPath = mihomo
	receipt := handlertest.PublishReceipt(t, handlertest.PostPublish(t, b, `{"operation_id":"op-publish"}`), http.StatusOK)
	if !receipt.OK {
		t.Fatalf("publication with both kernels = %+v", receipt)
	}
	// The Line candidate is gated first, then the two client documents. The
	// order is stable, so an operator reads the same evidence every time.
	var kinds []string
	for _, check := range receipt.Checks {
		kinds = append(kinds, check.Stage+"/"+check.Kernel)
	}
	want := "line-candidate/sing-box,client-document/sing-box,client-document/mihomo"
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
