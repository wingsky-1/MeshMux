// Package-level publication fixtures shared by the policy and root tests.

package handlertest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
)

func PublishApp(t *testing.T) (*Browser, *storetest.FixturePublishVerifier) {
	t.Helper()
	app, _ := TestApp(t)
	verifier := &storetest.FixturePublishVerifier{}
	app.PolicyDomainForTest().SetPublishGate(func() (store.PublishVerifier, error) { return verifier, nil })
	b := &Browser{App: app}
	Initialize(t, b)
	LoginAs(t, b, Password)
	return b, verifier
}

func PostPublish(t *testing.T, b *Browser, body string) *httptest.ResponseRecorder {
	t.Helper()
	return b.Post("/policies/publish", url.Values{"publish": {body}})
}

func PublishReceipt(t *testing.T, w *httptest.ResponseRecorder, status int) store.PolicyPublishReceipt {
	t.Helper()
	RequireStatus(t, w, status)
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
func SeedPublishLine(t *testing.T, app *handler.Server) string {
	t.Helper()
	now := app.Now()
	line := storetest.PairedStoreNode(t, app.Store, "edge", now)
	settings := storetest.TestLine(line, "line-a")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := app.Store.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	storetest.MarkLineOnline(t, app.Store, line, now)
	if _, _, err := app.Store.CreateSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	storetest.SeedInitialChain(t, app.Store, line, now)
	storetest.ConfirmChain(t, app.Store, line, now)
	return line
}

// activateViaAPI creates and activates one server policy through the write
// endpoint, so the publish test exercises the same rows an operator would
// produce. The client layer has been read-only since Task 6, so a client call
// seeds a legacy revision directly: that is the only way such a row can exist
// after the upgrade, and it keeps the preview path under test.
func ActivateViaAPI(t *testing.T, b *Browser, layer, payload string) {
	t.Helper()
	if layer == "client" {
		SeedLegacyClientPolicy(t, b, payload)
		return
	}
	created := PolicyReceipt(t, PostPolicy(t, b, "/policies",
		fmt.Sprintf(`{"layer":%q,"name":"策略-%s","payload":%s,"operation_id":"op-create"}`, layer, layer, payload)), http.StatusCreated)
	PolicyReceipt(t, PostPolicy(t, b, "/policies/activate",
		fmt.Sprintf(`{"id":%q,"revision":1,"operation_id":"op-activate"}`, created.ID)), http.StatusOK)
}
