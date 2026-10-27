// Package-level subscriber-wizard fixtures shared by the root tests.

package handlertest

import (
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
)

// wizardApp opens a Web runtime whose publish gate is the fixture verifier.
func WizardApp(t *testing.T) (*handler.Server, *Browser, *storetest.FixturePublishVerifier) {
	t.Helper()
	app, _ := TestApp(t)
	verifier := &storetest.FixturePublishVerifier{}
	app.PolicyDomainForTest().SetPublishGate(func() (store.PublishVerifier, error) { return verifier, nil })
	b := &Browser{App: app}
	Initialize(t, b)
	LoginAs(t, b, Password)
	return app, b, verifier
}

// wizardLine inserts one configured edge Line and returns its node id.
func WizardLine(t *testing.T, app *handler.Server, name string) string {
	t.Helper()
	node, _ := CreatePendingNode(t, app, "edge", name, 8443, 2222)
	storetest.ConfigureLine(t, app.Store, node.ID, name, app.Now())
	return node.ID
}

// wizardOut inserts one configured Out and returns its node id.
func WizardOut(t *testing.T, app *handler.Server, name string) string {
	t.Helper()
	node, _ := CreatePendingNode(t, app, "out", name, 8444, 2223)
	if _, err := app.Store.SetOutTransport(node.ID, "out.example.invalid", node.VlessPort, app.Now()); err != nil {
		t.Fatal(err)
	}
	return node.ID
}
