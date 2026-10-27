// Package mesh owns Mesh devices, one-time enrollment keys and subnet routes:
// the /mesh page and its mutations, the device-scoped sing-box configuration that
// combines a proxy subscription with a Tailscale endpoint, explicit Headscale
// node claiming, and the route approve/revoke pairs with their compensating
// readback.
//
// The Headscale control plane is reached through meshnet.Client only, so a test
// supplies a fake and no Headscale binary or socket is required. Every handler
// reads the shared infra.Runtime for the store, the clock and the failure writer.
package mesh

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
)

// Server is the Mesh domain: the runtime plus the narrow control-plane adapter.
// The adapter is a fixed local CLI runner in production and a fake in tests.
type Server struct {
	*infra.Runtime
	// client is the Headscale control-plane adapter behind the mesh pages.
	client meshnet.Client
}

// New builds the Mesh domain over one runtime and one control-plane adapter.
func New(rt *infra.Runtime, client meshnet.Client) *Server {
	return &Server{Runtime: rt, client: client}
}

// Client exposes the control-plane adapter, so a test swaps it for a fake
// exactly the way the single-package server let one field be replaced.
func (s *Server) Client() meshnet.Client { return s.client }

// SetClient installs a control-plane adapter. Production never calls it; a test
// uses it so no Headscale binary or socket is required.
func (s *Server) SetClient(client meshnet.Client) { s.client = client }

// RegisterRoutes registers the Mesh page and its mutations. The placeholder
// navigation loop in the root router must skip "/mesh", otherwise the
// placeholder page competes with the real page for the same path.
//
// The route table takes the wrappers as parameters, so this package never needs
// the root handler or the router type. Route approval is a separate, explicit
// action: the page's read-only snapshot never moves a prefix to approved on its
// own.
func (s *Server) RegisterRoutes(r chi.Router, authenticated func(func(http.ResponseWriter, *http.Request, infra.Session)) http.HandlerFunc, mutation func(func(http.ResponseWriter, *http.Request, infra.Session), bool) http.HandlerFunc) {
	r.Get("/mesh", authenticated(s.meshPage))
	r.Post("/mesh", mutation(s.meshCreate, true))
	r.Post("/mesh/config", mutation(s.meshConfigPage, true))
	r.Post("/mesh/claim", mutation(s.meshClaim, true))
	r.Post("/mesh/rekey", mutation(s.meshRekey, true))
	r.Post("/mesh/reconcile", mutation(s.meshReconcile, true))
	r.Post("/mesh/revoke", mutation(s.meshRevoke, true))
	r.Post("/mesh/retry", mutation(s.meshRevoke, true))
	r.Post("/mesh/routes/approve", mutation(s.meshRouteApprove, true))
	r.Post("/mesh/routes/revoke", mutation(s.meshRouteRevoke, true))
}
