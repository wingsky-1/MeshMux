// Package node owns the node lifecycle and the outbound-Agent channel: the
// Nodes page, node creation/reconcile/reissue/revoke, the one-time pairing
// exchange, agent metadata/candidate/task/heartbeat/result, the CLI artifact
// stream and Out management.
//
// Every handler here reads the shared infra.Runtime for the store, the clock and
// the failure writer; the domain state is the Headscale-free node records the
// store already owns. The Agent channel authenticates with Bearer identity, not
// an admin session, so its failures use agentFail and never the JSON boundary.
package node

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// Server is the node domain: the runtime plus nothing else. It owns no field a
// process must share, so one value serves every request.
type Server struct {
	*infra.Runtime
}

// New builds the node domain over one runtime.
func New(rt *infra.Runtime) *Server { return &Server{Runtime: rt} }

// NodesPage renders the pending-node workspace. It is the entry the router's
// GET /nodes uses, so the route table names one exported method instead of a
// closure over unexported state.
func (s *Server) NodesPage(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	s.nodesPage(w, r, sess, nil, "")
}

// NodesData is the read-only Out projection the Nodes page renders next to the
// node cards; it aliases the view model so the root route table can build one.
type NodesData = view.NodesData

// RegisterRoutes registers the node lifecycle, Out management and the Agent
// channel. The wrappers are passed in rather than imported, so this package
// never needs the root package or the router type.
//
// The route comments stay next to the routes: they record which boundaries are
// JSON by declaration, which are HTML twins, and which authenticate the Agent
// with Bearer identity instead of a session.
func (s *Server) RegisterRoutes(r chi.Router, jsonAPI func(http.HandlerFunc) http.HandlerFunc, authenticated func(func(http.ResponseWriter, *http.Request, infra.Session)) http.HandlerFunc, mutation func(func(http.ResponseWriter, *http.Request, infra.Session), bool) http.HandlerFunc) {
	// The diagnostics page owns "/logs": the single home of operational detail
	// (revisions, readback, task chains, error codes), kept off business pages.
	r.Get("/logs", authenticated(s.OpsPage))
	r.Get("/nodes", authenticated(s.NodesPage))
	r.Post("/nodes", mutation(s.nodesCreate, true))
	r.Post("/nodes/reconcile", mutation(s.nodesReconcile, true))
	r.Post("/nodes/reissue", mutation(s.nodesReissue, true))
	r.Post("/nodes/revoke", mutation(s.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/reconcile", mutation(s.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/recheck", mutation(s.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/retry", mutation(s.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/rollback-lkg", mutation(s.nodesRollbackLKG, true))
	r.Post("/nodes/{nodeID}/reissue", mutation(s.nodesReissue, true))
	r.Post("/nodes/{nodeID}/reissue-pairing", mutation(s.nodesReissue, true))
	r.Post("/nodes/{nodeID}/revoke", mutation(s.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/revoke-identity", mutation(s.nodesRevoke, true))
	// Out management. The binding endpoints are gone with the binding table
	// (Task 5): selecting an Out is a subscription edit. Their paths stay
	// registered and answer one stable "retired" code, so an old client learns
	// where the action moved instead of reading a bare 404 as a typo.
	// Delete is still an Out lifecycle action, not a subscription choice.
	// These are a JSON management API whose paths live under /nodes; they are
	// marked as JSON here, at registration, so the error writer never has to
	// recognise their path.
	r.Post("/nodes/out/bind", jsonAPI(mutation(s.outBindingAPIRetired, true)))
	r.Post("/nodes/out/unbind", jsonAPI(mutation(s.outBindingAPIRetired, true)))
	r.Post("/nodes/out/delete", jsonAPI(mutation(s.outDelete, true)))
	r.Post("/nodes/out/preview", jsonAPI(mutation(s.outPreview, true)))
	// The nodes-page Out actions are the HTML twins of the transport and delete
	// mutations above: same store calls, same session + CSRF boundary, but they
	// re-render the list instead of answering JSON.
	r.Post("/nodes/out-transport", mutation(s.outTransportSet, true))
	r.Post("/nodes/http-proxy", mutation(s.httpProxySet, true))
	r.Post("/nodes/out-unbind", mutation(s.outUnbindPage, true))
	r.Post("/nodes/out-delete", mutation(s.outDeletePage, true))
	// The JSON management routes declare their failure representation here, next
	// to the route. The error writer never infers it from the URL, so moving an
	// endpoint cannot silently change its failure body.
	r.Get("/api/nodes", jsonAPI(authenticated(s.nodesList)))
	r.Get("/api/nodes/cli", jsonAPI(authenticated(s.installArtifactDownload)))
	// Agent endpoints use Bearer identity, not admin session + browser Origin.
	r.Post("/api/agent/pair", jsonAPI(s.pairAgent))
	r.Get("/api/agent/node", jsonAPI(s.agentMetadata))
	r.Get("/api/agent/config/{revision}", jsonAPI(s.agentCandidate))
	r.Get("/api/agent/tasks", jsonAPI(s.agentTasks))
	r.Post("/api/agent/heartbeat", jsonAPI(s.agentHeartbeat))
	r.Post("/api/agent/result", jsonAPI(s.agentResult))
}

// AgentAuth authenticates one Agent request. It is exported for the upgrade
// channel, which is a read-only Agent surface that belongs to the upgrade domain
// but must use the same Bearer identity check.
func (s *Server) AgentAuth(w http.ResponseWriter, r *http.Request) (store.Node, bool) {
	return s.agentAuth(w, r)
}

// AgentFail writes one Agent failure in the Agent JSON shape.
func (s *Server) AgentFail(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	s.agentFail(w, r, status, code, message, next)
}
