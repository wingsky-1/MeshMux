// Package policy owns the route-policy surface: the read-only /policies
// snapshot, the validate/explain/preview helpers, the server-layer write API,
// the gated publication pipeline, the rule library, and the irreversible
// database-migration confirmation.
//
// The snapshot derives its client fallback from the read-only mesh preflight, so
// it receives the Mesh domain through Backends instead of importing it. The
// publication pipeline owns its two test seams (the runner and the gate), since
// they belong to this domain's kernel boundary.
package policy

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	policycore "github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// Backends is the narrow set of facts this domain needs from other domains. The
// root package satisfies it, so policy imports no other handler package.
type Backends struct {
	// MeshModel resolves the read-only mesh model the client layer falls back
	// to. It mints no key; ok=false means there is no usable mesh data.
	MeshModel func(record store.MeshDeviceRecord, now time.Time) (subscription.MeshConfigModel, bool)
}

// Server is the policy domain: the runtime, the down-stream domain backends and
// the publish gate's two process seams.
type Server struct {
	*infra.Runtime
	backends Backends
	// publishRunner is the fixed process boundary of the publish gate. It is nil
	// in production (node.ExecRunner) and replaced by a fixture runner in tests so
	// no kernel binary is required to exercise the gate.
	publishRunner node.CommandRunner
	// publishGate replaces the whole gate in tests. Production leaves it nil so
	// the real kernel verifier is always built from the deployment
	// configuration; it exists so a unit test never needs a kernel install.
	publishGate func() (store.PublishVerifier, error)
}

// New builds the policy domain over one runtime and the mesh preflight backends.
func New(rt *infra.Runtime, backends Backends) *Server {
	return &Server{Runtime: rt, backends: backends}
}

// SetPublishRunner installs the gate's process runner. Production never calls
// it; a test uses it so no kernel binary is required.
func (s *Server) SetPublishRunner(runner node.CommandRunner) { s.publishRunner = runner }

// SetPublishGate replaces the whole gate. Production never calls it; a test uses
// it to pin the boundary without a kernel install.
func (s *Server) SetPublishGate(gate func() (store.PublishVerifier, error)) { s.publishGate = gate }

// PublishGate reports the installed gate seam, if any.
func (s *Server) PublishGate() func() (store.PublishVerifier, error) { return s.publishGate }

// RegisterRoutes registers the /policies surface, the rule library and the
// irreversible database-migration confirmation.
//
// /policies is a snapshot, two read-only helpers, four intent writes and the
// publication gate. Writes persist intent through the store; /policies/publish
// assembles, gates and stores one immutable candidate revision.
//
// /rules is the rule library: the read-only list, the create and revise
// mutations (new versions only), and the two-step delete with used-by
// protection. Like the nodes-page Out twins, the mutations are HTML forms that
// re-render the list instead of answering JSON.
func (s *Server) RegisterRoutes(r chi.Router, jsonAPI func(http.HandlerFunc) http.HandlerFunc, authenticated func(func(http.ResponseWriter, *http.Request, infra.Session)) http.HandlerFunc, mutation func(func(http.ResponseWriter, *http.Request, infra.Session), bool) http.HandlerFunc) {
	r.Get("/policies", authenticated(s.policiesPage))
	r.Get("/policies/explain", authenticated(s.policiesExplain))
	r.Post("/policies/validate", jsonAPI(mutation(s.policiesValidate, true)))
	r.Post("/policies/server/preview", jsonAPI(mutation(s.policiesServerPreview, true)))
	r.Post("/policies", jsonAPI(mutation(s.policiesCreate, true)))
	r.Post("/policies/revise", jsonAPI(mutation(s.policiesRevise, true)))
	r.Post("/policies/activate", jsonAPI(mutation(s.policiesActivate, true)))
	r.Post("/policies/revoke", jsonAPI(mutation(s.policiesRevoke, true)))
	// Publication is the gated pipeline: assemble the active revisions, check
	// them with the pinned kernels and store one immutable candidate revision per
	// Line. It is never a bare render-to-response.
	r.Post("/policies/publish", jsonAPI(mutation(s.policiesPublish, true)))
	r.Get("/rules", authenticated(s.rulesLibraryPage))
	r.Post("/rules", mutation(s.rulesLibraryCreate, true))
	r.Post("/rules/revise", mutation(s.rulesLibraryRevise, true))
	r.Post("/rules/delete", mutation(s.rulesLibraryDelete, true))
	// The irreversible database migration confirmation (11c-3): it stores the
	// explicit operator bit on the Hub database backup record consumed by 11d.
	// It performs no migration and no database edit.
	r.Post("/tasks/db-migration/approve", jsonAPI(mutation(s.tasksDatabaseMigrationApprove, true)))
}

// RuleLibrary returns the rule-library store the wizard reads. It is the one
// fact the subscriber domain needs from this package.
func (s *Server) RuleLibrary() *policycore.Store {
	return s.rulesLib()
}

// PublishVerifier returns the kernel gate the wizard's save must pass.
func (s *Server) PublishVerifier() (store.PublishVerifier, error) {
	return s.publishVerifier()
}

// PolicySnapshot builds the page model. Exported for the root package's tests.
func (s *Server) PolicySnapshot(now time.Time) (view.PolicyPageView, policycore.ClientPolicy, bool) {
	return s.policySnapshot(now)
}
