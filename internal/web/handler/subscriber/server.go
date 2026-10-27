// Package subscriber owns the subscriber workspace: the subscriber page and its
// non-secret JSON projection, the per-Line selection, token rotation/revocation,
// state changes, the fan-out of a Line change to every credential holder, and
// the subscription wizard.
//
// The wizard is the only writer of a subscription selection: four groups (Lines,
// Out, rules, mesh devices), a preview that writes nothing, and a save that
// persists only an artifact which passed the kernel gate. It needs two facts from
// the policy domain — the current rule library and the publication verifier — and
// receives them through Backends instead of importing that package.
package subscriber

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// Backends is the narrow set of facts this domain needs from the policy domain.
// The root package satisfies it, so neither package imports the other.
type Backends struct {
	// RuleLibrary returns the rule-library store the wizard reads.
	RuleLibrary func() *policy.Store
	// PublishVerifier returns the kernel gate the wizard's save must pass.
	PublishVerifier func() (store.PublishVerifier, error)
	// Downloads is the public download boundary, needed for the URL the pages
	// show the operator.
	Downloads *subscription.Server
}

// Server is the subscriber domain: the runtime plus the policy backends.
type Server struct {
	*infra.Runtime
	backends Backends
}

// New builds the subscriber domain over one runtime.
func New(rt *infra.Runtime, backends Backends) *Server {
	return &Server{Runtime: rt, backends: backends}
}

// RegisterRoutes registers the subscriber page/API, the Line save and the
// subscription wizard. The placeholder navigation loop in the root router must
// skip "/subscribers", otherwise the placeholder page competes with the real page
// for the same path.
func (s *Server) RegisterRoutes(r chi.Router, authenticated func(func(http.ResponseWriter, *http.Request, infra.Session)) http.HandlerFunc, mutation func(func(http.ResponseWriter, *http.Request, infra.Session), bool) http.HandlerFunc) {
	r.Get("/subscribers", authenticated(s.subscribersPage))
	r.Get("/subscribers/wizard", authenticated(s.subscribersWizard))
	r.Post("/subscribers", mutation(s.subscribersCreate, true))
	r.Post("/subscribers/rename", mutation(s.subscribersRename, true))
	r.Post("/subscribers/state", mutation(s.subscribersState, true))
	r.Post("/subscribers/lines", mutation(s.subscribersSelectLines, true))
	r.Post("/subscribers/token/rotate", mutation(s.subscribersRotateToken, true))
	r.Post("/subscribers/token/revoke", mutation(s.subscribersRevokeToken, true))
	r.Post("/subscribers/sync", mutation(s.subscribersSync, true))
	r.Post("/subscribers/wizard/preview", mutation(s.subscriptionWizardPreview, true))
	r.Post("/subscribers/wizard/save", mutation(s.subscriptionWizardSave, true))
	r.Get("/api/subscribers", authenticated(s.subscribersAPI))
	r.Post("/lines", mutation(s.linesSave, true))
}

// SubscriberViewModel is the read-only projection of the subscriber page. It is
// exported for the root package's HTTP tests, which pin the projection the page
// and /api/subscribers share.
func (s *Server) SubscriberViewModel() (view.SubscriberPageView, error) {
	return s.subscriberViewModel()
}

// LineCredentialSubscriberIDs is the set of subscribers whose current credential
// one Line serves. Exported for the fan-out test in the root package.
func (s *Server) LineCredentialSubscriberIDs(nodeID string) ([]string, error) {
	return s.lineCredentialSubscriberIDs(nodeID)
}

// ReadWizardSelection parses one wizard form into a selection spec. It is the
// parser the preview and save share; exported so a test can pin that it is
// order-free without a round trip.
func ReadWizardSelection(r *http.Request) (store.SelectionSpec, string, error) {
	return readWizardSelection(r)
}
