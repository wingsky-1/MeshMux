package handler

// /policies snapshot for issue #10: rows rendered from each layer's active
// revision, falling back to the mesh-derived and built-in defaults. Nothing
// here stores or publishes a policy; server-layer writes are the policy API and
// publication is 10d-2b. The client layer is read-only since Task 6, so its
// rows are always a preview of a legacy (or default) revision.
//
// The handler's job is the store read and the fallback decision only: which
// source fills the page (active revision / mesh model / built-in default /
// broken draft) and what the page says about it. Every display row, label and
// conflict line is built in the view package (view.PolicyClientRows and
// friends), so the wording has exactly one home.

import (
	"net/http"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/policy"
	"github.com/wingsky-1/MeshMux/internal/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// defaultServerAIRulesetTag is the canonical AI ruleset tag; its pin is 10d.
const defaultServerAIRulesetTag = "ai"

// policySnapshot builds the page from the active stored revisions; a layer
// without one falls back to the read-only mesh model (client) and
// DefaultServerPolicy (server). An active payload that no longer validates is
// never presented as live: the page shows the design draft and the conflict.
//
// Flow: read Out projection → read both active intents → resolve each layer to
// its source → assemble the page model → return it with the client policy for
// the explain query. The bool reports whether the client policy is real (not
// the zero value), so the explain route knows whether it can evaluate a hit.
func (app *Server) policySnapshot(now time.Time) (view.PolicyPageView, policy.ClientPolicy, bool) {
	out := app.policyOutState(now)
	_, clientIntent, clientErr := app.ActivePolicyIntent(store.PolicyLayerClient)
	_, serverIntent, serverErr := app.ActivePolicyIntent(store.PolicyLayerServer)
	for _, err := range []error{clientErr, serverErr} {
		if err != nil && !strings.HasPrefix(err.Error(), "POLICY_NOT_FOUND") {
			return policyBrokenView(err), policy.ClientPolicy{}, false
		}
	}
	var clientPolicy policy.ClientPolicy
	if clientErr == nil {
		clientPolicy = policy.ClientPolicy{Default: clientIntent.Default, Rules: clientIntent.Rules}
		if err := clientPolicy.Validate(); err != nil {
			return policyBrokenView(err), policy.ClientPolicy{}, false
		}
	} else {
		model, ok := app.policyMeshModel(now)
		if !ok {
			return policyFallbackView(), policy.ClientPolicy{}, false
		}
		var err error
		if clientPolicy, err = policy.DefaultClientPolicy(model, model.LineLabels[0], policy.ClientDefaults{}); err != nil {
			return policyFallbackView(), policy.ClientPolicy{}, false
		}
	}
	var server policy.ServerPolicy
	if serverErr == nil {
		server = policy.ServerPolicy{Default: serverIntent.Default, Rules: serverIntent.Rules}
		if err := server.Validate(); err != nil {
			return policyBrokenView(err), policy.ClientPolicy{}, false
		}
	} else if server, serverErr = policy.DefaultServerPolicy(defaultServerAIRulesetTag, nil, nil); serverErr != nil {
		return policyFallbackView(), policy.ClientPolicy{}, false
	}
	page := view.PolicyPageView{
		Out:           out,
		Client:        view.PolicyClientRows(clientPolicy),
		Server:        view.PolicyServerRows(server, out),
		Conflicts:     view.PolicyConflictRows(clientPolicy),
		ClientDefault: clientErr != nil, ServerDefault: serverErr != nil,
	}
	return page, clientPolicy, true
}

func (app *Server) ActivePolicyIntent(layer store.PolicyLayer) (store.RoutePolicy, store.RoutePolicyPayload, error) {
	return app.store.ActivePolicyIntent(layer)
}

// policyFallbackView is the draft fallback before any active revision or mesh
// data exists; it says so on the page.
func policyFallbackView() view.PolicyPageView {
	page := view.PoliciesDraftView()
	page.Draft, page.ClientDefault, page.ServerDefault = true, true, true
	return page
}

// policyBrokenView never renders an active payload that failed re-validation
// as live policy; it shows the draft plus the blocking conflict.
func policyBrokenView(err error) view.PolicyPageView {
	page := view.PoliciesDraftView()
	page.Draft = true
	page.Conflicts = []view.PolicyConflictView{{Detail: "当前 active 策略未通过复核：" + view.PolicyErrorDetail(err), Blocked: true}}
	return page
}

// policyMeshModel reuses the read-only mesh preflight; it mints no key.
func (app *Server) policyMeshModel(now time.Time) (subscription.MeshConfigModel, bool) {
	devices, err := app.store.ListMeshDevices()
	if err != nil {
		return subscription.MeshConfigModel{}, false
	}
	for _, device := range devices {
		if device.Purpose != mesh.PurposeProxyMesh || device.SubscriberID == "" {
			continue
		}
		plan, err := app.meshConfigPreflight(device, now)
		if err == nil && len(plan.Model.LineLabels) > 0 {
			return plan.Model, true
		}
	}
	return subscription.MeshConfigModel{}, false
}

// policyOutState aggregates the read-only Out projection over all edge Lines:
// a configured-but-unavailable Out is degraded and outranks a healthy one.
func (app *Server) policyOutState(now time.Time) view.PolicyOutState {
	nodes, err := app.store.ListNodesAt(now)
	if err != nil {
		return view.PolicyOutAbsent
	}
	state := view.PolicyOutAbsent
	for _, node := range nodes {
		if node.Role != nodeRoleEdge {
			continue
		}
		facts, err := app.store.OutEgressFacts(node.ID, now)
		if err != nil || !facts.Configured {
			continue
		}
		if !facts.Available {
			return view.PolicyOutDegraded
		}
		state = view.PolicyOutActive
	}
	return state
}

// policiesPage renders the read-only snapshot.
func (app *Server) policiesPage(w http.ResponseWriter, r *http.Request, sess session) {
	page, _, _ := app.policySnapshot(app.now())
	app.renderPolicies(w, r, sess, page)
}

func (app *Server) renderPolicies(w http.ResponseWriter, r *http.Request, sess session, model view.PolicyPageView) {
	app.render(w, r, http.StatusOK, view.PoliciesPage(view.PageData{Title: "路由策略", Path: "/policies", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP, DirectProxy: app.cfg.DirectProxy}, model))
}
