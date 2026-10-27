package policy

// POST /policies/server/preview for the /policies page: the read-only server
// policy fragment. It writes nothing, publishes nothing and never touches a
// Line or an Out: the form carries one JSON intent, the same snapshot policy
// the publication would assemble is resolved in memory, and the route fragment
// comes back with the egress tri-state.
//
// Flow (parse → validate → assemble → render → return):
//  1. readPolicyServerPreview parses the single form field with strict JSON:
//     unknown fields are refused, so a retired or misspelled key cannot ride
//     along silently.
//  2. previewPolicyServer resolves the intent through the policy domain's own
//     validation, pin and render pipeline (pure, no store, no side effect).
//  3. writePolicyServerPreview answers one JSON body: the fragment and the
//     egress tri-state on success, a stable code plus the operation id on a
//     refusal. The fragment is capped at 40 lines; it is a preview, not a
//     document.

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

// policyServerPreviewFragmentLines caps the rendered fragment. The preview is
// a shape check for the operator, not a document download.
const policyServerPreviewFragmentLines = 40

// policyServerPreviewOut is the anti-corruption shape of the optional Out
// egress. The tri-state it carries is decided here (previewEgressState), never
// by the client.
type policyServerPreviewOut struct {
	Configured bool `json:"configured"`
	Available  bool `json:"available"`
	// ExternalDeclared says the egress is an external HTTP proxy: no ACL, no
	// readback and no controller exist for it, so "available" is the operator's
	// declaration and the preview must say so instead of implying a proof.
	ExternalDeclared bool   `json:"external_declared"`
	FallbackToLine   bool   `json:"fallback_to_line"`
	OperationID      string `json:"operation_id"`
}

// policyServerPreviewInput is the whole accepted request shape. Any JSON field
// outside this struct is refused: the preview must not inherit a payload key a
// later feature retires.
type policyServerPreviewInput struct {
	AIRuleset string                 `json:"ai_ruleset"`
	Domains   []string               `json:"domains"`
	CIDRs     []string               `json:"cidrs"`
	Out       policyServerPreviewOut `json:"out"`
}

// PolicyServerPreviewResponse is the server-preview answer.
type PolicyServerPreviewResponse struct {
	OK                   bool   `json:"ok"`
	EgressState          string `json:"egress_state"`
	EgressCode           string `json:"egress_code,omitempty"`
	RouteFragmentPreview string `json:"route_fragment_preview,omitempty"`
	ErrorCode            string `json:"error_code,omitempty"`
	OperationID          string `json:"operation_id"`
}

// policiesServerPreview is the authenticated, CSRF-protected preview route.
func (app *Server) policiesServerPreview(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	input, ok := app.readPolicyServerPreview(w, r)
	if !ok {
		return
	}
	fragment, state, code, err := previewPolicy(input)
	if err != nil {
		app.failPolicyServerPreview(w, r, err)
		return
	}
	app.writePolicyServerPreview(w, r, http.StatusOK, PolicyServerPreviewResponse{
		OK: true, EgressState: state, EgressCode: code, RouteFragmentPreview: fragment,
	})
}

// readPolicyServerPreview parses the one form field. Strict decoding refuses
// unknown fields, so the response cannot be shaped by a payload key this
// preview has already retired; a malformed body is one stable 400.
func (app *Server) readPolicyServerPreview(w http.ResponseWriter, r *http.Request) (policyServerPreviewInput, bool) {
	var input policyServerPreviewInput
	decoder := json.NewDecoder(strings.NewReader(r.PostForm.Get("preview")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		app.writePolicyServerPreview(w, r, http.StatusBadRequest, PolicyServerPreviewResponse{ErrorCode: policy.CodePolicyInvalid})
		return policyServerPreviewInput{}, false
	}
	return input, true
}

// previewPolicy is the pure transform: intent in, rendered fragment plus the
// egress tri-state out. It calls the policy domain only — no store, no HTTP, no
// side effect — so the preview and the publication cannot diverge on what the
// same intent renders.
func previewPolicy(input policyServerPreviewInput) (string, string, string, error) {
	serverIntent, err := policy.DefaultServerPolicy(input.AIRuleset, input.Domains, input.CIDRs)
	if err != nil {
		return "", "", "", err
	}
	state, code := previewEgressState(input.Out)
	serverIntent.OutConfigured, serverIntent.OutAvailable = input.Out.Configured, input.Out.Available
	serverIntent.FallbackToLine, serverIntent.OperationID = input.Out.FallbackToLine, strings.TrimSpace(input.Out.OperationID)
	// An Out that is not configured renders the same intent as direct: the
	// preview never invents a rule pointing at an absent egress.
	if !input.Out.Configured {
		for index := range serverIntent.Rules {
			serverIntent.Rules[index].Action = policy.CompilerActionDirect
		}
	}
	if serverIntent, err = policy.ResolveServerPolicy(serverIntent); err != nil {
		return "", "", "", err
	}
	pins := policy.RuleSetPins{}
	if err = pins.Validate(serverIntent.Rules); err != nil {
		return "", "", "", err
	}
	fragment, err := policy.RenderServerRoute(serverIntent, pins)
	if err != nil {
		return "", "", "", err
	}
	return capPreviewFragment(string(fragment)), state, code, nil
}

// capPreviewFragment trims the rendered route to the preview cap. A trailing
// newline is kept so the fragment stays a paste-ready document head.
func capPreviewFragment(fragment string) string {
	lines := strings.Split(strings.TrimSuffix(fragment, "\n"), "\n")
	if len(lines) > policyServerPreviewFragmentLines {
		lines = lines[:policyServerPreviewFragmentLines]
	}
	return strings.Join(lines, "\n") + "\n"
}

// previewEgressState decides the tri-state the fragment renders under. It is
// the anti-corruption point for the Out flags: the client states only facts
// (configured, available), this function states the meaning.
func previewEgressState(out policyServerPreviewOut) (string, string) {
	if !out.Configured {
		return policy.AIEgressLine, ""
	}
	if out.Available {
		if out.ExternalDeclared {
			// The route still selects the out tag, but the egress is an external
			// proxy whose availability the Hub cannot prove. The code names the
			// declaration so a preview never reads as a confirmed Out.
			return policy.AIEgressOut, store.CodeLineEgressExternalDeclared
		}
		return policy.AIEgressOut, ""
	}
	if out.FallbackToLine && strings.TrimSpace(out.OperationID) != "" {
		return policy.AIEgressLineFallback, policy.CodeOutOfflineFailClosed
	}
	return "fail-closed", policy.CodeOutOfflineFailClosed
}

// failPolicyServerPreview maps a preview refusal onto status and code. The
// policy domain's own stable codes are passed through; anything unregistered
// collapses to POLICY_INVALID so a message can never become a code.
func (app *Server) failPolicyServerPreview(w http.ResponseWriter, r *http.Request, err error) {
	code := previewFailure(err)
	app.Event(r, code)
	status := http.StatusUnprocessableEntity
	switch code {
	case policy.CodeOutOfflineFailClosed, policy.CodeOutFallbackUnaudited, infra.CodeOutBindingInvalid:
		status = http.StatusConflict
	}
	app.writePolicyServerPreview(w, r, status, PolicyServerPreviewResponse{ErrorCode: code})
}

// previewFailure extracts the stable code from a policy-domain refusal.
func previewFailure(err error) string {
	code, _, _ := strings.Cut(err.Error(), ": ")
	for _, known := range []string{
		policy.CodePolicyInvalid, policy.CodeRulesetUnpinned, policy.CodeOutOfflineFailClosed,
		policy.CodeOutFallbackUnaudited, infra.CodeOutBindingInvalid,
	} {
		if code == known {
			return code
		}
	}
	return policy.CodePolicyInvalid
}

// writePolicyServerPreview is the single response writer of this route.
func (app *Server) writePolicyServerPreview(w http.ResponseWriter, r *http.Request, status int, body PolicyServerPreviewResponse) {
	body.OperationID = infra.Operation(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
