package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/compiler"
)

type policyServerPreviewOut struct {
	Configured     bool   `json:"configured"`
	Available      bool   `json:"available"`
	FallbackToLine bool   `json:"fallback_to_line"`
	OperationID    string `json:"operation_id"`
}

type policyServerPreviewInput struct {
	AIRuleset string                 `json:"ai_ruleset"`
	Domains   []string               `json:"domains"`
	CIDRs     []string               `json:"cidrs"`
	Out       policyServerPreviewOut `json:"out"`
}

type policyServerPreviewResponse struct {
	OK                   bool   `json:"ok"`
	EgressState          string `json:"egress_state"`
	EgressCode           string `json:"egress_code,omitempty"`
	RouteFragmentPreview string `json:"route_fragment_preview,omitempty"`
	ErrorCode            string `json:"error_code,omitempty"`
	OperationID          string `json:"operation_id"`
}

func (app *Server) policiesServerPreview(w http.ResponseWriter, r *http.Request, _ session) {
	var input policyServerPreviewInput
	raw := strings.TrimSpace(r.PostForm.Get("preview"))
	if raw == "" || json.Unmarshal([]byte(raw), &input) != nil {
		app.writePolicyServerPreview(w, r, http.StatusBadRequest, policyServerPreviewResponse{ErrorCode: compiler.CodePolicyInvalid})
		return
	}
	fragment, state, code, err := previewPolicy(input)
	if err != nil {
		app.failPolicyServerPreview(w, r, err)
		return
	}
	app.writePolicyServerPreview(w, r, http.StatusOK, policyServerPreviewResponse{
		OK: true, EgressState: state, EgressCode: code, RouteFragmentPreview: fragment,
	})
}

func previewPolicy(input policyServerPreviewInput) (string, string, string, error) {
	policy, err := compiler.DefaultServerPolicy(input.AIRuleset, input.Domains, input.CIDRs)
	if err != nil {
		return "", "", "", err
	}
	state, code := previewEgressState(input.Out)
	policy.OutConfigured, policy.OutAvailable = input.Out.Configured, input.Out.Available
	policy.FallbackToLine, policy.OperationID = input.Out.FallbackToLine, strings.TrimSpace(input.Out.OperationID)
	if !input.Out.Configured {
		for index := range policy.Rules {
			policy.Rules[index].Action = compiler.ActionDirect
		}
	}
	if policy, err = compiler.ResolveServerPolicy(policy); err != nil {
		return "", "", "", err
	}
	pins := compiler.RuleSetPins{}
	if err = pins.Validate(policy.Rules); err != nil {
		return "", "", "", err
	}
	fragment, err := compiler.RenderServerRoute(policy, pins)
	if err != nil {
		return "", "", "", err
	}
	lines := strings.Split(strings.TrimSuffix(string(fragment), "\n"), "\n")
	if len(lines) > 40 {
		lines = lines[:40]
	}
	return strings.Join(lines, "\n") + "\n", state, code, nil
}

func previewEgressState(out policyServerPreviewOut) (string, string) {
	if !out.Configured {
		return compiler.AIEgressLine, ""
	}
	if out.Available {
		return compiler.AIEgressOut, ""
	}
	if out.FallbackToLine && strings.TrimSpace(out.OperationID) != "" {
		return compiler.AIEgressLineFallback, compiler.CodeOutOfflineFailClosed
	}
	return "fail-closed", compiler.CodeOutOfflineFailClosed
}

func (app *Server) failPolicyServerPreview(w http.ResponseWriter, r *http.Request, err error) {
	code := previewFailure(err)
	app.event(r, code)
	status := http.StatusUnprocessableEntity
	switch code {
	case compiler.CodeOutOfflineFailClosed, compiler.CodeOutFallbackUnaudited, "OUT_BINDING_INVALID":
		status = http.StatusConflict
	}
	app.writePolicyServerPreview(w, r, status, policyServerPreviewResponse{ErrorCode: code})
}

func previewFailure(err error) string {
	code, _, _ := strings.Cut(err.Error(), ": ")
	for _, known := range []string{
		compiler.CodePolicyInvalid, compiler.CodeRulesetUnpinned, compiler.CodeOutOfflineFailClosed,
		compiler.CodeOutFallbackUnaudited, "OUT_BINDING_INVALID",
	} {
		if code == known {
			return code
		}
	}
	return compiler.CodePolicyInvalid
}

func (app *Server) writePolicyServerPreview(w http.ResponseWriter, r *http.Request, status int, body policyServerPreviewResponse) {
	body.OperationID = operation(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
