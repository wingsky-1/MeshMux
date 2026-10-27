package policy

// /policies read-only helpers: the explain query and the conflict dry run.
// Neither stores a policy, creates a revision nor publishes to a Line/Out.
//
// Explain (GET /policies/explain): parse the target → guard its shape →
// resolve against the same snapshot the page renders → render the page with
// the hit chain. An empty target renders the plain page; an unresolvable
// snapshot renders the plain page too (the page never fakes a hit).
//
// Validate (POST /policies/validate): parse one strict-JSON policy →
// validate through the policy domain → answer the stable code or OK. It writes
// no row and publishes nothing; it is the dry run behind the save button.

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// policyExplainTargetMax is the explain form's length guard: longer input is
// neither a domain nor an IP, so it is refused before any evaluation.
const policyExplainTargetMax = 253

// PolicyValidationResponse is the validate dry-run answer.
type PolicyValidationResponse struct {
	OK          bool   `json:"ok"`
	Rules       int    `json:"rules"`
	ErrorCode   string `json:"error_code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	OperationID string `json:"operation_id"`
}

// policiesExplain resolves one target against the same snapshot policy.
func (app *Server) policiesExplain(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	page, clientPolicy, ok := app.policySnapshot(app.Now())
	page.Target = target
	if target == "" {
		app.renderPolicies(w, r, sess, page)
		return
	}
	if len(target) > policyExplainTargetMax {
		app.Fail(w, r, http.StatusBadRequest, policy.CodePolicyInvalid, "目标长度超出域名或 IP 的合理范围。", "请缩短后重试。")
		return
	}
	if !ok {
		app.renderPolicies(w, r, sess, page)
		return
	}
	hit, err := policy.ExplainHit(target, clientPolicy)
	if err != nil {
		code, _ := policyFailure(err)
		app.Fail(w, r, http.StatusConflict, code, "无法计算命中说明。", "请检查策略后重试。")
		return
	}
	page.Hits = []view.PolicyHitView{view.PolicyHitResult(hit, target)}
	app.renderPolicies(w, r, sess, page)
}

// policiesValidate is the conflict dry run: the CSRF-protected form carries one
// policy as JSON; it returns the stable POLICY_* code and overlap detail,
// writing no row and publishing nothing.
func (app *Server) policiesValidate(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	raw := strings.TrimSpace(r.PostForm.Get("rules"))
	if raw == "" {
		app.writePolicyValidation(w, r, http.StatusBadRequest, PolicyValidationResponse{ErrorCode: policy.CodePolicyInvalid, Detail: "缺少 rules 字段（JSON）"})
		return
	}
	input, ok := readPolicyValidationInput(raw)
	if !ok {
		app.writePolicyValidation(w, r, http.StatusBadRequest, PolicyValidationResponse{ErrorCode: policy.CodePolicyInvalid, Detail: "rules 不是合法的策略 JSON"})
		return
	}
	if input.Default == "" {
		input.Default = policy.CompilerActionProxy
	}
	clientPolicy := policy.ClientPolicy{Default: input.Default, Rules: input.Rules}
	if err := clientPolicy.Validate(); err != nil {
		code, detail := policyFailure(err)
		app.Event(r, "POLICY_VALIDATION_REJECTED")
		app.writePolicyValidation(w, r, http.StatusUnprocessableEntity, PolicyValidationResponse{ErrorCode: code, Detail: detail, Rules: len(input.Rules)})
		return
	}
	app.Event(r, "POLICY_VALIDATED")
	app.writePolicyValidation(w, r, http.StatusOK, PolicyValidationResponse{OK: true, Rules: len(input.Rules)})
}

// readPolicyValidationInput parses the dry-run policy with strict decoding.
// Unknown fields are refused so a retired key (exceptions/ssids) cannot slip
// through the dry run while the write path rejects it.
func readPolicyValidationInput(raw string) (struct {
	Default policy.CompilerAction `json:"default"`
	Rules   []policy.CompilerRule `json:"rules"`
}, bool) {
	var input struct {
		Default policy.CompilerAction `json:"default"`
		Rules   []policy.CompilerRule `json:"rules"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, false
	}
	return input, true
}

func (app *Server) writePolicyValidation(w http.ResponseWriter, r *http.Request, status int, body PolicyValidationResponse) {
	body.OperationID = infra.Operation(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// policyFailure splits a stable policy code from its detail.
func policyFailure(err error) (string, string) {
	for _, code := range []string{policy.CodePolicyConflict, policy.CodePolicyInvalid, policy.CodePolicyNodeUnknown} {
		if prefix := code + ": "; strings.HasPrefix(err.Error(), prefix) {
			return code, strings.TrimPrefix(err.Error(), prefix)
		}
	}
	return policy.CodePolicyInvalid, err.Error()
}
