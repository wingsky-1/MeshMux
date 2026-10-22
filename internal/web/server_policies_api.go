package web

// /policies read-only helpers for issue #10: the explain query and the conflict
// dry run. Neither stores a policy, creates a revision nor publishes to a
// Line/Out; that pipeline is 10d.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/compiler"
)

type policyValidationResponse struct {
	OK          bool   `json:"ok"`
	Rules       int    `json:"rules"`
	ErrorCode   string `json:"error_code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	OperationID string `json:"operation_id"`
}

// policiesExplain resolves one target against the same snapshot policy.
func (app *Server) policiesExplain(w http.ResponseWriter, r *http.Request, sess session) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	view, policy, ok := app.policySnapshot(app.now())
	view.Target = target
	if target == "" {
		app.renderPolicies(w, r, sess, view)
		return
	}
	if len(target) > 253 {
		app.fail(w, r, http.StatusBadRequest, compiler.CodePolicyInvalid, "目标长度超出域名或 IP 的合理范围。", "请缩短后重试。")
		return
	}
	if !ok {
		app.renderPolicies(w, r, sess, view)
		return
	}
	hit, err := compiler.ExplainHit(target, policy)
	if err != nil {
		code, _ := policyFailure(err)
		app.fail(w, r, http.StatusConflict, code, "无法计算命中说明。", "请检查策略后重试。")
		return
	}
	view.Hits = []policyHitView{policyHitResult(hit, target)}
	app.renderPolicies(w, r, sess, view)
}

func policyHitResult(hit compiler.HitExplanation, target string) policyHitView {
	rule := fmt.Sprintf("优先级 %d · %s", hit.Priority, hit.Matcher)
	title := "命中说明：" + target
	if hit.Priority == 0 {
		rule = "未命中任何显式规则，使用兜底"
		title = "兜底路径：" + target
	}
	dns := "境内 DNS，解析出口与访问出口一致"
	if hit.DNS == compiler.DNSEncrypted {
		dns = "加密 DNS，解析出口与访问出口一致"
	}
	return policyHitView{
		Title: title,
		Note:  "仅对域名、域名后缀与 CIDR 规则求值；geo 与远端 ruleset 需要锁定数据，本结果不猜测其匹配。",
		Steps: []policyHitStep{
			{Stage: "规则", Value: rule},
			{Stage: "动作", Value: policyActionLabel(hit.Action)},
			{Stage: "实际出口", Value: hit.Egress},
			{Stage: "DNS", Value: dns},
		},
	}
}

// policiesValidate is the conflict dry run: the CSRF-protected form carries one
// policy as JSON; it returns the stable POLICY_* code and overlap detail,
// writing no row and publishing nothing.
func (app *Server) policiesValidate(w http.ResponseWriter, r *http.Request, _ session) {
	raw := strings.TrimSpace(r.PostForm.Get("rules"))
	if raw == "" {
		app.writePolicyValidation(w, r, http.StatusBadRequest, policyValidationResponse{ErrorCode: compiler.CodePolicyInvalid, Detail: "缺少 rules 字段（JSON）"})
		return
	}
	var input struct {
		Default compiler.Action `json:"default"`
		Rules   []compiler.Rule `json:"rules"`
	}
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		app.writePolicyValidation(w, r, http.StatusBadRequest, policyValidationResponse{ErrorCode: compiler.CodePolicyInvalid, Detail: "rules 不是合法的策略 JSON"})
		return
	}
	if input.Default == "" {
		input.Default = compiler.ActionProxy
	}
	policy := compiler.ClientPolicy{Default: input.Default, Rules: input.Rules}
	if err := policy.Validate(); err != nil {
		code, detail := policyFailure(err)
		app.event(r, "POLICY_VALIDATION_REJECTED")
		app.writePolicyValidation(w, r, http.StatusUnprocessableEntity, policyValidationResponse{ErrorCode: code, Detail: detail, Rules: len(input.Rules)})
		return
	}
	app.event(r, "POLICY_VALIDATED")
	app.writePolicyValidation(w, r, http.StatusOK, policyValidationResponse{OK: true, Rules: len(input.Rules)})
}

func (app *Server) writePolicyValidation(w http.ResponseWriter, r *http.Request, status int, body policyValidationResponse) {
	body.OperationID = operation(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// policyFailure splits a stable compiler code from its detail.
func policyFailure(err error) (string, string) {
	for _, code := range []string{compiler.CodePolicyConflict, compiler.CodePolicyInvalid, compiler.CodePolicyNodeUnknown} {
		if prefix := code + ": "; strings.HasPrefix(err.Error(), prefix) {
			return code, strings.TrimPrefix(err.Error(), prefix)
		}
	}
	return compiler.CodePolicyInvalid, err.Error()
}
