package handler

// POST /policies/publish for issue #10 (10d-2b): the single publication
// endpoint.
//
// The handler is deliberately a thin coordinator. It parses the strict body,
// asks the store for a gated assembly (validate -> resolve -> pin -> render ->
// kernel check), stores the assembly in one transaction and reports the
// receipt. It never renders a document itself, never touches SQL and never
// executes a shell: the two kernels are reached through the fixed verifier
// wrapper.
//
// A publication is queued, not applied. The receipt says "queued" and names the
// candidate revision; the Agent's own four-task chain and readback are what
// eventually prove the Line. A gate refusal stores nothing and returns the
// stable code, so a failed publication leaves the previous revision live.

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// policiesPublishHandle is the authenticated management endpoint.
//
// Flow: parse the strict publish intent → build the kernel verifier → ask the
// store for a gated assembly (validate → resolve → pin → render → kernel
// check) → store the assembly in one transaction → write the receipt. The
// handler never renders a document itself, never touches SQL and never executes
// a shell: the two kernels are reached through the fixed verifier wrapper. A
// gate refusal stores nothing and returns the stable code, so a failed
// publication leaves the previous revision live.
func (app *Server) policiesPublish(w http.ResponseWriter, r *http.Request, _ session) {
	raw := strings.TrimSpace(r.PostForm.Get("publish"))
	if raw == "" {
		app.writePublishFailure(w, r, http.StatusBadRequest, infra.CodePolicyPayloadInvalid, "缺少 publish 字段（JSON）。", "请提交 layer、operation_id 与可选 fallback_to_line。", infra.Operation(r))
		return
	}
	request, err := store.ParsePolicyPublishRequest(json.RawMessage(raw))
	if err != nil {
		app.failPublish(w, r, err)
		return
	}
	verifier, err := app.publishVerifier()
	if err != nil {
		app.failPublish(w, r, err)
		return
	}
	assembly, err := app.Store.AssemblePolicyPublication(r.Context(), verifier, request, app.Now())
	if err != nil {
		app.failPublish(w, r, err)
		return
	}
	publication, err := app.Store.PublishPolicyAssembly(assembly, app.Now())
	if err != nil {
		app.failPublish(w, r, err)
		return
	}
	receipt := store.PublicationReceipt(assembly, publication)
	app.Event(r, "POLICY_PUBLISHED")
	writePublicationReceipt(w, http.StatusOK, receipt, infra.Operation(r))
}

// writePublicationReceipt writes the stable publication receipt. It lives in
// the handler: the store returns domain data and never touches an
// http.ResponseWriter.
func writePublicationReceipt(w http.ResponseWriter, status int, receipt store.PolicyPublishReceipt, operationID string) {
	receipt.OperationID = operationID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(receipt)
}

// publishVerifier builds the kernel verifier. The sing-box path is the
// installer-owned kernel; the Mihomo path is optional deployment configuration
// and its absence is refused only when a Mihomo document is actually checked.
func (app *Server) publishVerifier() (store.PublishVerifier, error) {
	if app.publishGate != nil {
		return app.publishGate()
	}
	runner := app.publishRunner
	if runner == nil {
		runner = node.ExecRunner{}
	}
	dir, err := app.Store.ScratchDir()
	if err != nil {
		return nil, err
	}
	singBoxPath := app.Cfg.SingBoxPath
	if singBoxPath == "" {
		// A co-located Line keeps its kernel at the fixed host path. The gate
		// exists whether or not that Line is installed: a missing kernel is an
		// explicit refusal, never a skipped check.
		singBoxPath = node.SingBoxBinaryPath
	}
	return store.NewPublishVerifier(store.PublishGateConfig{
		SingBoxPath: singBoxPath,
		MihomoPath:  app.Cfg.MihomoPath,
		Runner:      runner,
	}, dir)
}

// failPublish maps one publication refusal onto the JSON error envelope with
// the stable code and the operation id.
func (app *Server) failPublish(w http.ResponseWriter, r *http.Request, err error) {
	status, code, detail := store.PolicyPublishFailure(err)
	app.writePublishFailure(w, r, status, code, detail, store.PublishRetryHint(err), infra.Operation(r))
}

func (app *Server) writePublishFailure(w http.ResponseWriter, r *http.Request, status int, code, message, next, operationID string) {
	app.Event(r, code)
	body := store.PolicyPublishReceipt{
		Status:               "failed",
		PolicySchema:         store.PolicySchemaVersion,
		RoutePolicyRevisions: map[string]int64{},
		Checks:               []store.PolicyCheckEvidence{},
		ErrorCode:            code,
		Detail:               message,
		NextAction:           next,
	}
	writePublicationReceipt(w, status, body, operationID)
}
