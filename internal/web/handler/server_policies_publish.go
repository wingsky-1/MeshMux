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
	"github.com/wingsky-1/MeshMux/internal/web/store"
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
		app.writePublishFailure(w, r, http.StatusBadRequest, codePolicyPayloadInvalid, "缺少 publish 字段（JSON）。", "请提交 layer、operation_id 与可选 fallback_to_line。", operation(r))
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
	assembly, err := app.store.AssemblePolicyPublication(r.Context(), verifier, request, app.now())
	if err != nil {
		app.failPublish(w, r, err)
		return
	}
	publication, err := app.store.PublishPolicyAssembly(assembly, app.now())
	if err != nil {
		app.failPublish(w, r, err)
		return
	}
	receipt := store.PublicationReceipt(assembly, publication)
	app.event(r, "POLICY_PUBLISHED")
	store.WritePublicationReceipt(w, http.StatusOK, receipt, operation(r))
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
	dir, err := app.store.ScratchDir()
	if err != nil {
		return nil, err
	}
	singBoxPath := app.cfg.SingBoxPath
	if singBoxPath == "" {
		// A co-located Line keeps its kernel at the fixed host path. The gate
		// exists whether or not that Line is installed: a missing kernel is an
		// explicit refusal, never a skipped check.
		singBoxPath = node.SingBoxBinaryPath
	}
	return store.NewPublishVerifier(store.PublishGateConfig{
		SingBoxPath: singBoxPath,
		MihomoPath:  app.cfg.MihomoPath,
		Runner:      runner,
	}, dir)
}

// failPublish maps one publication refusal onto the JSON error envelope with
// the stable code and the operation id.
func (app *Server) failPublish(w http.ResponseWriter, r *http.Request, err error) {
	status, code, detail := store.PolicyPublishFailure(err)
	app.writePublishFailure(w, r, status, code, detail, store.PublishRetryHint(err), operation(r))
}

func (app *Server) writePublishFailure(w http.ResponseWriter, r *http.Request, status int, code, message, next, operationID string) {
	app.event(r, code)
	body := store.PolicyPublishReceipt{
		Status:               "failed",
		PolicySchema:         store.PolicySchemaVersion,
		RoutePolicyRevisions: map[string]int64{},
		Checks:               []store.PolicyCheckEvidence{},
		ErrorCode:            code,
		Detail:               message,
		NextAction:           next,
		OperationID:          operationID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
