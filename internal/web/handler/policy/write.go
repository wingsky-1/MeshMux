package policy

// Policy write API for issue #10 (10d-2a): create, revise, activate and revoke
// through the 10d-1 store methods. One CSRF-protected form field carries the
// JSON intent, like the validate and preview helpers. Intent is persisted only:
// nothing is rendered to a Line/Out or published; publication is 10d-2b.

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

// policyWriteRequest is shared by the four actions; unused fields are ignored.
// operation_id is mandatory here and in the store, so an anonymous write never
// reaches a row.
type policyWriteRequest struct {
	ID          string          `json:"id"`
	Layer       string          `json:"layer"`
	Name        string          `json:"name"`
	Payload     json.RawMessage `json:"payload"`
	Pins        json.RawMessage `json:"pins"`
	Revision    int64           `json:"revision"`
	OperationID string          `json:"operation_id"`
}

// policyWriteResponse is the stable success receipt; failures use the shared
// JSON error envelope, which also carries error_code and operation_id.
// PolicyWriteResponse is the receipt of one intent write.
type PolicyWriteResponse struct {
	OK          bool   `json:"ok"`
	ID          string `json:"id,omitempty"`
	Revision    int64  `json:"revision,omitempty"`
	Status      string `json:"status,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	OperationID string `json:"operation_id"`
}

// readPolicyWrite parses one write. The mutation wrapper already enforced the
// admin infra.Session, Origin, CSRF token and the 4 KiB form limit.
//
// Flow: strict-decode the JSON intent → require a non-empty operation_id →
// return. The store re-validates everything; this guard exists so an anonymous
// or malformed write never reaches a row.
func (app *Server) readPolicyWrite(w http.ResponseWriter, r *http.Request) (policyWriteRequest, bool) {
	var in policyWriteRequest
	decoder := json.NewDecoder(strings.NewReader(r.PostForm.Get("policy")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		app.Fail(w, r, http.StatusBadRequest, infra.CodePolicyPayloadInvalid, "策略 JSON 缺失或格式不正确。", "请检查 payload 后重试。")
		return in, false
	}
	if strings.TrimSpace(in.OperationID) == "" {
		app.Fail(w, r, http.StatusBadRequest, infra.CodePolicyOperationRequired, "策略写操作缺少 operation_id。", "请携带非空 operation_id 后重试。")
		return in, false
	}
	return in, true
}

func (app *Server) policiesCreate(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	in, ok := app.readPolicyWrite(w, r)
	if !ok {
		return
	}
	stored, err := app.Store.CreateRoutePolicy(store.PolicyLayer(strings.TrimSpace(in.Layer)), in.Name, in.Payload, in.Pins, in.OperationID, app.Now())
	if err != nil {
		app.failPolicyWrite(w, r, err)
		return
	}
	app.writePolicyWrite(w, r, http.StatusCreated, PolicyWriteResponse{OK: true, ID: stored.ID, Revision: stored.Revision, Status: string(stored.Status)})
}

func (app *Server) policiesRevise(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	in, ok := app.readPolicyWrite(w, r)
	if !ok {
		return
	}
	stored, err := app.Store.ReviseRoutePolicy(strings.TrimSpace(in.ID), in.Payload, in.Pins, in.OperationID, app.Now())
	if err != nil {
		app.failPolicyWrite(w, r, err)
		return
	}
	app.writePolicyWrite(w, r, http.StatusOK, PolicyWriteResponse{OK: true, ID: stored.ID, Revision: stored.Revision, Status: string(stored.Status)})
}

func (app *Server) policiesActivate(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	app.policyTransition(w, r, app.Store.ActivateRoutePolicy)
}

func (app *Server) policiesRevoke(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	app.policyTransition(w, r, app.Store.RevokeRoutePolicy)
}

func (app *Server) policyTransition(w http.ResponseWriter, r *http.Request, transition func(string, int64, string, time.Time) (store.RoutePolicy, error)) {
	in, ok := app.readPolicyWrite(w, r)
	if !ok {
		return
	}
	stored, err := transition(strings.TrimSpace(in.ID), in.Revision, in.OperationID, app.Now())
	if err != nil {
		app.failPolicyWrite(w, r, err)
		return
	}
	app.writePolicyWrite(w, r, http.StatusOK, PolicyWriteResponse{OK: true, ID: stored.ID, Revision: stored.Revision, Status: string(stored.Status)})
}

// policyWriteFailure maps a sanitized store error onto the HTTP contract.
// The code segment is compared against the constants of codes.go; anything
// unregistered is a 500 with the raw code, never a guessed status.
func policyWriteFailure(err error) (int, string) {
	code := store.ErrorCodeOf(err)
	switch code {
	case infra.CodePolicyOperationRequired, infra.CodePolicyLayerInvalid, "POLICY_NAME_INVALID",
		infra.CodePolicyPayloadInvalid, infra.CodePolicyPinsInvalid, policy.CodePolicyInvalid,
		store.CodePolicyPayloadRetired:
		return http.StatusBadRequest, code
	case infra.CodePolicyNotFound:
		return http.StatusNotFound, code
	case infra.CodePolicyConflict, infra.CodePolicyStateInvalid, store.CodePolicyLayerRetired:
		return http.StatusConflict, code
	case store.CodeDatabaseUnavailable:
		return http.StatusServiceUnavailable, code
	default:
		return http.StatusInternalServerError, code
	}
}

func (app *Server) failPolicyWrite(w http.ResponseWriter, r *http.Request, err error) {
	status, code := policyWriteFailure(err)
	switch code {
	case store.CodePolicyLayerRetired:
		app.Fail(w, r, status, code, "客户端策略层已停写：它不再影响任何订阅。", "请在规则库维护客户端分流；客户端层只保留既有版本的只读预览。")
	case store.CodePolicyPayloadRetired:
		app.Fail(w, r, status, code, "payload 仍携带已退役的 exceptions 或 ssids 字段。", "请改为 rules 表达同一意图后重试。")
	default:
		app.Fail(w, r, status, code, "策略写操作未完成。", "请稍后重试。")
	}
}

func (app *Server) writePolicyWrite(w http.ResponseWriter, r *http.Request, status int, body PolicyWriteResponse) {
	body.OperationID = infra.Operation(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
