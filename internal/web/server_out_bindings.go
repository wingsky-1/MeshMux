package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

// outBindingFailure maps one sanitized store error onto the stable HTTP
// contract: status, error_code, Chinese operator message and next_action.
// It never echoes database text or node identifiers beyond the code.
func outBindingFailure(err error) (status int, code, message, next string) {
	switch {
	case strings.HasPrefix(err.Error(), "OUT_NOT_FOUND"):
		return 404, "OUT_NOT_FOUND", "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。"
	case strings.HasPrefix(err.Error(), "OUT_ROLE_INVALID"):
		return 409, "OUT_ROLE_INVALID", "所选节点不是 Out 角色。", "请选择角色为 Out 的节点。"
	case strings.HasPrefix(err.Error(), "LINE_NOT_FOUND"):
		return 404, "LINE_NOT_FOUND", "Line 节点不存在。", "请先在节点页纳管该 Line 后重试。"
	case strings.HasPrefix(err.Error(), "LINE_ROLE_INVALID"):
		return 409, "LINE_ROLE_INVALID", "所选节点不是 Line 角色。", "请选择角色为 Edge 的 Line。"
	case strings.HasPrefix(err.Error(), "OUT_NOT_AUTHORIZED"):
		return 409, "OUT_NOT_AUTHORIZED", "绑定两端尚未完成配对或身份已撤销。", "请先完成两端配对并保持身份有效后重试。"
	case strings.HasPrefix(err.Error(), "OUT_BINDING_NOT_FOUND"):
		return 404, "OUT_BINDING_NOT_FOUND", "该 Out 尚无绑定记录。", "请先创建绑定后再操作。"
	case strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID"):
		return 400, "OUT_BINDING_INVALID", "绑定参数不正确。", "请检查 Out、Line 与启用状态后重试。"
	case strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE"):
		return 503, "DATABASE_UNAVAILABLE", "无法读写 Out 绑定。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "OUT_BINDING_FAILED", "Out 绑定操作未完成。", "请凭操作编号检查服务日志。"
	}
}

// parseOutBindingEnabled accepts only explicit on/off spellings. An omitted
// field defaults to enabled because bind is the enabling action; an unknown
// value is rejected instead of silently enabling an egress.
func parseOutBindingEnabled(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "1", "true", "on", "yes":
		return true, true
	case "0", "false", "off", "no":
		return false, true
	}
	return false, false
}

// writeOutBinding renders the flat management response. The binding fields are
// embedded so future UI code can read them without unwrapping a nested object.
func (s *Server) writeOutBinding(w http.ResponseWriter, r *http.Request, status int, action string, binding OutBinding) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		OutBinding
		OperationID string `json:"operation_id"`
	}{Status: action, OutBinding: binding, OperationID: operation(r)})
}

// outBind creates or updates one Out-to-Line binding. The mutation wrapper
// already enforced the admin session, Origin and CSRF token before this runs.
func (s *Server) outBind(w http.ResponseWriter, r *http.Request, _ session) {
	enabled, ok := parseOutBindingEnabled(r.PostForm.Get("enabled"))
	if !ok {
		s.fail(w, r, 400, "OUT_BINDING_INVALID", "启用参数不正确。", "请使用页面表单重新提交。")
		return
	}
	binding := OutBinding{
		OutID:     strings.TrimSpace(r.PostForm.Get("out_id")),
		LineID:    strings.TrimSpace(r.PostForm.Get("line_id")),
		Enabled:   enabled,
		UpdatedAt: s.now().Unix(),
	}
	if err := s.store.setOutBindingAt(binding, s.now()); err != nil {
		status, code, message, next := outBindingFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	stored, err := s.store.GetOutBinding(binding.OutID)
	if err != nil {
		status, code, message, next := outBindingFailure(err)
		if status == 500 {
			status, code, message, next = 503, "DATABASE_UNAVAILABLE", "绑定已保存，但读取回执失败。", "请重新打开页面确认绑定状态。"
		}
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_BOUND")
	s.writeOutBinding(w, r, 200, "bound", stored)
}

// outUnbind clears the Line of one Out and preserves the row as an audit
// record. Traffic returns to the direct Line egress; no other state changes.
func (s *Server) outUnbind(w http.ResponseWriter, r *http.Request, _ session) {
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	if err := s.store.clearOutBindingAt(outID, s.now()); err != nil {
		status, code, message, next := outBindingFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	stored, err := s.store.GetOutBinding(outID)
	if err != nil {
		status, code, message, next := outBindingFailure(err)
		if status == 500 {
			status, code, message, next = 503, "DATABASE_UNAVAILABLE", "解绑已记录，但读取回执失败。", "请重新打开页面确认绑定状态。"
		}
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_UNBOUND")
	s.writeOutBinding(w, r, 200, "unbound", stored)
}

// outPreview is a read-only projection. It goes through the mutation wrapper
// only to require the same session + CSRF boundary as every management POST;
// it never writes a row.
func (s *Server) outPreview(w http.ResponseWriter, r *http.Request, _ session) {
	preview, err := s.store.PreviewOutBinding(
		strings.TrimSpace(r.PostForm.Get("out_id")),
		strings.TrimSpace(r.PostForm.Get("line_id")),
	)
	if err != nil {
		status, code, message, next := outBindingFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OutBindingPreview
		OperationID string `json:"operation_id"`
	}{OutBindingPreview: preview, OperationID: operation(r)})
}
