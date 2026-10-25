package handler

// The Out management API after the authorization migration (Task 5).
//
// Two endpoints were deleted with the binding table, because the state they
// edited no longer exists:
//
//	POST /nodes/out/bind   — selecting an Out is a subscription edit now. The
//	                         subscription wizard owns it, and the same-Line
//	                         consistency rule (SUBSCRIPTION_OUT_CONFLICT) lives
//	                         there too, so a second write path could only create a
//	                         way to violate it.
//	POST /nodes/out/unbind — a subscription that stops selecting the Out is the
//	                         unbind, and it republishes the empty guard through
//	                         the same store drain.
//
// Both paths stay registered on purpose: an operator tooling or a bookmark that
// still calls them gets an explicit, stable "moved" answer instead of a bare 404
// that would read like a typo.
//
// The delete action stays: it is an Out lifecycle action, not a subscription
// choice.

import (
	"encoding/json"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"net/http"
	"strings"
)

// CodeBindingAPIRetired is the stable refusal of the two retired endpoints.
const CodeBindingAPIRetired = "OUT_BINDING_API_RETIRED"

// outBindingFailure maps one sanitized Out management error onto the stable HTTP
// contract: status, error_code, Chinese operator message and next_action. It never
// echoes database text or node identifiers beyond the code.
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
	case strings.HasPrefix(err.Error(), store.CodeOutReferenced):
		return 409, store.CodeOutReferenced, "该 Out 仍被订阅选中。", "请在订阅向导中先解除这些订阅的 Out 选择，再删除出口。"
	case strings.HasPrefix(err.Error(), store.CodeOutSyncPending):
		return 202, store.CodeOutSyncPending, "路由已清理，主机 ACL 等待下发。", "Out 上线后会自动完成；也可在节点页重试。"
	case strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID"):
		return 400, "OUT_BINDING_INVALID", "Out 参数不正确。", "请检查 Out 标识后重试。"
	case strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE"):
		return 503, "DATABASE_UNAVAILABLE", "无法读写 Out 状态。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "OUT_MANAGEMENT_FAILED", "Out 操作未完成。", "请凭操作编号检查服务日志。"
	}
}

// outBindingAPIRetired answers the two deleted routes with one stable code and the
// replacement action, so an old client cannot mistake the refusal for a typo.
func (s *Server) outBindingAPIRetired(w http.ResponseWriter, r *http.Request, _ session) {
	s.fail(w, r, http.StatusGone, CodeBindingAPIRetired,
		"该接口已移除：Out 授权改由订阅选择派生。",
		"请在订阅用户页的向导中为该订阅选择或取消 Out；服务端 ACL 会随订阅自动重算。")
}

// outDelete removes one Out from the routing model and clears its ACL.
//
// The delete is a management action with the same session + CSRF boundary as every
// other mutation. Success means the route is gone and the empty authorization was
// published; a host cleanup that could not be delivered is reported as
// OUT_SYNC_PENDING instead of a fabricated success. The node identity and its dial
// address are deliberately untouched: deleting the route is not revoking the host,
// and the operator can select the same Out again.
func (s *Server) outDelete(w http.ResponseWriter, r *http.Request, _ session) {
	now := s.now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	if err := s.store.DeleteOutAt(outID, now); err != nil {
		if errors.Is(err, store.ErrOutCleanupPending) {
			// Nothing was destroyed (Ruling R9): the host has not proved the empty guard
			// yet, so the delete is a refusal, not a partial success. Reporting 202 here
			// would let an operator believe the Out is gone while its row still exists.
			s.event(r, store.CodeOutSyncPending)
			s.fail(w, r, 409, store.CodeOutSyncPending,
				"删除未执行：Out 尚未确认清空授权（Out 离线或仍有未完成的链）。",
				"请确认 Out 在线并等待当前链结束后重试；本次未删除任何内容。")
			return
		}
		status, code, message, next := outBindingFailure(err)
		// A live subscription reference is the one refusal whose value is the
		// names: the operator has to know which subscription to migrate, and the
		// names are already public on the subscriber page.
		if code == store.CodeOutReferenced {
			if names := outReferencedSubscribers(err.Error()); names != "" {
				message = "该 Out 仍被订阅选中：" + names + "。"
			}
		}
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_DELETED")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Status      string `json:"status"`
		OutID       string `json:"out_id"`
		OperationID string `json:"operation_id"`
	}{Status: "deleted", OutID: outID, OperationID: operation(r)})
}

// outReferencedSubscribers extracts the subscription names from the store's
// OUT_REFERENCED_BY_SUBSCRIPTIONS refusal.
//
// The store builds that message as "<code>: out <id> is still selected by <names>;
// migrate those subscriptions first", so the names are the segment between the
// marker and the trailing clause. Only the display names come back: a name is
// already public on the subscriber page, while the node id and any SQL text stay
// out of the response. An unparsable message yields "" and the caller falls back to
// the generic text.
func outReferencedSubscribers(raw string) string {
	const marker = "is still selected by "
	index := strings.Index(raw, marker)
	if index < 0 {
		return ""
	}
	names := strings.TrimSpace(raw[index+len(marker):])
	if cut := strings.Index(names, ";"); cut >= 0 {
		names = names[:cut]
	}
	return strings.TrimSpace(names)
}
