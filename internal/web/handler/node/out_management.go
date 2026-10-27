package node

// The Out management API after the authorization migration (Task 5).
//
// Two endpoints were deleted with the binding table, because the state they
// edited no longer exists:
//
//	POST /nodes/out/bind   — selecting an Out is a subscription edit now. The
//	                         subscription wizard owns it as the single write
//	                         path, so this API could only create a second,
//	                         conflicting way to edit the same choice.
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
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
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
	case strings.HasPrefix(err.Error(), infra.CodeOutNotFound):
		return 404, infra.CodeOutNotFound, "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。"
	case strings.HasPrefix(err.Error(), infra.CodeOutRoleInvalid):
		return 409, infra.CodeOutRoleInvalid, "所选节点不是 Out 角色。", "请选择角色为 Out 的节点。"
	case strings.HasPrefix(err.Error(), infra.CodeLineNotFound):
		return 404, infra.CodeLineNotFound, "Line 节点不存在。", "请先在节点页纳管该 Line 后重试。"
	case strings.HasPrefix(err.Error(), infra.CodeLineRoleInvalid):
		return 409, infra.CodeLineRoleInvalid, "所选节点不是 Line 角色。", "请选择角色为 Edge 的 Line。"
	case strings.HasPrefix(err.Error(), store.CodeOutReferenced):
		return 409, store.CodeOutReferenced, "该 Out 仍被订阅选中。", "请在订阅向导中先解除这些订阅的 Out 选择，再删除出口。"
	case strings.HasPrefix(err.Error(), store.CodeOutSyncPending):
		// Defensive fallback only: no production caller reaches this case today.
		// Both delete handlers intercept ErrOutCleanupPending above and answer 409 (a
		// delete that cannot prove the guard is refused, never half-done), and
		// outUnbindPage explicitly skips OUT_SYNC_PENDING so it can render the pending
		// notice on the nodes page instead. The case is kept so an unexpected path
		// degrades to a stable code instead of OUT_MANAGEMENT_FAILED; the wording says
		// only that the hub-side publication is still unconfirmed — under Ruling R10 the
		// set being published is the node membership, not an empty authorization.
		return 202, store.CodeOutSyncPending, "该 Out 授权的下发待同步。", "Out 上线后会自动完成；也可在节点页重试。"
	case strings.HasPrefix(err.Error(), infra.CodeOutBindingInvalid):
		return 400, infra.CodeOutBindingInvalid, "Out 参数不正确。", "请检查 Out 标识后重试。"
	case strings.HasPrefix(err.Error(), store.CodeDatabaseUnavailable):
		return 503, store.CodeDatabaseUnavailable, "无法读写 Out 状态。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "OUT_MANAGEMENT_FAILED", "Out 操作未完成。", "请凭操作编号检查服务日志。"
	}
}

// outBindingAPIRetired answers the two deleted routes with one stable code and the
// replacement action, so an old client cannot mistake the refusal for a typo.
//
// Both routes edited the binding that no longer exists. The authorization itself is
// node membership (Ruling R10), which no request can edit; what the operator configures
// through the wizard is which egress a client document names.
func (s *Server) outBindingAPIRetired(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	s.Fail(w, r, http.StatusGone, CodeBindingAPIRetired,
		"该接口已移除：Out 授权来自节点成员（纳管即互通），不再由绑定或订阅写入。",
		"若要让客户端走该 Out，请在订阅向导中选择它；若要让某条 Line 不再被 Out 接受，请吊销该 Line 身份。")
}

// outDelete removes one Out entirely: its ACL is brought back to default-deny, then the
// node row, the dial address and the Hub-issued link key are deleted (Ruling R9).
//
// The delete is a management action with the same infra.Session + CSRF boundary as every
// other mutation. Success means the host proved the empty authorization and the node is
// gone. A delete that cannot reach that state is refused with nothing destroyed — it is
// never reported as a partial success, because once the row disappears there is nothing
// left to retry from.
func (s *Server) outDelete(w http.ResponseWriter, r *http.Request, _ infra.Session) {
	now := s.Now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	if err := s.Store.DeleteOutAt(outID, now); err != nil {
		if errors.Is(err, store.ErrOutCleanupPending) {
			// Nothing was destroyed (Ruling R9): the host has not proved the empty guard
			// yet, so the delete is a refusal, not a partial success. Reporting 202 here
			// would let an operator believe the Out is gone while its row still exists.
			s.Event(r, store.CodeOutSyncPending)
			s.Fail(w, r, 409, store.CodeOutSyncPending,
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
		s.Fail(w, r, status, code, message, next)
		return
	}
	s.Event(r, "OUT_DELETED")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Status      string `json:"status"`
		OutID       string `json:"out_id"`
		OperationID string `json:"operation_id"`
	}{Status: "deleted", OutID: outID, OperationID: infra.Operation(r)})
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
