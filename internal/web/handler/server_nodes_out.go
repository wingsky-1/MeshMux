package handler

// The nodes-page Out actions and the read-only Out preview.
//
// Out authorization is node membership (Ruling R10): every enrolled Line is accepted
// by every enrolled Out, and a subscription edit never touches the ACL. This file
// therefore owns only the dial address and the delete (Ruling R9, which removes the
// node, its dial address and its link key), and answers the read-only preview from the
// same membership projection the rest of the Hub reads.

import (
	"encoding/json"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"net/http"
	"strings"
)

// outTransportSet stores the dial address of one Out node. The port is taken from
// the node record itself, so it always matches the VLESS port by construction; only
// the server address comes from the form.
//
// Flow: parse (out_id, server) → load the node (404 when unknown) → store the
// transport → re-render the page with the receipt. The port never comes from the
// form, so the stored pair cannot disagree with the VLESS listener.
func (s *Server) outTransportSet(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.Now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	server := strings.TrimSpace(r.PostForm.Get("server"))
	node, err := s.Store.GetNodeAt(outID, now)
	if err != nil {
		if strings.HasPrefix(err.Error(), infra.CodeNodeNotFound) {
			s.Fail(w, r, 404, infra.CodeOutNotFound, "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。")
			return
		}
		s.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取节点。", "请检查数据库。")
		return
	}
	transport, err := s.Store.SetOutTransport(outID, server, node.VlessPort, now)
	if err != nil {
		status, code, message, next := outTransportFailure(err)
		s.Fail(w, r, status, code, message, next)
		return
	}
	s.Event(r, "OUT_TRANSPORT_SET")
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "Out 出口地址已保存为 " + transport.Server + "。"})
}

// outUnbindPage releases the Lines an Out serves by removing the Out choice from the
// subscriptions that selected it.
//
// This is the HTML twin of the retired JSON unbind endpoint, but it does not silently
// mutate subscriptions: an Out with a live reference has to be migrated by the operator,
// and the page names the subscriptions so the action is explicit. Under Ruling R10 the
// release changes only which egress the client document names — the ACL is node
// membership and is untouched — so an Out no subscription selects is already unbound and
// this call is an idempotent no-op that publishes nothing.
func (s *Server) outUnbindPage(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.Now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	usedBy, err := s.Store.OutAuthorizedSubscribers(outID)
	if err != nil {
		status, code, message, next := outBindingFailure(err)
		s.Fail(w, r, status, code, message, next)
		return
	}
	if len(usedBy) > 0 {
		s.Event(r, store.CodeOutReferenced)
		s.Fail(w, r, 409, store.CodeOutReferenced,
			"该 Out 仍被订阅选中："+strings.Join(usedBy, "、")+"。",
			"请在订阅向导中取消这些订阅的 Out 选择后重试。ACL 由节点成员制决定（纳管即互通），订阅变更不会重算 ACL。")
		return
	}
	// Nothing selects it. This action does NOT empty the Out's allowlist: under
	// Ruling R10 the authorization is node membership, so publishing here re-derives
	// the member set (which is non-empty as long as any Line is enrolled). All this
	// call can do is republish the current authorization, which is a no-op when the
	// newest chain already carries it; a chain still in flight defers the republish —
	// the intent is durable and the next Out event completes it, so the page reports
	// the pending state instead of an error the operator cannot fix.
	retryErr := s.Store.RetryOutSync(outID, now)
	if retryErr != nil && !strings.HasPrefix(retryErr.Error(), store.CodeOutSyncPending) {
		status, code, message, next := outBindingFailure(retryErr)
		s.Fail(w, r, status, code, message, next)
		return
	}
	s.Event(r, "OUT_UNBOUND")
	notice := "已解除：没有任何订阅选中该 Out。Out 的 ACL 由节点成员制决定（纳管即互通），订阅变更不会重算 ACL；本次已按当前成员集重新下发。"
	if retryErr != nil {
		s.Event(r, store.CodeOutSyncPending)
		notice = "已解除：没有任何订阅选中该 Out。Out 的 ACL 由节点成员制决定，订阅变更不会重算 ACL；本次下发的确认待同步（OUT_SYNC_PENDING），Out 上线后自动完成。"
	}
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: notice})
}

// outDeletePage removes one Out entirely with an explicit used-by confirm. The first
// POST names the Out and re-renders the page with the impacted Lines; only a second
// POST with confirm=1 deletes.
//
// Deleting is not revoking the host: the identity is untouched, but the routing model,
// the dial parameters and the link key are all gone (Ruling R9), so a later use means
// enrolling the Out again.
func (s *Server) outDeletePage(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.Now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	if r.PostForm.Get("confirm") != "1" {
		node, err := s.Store.GetNodeAt(outID, now)
		if err != nil {
			if strings.HasPrefix(err.Error(), infra.CodeNodeNotFound) {
				s.Fail(w, r, 404, infra.CodeOutNotFound, "出口节点不存在。", "请先在节点页纳管该出口后重试。")
				return
			}
			s.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取节点。", "请检查数据库。")
			return
		}
		if node.Role != infra.NodeRoleOut && node.Role != infra.NodeRoleHTTP {
			s.Fail(w, r, 409, "OUT_ROLE_INVALID", "所选节点不是出口角色。", "请选择角色为 Out 或 HTTP 代理的节点。")
			return
		}
		s.Event(r, "OUT_DELETE_PENDING")
		s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{PendingDeleteOut: outID})
		return
	}
	role := ""
	if node, err := s.Store.GetNodeAt(outID, now); err == nil {
		role = node.Role
	}
	if err := s.Store.DeleteOutAt(outID, now); err != nil {
		if errors.Is(err, store.ErrOutCleanupPending) {
			// Nothing was destroyed (Ruling R9). The JSON endpoint answers the same way:
			// a deferral is a refusal, because once the node row is gone there is nothing
			// left to retry from. Reporting "route deleted" here would be a lie.
			s.Event(r, store.CodeOutSyncPending)
			s.Fail(w, r, 409, store.CodeOutSyncPending,
				"删除未执行：该 Out 尚未确认清空授权（可能离线，或仍有未完成的链）。",
				"请确认该 Out 在线并等待当前链结束后重试；本次未删除任何内容。")
			return
		}
		status, code, message, next := outBindingFailure(err)
		if code == store.CodeOutReferenced {
			if names := outReferencedSubscribers(err.Error()); names != "" {
				message = "该出口仍被订阅选中：" + names + "。"
			}
		}
		s.Fail(w, r, status, code, message, next)
		return
	}
	s.Event(r, "OUT_DELETED")
	notice := "出口已彻底删除：节点行、出口地址与 link key 均已清除；引用过它的 Line 路由已按 fail-closed 重算。"
	if role == infra.NodeRoleHTTP {
		notice = "HTTP 代理节点已彻底删除：节点行与存储的 URL/凭据均已清除；引用过它的 Line 路由已按 fail-closed 重算。"
	}
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: notice})
}

// outPreview is a read-only projection. It goes through the mutation wrapper only
// to require the same session + CSRF boundary as every management POST; it never
// writes a row.
//
// The projection answers "which enrolled Lines does this Out accept, and which sources
// would the Agent be told to allow", derived from node membership (Ruling R10). A
// subscription that selects the Out is reported only as a used-by name for the delete
// guard; it never contributes a source. A single-Line projection is never reported as
// an established path: nothing has been published for it yet.
func (s *Server) outPreview(w http.ResponseWriter, r *http.Request, _ session) {
	preview, err := s.Store.PreviewOutAuthorization(
		strings.TrimSpace(r.PostForm.Get("out_id")),
		strings.TrimSpace(r.PostForm.Get("line_id")),
	)
	if err != nil {
		status, code, message, next := outBindingFailure(err)
		s.Fail(w, r, status, code, message, next)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		store.OutAuthorizationPreview
		OperationID string `json:"operation_id"`
	}{OutAuthorizationPreview: preview, OperationID: infra.Operation(r)})
}

// outTransportFailure maps one transport-store refusal onto the stable HTTP
// contract. It never echoes the submitted address beyond the success notice;
// failure bodies carry only the code, the message and the next action.
func outTransportFailure(err error) (status int, code, message, next string) {
	switch {
	case strings.HasPrefix(err.Error(), "OUT_TRANSPORT_INVALID"):
		return 400, "OUT_TRANSPORT_INVALID", "出口地址不正确。", "请填写一个主机名或 IP 地址，不要带 scheme、路径或端口。"
	case strings.HasPrefix(err.Error(), "OUT_PORT_MISMATCH"):
		return 409, "OUT_PORT_MISMATCH", "出口端口与节点 VLESS 端口不一致。", "请确认 Out 节点的 VLESS 端口后重试。"
	case strings.HasPrefix(err.Error(), "OUT_TRANSPORT_FAILED"):
		return 500, "OUT_TRANSPORT_FAILED", "出口地址未保存。", "请凭操作编号检查服务日志后重试。"
	case strings.HasPrefix(err.Error(), infra.CodeOutNotFound):
		return 404, infra.CodeOutNotFound, "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。"
	case strings.HasPrefix(err.Error(), infra.CodeOutRoleInvalid):
		return 409, infra.CodeOutRoleInvalid, "所选节点不是 Out 角色。", "请选择角色为 Out 的节点。"
	case strings.HasPrefix(err.Error(), infra.CodeOutBindingInvalid):
		return 400, infra.CodeOutBindingInvalid, "节点标识不正确。", "请检查所选 Out 后重试。"
	case strings.HasPrefix(err.Error(), store.CodeDatabaseUnavailable):
		return 503, store.CodeDatabaseUnavailable, "无法读写 Out 传输参数。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "OUT_TRANSPORT_FAILED", "出口地址未保存。", "请凭操作编号检查服务日志后重试。"
	}
}
