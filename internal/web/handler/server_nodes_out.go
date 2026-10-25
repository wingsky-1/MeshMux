package handler

// The nodes-page Out actions and the read-only Out preview.
//
// After Task 5 the Out authorization is derived from the subscription edges, so
// this file no longer edits a binding. It keeps the two operations the nodes page
// really owns — the dial address and the delete — and answers the read-only
// preview from the same projection the wizard uses.

import (
	"encoding/json"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"net/http"
	"strings"
)

// outTransportSet stores the dial address of one Out node. The port is taken from
// the node record itself, so it always matches the VLESS port by construction; only
// the server address comes from the form.
func (s *Server) outTransportSet(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	server := strings.TrimSpace(r.PostForm.Get("server"))
	node, err := s.store.GetNodeAt(outID, now)
	if err != nil {
		if strings.HasPrefix(err.Error(), "NODE_NOT_FOUND") {
			s.fail(w, r, 404, "OUT_NOT_FOUND", "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。")
			return
		}
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点。", "请检查数据库。")
		return
	}
	transport, err := s.store.SetOutTransport(outID, server, node.VlessPort, now)
	if err != nil {
		status, code, message, next := outTransportFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_TRANSPORT_SET")
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "Out 出口地址已保存为 " + transport.Server + "。"})
}

// outUnbindPage releases the Lines an Out serves by removing the Out choice from
// the subscriptions that selected it.
//
// This is the HTML twin of the retired JSON unbind endpoint, but it does not
// silently mutate subscriptions: an Out with a live reference has to be migrated by
// the operator, and the page names the subscriptions so the action is explicit. An
// Out no subscription selects is already unbound, so the call is an idempotent
// no-op that republishes nothing.
func (s *Server) outUnbindPage(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	usedBy, err := s.store.OutAuthorizedSubscribers(outID)
	if err != nil {
		status, code, message, next := outBindingFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	if len(usedBy) > 0 {
		s.event(r, store.CodeOutReferenced)
		s.fail(w, r, 409, store.CodeOutReferenced,
			"该 Out 仍被订阅选中："+strings.Join(usedBy, "、")+"。",
			"请在订阅向导中取消这些订阅的 Out 选择；ACL 会随订阅自动重算。")
		return
	}
	// Nothing selects it: republish the empty guard so a host that still carries
	// the last authorization is brought back to default-deny. The drain is a no-op
	// when the newest chain already names the empty set, and a chain still in
	// flight defers the republish — the intent is already durable and the next Out
	// event completes it, so the page reports the pending state instead of an error
	// the operator cannot fix.
	retryErr := s.store.RetryOutSync(outID, now)
	if retryErr != nil && !strings.HasPrefix(retryErr.Error(), store.CodeOutSyncPending) {
		status, code, message, next := outBindingFailure(retryErr)
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_UNBOUND")
	notice := "已解除：没有任何订阅选中该 Out，ACL 已按空授权重算。"
	if retryErr != nil {
		s.event(r, store.CodeOutSyncPending)
		notice = "已解除：没有任何订阅选中该 Out；主机 ACL 的空授权下发待同步（OUT_SYNC_PENDING），Out 上线后自动完成。"
	}
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: notice})
}

// outDeletePage removes one Out from the routing model with an explicit used-by
// confirm. The first POST names the Out and re-renders the page with the impacted
// Lines; only a second POST with confirm=1 deletes. The node identity is untouched:
// deleting the route is not revoking the host.
func (s *Server) outDeletePage(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	if r.PostForm.Get("confirm") != "1" {
		node, err := s.store.GetNodeAt(outID, now)
		if err != nil {
			if strings.HasPrefix(err.Error(), "NODE_NOT_FOUND") {
				s.fail(w, r, 404, "OUT_NOT_FOUND", "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。")
				return
			}
			s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点。", "请检查数据库。")
			return
		}
		if node.Role != "out" {
			s.fail(w, r, 409, "OUT_ROLE_INVALID", "所选节点不是 Out 角色。", "请选择角色为 Out 的节点。")
			return
		}
		s.event(r, "OUT_DELETE_PENDING")
		s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{PendingDeleteOut: outID})
		return
	}
	if err := s.store.DeleteOutAt(outID, now); err != nil {
		if errors.Is(err, store.ErrOutCleanupPending) {
			s.event(r, store.CodeOutSyncPending)
			s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "路由已删除，主机清理待同步（OUT_SYNC_PENDING）：Out 上线后自动完成。"})
			return
		}
		status, code, message, next := outBindingFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_DELETED")
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "出口已删除；订阅未选中它，因此没有任何 Line 需要恢复直连。"})
}

// outPreview is a read-only projection. It goes through the mutation wrapper only
// to require the same session + CSRF boundary as every management POST; it never
// writes a row.
//
// The projection answers "which Lines would this Out serve if the operator selected
// it", derived from the same subscription edges the allowlist uses. A proposal is
// never reported as an established path: nothing has been published for it yet.
func (s *Server) outPreview(w http.ResponseWriter, r *http.Request, _ session) {
	preview, err := s.store.PreviewOutAuthorization(
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
		store.OutAuthorizationPreview
		OperationID string `json:"operation_id"`
	}{OutAuthorizationPreview: preview, OperationID: operation(r)})
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
	case strings.HasPrefix(err.Error(), "OUT_NOT_FOUND"):
		return 404, "OUT_NOT_FOUND", "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。"
	case strings.HasPrefix(err.Error(), "OUT_ROLE_INVALID"):
		return 409, "OUT_ROLE_INVALID", "所选节点不是 Out 角色。", "请选择角色为 Out 的节点。"
	case strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID"):
		return 400, "OUT_BINDING_INVALID", "节点标识不正确。", "请检查所选 Out 后重试。"
	case strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE"):
		return 503, "DATABASE_UNAVAILABLE", "无法读写 Out 传输参数。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "OUT_TRANSPORT_FAILED", "出口地址未保存。", "请凭操作编号检查服务日志后重试。"
	}
}
