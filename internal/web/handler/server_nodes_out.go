package handler

import (
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"net/http"
	"strings"
)

// The nodes-page Out actions (Task 2): the operator-facing HTML mutations
// behind the Out pool strip and the per-card transport/binding state. They
// wrap the same store calls as the JSON out-binding API and re-render the
// nodes page, so an operator never has to leave the list to configure the
// Out access path.
//
// The binding itself stays API-owned: creating a binding is the Task 4
// subscription wizard's job, so this page only configures the dial address,
// unbinds and deletes with an explicit used-by confirm.

// outTransportSet stores the dial address of one Out node. The port is taken
// from the node record itself, so it always matches the VLESS port by
// construction; only the server address comes from the form.
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

// outUnbindPage clears the Line of one Out and preserves the audit row. The
// released Line falls back to direct on its next convergence.
func (s *Server) outUnbindPage(w http.ResponseWriter, r *http.Request, sess session) {
	now := s.now()
	outID := strings.TrimSpace(r.PostForm.Get("out_id"))
	if err := s.store.ClearOutBindingAt(outID, now); err != nil {
		status, code, message, next := outBindingFailure(err)
		s.fail(w, r, status, code, message, next)
		return
	}
	s.event(r, "OUT_UNBOUND")
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "已解绑，该 Out 不再服务任何 Line。"})
}

// outDeletePage removes one Out from the routing model with an explicit
// used-by confirm. The first POST names the Out and re-renders the page with
// the impacted Line; only a second POST with confirm=1 deletes. The node
// identity is untouched: deleting the route is not revoking the host.
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
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "出口已删除，关联 Line 已恢复直连。"})
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
