package node

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
	"strconv"
	"strings"
)

// outTransportSet stores the dial address of one Out node. The port is taken from
// the node record itself, so it always matches the VLESS port by construction; only
// the server address comes from the form.
//
// Flow: parse (out_id, server) → load the node (404 when unknown) → store the
// transport → re-render the page with the receipt. The port never comes from the
// form, so the stored pair cannot disagree with the VLESS listener.
func (s *Server) outTransportSet(w http.ResponseWriter, r *http.Request, sess infra.Session) {
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

// httpProxySet replaces the dial body of one external HTTP proxy. It is the
// exact twin of outTransportSet: a changed URL must converge the Lines that
// render it, which is why the store drains them after its own commit. The
// external proxy has no Agent, so there is no chain to wait for — only the
// Line candidates that embed the new endpoint.
func (s *Server) httpProxySet(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	now := s.Now()
	proxyID := strings.TrimSpace(r.PostForm.Get("out_id"))
	proxyURL := strings.TrimSpace(r.PostForm.Get("proxy_url"))
	proxy, err := s.Store.SetHTTPProxy(proxyID, proxyURL, now)
	if err != nil {
		s.Event(r, "HTTP_PROXY_UPDATE_FAILED")
		status, code, message, next := httpProxyUpdateFailure(err)
		s.Fail(w, r, status, code, message, next)
		return
	}
	s.Event(r, "HTTP_PROXY_UPDATED")
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{
		Notice: "HTTP 代理已更新为 " + proxyAddress(proxy.Server, proxy.Port) + "（外部声明）。",
	})
}

// proxyAddress renders host:port without ever including credentials.
func proxyAddress(server string, port int) string {
	return server + ":" + strconv.Itoa(port)
}

// outUnbindPage releases the Lines an Out serves by removing the Out choice from the
// subscriptions that selected it.
//
// This is the HTML twin of the retired JSON unbind endpoint, but it does not silently
// mutate subscriptions: an Out with a live reference has to be migrated by the operator,
// and the page names the subscriptions so the action is explicit. Under Ruling R10 the
// release changes only which egress the client document names — the Out admits
// by link key and has no source allowlist to rewrite.
// membership and is untouched — so an Out no subscription selects is already unbound and
// this call is an idempotent no-op that publishes nothing.
func (s *Server) outUnbindPage(w http.ResponseWriter, r *http.Request, sess infra.Session) {
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
			"请在订阅向导中取消这些订阅的 Out 选择后重试。Out 按订阅下发的 link key 接入，订阅选择变化不会改变 Out 本身的凭据。")
		return
	}
	// Nothing selects it. The source allowlist is retired, so this action cannot
	// revoke access: the Out still admits any client that presents the link key
	// its own candidate publishes. All this call can do is reconcile that chain,
	// which is a no-op when the newest revision already matches; a chain still in
	// flight defers the republish, so the page reports the pending state instead
	// of an error the operator cannot fix.
	//
	// An external HTTP proxy has no chain, no ACL and no readback at all (Ruling
	// R11): the drain answers OUT_SYNC_NOT_APPLICABLE, which is an explicit no-op
	// rather than a failure and rather than a silent success. The page says so.
	retryErr := s.Store.RetryOutSync(outID, now)
	if retryErr != nil && strings.HasPrefix(retryErr.Error(), store.CodeOutSyncNotApplicable) {
		s.Event(r, store.CodeOutSyncNotApplicable)
		s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{
			Notice: "已解除：还没有订阅使用这个 HTTP 代理（OUT_SYNC_NOT_APPLICABLE）；本次未下发任何任务。",
		})
		return
	}
	if retryErr != nil && !strings.HasPrefix(retryErr.Error(), store.CodeOutSyncPending) {
		status, code, message, next := outBindingFailure(retryErr)
		s.Fail(w, r, status, code, message, next)
		return
	}
	s.Event(r, "OUT_UNBOUND")
	notice := "已解除：还没有订阅使用这个出口。Out 仍按 link key 接受订阅者；本次只重新下发 Out 自身配置。"
	if retryErr != nil {
		s.Event(r, store.CodeOutSyncPending)
		notice = "已解除：还没有订阅使用这个出口。Out 仍按 link key 接受订阅者；本次下发待同步，Out 上线后自动完成。"
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
func (s *Server) outDeletePage(w http.ResponseWriter, r *http.Request, sess infra.Session) {
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
	notice := "出口已删除：节点、出口地址与签发的 key 一并清除；使用它的订阅在下次下载时拿到新配置。"
	if role == infra.NodeRoleHTTP {
		notice = "HTTP 代理节点已删除：节点与保存的 URL/凭据一并清除；使用它的订阅在下次下载时拿到新配置。"
	}
	s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: notice})
}

// outPreview is a read-only projection. It goes through the mutation wrapper only
// to require the same infra.Session + CSRF boundary as every management POST; it never
// writes a row.
//
// The projection answers "which enrolled Lines does this Out accept, and which sources
// would the Agent be told to allow", derived from node membership (Ruling R10). A
// subscription that selects the Out is reported only as a used-by name for the delete
// guard; it never contributes a source. A single-Line projection is never reported as
// an established path: nothing has been published for it yet.
func (s *Server) outPreview(w http.ResponseWriter, r *http.Request, _ infra.Session) {
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
		return 500, "OUT_TRANSPORT_FAILED", "出口地址未保存。", "请稍后重试。"
	case strings.HasPrefix(err.Error(), infra.CodeOutNotFound):
		return 404, infra.CodeOutNotFound, "Out 节点不存在。", "请先在节点页纳管该 Out 后重试。"
	case strings.HasPrefix(err.Error(), infra.CodeOutRoleInvalid):
		return 409, infra.CodeOutRoleInvalid, "所选节点不是 Out 角色。", "请选择角色为 Out 的节点。"
	case strings.HasPrefix(err.Error(), infra.CodeOutBindingInvalid):
		return 400, infra.CodeOutBindingInvalid, "节点标识不正确。", "请检查所选 Out 后重试。"
	case strings.HasPrefix(err.Error(), store.CodeDatabaseUnavailable):
		return 503, store.CodeDatabaseUnavailable, "无法读写 Out 传输参数。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "OUT_TRANSPORT_FAILED", "出口地址未保存。", "请稍后重试。"
	}
}

// httpProxyUpdateFailure maps one proxy-update refusal onto the stable HTTP
// contract. The submitted URL and its userinfo never reach the response: the
// success notice renders host:port only.
func httpProxyUpdateFailure(err error) (status int, code, message, next string) {
	switch {
	case strings.HasPrefix(err.Error(), "HTTP_PROXY_INVALID"):
		return 400, "HTTP_PROXY_INVALID", "HTTP 代理 URL 不正确。", "请填写一个 http://主机:端口 的 URL，可带用户名与密码，不要带路径或查询参数。"
	case strings.HasPrefix(err.Error(), "HTTP_PROXY_UPDATE_FAILED"):
		return 500, "HTTP_PROXY_UPDATE_FAILED", "HTTP 代理 URL 未保存。", "请稍后重试。"
	case strings.HasPrefix(err.Error(), "OUT_NOT_FOUND"):
		return 404, "OUT_NOT_FOUND", "出口节点不存在。", "请先在节点页纳管该 HTTP 代理后重试。"
	case strings.HasPrefix(err.Error(), "OUT_ROLE_INVALID"):
		return 409, "OUT_ROLE_INVALID", "所选节点不是 HTTP 代理。", "请选择角色为 HTTP 代理的节点。"
	case strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID"):
		return 400, "OUT_BINDING_INVALID", "节点标识不正确。", "请检查所选节点后重试。"
	case strings.HasPrefix(err.Error(), store.CodeDatabaseUnavailable):
		return 503, store.CodeDatabaseUnavailable, "无法读写 HTTP 代理参数。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "HTTP_PROXY_UPDATE_FAILED", "HTTP 代理 URL 未保存。", "请稍后重试。"
	}
}
