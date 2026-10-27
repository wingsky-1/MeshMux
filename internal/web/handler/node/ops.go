package node

// The /logs diagnostics page: the single home of operational detail.
//
// Business pages keep revisions, readback versions, task chains and error
// codes off their cards; this page reads the same node rows and shows that
// detail as read-only diagnostics. It is a page render with the standard
// authenticated boundary, no mutation.

import (
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"net/http"
)

// OpsPage renders the 日志与诊断 page with every enrolled node's operational
// detail. Failures degrade to the stable database refusal; nothing is mutated.
func (s *Server) OpsPage(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	nodes, err := s.Store.ListNodesAt(s.Now())
	if err != nil {
		s.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取节点列表。", "请检查数据库与服务日志后重试。")
		return
	}
	if nodes == nil {
		nodes = []store.Node{}
	}
	s.Render(w, r, 200, view.OpsPage(view.PageData{Title: "日志与诊断", Path: "/logs", CSRF: sess.CSRF, Dev: s.Cfg.DevHTTP}, nodes, s.Cfg.InstallArtifact))
}
