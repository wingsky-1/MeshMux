package handler

import (
	"encoding/json"
	"net/http"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// agentManifest is the read-only manifest-to-node channel of the restricted
// executor (#11c-1). It serves this Hub build's pinned dual-arch set (U4): the
// body is never stored, never supplied by the caller and never stuffed into
// config.* task params, which stay frozen. Each embedded architecture table is
// byte-identical to upgrade.ForArch(arch), so an authenticated node can select
// its own runtime.GOARCH projection and hand exactly those bytes to the local
// update path, which treats the per-arch manifest SHA-256 pin as its trust
// anchor. No query parameter or request field selects an architecture or a
// version.
func (s *Server) agentManifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.agentAuth(w, r); !ok {
		return
	}
	set, err := upgrade.ForArchSet()
	if err != nil {
		s.agentFail(w, r, 500, "MANIFEST_UNAVAILABLE", "当前构建没有固定的双架构发行 manifest。", "请在受支持的 Debian 架构上重新构建 Hub。")
		return
	}
	body, err := json.Marshal(set)
	if err != nil {
		s.agentFail(w, r, 500, "MANIFEST_UNAVAILABLE", "发行 manifest 无法编码。", "请重新构建 Hub。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
