package web

import (
	"encoding/json"
	"net/http"
	"runtime"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// agentManifest is the read-only manifest-to-node channel of the restricted
// executor (#11c-1). It serves exactly the pinned manifest of this Hub build:
// the body is never stored, never supplied by the caller and never stuffed into
// config.* task params, which stay frozen. An authenticated node receives
// application/json bytes; the agent client hands the body to the local update
// path, which treats the manifest SHA-256 pin as its trust anchor.
func (s *Server) agentManifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.agentAuth(w, r); !ok {
		return
	}
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		s.agentFail(w, r, 500, "MANIFEST_UNAVAILABLE", "当前架构没有固定的发行 manifest。", "请在受支持的 Debian 架构上重新构建 Hub。")
		return
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		s.agentFail(w, r, 500, "MANIFEST_UNAVAILABLE", "发行 manifest 无法编码。", "请重新构建 Hub。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
