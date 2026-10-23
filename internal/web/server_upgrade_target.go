package web

// The read-only upgrade-target channel of the restricted executor (#11c-1).
//
// The stamped target cannot travel in the task envelope: config.* params are
// frozen to revision/allowed_sources. The Agent therefore reads its own stamp
// over the authenticated agent channel, exactly like the manifest body, and
// never receives a URL or a path from the Hub.
//
// The read is deliberately not pending-only. The stamp is written while the row
// is pending, but the Agent may poll after the Hub has already recorded a
// result, so filtering on status would lose the target. An unstamped row is
// simply "no upgrade" (404).

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// agentUpgradeTarget serves one stamped target to the node that owns the row.
// Another node's row is not found, so the channel never discloses that some
// other node is being upgraded.
func (s *Server) agentUpgradeTarget(w http.ResponseWriter, r *http.Request) {
	n, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.agentFail(w, r, 400, "QUERY_REJECTED", "升级目标端点不接受查询参数。", "请使用固定的 operation_id 路径。")
		return
	}
	operationID := strings.TrimSpace(chi.URLParam(r, "operationID"))
	if !agentOperationIDPattern.MatchString(operationID) {
		s.agentFail(w, r, 400, "OPERATION_ID_INVALID", "操作编号不正确。", "请从固定任务获取 operation_id。")
		return
	}
	target, found, err := s.store.stampedStageTarget(n.ID, operationID)
	if err != nil {
		s.agentFail(w, r, 500, "UPGRADE_TARGET_UNAVAILABLE", "升级目标无法读取。", "请检查数据库后重试。")
		return
	}
	if !found {
		s.agentFail(w, r, 404, "UPGRADE_TARGET_NOT_FOUND", "该任务没有固定的升级目标。", "普通配置任务请直接按任务参数执行。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write([]byte(`{"target_version":"` + target.Version + `","manifest_sha256":"` + target.ManifestSHA256 + `"}` + "\n"))
}
