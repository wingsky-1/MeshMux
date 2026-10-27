package upgrade

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
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// agentUpgradeTarget serves one stamped target to the node that owns the row.
// Another node's row is not found, so the channel never discloses that some
// other node is being upgraded.
//
// Flow: Bearer auth → reject query strings → validate the path's operation id
// against the frozen grammar (isValidOperationID) → read the stamp → answer
// one two-field JSON document. Both values were validated by
// stampedStageTarget (SemVer + 64 lowercase hex), so encoding is a formality;
// it is still the encoder rather than string concatenation, so a future field
// can never break the document.
func (s *Server) agentUpgradeTarget(w http.ResponseWriter, r *http.Request) {
	n, ok := s.nodeAuth.AgentAuth(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.nodeAuth.AgentFail(w, r, 400, "QUERY_REJECTED", "升级目标端点不接受查询参数。", "请使用固定的 operation_id 路径。")
		return
	}
	operationID := strings.TrimSpace(chi.URLParam(r, "operationID"))
	if !infra.IsValidOperationID(operationID) {
		s.nodeAuth.AgentFail(w, r, 400, "OPERATION_ID_INVALID", "操作编号不正确。", "请从固定任务获取 operation_id。")
		return
	}
	target, found, err := s.Store.StampedStageTarget(n.ID, operationID)
	if err != nil {
		s.nodeAuth.AgentFail(w, r, 500, "UPGRADE_TARGET_UNAVAILABLE", "升级目标无法读取。", "请检查数据库后重试。")
		return
	}
	if !found {
		s.nodeAuth.AgentFail(w, r, 404, "UPGRADE_TARGET_NOT_FOUND", "该任务没有固定的升级目标。", "普通配置任务请直接按任务参数执行。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	// Both values were validated by stampedStageTarget (SemVer + 64 lowercase
	// hex), so encoding is a formality; it is still the encoder rather than
	// string concatenation, so a future field can never break the document.
	_ = json.NewEncoder(w).Encode(struct {
		TargetVersion  string `json:"target_version"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}{TargetVersion: target.Version, ManifestSHA256: target.ManifestSHA256})
}
