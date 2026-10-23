package web

// The explicit release check and the gated approval of one target per node
// (#11c-1 Task 6).
//
// The check is the operator's "检查新版本" button: one authenticated request
// queries the latest published release tag and reports it as unverified. It
// stores nothing, starts nothing and is never a background task — a newer tag is
// a suggestion, not an approval.
//
// The approval is the only path that turns a suggestion into work. It resolves
// the requested version to the manifest this Hub can pin, runs the
// mixed-version, policy-schema and adjacency gates, then in ONE transaction
// stores a new candidate revision, the fixed four-task chain and the stamped
// target on that chain's pending config.stage row. A refusal stores nothing and
// leaves the previous revision live.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/jobs"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// Stable approval refusals of this task.
const (
	// codeUpgradeManifestUnavailable: no pinned manifest describes the
	// requested release, so the operator's tag is still only a suggestion. The
	// Hub never falls back to a cached or newer release.
	codeUpgradeManifestUnavailable = "MANIFEST_UNAVAILABLE"
	// codeUpgradeTargetInvalid: the requested version is not a SemVer release.
	codeUpgradeTargetInvalid = "UPGRADE_TARGET_INVALID"
	// codeUpgradeNotAdjacent: the target is not the immediate successor of the
	// node's approved chain; a skipped release would make rollback an
	// unverified N-2.
	codeUpgradeNotAdjacent = "UPGRADE_NOT_ADJACENT"
	// codeUpgradeAgentIncompatible: the node's read-back Agent version cannot
	// consume the candidate this target would publish. The Hub refuses instead
	// of forcing a mixed-version fleet.
	codeUpgradeAgentIncompatible = "UPGRADE_AGENT_INCOMPATIBLE"
	// codeUpgradeSchemaIncompatible: the target names another stored policy
	// schema, so it cannot be adopted by this Hub.
	codeUpgradeSchemaIncompatible = "UPGRADE_SCHEMA_INCOMPATIBLE"
)

// githubReleasesLatest is the only external address the check reads. It is a
// fixed constant: no request field, query parameter or task parameter selects a
// URL.
const githubReleasesLatest = "https://api.github.com/repos/wingsky-1/MeshMux/releases/latest"

// releaseClient bounds the operator-triggered check. A slow upstream is shown as
// unknown instead of holding the page.
var releaseClient = &http.Client{Timeout: 10 * time.Second}

// upgradeVersionPattern mirrors the SemVer shape jobs/upgrade/update enforce.
// Those packages do not export their regexp; all of them must change together.
var upgradeVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

// upgradeNodeIDPattern is the fixed node id shape, repeated here so a form field
// never reaches a query before its shape is checked.
var upgradeNodeIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// agentOperationIDPattern is the fixed operation id shape of the agent read. It
// is repeated here for the same reason: a path segment is validated before any
// query runs.
var agentOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// upgradeApproveReceipt is the typed approval result. It reports queued work and
// the pinned release, never that the target is installed.
type upgradeApproveReceipt struct {
	OK                   bool             `json:"ok"`
	Status               string           `json:"status"`
	Target               string           `json:"target,omitempty"`
	ManifestSHA256       string           `json:"manifest_sha256,omitempty"`
	PolicySchema         int              `json:"policy_schema"`
	RoutePolicyRevisions map[string]int64 `json:"route_policy_revisions"`
	Revision             int64            `json:"revision,omitempty"`
	StageOperationID     string           `json:"stage_operation_id,omitempty"`
	Tasks                []string         `json:"tasks,omitempty"`
	// Order is the upgrade sequence this approval belongs to. The Hub is first
	// (ruling U2): a new Hub is what lets a mixed-version fleet be decided per
	// node, so a node chain is queued after it, never instead of it.
	Order       []string `json:"order,omitempty"`
	ErrorCode   string   `json:"error_code,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	NextAction  string   `json:"next_action,omitempty"`
	OperationID string   `json:"operation_id"`
}

// tasksCheck is the explicit release check. It is a read-only GET: the response
// is the page with the unverified suggestion, and a failed query is shown as
// unknown rather than as a version.
func (app *Server) tasksCheck(w http.ResponseWriter, r *http.Request, sess session) {
	view, err := app.upgradeView(app.now())
	if err != nil {
		app.fail(w, r, 503, "UPGRADE_SNAPSHOT_UNAVAILABLE", "无法读取升级只读快照。", "请检查数据库后重试。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	release, err := app.latestRelease(ctx)
	if err != nil {
		view.CheckErr = "无法确认最新版本：发行源查询失败。"
	} else {
		view.Checked = strings.TrimPrefix(release, "v")
	}
	app.render(w, r, 200, upgradePage(pageData{Title: "任务与升级", Path: "/tasks", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, view))
}

// latestRelease reads the newest published release tag. It is a seam so the
// explicit check is testable without a network; production reads the fixed
// GitHub releases endpoint and accepts only a SemVer tag.
func (app *Server) latestRelease(ctx context.Context) (string, error) {
	if app.releaseSource != nil {
		return app.releaseSource(ctx)
	}
	return githubLatestRelease(ctx)
}

// githubLatestRelease reads one tag. The body is bounded and decoded, never
// echoed; a non-200 or a non-SemVer tag is unknown, not a release.
func githubLatestRelease(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubReleasesLatest, nil)
	if err != nil {
		return "", errors.New("RELEASE_QUERY_FAILED")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	response, err := releaseClient.Do(req)
	if err != nil {
		return "", errors.New("RELEASE_QUERY_FAILED")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("RELEASE_QUERY_FAILED")
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body); err != nil {
		return "", errors.New("RELEASE_QUERY_FAILED")
	}
	tag := strings.TrimPrefix(strings.TrimSpace(body.TagName), "v")
	if !upgradeVersionPattern.MatchString(tag) {
		return "", errors.New("RELEASE_QUERY_FAILED")
	}
	return tag, nil
}

// tasksApprove is the confirm step. It accepts exactly one node id and one
// version, resolves the version to the pinned manifest of this build, and
// enqueues the chain in one transaction with its stamped stage row.
func (app *Server) tasksApprove(w http.ResponseWriter, r *http.Request, _ session) {
	nodeID := strings.TrimSpace(r.PostForm.Get("node_id"))
	version := strings.TrimPrefix(strings.TrimSpace(r.PostForm.Get("version")), "v")
	if !upgradeNodeIDPattern.MatchString(nodeID) {
		app.writeUpgradeFailure(w, r, http.StatusBadRequest, codeUpgradeTargetInvalid,
			"节点标识不正确。", "请从任务页面的节点行重新提交批准。")
		return
	}
	if !upgradeVersionPattern.MatchString(version) {
		app.writeUpgradeFailure(w, r, http.StatusBadRequest, codeUpgradeTargetInvalid,
			"目标版本不是 SemVer 发行版。", "请重新检查新版本后再批准。")
		return
	}
	manifest, manifestSHA, err := pinnedManifest()
	if err != nil {
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeManifestUnavailable,
			"当前构建没有可验证的发行 manifest。", "请修复 Hub 构建后重试；未写入任何升级记录。")
		return
	}
	// The pin is the manifest this Hub can hand the Agent; a tag alone never
	// becomes a target.
	if manifest.Version != version {
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeManifestUnavailable,
			"该版本尚未有可验证的 manifest pin。", "latest 只是建议；请等待该发行提供 manifest 后再批准。")
		return
	}
	if manifest.PolicySchema != upgrade.PolicySchema {
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeSchemaIncompatible,
			"目标发行声明了另一套策略 schema。", "升级会破坏现有策略，已拒绝；当前修订保持不变。")
		return
	}
	target, err := app.store.approveUpgrade(nodeID, manifest, manifestSHA, app.now())
	if err != nil {
		app.failUpgradeApprove(w, r, err)
		return
	}
	app.event(r, "UPGRADE_APPROVED")
	app.writeJSON(w, http.StatusOK, upgradeApproveReceipt{
		OK: true, Status: "queued", Target: target.Version, ManifestSHA256: target.ManifestSHA256,
		PolicySchema: manifest.PolicySchema, RoutePolicyRevisions: routePolicySlots(manifest),
		Revision: target.CandidateRevision, StageOperationID: target.StageOperationID,
		Tasks: target.Tasks, Order: target.Order, OperationID: operation(r),
		NextAction: "已排队：候选与四任务链已同事务写入，stage 行带有固定目标；节点下次轮询才执行，queued 不等于已生效。",
	})
}

// approvedUpgrade is one stored approval.
type approvedUpgrade struct {
	jobs.Target
	StageOperationID string
	Tasks            []string
	Order            []string
}

// approveUpgrade is the single write path of an approval. Everything happens in
// one transaction: the new candidate revision, the fixed chain and the stamp.
func (s *store) approveUpgrade(nodeID string, manifest upgrade.Manifest, manifestSHA string, now time.Time) (approvedUpgrade, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return approvedUpgrade{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var observed string
	if err = tx.QueryRow(`SELECT observed_agent_version FROM nodes WHERE id=?`, nodeID).Scan(&observed); errors.Is(err, sql.ErrNoRows) {
		return approvedUpgrade{}, errors.New("NODE_NOT_FOUND")
	} else if err != nil {
		return approvedUpgrade{}, errors.New("DATABASE_UNAVAILABLE")
	}
	// Without a read-back version the Hub cannot prove which candidate schema
	// this node consumes, so it refuses instead of guessing. This is the same
	// rule the page applies by not offering the control.
	if observed == "" {
		return approvedUpgrade{}, errors.New("UPGRADE_AGENT_UNOBSERVED: the node has no read-back Agent version")
	}
	// Single flight: an unfinished chain owns the node, so a second approval
	// would replace work in progress. Checked inside the write transaction.
	var unfinished int
	if err = tx.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying')`,
		nodeID).Scan(&unfinished); err != nil {
		return approvedUpgrade{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if unfinished != 0 {
		return approvedUpgrade{}, errors.New("TASKS_IN_PROGRESS: the node has an unfinished task chain")
	}
	// Adjacency: the ordered history is the approved 11b chain (ruling U5), and
	// the current version is the node's own read-back — never
	// node.CurrentAgentVersion, which would never match a real release history.
	//
	// The Hub can only pin its own build, so at most one target is offerable at
	// a time; the rules below still matter because they refuse a chain that
	// disagrees with the read-back and they refuse a skip as soon as the history
	// names more than one release.
	history, err := approvedReleaseChainTx(tx, nodeID)
	if err != nil {
		return approvedUpgrade{}, err
	}
	if manifest.Version == observed {
		return approvedUpgrade{}, errors.New("UPGRADE_ALREADY_CURRENT: the node already runs the approved release")
	}
	if len(history) > 0 {
		current := history[len(history)-1]
		switch {
		case current == manifest.Version:
			// Retrying a release whose chain failed: the previous chain is
			// terminal (TASKS_IN_PROGRESS already cleared it), so a new attempt
			// is allowed and stays auditable as its own revision.
		case current != observed:
			return approvedUpgrade{}, errors.New(codeUpgradeNotAdjacent +
				": the node reports a version the approved chain never named")
		default:
			chain := append(append([]string(nil), history...), manifest.Version)
			if err := upgrade.AdjacentRelease(chain, current, manifest.Version); err != nil {
				return approvedUpgrade{}, err
			}
		}
	}
	revision, err := nextCandidateRevisionTx(tx, nodeID)
	if err != nil {
		return approvedUpgrade{}, err
	}
	candidate, err := buildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return approvedUpgrade{}, err
	}
	// An approval must not silently drop a route a policy publication already
	// resolved for this node: the new revision carries the same route forward,
	// so the data plane stays identical while the revision advances.
	if latest, err := candidateTx(tx, nodeID); err == nil && len(latest.Document.Route) > 0 {
		candidate.Route = append(json.RawMessage(nil), latest.Document.Route...)
	}
	if err := mixedVersionGate(candidate, observed); err != nil {
		return approvedUpgrade{}, err
	}
	tasks, err := publishCandidateTx(tx, nodeID, candidate, now)
	if err != nil {
		return approvedUpgrade{}, err
	}
	stageOperation := ""
	for _, task := range tasks {
		if task.Kind == protocol.KindConfigStage {
			stageOperation = task.OperationID
		}
	}
	if stageOperation == "" {
		return approvedUpgrade{}, errors.New("UPGRADE_CHAIN_INVALID: the fixed chain has no stage step")
	}
	target := jobs.Target{Version: manifest.Version, ManifestSHA256: manifestSHA,
		PolicySchema: manifest.PolicySchema, CandidateRevision: revision}
	// Same transaction as the enqueue: the first poll can never see an
	// unstamped pending row.
	if err := stampUpgradeTargetTx(tx, stageOperation, target, now); err != nil {
		return approvedUpgrade{}, err
	}
	if err := tx.Commit(); err != nil {
		return approvedUpgrade{}, errors.New("DATABASE_UNAVAILABLE")
	}
	out := approvedUpgrade{Target: target, StageOperationID: stageOperation, Order: []string{"hub", nodeID}}
	for _, task := range tasks {
		out.Tasks = append(out.Tasks, task.Kind)
	}
	return out, nil
}

// approvedReleaseChainTx is the transaction-scoped ordered history of the
// versions this node was approved for. Consecutive duplicates collapse, so a
// re-approval never fakes an extra release.
func approvedReleaseChainTx(tx *sql.Tx, nodeID string) ([]string, error) {
	rows, err := tx.Query(`SELECT target_version FROM agent_tasks
 WHERE node_id=? AND target_version<>'' ORDER BY revision ASC, updated_at ASC`, nodeID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	var history []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		if len(history) == 0 || history[len(history)-1] != version {
			history = append(history, version)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return history, nil
}

// mixedVersionGate refuses to publish a candidate the node's read-back Agent
// version cannot consume. A v3 document (one carrying a resolved route) needs a
// node that already reports this build; an unknown version counts as unable. A
// v1/v2 document stays publishable to an older fleet, so a mixed-version fleet
// keeps proxying instead of being force-upgraded.
func mixedVersionGate(candidate node.Candidate, observed string) error {
	if len(candidate.Route) == 0 {
		return nil
	}
	if observed != node.CurrentAgentVersion {
		return errors.New(codeUpgradeAgentIncompatible + ": the node cannot consume a v3 candidate")
	}
	return nil
}

// pinnedManifest returns this build's canonical manifest and its exact digest,
// the value the approval pins and the Agent later verifies.
func pinnedManifest() (upgrade.Manifest, string, error) {
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		return upgrade.Manifest{}, "", err
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return upgrade.Manifest{}, "", err
	}
	sum := sha256.Sum256(body)
	return manifest, hex.EncodeToString(sum[:]), nil
}

// routePolicySlots reports the manifest's target contract for the two layers. An
// absent slot is zero, never a live revision.
func routePolicySlots(manifest upgrade.Manifest) map[string]int64 {
	return map[string]int64{"client": manifest.RoutePolicyRevisions["client"], "server": manifest.RoutePolicyRevisions["server"]}
}

// writeUpgradeFailure writes the approval refusal in the management JSON shape.
func (app *Server) writeUpgradeFailure(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	app.event(r, code)
	app.writeJSON(w, status, upgradeApproveReceipt{
		Status: "failed", PolicySchema: upgrade.PolicySchema, RoutePolicyRevisions: map[string]int64{},
		ErrorCode: code, Detail: message, NextAction: next, OperationID: operation(r),
	})
}

// failUpgradeApprove maps one store refusal onto its status and operator hint.
// Every branch returns: the writer must never emit two JSON bodies for one
// request.
func (app *Server) failUpgradeApprove(w http.ResponseWriter, r *http.Request, err error) {
	code := err.Error()
	switch {
	case strings.HasPrefix(code, "TASKS_IN_PROGRESS"):
		app.writeUpgradeFailure(w, r, http.StatusConflict, "TASKS_IN_PROGRESS",
			"该节点仍有未结束的任务链。", "等待当前链结束或失败后再批准；已应用修订保持不变。")
	case strings.HasPrefix(code, codeUpgradeNotAdjacent):
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeNotAdjacent,
			"目标版本不是当前已批准版本的下一个发行版。", "请按发行顺序逐版批准；未写入任何升级记录。")
	case strings.HasPrefix(code, codeUpgradeAgentIncompatible):
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeAgentIncompatible,
			"节点回读的 Agent 版本无法消费该候选。", "请先升级该节点到理解该候选的版本；未下发任何内容。")
	case strings.HasPrefix(code, "NODE_NOT_FOUND"):
		app.writeUpgradeFailure(w, r, http.StatusNotFound, "NODE_NOT_FOUND",
			"节点不存在。", "请刷新任务页面后重试。")
	case strings.HasPrefix(code, "UPGRADE_ALREADY_CURRENT"):
		app.writeUpgradeFailure(w, r, http.StatusConflict, "UPGRADE_ALREADY_CURRENT",
			"该节点已运行该发行版本。", "无需重复升级；如需重装，请走重新复核流程。")
	case strings.HasPrefix(code, "UPGRADE_AGENT_UNOBSERVED"):
		app.writeUpgradeFailure(w, r, http.StatusConflict, "UPGRADE_AGENT_UNOBSERVED",
			"该节点尚未回读 Agent 版本。", "请先完成一次成功的配置回读，再批准升级。")
	case strings.HasPrefix(code, "UPGRADE_CHAIN_INVALID"), strings.HasPrefix(code, "CANDIDATE_INVALID"),
		strings.HasPrefix(code, "CANDIDATE_MISMATCH"):
		app.writeUpgradeFailure(w, r, http.StatusConflict, "UPGRADE_CHAIN_INVALID",
			"当前快照无法生成合法的升级链。", "请先复核该节点配置；未写入任何升级记录。")
	default:
		app.writeUpgradeFailure(w, r, http.StatusServiceUnavailable, "UPGRADE_APPROVAL_FAILED",
			"批准未完成。", "请凭操作编号检查服务日志；已应用修订保持不变。")
	}
}

// writeJSON is the management JSON writer of this task.
func (app *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
