package handler

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
//
// Until 11d (Hub self-upgrade) ships with real release pins, this Hub can pin
// only the release it runs, so a target newer than the running build cannot be
// approved (MANIFEST_UNAVAILABLE). A node already reporting the running build is
// refused as UPGRADE_ALREADY_CURRENT. A node whose read-back is older — for
// example a fleet node recorded by a previous Hub build and still persisted in
// observed_agent_version — can be approved to the running build and queues
// normally; that is an intended path today, and the mixed-version, retry and
// adjacency branches below govern it. Those branches are not conditionally
// reachable code: they run on every lagging-node approval.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

// Stable approval refusals of this task. The literals live in codes.go so a
// second handler never re-spells them.
const (
	// codeUpgradeManifestUnavailable: no pinned manifest describes the
	// requested release, so the operator's tag is still only a suggestion. The
	// Hub never falls back to a cached or newer release.
	codeUpgradeManifestUnavailable = codeManifestUnavailable
	// codeUpgradeTargetInvalid: the requested version is not a SemVer release.
	codeUpgradeTargetInvalid = "UPGRADE_TARGET_INVALID"
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
	// There is deliberately no "order"/"hub first" field: only the node's own
	// four-task chain is enqueued. The Hub upgrades itself in 11d, and until
	// then a receipt must not advertise an order it did not create.
	ErrorCode   string `json:"error_code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	NextAction  string `json:"next_action,omitempty"`
	OperationID string `json:"operation_id"`
}

// tasksCheck is the explicit release check. It is a read-only GET: the response
// is the page with the unverified suggestion, and a failed query is shown as
// unknown rather than as a version.
func (app *Server) tasksCheck(w http.ResponseWriter, r *http.Request, sess session) {
	page, err := app.upgradeView(app.now())
	if err != nil {
		app.fail(w, r, 503, "UPGRADE_SNAPSHOT_UNAVAILABLE", "无法读取升级只读快照。", "请检查数据库后重试。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	release, err := app.latestRelease(ctx)
	if err != nil {
		page.CheckErr = "无法确认最新版本：发行源查询失败。"
	} else {
		page.Checked = strings.TrimPrefix(release, "v")
	}
	app.render(w, r, 200, view.UpgradePage(view.PageData{Title: "任务与升级", Path: "/tasks", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, page))
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
	if !isValidReleaseVersion(tag) {
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
	if !isValidNodeID(nodeID) {
		app.writeUpgradeFailure(w, r, http.StatusBadRequest, codeUpgradeTargetInvalid,
			"节点标识不正确。", "请从任务页面的节点行重新提交批准。")
		return
	}
	if !isValidReleaseVersion(version) {
		app.writeUpgradeFailure(w, r, http.StatusBadRequest, codeUpgradeTargetInvalid,
			"目标版本不是 SemVer 发行版。", "请重新检查新版本后再批准。")
		return
	}
	architecture, err := app.store.ObservedArchitecture(nodeID)
	if err != nil {
		app.failUpgradeApprove(w, r, err)
		return
	}
	// A node that has not read back an architecture is pinned to this Hub's own
	// projection. A cross-arch node then refuses the digest mismatch instead of
	// installing wrong-arch bytes; once it reports its architecture the approval
	// pins that table from the same set.
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	manifest, manifestSHA, err := pinnedManifest(architecture)
	if err != nil {
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeManifestUnavailable,
			"该节点架构没有可验证的发行 manifest。", "请确认节点架构受支持（amd64/arm64）后重试；未写入任何升级记录。")
		return
	}
	// The pin is the manifest this Hub can hand the Agent; a tag alone never
	// becomes a target.
	//
	// Consequence until 11d: this Hub can pin only the build it runs, so a
	// requested release other than node.CurrentAgentVersion is refused here
	// (MANIFEST_UNAVAILABLE). The running build itself is refused below as
	// UPGRADE_ALREADY_CURRENT only when the node already reports it; a lagging
	// node's read-back differs, so it passes through to the gates below, which
	// decide whether the chain may queue.
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
	target, err := app.store.ApproveUpgrade(nodeID, manifest, manifestSHA, app.now())
	if err != nil {
		app.failUpgradeApprove(w, r, err)
		return
	}
	app.event(r, "UPGRADE_APPROVED")
	app.writeJSON(w, http.StatusOK, upgradeApproveReceipt{
		OK: true, Status: "queued", Target: target.Version, ManifestSHA256: target.ManifestSHA256,
		PolicySchema: manifest.PolicySchema, RoutePolicyRevisions: routePolicySlots(manifest),
		Revision: target.CandidateRevision, StageOperationID: target.StageOperationID,
		Tasks: target.Tasks, OperationID: operation(r),
		NextAction: "已排队：候选与四任务链已同事务写入，stage 行带有固定目标；节点下次轮询才执行，queued 不等于已生效。",
	})
}

// pinnedManifest returns the canonical per-architecture manifest this build can
// hand a target node and its exact digest, the value the approval pins and the
// Agent later verifies. The Agent selects the same architecture's entry from
// the served set and reproduces these bytes exactly, so the pin stays the
// per-arch manifest projection rather than the set envelope; for the Hub's own
// architecture this is byte-identical to the pre-set document.
func pinnedManifest(architecture string) (upgrade.Manifest, string, error) {
	manifest, err := upgrade.ForArch(architecture)
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
	code := store.ErrorCodeOf(err)
	switch {
	case code == codeTasksInProgress:
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeTasksInProgress,
			"该节点仍有未结束的任务链。", "等待当前链结束或失败后再批准；已应用修订保持不变。")
	case code == store.CodeUpgradeNotAdjacent:
		app.writeUpgradeFailure(w, r, http.StatusConflict, store.CodeUpgradeNotAdjacent,
			"目标版本不是当前已批准版本的下一个发行版。", "请按发行顺序逐版批准；未写入任何升级记录。")
	case code == store.CodeUpgradeAgentIncompatible:
		app.writeUpgradeFailure(w, r, http.StatusConflict, store.CodeUpgradeAgentIncompatible,
			"节点回读的 Agent 版本无法消费该候选。", "请先升级该节点到理解该候选的版本；未下发任何内容。")
	case code == codeNodeNotFound:
		app.writeUpgradeFailure(w, r, http.StatusNotFound, codeNodeNotFound,
			"节点不存在。", "请刷新任务页面后重试。")
	case code == codeUpgradeAlreadyCurrent:
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeAlreadyCurrent,
			"该节点已运行该发行版本。", "无需重复升级；如需重装，请走重新复核流程。")
	case code == codeUpgradeAgentUnobserved:
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeAgentUnobserved,
			"该节点尚未回读 Agent 版本。", "请先完成一次成功的配置回读，再批准升级。")
	case code == codeUpgradeChainInvalid, code == codeCandidateInvalid, code == codeCandidateMismatch:
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeChainInvalid,
			"当前快照无法生成合法的升级链。", "请先复核该节点配置；未写入任何升级记录。")
	// The approval re-derives the Line route from the live policy, so it can
	// meet the same Out contract a publication does. The refusal is reported
	// with the policy package's own stable code and the operator's next step (fix the
	// Out, or publish a direct server policy) instead of a generic retry hint.
	case code == codeOutBindingInvalid:
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeOutBindingInvalid,
			"当前服务端策略指向一个该线路没有的 Out。", "请先绑定 Out 或发布不含 Out 的服务端策略；未写入任何升级记录。")
	case code == policy.CodeOutOfflineFailClosed:
		app.writeUpgradeFailure(w, r, http.StatusConflict, policy.CodeOutOfflineFailClosed,
			"当前服务端策略指向的 Out 不可用。", "请恢复 Out 或发布不含 Out 的服务端策略；未写入任何升级记录。")
	case code == codePolicyCorrupt, code == codePolicyPinsInvalid,
		code == policy.CodePolicyInvalid, code == policy.CodePolicyConflict,
		code == policy.CodeRulesetUnpinned:
		app.writeUpgradeFailure(w, r, http.StatusConflict, codeUpgradeChainInvalid,
			"当前 active 服务端策略无法解析出线路路由。", "请先修复并重新发布服务端策略；未写入任何升级记录。")
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
