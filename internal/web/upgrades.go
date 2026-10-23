package web

// Read-only upgrade view for issue #11a (GET /tasks): the release manifest of
// this Hub build and, per node, the observed active readback next to the staged
// target. #11b persists that target on the existing agent_tasks row (version,
// manifest digest, policy schema and candidate revision); the pre-existing
// derivation from a healthy config.stage task stays as the labelled fallback for
// nodes without a record. There is still no apply, rollback, retry or enqueue
// path; those belong to #11c-11e, so the page offers no control that cannot act.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/wingsky-1/MeshMux/internal/jobs"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// StagedReadback is the newest staged evidence of one node. A formal upgrade
// record (#11b) supplies the target release; without one the row is derived
// from the newest healthy config.stage task and marked Derived. Neither proves
// apply, public reachability or a live handshake.
type StagedReadback struct {
	Revision       int64
	ConfigSHA256   string
	OperationID    string
	TargetVersion  string
	ManifestSHA256 string
	PolicySchema   int
	Derived        bool
}

// stagedReadbacks returns the newest healthy stage per node. A row carrying a
// persisted upgrade target is the formal record; an empty target falls back to
// the #11a derivation and is labelled. An undecodable row is an error, never a
// guessed revision.
func (s *store) stagedReadbacks() (map[string]StagedReadback, error) {
	rows, err := s.db.Query(`SELECT t.node_id, t.operation_id, t.params, t.target_version,
 t.target_manifest_sha256, t.policy_schema, t.target_revision FROM agent_tasks t
WHERE t.kind=? AND t.status='healthy' AND t.revision=(SELECT MAX(x.revision) FROM agent_tasks x
 WHERE x.node_id=t.node_id AND x.kind=? AND x.status='healthy')`, protocol.KindConfigStage, protocol.KindConfigStage)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	type pending struct {
		nodeID string
		staged StagedReadback
	}
	var found []pending
	for rows.Next() {
		var row pending
		var params, targetVersion, manifest string
		var policySchema, targetRevision int64
		if err := rows.Scan(&row.nodeID, &row.staged.OperationID, &params, &targetVersion,
			&manifest, &policySchema, &targetRevision); err != nil {
			rows.Close()
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		var revision struct {
			Revision int64 `json:"revision"`
		}
		if err := json.Unmarshal([]byte(params), &revision); err != nil || revision.Revision < 1 {
			rows.Close()
			return nil, errors.New("STAGED_READBACK_CORRUPT: the stage task has no candidate revision")
		}
		row.staged.Revision = revision.Revision
		if targetVersion == "" {
			// No formal record: keep the pre-#11b derivation and label it.
			if manifest != "" || policySchema != 0 || targetRevision != 0 {
				rows.Close()
				return nil, errors.New("UPGRADE_RECORD_CORRUPT: the upgrade target is incomplete")
			}
			row.staged.Derived = true
		} else {
			target := jobs.Target{Version: targetVersion, ManifestSHA256: manifest,
				PolicySchema: int(policySchema), CandidateRevision: targetRevision}
			if err := target.Validate(); err != nil || targetRevision != revision.Revision {
				rows.Close()
				return nil, errors.New("UPGRADE_RECORD_CORRUPT: the persisted upgrade target is not actionable")
			}
			row.staged.TargetVersion = targetVersion
			row.staged.ManifestSHA256 = manifest
			row.staged.PolicySchema = int(policySchema)
		}
		found = append(found, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	// The store holds one connection: the candidate digest is read only after
	// the task rows are drained and closed.
	if err := rows.Close(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	out := make(map[string]StagedReadback, len(found))
	for _, row := range found {
		staged := row.staged
		if err := s.db.QueryRow(`SELECT config_sha256 FROM node_candidates WHERE node_id=? AND revision=?`,
			row.nodeID, staged.Revision).Scan(&staged.ConfigSHA256); err != nil {
			return nil, errors.New("STAGED_READBACK_CORRUPT: the staged candidate revision is missing")
		}
		out[row.nodeID] = staged
	}
	return out, nil
}

// upgradeSnapshot is the whole page input. An invalid manifest is shown as a
// stable refusal, never as a plausible release.
type upgradeSnapshot struct {
	Manifest    upgrade.Manifest
	ManifestErr string
	Nodes       []Node
	Staged      map[string]StagedReadback
	// Approved is the newest #11b target per node, so the page can show what an
	// operator approved next to what the node actually read back.
	Approved map[string]ApprovedTarget
	// Checked and CheckErr carry the explicit "check new version" result. An
	// empty Checked with an empty CheckErr means the operator has not asked.
	Checked  string
	CheckErr string
	// LivePolicyRevisions is the active revision per layer read from the store.
	// The manifest's route_policy_revisions slot is a target release contract and
	// is deliberately not filled from live state.
	LivePolicyRevisions map[string]int64
}

// converged compares two Hub-side reports: the newest staged revision is the
// observed active one with the same compiled digest. It is not a health claim.
func (v upgradeSnapshot) converged(n Node) bool {
	staged := v.Staged[n.ID]
	return staged.Revision > 0 && staged.Revision == n.ObservedRevision &&
		staged.ConfigSHA256 != "" && staged.ConfigSHA256 == n.ObservedConfigSHA256
}

func (app *Server) upgradeView(now time.Time) (upgradeSnapshot, error) {
	view := upgradeSnapshot{LivePolicyRevisions: map[string]int64{"client": 0, "server": 0}}
	for _, layer := range []PolicyLayer{PolicyLayerClient, PolicyLayerServer} {
		if record, err := app.store.activeRoutePolicy(layer); err == nil {
			view.LivePolicyRevisions[string(layer)] = record.Revision
		}
	}
	if manifest, err := upgrade.ForArch(runtime.GOARCH); err != nil {
		view.ManifestErr = err.Error()
	} else {
		view.Manifest = manifest
	}
	nodes, err := app.store.listNodesAt(now)
	if err != nil {
		return upgradeSnapshot{}, err
	}
	view.Nodes = nodes
	if view.Staged, err = app.store.stagedReadbacks(); err != nil {
		return upgradeSnapshot{}, err
	}
	if view.Approved, err = app.store.approvedTargets(); err != nil {
		return upgradeSnapshot{}, err
	}
	return view, nil
}

// targetExcluded reports whether an approval cannot be offered for this node:
// without a read-back Agent version the Hub cannot prove which candidate schema
// the node consumes, so it is excluded instead of guessed.
func (v upgradeSnapshot) targetExcluded(n Node) bool {
	return n.ObservedAgentVersion == ""
}

// tasksPage is the "任务与升级" route. It reads the manifest and the two
// readbacks and registers no mutation.
func (app *Server) tasksPage(w http.ResponseWriter, r *http.Request, sess session) {
	view, err := app.upgradeView(app.now())
	if err != nil {
		app.fail(w, r, 503, "UPGRADE_SNAPSHOT_UNAVAILABLE", "无法读取升级只读快照。", "请检查数据库后重试。")
		return
	}
	app.render(w, r, 200, upgradePage(pageData{Title: "任务与升级", Path: "/tasks", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, view))
}

// upgradePage renders the page. It reuses Document for the head and assets. It
// is not read-only any more: the per-node approval form is the single mutation,
// and the check link is a GET that stores nothing. The page never claims that a
// queued chain is an applied release.
func upgradePage(p pageData, v upgradeSnapshot) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		var nav strings.Builder
		for _, item := range navigation {
			class := ""
			if item.Path == p.Path {
				class = ` class="active" aria-current="page"`
			}
			nav.WriteString(`<a` + class + ` href="` + templ.EscapeString(item.Path) + `"><span aria-hidden="true">` +
				templ.EscapeString(item.Icon) + `</span>` + templ.EscapeString(item.Title) + `</a>`)
		}
		body := `<a class="skip" href="#main">跳到内容</a><div class="shell"><aside class="sidebar">` +
			`<a class="brand" href="/" aria-label="MeshMux 概览"><span class="mark" aria-hidden="true">M</span><span>MeshMux<small>网络，由你掌控</small></span></a>` +
			`<div class="nav-label">工作空间</div><nav aria-label="主导航">` + nav.String() + `</nav>` +
			`<div class="sidebar-foot"><span class="dot"></span> 任务与升级 · 批准后排队<small>首个正式版本目标 v1.0.0</small></div></aside>` +
			`<div class="workspace"><header class="topbar"><span>控制台 <span class="crumb">/ ` + templ.EscapeString(p.Title) + `</span></span>` +
			`<div class="account"><span class="avatar">A</span><span>管理员</span><form action="/logout" method="post">` +
			`<input type="hidden" name="csrf" value="` + templ.EscapeString(p.CSRF) + `"/><button class="text-button" type="submit">退出</button></form></div></header>` +
			`<main id="main" class="content"><div class="page-heading"><div><p class="eyebrow">MESHMUX CONSOLE</p><h1>` +
			templ.EscapeString(p.Title) + `</h1></div><span class="pill">发行 manifest · 逐台批准</span></div>` +
			`<p class="subtitle">本页展示发行 manifest 与各节点已回读的 active / staged / 已批准版本。“检查新版本”只是建议；批准只登记目标并排队固定四任务链，执行在目标机本地完成。它不执行 apply、不回滚，也不把已排队说成已生效。</p>`
		if p.Dev {
			body += `<div class="notice">本地开发模式：仅用于隔离验收，未启用 HTTPS。</div>`
		}
		body += upgradeCheckHTML(v) + upgradeManifestHTML(v) + upgradeNodesHTML(v, p.CSRF) +
			`<footer class="page-footer"><span>MeshMux · 自托管网络控制台</span><span><a href="/">返回控制台 →</a></span></footer></main></div></div>`
		return Document(p.Title).Render(templ.WithChildren(ctx, templ.Raw(body)), w)
	})
}

// upgradeCheckHTML is the explicit "check new version" button and its
// advisory-only result. It is a GET link, so a check can never mutate anything;
// the approve form next to each node is the only write on the page.
func upgradeCheckHTML(v upgradeSnapshot) string {
	out := `<section class="panel"><div class="panel-heading"><h2>检查新版本</h2><span class="badge">显式触发</span></div>` +
		`<p class="hint">新版本只在操作员点击时查询，没有后台定时任务。查到的标签只是<b>未验证</b>建议：只有带固定 manifest pin 的版本才能批准，latest 永远不会直接落地。</p>` +
		`<p class="hint">本机构建只能 pin 自己的发行版本：比本机新的版本在 Hub 自升级（11d）与真实发行 pin 就绪前无法批准；落后于本机的节点仍可批准到本机发行，已运行本机构建的节点会被判为无需升级。</p>` +
		`<p><a class="refresh" href="/tasks/check">检查新版本 ↻</a></p>`
	if v.Checked != "" {
		out += `<div class="notice" role="status">发现 ` + templ.EscapeString(v.Checked) +
			`（未验证）。仅提示，不代表可升级；请核对发行 manifest 后再逐台批准。</div>`
	}
	if v.CheckErr != "" {
		out += `<div class="error" role="alert">` + templ.EscapeString(v.CheckErr) + `</div>`
	}
	return out + `</section>`
}

func upgradeManifestHTML(v upgradeSnapshot) string {
	if v.ManifestErr != "" {
		return `<section class="panel"><div class="panel-heading"><h2>发行 manifest</h2><span class="badge failure">manifest 不可用</span></div>` +
			`<div class="error" role="alert">` + templ.EscapeString(v.ManifestErr) + `</div>` +
			`<p class="hint">当前构建无法给出可信的发行清单，因此不展示任何组件版本。</p></section>`
	}
	m := v.Manifest
	out := `<section class="panel"><div class="panel-heading"><h2>发行 manifest</h2><span class="badge accent">` +
		templ.EscapeString(m.Version) + `</span></div><dl class="details">` +
		`<dt>schema / 架构</dt><dd><code>` + templ.EscapeString(m.Schema) + `</code> · <code>` + templ.EscapeString(m.Architecture) + `</code></dd>` +
		`<dt>policy_schema</dt><dd><code>` + strconv.Itoa(m.PolicySchema) + `</code> · 当前 active 策略 client ` +
		strconv.FormatInt(v.LivePolicyRevisions["client"], 10) + ` · server ` + strconv.FormatInt(v.LivePolicyRevisions["server"], 10) + `</dd>` +
		`<dt>route_policy_revisions 槽位</dt><dd>`
	if len(m.RoutePolicyRevisions) == 0 {
		out += `<span class="muted">目标发行未声明策略版本；上行为本机 active，不是 manifest 承诺</span>`
	} else {
		for layer, revision := range m.RoutePolicyRevisions {
			out += templ.EscapeString(layer) + " rev " + strconv.FormatInt(revision, 10) + " "
		}
	}
	out += `</dd></dl><table class="details"><thead><tr><th>组件</th><th>版本</th><th>架构</th><th>SHA-256</th></tr></thead><tbody>`
	for _, c := range m.Components {
		out += `<tr><td>` + templ.EscapeString(c.Name) + `</td><td>` + templ.EscapeString(c.Version) + `</td><td>` +
			templ.EscapeString(c.Architecture) + `</td><td><code>` + templ.EscapeString(c.SHA256) + `</code></td></tr>`
	}
	return out + `</tbody></table></section>`
}

func upgradeNodesHTML(v upgradeSnapshot, csrf string) string {
	out := `<section class="panel"><div class="panel-heading"><h2>节点 active vs staged</h2><span class="badge">回读 + 批准</span></div>` +
		`<p class="hint">active 来自最近一次严格 <code>config.readback</code>；staged 优先来自持久化的升级任务记录（#11b），只有没有记录的节点才回退到最近一次成功 <code>config.stage</code> 并标注“派生”。批准只登记目标并排队，不证明已安装、公网可达或客户端可用。</p>`
	if len(v.Nodes) == 0 {
		return out + `<p class="muted">尚未纳管节点，没有可展示的版本回读。</p></section>`
	}
	out += `<table class="details"><thead><tr><th>节点</th><th>active</th><th>staged</th><th>已批准目标</th><th>结论</th></tr></thead><tbody>`
	for _, n := range v.Nodes {
		staged := v.Staged[n.ID]
		approved := v.Approved[n.ID]
		verdict := "尚无 staged"
		if v.converged(n) {
			verdict = "staged 已回读为 active"
		} else if staged.Revision > 0 {
			verdict = "staged 未回读为 active"
		}
		out += `<tr><td>` + templ.EscapeString(n.DisplayName) + `<br/><code>` + templ.EscapeString(n.ID) + `</code></td>` +
			`<td>Agent ` + valueOrUnknown(n.ObservedAgentVersion) + ` · kernel ` + valueOrUnknown(n.ObservedKernelVersion) +
			` · rev ` + strconv.FormatInt(n.ObservedRevision, 10) + `<br/><code>` + valueOrUnknown(n.ObservedConfigSHA256) +
			`</code><br/>` + n.ObservedAtString() + `</td><td>`
		if staged.Revision == 0 {
			out += `<span class="muted">无成功 stage 回读</span>`
		} else if staged.Derived {
			out += `<span class="badge">派生</span> rev ` + strconv.FormatInt(staged.Revision, 10) + `<br/><code>` +
				templ.EscapeString(staged.ConfigSHA256) + `</code><br/><code>` + templ.EscapeString(staged.OperationID) + `</code>`
		} else {
			out += `<span class="badge accent">` + templ.EscapeString(staged.TargetVersion) + `</span> · policy_schema ` +
				strconv.Itoa(staged.PolicySchema) + `<br/>rev ` + strconv.FormatInt(staged.Revision, 10) +
				`<br/><code>` + templ.EscapeString(staged.ConfigSHA256) + `</code><br/>manifest <code>` +
				templ.EscapeString(staged.ManifestSHA256) + `</code><br/><code>` + templ.EscapeString(staged.OperationID) + `</code>`
		}
		out += `</td><td>` + approvedTargetHTML(v, n, approved, csrf) + `</td><td>` + verdict + `</td></tr>`
	}
	return out + `</tbody></table><p class="hint">批准只写入既有 <code>agent_tasks</code> 的目标记录并排队固定四任务链；执行由目标机本地 update 完成，备份指针、兼容回退与 Hub 自升级属后续段。queued 不等于已生效。</p></section>`
}

// approvedTargetHTML renders the newest persisted approval and the single
// per-node approval control. The control only exists when the Hub can prove the
// node's Agent version and the manifest can name a target; otherwise the cell
// says why the node is excluded instead of offering a refusal to the operator.
func approvedTargetHTML(v upgradeSnapshot, n Node, approved ApprovedTarget, csrf string) string {
	out := ""
	if approved.Version != "" {
		out += `<span class="badge accent">` + templ.EscapeString(approved.Version) + `</span> · ` +
			templ.EscapeString(approved.Status) + `<br/>policy_schema ` + strconv.Itoa(approved.PolicySchema) +
			`<br/>rev ` + strconv.FormatInt(approved.Revision, 10) + `<br/>manifest <code>` +
			templ.EscapeString(approved.ManifestSHA256) + `</code><br/><code>` + templ.EscapeString(approved.OperationID) + `</code>`
	} else {
		out += `<span class="muted">未批准</span>`
	}
	if v.targetExcluded(n) {
		return out + `<br/><span class="muted">无 Agent 回读版本，已排除（不猜 schema）</span>`
	}
	if n.ObservedAgentVersion != v.Manifest.Version {
		out += `<br/><span class="muted">混版本：该节点仍运行 ` + templ.EscapeString(n.ObservedAgentVersion) +
			`，批准前请确认它理解的候选 schema</span>`
	}
	if v.Manifest.Version == "" || v.ManifestErr != "" {
		return out + `<br/><span class="muted">本机 manifest 不可用，无法批准</span>`
	}
	return out + `<form action="/tasks/approve" method="post"><input type="hidden" name="csrf" value="` +
		templ.EscapeString(csrf) + `"/><input type="hidden" name="node_id" value="` + templ.EscapeString(n.ID) +
		`"/><input type="hidden" name="version" value="` + templ.EscapeString(v.Manifest.Version) +
		`"/><button class="text-button" type="submit">批准 ` + templ.EscapeString(v.Manifest.Version) + `</button></form>`
}

// valueOrUnknown marks an empty readback field as unknown instead of printing an
// empty value that reads like a valid version or digest.
func valueOrUnknown(value string) string {
	if value == "" {
		return "未回读"
	}
	return templ.EscapeString(value)
}
