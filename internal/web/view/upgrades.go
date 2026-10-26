package view

// Read-only upgrade view for issue #11a (GET /tasks): the release manifest of
// this Hub build and, per node, the observed active readback next to the staged
// target. #11b persists that target on the existing agent_tasks row (version,
// manifest digest, policy schema and candidate revision); the pre-existing
// derivation from a healthy config.stage task stays as the labelled fallback for
// nodes without a record. There is still no apply, rollback, retry or enqueue
// path; those belong to #11c-11e, so the page offers no control that cannot act.

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
	"github.com/wingsky-1/MeshMux/internal/web/store"
)

// UpgradeSnapshot is the whole page input. An invalid manifest is shown as a
// stable refusal, never as a plausible release.
type UpgradeSnapshot struct {
	Manifest    upgrade.Manifest
	ManifestErr string
	Nodes       []store.Node
	Staged      map[string]store.StagedReadback
	// Approved is the newest #11b target per node, so the page can show what an
	// operator approved next to what the node actually read back.
	Approved map[string]store.ApprovedTarget
	// Checked and CheckErr carry the explicit "check new version" result. An
	// empty Checked with an empty CheckErr means the operator has not asked.
	Checked  string
	CheckErr string
	// LivePolicyRevisions is the active revision per layer read from the store.
	// The manifest's route_policy_revisions slot is a target release contract and
	// is deliberately not filled from live state.
	LivePolicyRevisions map[string]int64
	// Hub is the read-only Hub self-upgrade block (#11d Task 5). It is the same
	// journal the reconcile pass advances, rendered without a write.
	Hub HubUpgradeView
}

// HubIdentity is the management view of this build's identity. Code is
// empty when the identity is confirmed; otherwise it is exactly one of the
// spec §5.4 codes.
type HubIdentity struct {
	Version     string
	Schema      int
	UserVersion int
	Row         store.DatabaseVersion
	HasRow      bool
	Code        string
	CheckedAt   time.Time
}

// Confirmed reports whether this database proved it belongs to the running
// build. It is true only when no event applies and a readback has actually
// happened: the zero value is "not primed yet", not "confirmed".
func (s HubIdentity) Confirmed() bool { return s.Code == "" && !s.CheckedAt.IsZero() }

// HubUpgradeView is the read-only Hub self-upgrade block of /tasks (spec
// §5.4/§5.5/§5.11). Every field is a read: the current operation from the
// journal, the fixed-path result the root dispatcher wrote, the latest verified
// per-operation record, the restored marker and the identity snapshot. Errors
// are captured as stable codes so one unreadable metadata file cannot turn the
// whole page into a 503.
type HubUpgradeView struct {
	Op          hubupgrade.Op
	HasOp       bool
	Record      backup.Record
	HasRecord   bool
	Result      hubupgrade.Result
	HasResult   bool
	Restored    hubupgrade.RestoredMarker
	HasRestored bool
	Identity    HubIdentity
	// Err is the journal/marker failure; ResultErr is the (non-authoritative)
	// result document failure.
	Err       string
	ResultErr string
	// ExpiresAt is updated_at+30m for backing_up/backed_up: the reconcile pass
	// will fail the row with HUB_BACKUP_ORPHANED then, and the operator should
	// see that before walking away from a backup.
	ExpiresAt time.Time
}

// NewHubUpgradeView reads the Hub upgrade facts. The journal is the authority
// (D3): no mirror table is queried, and no directory under database-backup/ is
// scanned to guess the current record.
func NewHubUpgradeView(dataDir, resultsDir string, now time.Time, identity HubIdentity) HubUpgradeView {
	view := HubUpgradeView{Identity: identity}
	owner := os.Geteuid()
	ops, err := hubupgrade.ListOps(dataDir, owner)
	if err != nil {
		view.Err = store.ErrorCodeOf(err)
		return view
	}
	if op, ok := newestUpdateOp(ops); ok {
		view.Op, view.HasOp = op, true
		if op.State == hubupgrade.StateBackingUp || op.State == hubupgrade.StateBackedUp {
			view.ExpiresAt = op.UpdatedAt.Add(hubupgrade.OrphanTimeout)
		}
		result, ok, err := hubupgrade.ReadResult(resultsDir, op.OperationID)
		switch {
		case err != nil:
			view.ResultErr = store.ErrorCodeOf(err)
		case ok:
			view.Result, view.HasResult = result, true
		}
	}
	if _, record, ok, err := hubupgrade.LatestBackup(dataDir, owner); err == nil && ok {
		view.Record, view.HasRecord = record, true
	} else if err != nil && view.Err == "" {
		view.Err = store.ErrorCodeOf(err)
	}
	if marker, ok, err := hubupgrade.ReadRestoredMarker(dataDir); err == nil && ok {
		view.Restored, view.HasRestored = marker, true
	} else if err != nil && view.Err == "" {
		view.Err = store.ErrorCodeOf(err)
	}
	return view
}

// newestUpdateOp is the journal's current update operation: the highest backup
// generation, then the newest update time. It is journal-backed, so an
// operation directory no journal names can never become "current".
func newestUpdateOp(ops []hubupgrade.Op) (hubupgrade.Op, bool) {
	var newest hubupgrade.Op
	found := false
	for _, op := range ops {
		if op.Kind != hubupgrade.KindUpdate {
			continue
		}
		switch {
		case !found,
			op.BackupGeneration > newest.BackupGeneration,
			op.BackupGeneration == newest.BackupGeneration && op.UpdatedAt.After(newest.UpdatedAt):
			newest, found = op, true
		}
	}
	return newest, found
}

// converged compares two Hub-side reports: the newest staged revision is the
// observed active one with the same compiled digest. It is not a health claim.
func (v UpgradeSnapshot) converged(n store.Node) bool {
	staged := v.Staged[n.ID]
	return staged.Revision > 0 && staged.Revision == n.ObservedRevision &&
		staged.ConfigSHA256 != "" && staged.ConfigSHA256 == n.ObservedConfigSHA256
}

// targetExcluded reports whether an approval cannot be offered for this node:
// without a read-back Agent version the Hub cannot prove which candidate schema
// the node consumes, so it is excluded instead of guessed.
func (v UpgradeSnapshot) TargetExcluded(n store.Node) bool {
	return n.ObservedAgentVersion == ""
}

// tasksPage is the "任务与升级" route. It reads the manifest and the two
// readbacks and registers no mutation.
// UpgradePage renders the page. It reuses Document for the head and assets. It
// is not read-only any more: the per-node approval form is the single mutation,
// and the check link is a GET that stores nothing. The page never claims that a
// queued chain is an applied release.
func UpgradePage(p PageData, v UpgradeSnapshot) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		var nav strings.Builder
		for _, item := range Navigation {
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
			`<p class="subtitle">本页展示发行 manifest 与各节点已回读的 active / staged / 已批准版本。“检查新版本”只是建议；节点批准只登记目标并排队固定四任务链，执行在目标机本地完成。下方的 Hub 自升级区块另有备份、交接与恢复三个写操作，全部走同一会话、Origin 与 CSRF 边界；queued / restoring 都不等于已生效。</p>`
		if p.Dev {
			body += `<div class="notice">本地开发模式：仅用于隔离验收，未启用 HTTPS。</div>`
		}
		body += upgradeCheckHTML(v) + upgradeManifestHTML(v) + hubUpgradeHTML(v.Hub, p.CSRF) + upgradeNodesHTML(v, p.CSRF) +
			`<footer class="page-footer"><span>MeshMux · 自托管网络控制台</span><span><a href="/">返回控制台 →</a></span></footer></main></div></div>`
		return Document(p.Title).Render(templ.WithChildren(ctx, templ.Raw(body)), w)
	})
}

// hubUpgradeHTML renders the Hub self-upgrade block of #11d Task 7 (spec §5.11).
// It is the only place the three Hub write forms live: backup, handoff and
// restore, each with the existing session/Origin/CSRF mutation boundary. The
// block is a readback of the journal, the per-operation record, the fixed result
// and the restored marker; no form can supply a path, digest, argv or unit
// attribute.
func hubUpgradeHTML(v HubUpgradeView, csrf string) string {
	out := `<section class="panel" id="hub-upgrade"><div class="panel-heading"><h2>Hub 自升级</h2><span class="badge accent">journal 唯一权威</span></div>` +
		`<p class="hint">Hub 自升级只更换 MeshMux 程序与发行包中明确兼容的固定组件；目标 manifest 必须由 root 预置，Web 不能提供字节、摘要或 ExecStart。12e 之前生产目标 manifest 不存在：备份与交接会如实返回 <code>MANIFEST_UNAVAILABLE</code>，不会静默升级。root 也可在无 Web 的控制台按验收文档直接运行旧包的 <code>__internal-hub-restore</code>，或向请求目录投递一份恢复请求。</p>`
	if v.Err != "" {
		out += `<div class="error" role="alert">Hub 升级记录不可读：` + templ.EscapeString(v.Err) + `。本区块不猜测状态。</div>`
	}
	if v.HasRestored {
		out += `<div class="error" role="alert"><b>有损恢复（LOSSY）</b>：本数据目录已从操作 <code>` +
			templ.EscapeString(v.Restored.OperationID) + `</code> 的备份恢复。快照时间 <b>snapshot_at=` +
			templ.EscapeString(v.Restored.SnapshotAt.UTC().Format(time.RFC3339)) +
			`</b>；该时间之后的写入已丢失。携带的旧记录只能作诊断，不能作为下一次恢复源；下一次已提交的备份会清除此标记。</div>`
	}
	out += `<dl class="details">`
	if v.HasRecord {
		out += `<dt>当前备份记录</dt><dd><code>` + templ.EscapeString(v.Record.OperationID) + `</code> · 状态 ` +
			templ.EscapeString(v.Record.State) + ` · from_version ` + templ.EscapeString(v.Record.FromVersion) +
			` · db_schema ` + strconv.FormatInt(v.Record.DBSchema, 10) + ` · payload 文件 ` +
			strconv.Itoa(v.Record.PayloadFiles) + ` · integrity_ok ` + boolLabel(v.Record.IntegrityOK) + `</dd>`
	} else {
		out += `<dt>当前备份记录</dt><dd class="muted">尚无 journal 可解析的 per-op 备份记录（不扫描 database-backup/ 目录猜测）</dd>`
	}
	if v.HasOp {
		out += `<dt>当前操作</dt><dd><code>` + templ.EscapeString(v.Op.OperationID) + `</code> · ` +
			templ.EscapeString(string(v.Op.State)) + ` · from ` + templ.EscapeString(v.Op.FromVersion) +
			` → target ` + templ.EscapeString(v.Op.TargetVersion) + ` · db_schema ` +
			strconv.FormatInt(v.Op.DBSchema, 10) + ` · 更新于 ` +
			templ.EscapeString(v.Op.UpdatedAt.UTC().Format(time.RFC3339)) + `</dd>`
		if !v.ExpiresAt.IsZero() {
			out += `<dt>孤儿超时</dt><dd>` + templ.EscapeString(v.ExpiresAt.UTC().Format(time.RFC3339)) +
				` 之后本操作会被对账判为 <code>HUB_BACKUP_ORPHANED</code>；请不要在备份后离场过久。</dd>`
		}
		if v.HasResult {
			out += `<dt>result 阶段</dt><dd>` + templ.EscapeString(string(v.Result.Phase))
			if v.Result.ErrorCode != "" {
				out += ` · <code>` + templ.EscapeString(v.Result.ErrorCode) + `</code>`
			}
			out += ` · ` + templ.EscapeString(v.Result.UpdatedAt.UTC().Format(time.RFC3339)) + `</dd>`
		} else if v.ResultErr != "" {
			out += `<dt>result 阶段</dt><dd>不可读：<code>` + templ.EscapeString(v.ResultErr) + `</code></dd>`
		} else {
			out += `<dt>result 阶段</dt><dd class="muted">尚无 root 执行体写入的 result</dd>`
		}
	} else {
		out += `<dt>当前操作</dt><dd class="muted">尚无 Hub 自升级操作</dd>`
	}
	out += `</dl>`
	if v.HasRecord && v.Record.IrreversibleApproved {
		out += `<div class="notice" role="status">不可逆确认位：<b>已确认</b>（只表示操作员同意，不表示迁移完成；确认位由 <code>POST /tasks/db-migration/approve</code> 写入）。</div>`
	} else if v.HasRecord {
		out += `<p class="hint">不可逆确认位：<b>未确认</b>。若目标 manifest 声明 <code>database_migration=irreversible</code>，交接与恢复会在执行前以 <code>IRREVERSIBLE_CONFIRM_REQUIRED</code> 拒绝。</p>`
	}
	if v.HasRecord {
		out += `<p class="hint">确认位只由 <code>POST /tasks/db-migration/approve</code>（管理员会话 + 精确 Origin + CSRF + 字面值 <code>irreversible_confirm=1</code>）写入；不存在 flag 或环境变量绕过。</p>`
	}
	if v.HasOp && v.Op.State == hubupgrade.StateBackedUp {
		out += `<form action="/tasks/hub-upgrade/apply" method="post"><input type="hidden" name="csrf" value="` +
			templ.EscapeString(csrf) + `"/><input type="hidden" name="operation_id" value="` +
			templ.EscapeString(v.Op.OperationID) + `"/><button class="text-button" type="submit">交接升级（排队）</button></form>` +
			`<p class="hint">交接只校验备份、root manifest 与空间，然后写一份请求给 root dispatcher；<code>queued</code> 不代表已开始或已生效。</p>`
	}
	if v.HasOp && (v.Op.State == hubupgrade.StateFailed || v.Op.State == hubupgrade.StatePartial || v.Op.State == hubupgrade.StateVerifying) {
		out += `<form action="/tasks/hub-upgrade/restore" method="post"><input type="hidden" name="csrf" value="` +
			templ.EscapeString(csrf) + `"/><input type="hidden" name="operation_id" value="` +
			templ.EscapeString(v.Op.OperationID) + `"/><button class="text-button" type="submit">从该备份恢复（有损）</button></form>` +
			`<p class="hint"><b>恢复是有损的（LOSSY）</b>：只按这个失败操作的 per-op 副本恢复到新目录，快照之后写入丢失；不会自动选择更早的 confirmed 代。恢复执行体是旧包，root 也可以在无 Web 时从控制台直接运行。</p>`
	}
	out += `<form action="/tasks/hub-upgrade/backup" method="post"><input type="hidden" name="csrf" value="` +
		templ.EscapeString(csrf) + `"/><label class="field">目标版本 <input name="target_version" placeholder="1.0.1" autocomplete="off" required/></label> ` +
		`<button class="text-button" type="submit">创建 Hub 数据库备份</button></form>` +
		`<p class="hint">目标版本必须已有 root 预置的 <code>manifest-&lt;target&gt;.json</code>；备份只写 per-op 记录与载荷，回执中的 operation_id 也是 <code>POST /tasks/db-migration/approve</code> 需要的 <code>backup_operation_id</code>。</p>` +
		`<p class="hint">已知边界：交接阶段的目标包暂存失败会让 journal 停在 <code>backed_up</code>（备份仍有效、可重试同一操作）；<code>verifying</code> 只由 Web 的启动对账确认，ticker 不会自行确认，因此看到 verifying 时重启一次 Web 触发启动对账；root 执行体在停机前或写入前的失败不写 result，只在 stderr 给出稳定码与 operation id。</p></section>`
	return out
}

// boolLabel prints an explicit yes/no instead of relying on a Go boolean's
// absence to mean "not verified".
func boolLabel(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// upgradeCheckHTML is the explicit "check new version" button and its
// advisory-only result. It is a GET link, so a check can never mutate anything;
// the approve form next to each node is the only write on the page.
func upgradeCheckHTML(v UpgradeSnapshot) string {
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

func upgradeManifestHTML(v UpgradeSnapshot) string {
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

func upgradeNodesHTML(v UpgradeSnapshot, csrf string) string {
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
	return out + `</tbody></table><p class="hint">批准只写入既有 <code>agent_tasks</code> 的目标记录并排队固定四任务链；执行由目标机本地 update 完成。Hub 自升级见上方区块：备份、交接与有损恢复是三个独立的、带 operation_id 的写操作。queued / restoring 都不等于已生效。</p></section>`
}

// approvedTargetHTML renders the newest persisted approval and the single
// per-node approval control. The control only exists when the Hub can prove the
// node's Agent version and the manifest can name a target; otherwise the cell
// says why the node is excluded instead of offering a refusal to the operator.
func approvedTargetHTML(v UpgradeSnapshot, n store.Node, approved store.ApprovedTarget, csrf string) string {
	out := ""
	if approved.Version != "" {
		out += `<span class="badge accent">` + templ.EscapeString(approved.Version) + `</span> · ` +
			templ.EscapeString(approved.Status) + `<br/>policy_schema ` + strconv.Itoa(approved.PolicySchema) +
			`<br/>rev ` + strconv.FormatInt(approved.Revision, 10) + `<br/>manifest <code>` +
			templ.EscapeString(approved.ManifestSHA256) + `</code><br/><code>` + templ.EscapeString(approved.OperationID) + `</code>`
	} else {
		out += `<span class="muted">未批准</span>`
	}
	if v.TargetExcluded(n) {
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
