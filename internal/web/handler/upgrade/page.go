package upgrade

import (
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"runtime"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

func (app *Server) upgradeView(now time.Time) (view.UpgradeSnapshot, error) {
	snap := view.UpgradeSnapshot{LivePolicyRevisions: map[string]int64{
		"client": 0,
		"server": 0}}
	for _, layer := range []store.PolicyLayer{store.PolicyLayerClient, store.PolicyLayerServer} {
		if record, err := app.Store.ActiveRoutePolicy(layer); err == nil {
			snap.LivePolicyRevisions[string(layer)] = record.Revision
		}
	}
	if manifest, err := upgrade.ForArch(runtime.GOARCH); err != nil {
		snap.ManifestErr = err.Error()
	} else {
		snap.Manifest = manifest
	}
	nodes, err := app.Store.ListNodesAt(now)
	if err != nil {
		return view.UpgradeSnapshot{}, err
	}
	snap.Nodes = nodes
	if snap.Staged, err = app.Store.StagedReadbacks(); err != nil {
		return view.UpgradeSnapshot{}, err
	}
	if snap.Approved, err = app.Store.ApprovedTargets(); err != nil {
		return view.UpgradeSnapshot{}, err
	}
	snap.Hub = app.hubUpgradeView(now)
	return snap, nil
}

func (app *Server) tasksPage(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	snap, err := app.upgradeView(app.Now())
	if err != nil {
		app.Fail(w, r, 503,
			"UPGRADE_SNAPSHOT_UNAVAILABLE",
			"无法读取升级只读快照。",
			"请检查数据库后重试。")
		return
	}
	app.Render(w, r, 200, view.UpgradePage(view.PageData{Title: "任务与升级", Path: "/tasks", CSRF: sess.CSRF, Dev: app.Cfg.DevHTTP}, snap))
}
