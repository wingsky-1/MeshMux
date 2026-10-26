package handler

import (
	"net/http"
	"runtime"
	"time"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

func (app *Server) upgradeView(now time.Time) (view.UpgradeSnapshot, error) {
	snap := view.UpgradeSnapshot{LivePolicyRevisions: map[string]int64{
		"client": 0,
		"server": 0}}
	for _, layer := range []store.PolicyLayer{store.PolicyLayerClient, store.PolicyLayerServer} {
		if record, err := app.store.ActiveRoutePolicy(layer); err == nil {
			snap.LivePolicyRevisions[string(layer)] = record.Revision
		}
	}
	if manifest, err := upgrade.ForArch(runtime.GOARCH); err != nil {
		snap.ManifestErr = err.Error()
	} else {
		snap.Manifest = manifest
	}
	nodes, err := app.store.ListNodesAt(now)
	if err != nil {
		return view.UpgradeSnapshot{}, err
	}
	snap.Nodes = nodes
	if snap.Staged, err = app.store.StagedReadbacks(); err != nil {
		return view.UpgradeSnapshot{}, err
	}
	if snap.Approved, err = app.store.ApprovedTargets(); err != nil {
		return view.UpgradeSnapshot{}, err
	}
	snap.Hub = view.NewHubUpgradeView(app.store.Dir, app.hubResultsDirValue(), now, app.hubIdentity(now))
	return snap, nil
}

func (app *Server) tasksPage(w http.ResponseWriter, r *http.Request, sess session) {
	snap, err := app.upgradeView(app.now())
	if err != nil {
		app.fail(w, r, 503,
			"UPGRADE_SNAPSHOT_UNAVAILABLE",
			"无法读取升级只读快照。",
			"请检查数据库后重试。")
		return
	}
	app.render(w, r, 200, view.UpgradePage(view.PageData{Title: "任务与升级", Path: "/tasks", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, snap))
}
