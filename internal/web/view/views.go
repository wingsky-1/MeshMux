package view

import "github.com/wingsky-1/MeshMux/internal/web/store"

type NavItem struct{ Path, Title, Icon string }

var Navigation = []NavItem{
	{"/", "概览", "◈"}, {"/nodes", "代理节点", "◇"}, {"/subscribers", "订阅用户", "◎"}, {"/mesh", "Mesh 设备", "⌘"},
	{"/policies", "路由策略", "⇄"}, {"/rules", "规则库", "▦"}, {"/tasks", "任务与升级", "▤"}, {"/logs", "日志与诊断", "≡"}, {"/settings", "系统设置", "⚙"},
}

type PageData struct {
	Title, Path, CSRF string
	Dev, DirectProxy  bool
}

// NodesData carries the node-pool projection of the nodes page: the Out pool
// strip, the one-shot action notice and the pending delete confirm.
type NodesData struct {
	// Pool lists every enrolled Out with its transport and the Lines a
	// subscription selects it for. It is the selection datasource the wizard
	// consumes; it never carries the Hub-issued SS link key.
	Pool []store.OutPoolEntry
	// ByOut indexes Pool by Out id for the card lookup.
	ByOut map[string]store.OutPoolEntry
	// ByLine groups Pool by the Lines each Out is selected for, for the reverse
	// lookup on a Line card.
	ByLine map[string][]store.OutPoolEntry
	// Notice is one-shot feedback of the last management action (transport
	// saved, released, deleted, cleanup pending). Empty renders nothing.
	Notice string
	// PendingDeleteOut names the Out awaiting an explicit delete confirm.
	// Empty renders no confirm block.
	PendingDeleteOut string
}

func authAction(setup bool) string {
	if setup {
		return "/setup"
	}
	return "/login"
}
