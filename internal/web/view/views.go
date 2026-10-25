package view

//go:generate go run github.com/a-h/templ/cmd/templ@v0.3.1070 generate

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

// NodesData carries the Task 2 node-pool projection of the nodes page: the
// Out pool strip, the one-shot action notice and the pending delete confirm.
type NodesData struct {
	// Pool lists every enrolled Out with its transport and binding state. It
	// is the selection datasource Task 4 consumes; it never carries the
	// Hub-issued link credential.
	Pool []store.OutPoolEntry
	// ByOut indexes Pool by Out id for the card lookup.
	ByOut map[string]store.OutPoolEntry
	// ByLine groups Pool by the bound Line id for the reverse lookup.
	ByLine map[string][]store.OutPoolEntry
	// Notice is one-shot feedback of the last management action (transport
	// saved, unbound, deleted, cleanup pending). Empty renders nothing.
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
