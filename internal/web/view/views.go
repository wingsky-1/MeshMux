package view

//go:generate go run github.com/a-h/templ/cmd/templ@v0.3.1070 generate

type NavItem struct{ Path, Title, Icon string }

var Navigation = []NavItem{
	{"/", "概览", "◈"}, {"/nodes", "代理节点", "◇"}, {"/subscribers", "订阅用户", "◎"}, {"/mesh", "Mesh 设备", "⌘"},
	{"/policies", "路由策略", "⇄"}, {"/tasks", "任务与升级", "▤"}, {"/logs", "日志与诊断", "≡"}, {"/settings", "系统设置", "⚙"},
}

type PageData struct {
	Title, Path, CSRF string
	Dev, DirectProxy  bool
}

func authAction(setup bool) string {
	if setup {
		return "/setup"
	}
	return "/login"
}
