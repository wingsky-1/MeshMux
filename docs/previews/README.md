# 阶段一界面与验收证据

页面由实际 Go Web/templ 渲染，没有静态假登录或业务成功状态。桌面/手机截图作为 PR 的 `web-preview` Actions artifact 保存；不将自动化截图纳入源码提交，避免仓库积累无关二进制产物。

## 已运行的本地验证

- Go 1.27.2，Ubuntu 24.04 隔离容器：gofmt、vet、test、race、amd64 构建通过；CGO_ENABLED=0 的 Linux arm64 交叉构建通过。
- 认证生命周期、Cookie、CSRF/Origin/Host、异常表单/重复 header、会话轮换/重放/过期、限速跨重启、迁移重复/回滚/拒绝未来 schema、状态权限/符号链接、数据库故障与日志脱敏测试通过。
- root 启动真实 Web 二进制返回 `ROOT_FORBIDDEN`，未创建状态目录；install 继续非零拒绝。
- Caddy 2.11.7 候选 `validate` 通过；systemd unit 在临时副本中替换为已构建二进制路径后通过 `systemd-analyze verify`，没有启动 systemd 服务。
- Fail2ban 1.1.0 `fail2ban-regex`：6 行 fixture，IPv4/IPv6 的 2 行可信事件命中，其余 4 行忽略。没有实际封禁网络地址。

## CI 与浏览器验收

- PR #13 提交 `30f29de` 的 [CI run #39140837582](https://github.com/wingsky-1/MeshMux/actions/runs/39140837582) 已完成且 `go`、`web-preview` 均成功（2026-10-18 UTC）。
- [web-preview 截图 artifact](https://github.com/wingsky-1/MeshMux/actions/runs/39140837582/artifacts/12141855681) 包含桌面登录/概览/设置以及手机登录/概览/任务截图，供审阅。截图证明的是开发 HTTP 下的 UI，不等价于公网 HTTPS 或手机真机联调。

现有 Go CI 保留。另设 `web-preview` 作业，仅在隔离 runner 中构建服务、安装固定 Playwright 1.62.1 测试运行时，并执行 `scripts/browser-smoke.cjs`。普通用户真实启动 loopback Web，临时目录不含任何个人基础设施信息。测试截图使用显式本机 HTTP 开发模式，界面会显示提醒；生产 Secure Cookie 在 HTTP 安全测试中另行断言。

浏览器 CI 实测流程：初始化、错误密码反馈、登录、只读 HTMX 刷新、八个页面手机宽度下无横向溢出、改密后重新登录、CSRF 拒绝、退出。截图尺寸为桌面 1440×1000、手机 390×844。测试未使用真实代理/组网，未进行 iOS/Android 真机或公网部署验收。

本地容器只映射 root，不能运行普通用户进程，Chrome 创建 Unix socket 也被环境拒绝；云浏览器无法访问本地 loopback。因此这些实际非 root/浏览器证据交给 GitHub Actions 执行，不修改产品的 root 拒绝边界来绕过环境限制。

## 明确未验证

Debian 13 的实际 systemd/Caddy TLS/Fail2ban action、SSH 实际端口、云防火墙和手机真机；这些属于后续隔离部署验收。PR 不访问任何现网服务器、NAS、Headscale 数据库或订阅，不发布 Tag/Release。
