# Web 基座依赖核查

阶段一选型保持既定 chi + templ/HTMX + SQLite，不新增前端打包器、Redis、队列或通用框架。下表版本固定在 go.mod/go.sum、生成指令或仓库静态资产中；2026-10-18 查询上游发布/包元数据与许可证后采用。维护活跃不是“没有漏洞”的保证，升级仍需行为测试。

| 依赖 | 固定版本 / 许可证 | 用途与必要性 | 上游核查 |
| --- | --- | --- | --- |
| Go 标准库 | 1.27.2 / BSD-3-Clause | HTTP、随机数、Cookie、slog、SQL API、进程信号 | [Go](https://go.dev/doc/devel/release) |
| go-chi/chi/v5 | v5.5.0 / MIT | 小型 net/http 路由器，兼容标准库，不引入额外运行时依赖 | [包与许可证](https://pkg.go.dev/github.com/go-chi/chi/v5@v5.5.0)，2026-10 发布 |
| a-h/templ | v0.3.1070 / MIT | 编译期 HTML 模板和自动转义；生成器固定相同版本 | [包与许可证](https://pkg.go.dev/github.com/a-h/templ@v0.3.1070)，2026-10 发布 |
| golang.org/x/crypto | v0.58.0 / BSD-3-Clause | Go 团队维护的 Argon2id；不自写密码算法 | [Argon2](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/argon2)，2026-10 发布 |
| modernc.org/sqlite | v1.60.1 / BSD-3-Clause | database/sql 驱动，无 CGO，支持 Linux amd64/arm64 交叉构建 | [驱动与维护记录](https://pkg.go.dev/modernc.org/sqlite@v1.60.1)，2026-09 发布 |
| HTMX | 2.0.11 / BSD-2-Clause | 仅渐进增强只读状态刷新；本地静态文件，不需要 npm 工具链 | [文档](https://htmx.org/docs/)、[固定源码](https://github.com/bigskysoftware/htmx/tree/v2.0.11)，LICENSE 随资产保存 |

SQLite 的 libc 必须与驱动 go.mod 保持一致，本次为 modernc.org/libc v1.77.1。其他传递依赖由 go.mod/go.sum 固定；不单独升级 libc。templ CLI 的开发期依赖由固定 `go run ...@v0.3.1070` 获取，不要求部署机器安装。

HTMX 文件：`internal/web/assets/htmx.min.js`，SHA-256：

```text
d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717
```

浏览器资源不调用第三方 CDN，无外部字体/统计脚本。当前单管理员、低并发认证的会话及限速以少量事务 SQL 实现，避免引入 Redis 或完整身份平台。密码哈希、随机数、HTML 转义与数据库引擎均复用成熟组件。

仅 CI 浏览器验证使用固定 Playwright 1.62.1（Apache-2.0，[上游](https://github.com/microsoft/playwright)）和 Node.js 22；安装到 runner 临时目录，不进入 Web 制品或部署依赖。
