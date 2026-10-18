# 开发和协作

## 原则

每次只做一个能独立验收的 PR。禁止直接在 main 推送未经测试的业务代码。用户以手机审阅 GitHub PR 为主要工作流，PR 描述需足够完整，中文文档优先。所有新增公共行为同时更新 FEATURES、ACCEPTANCE 与适当 ADR。

## 初始目录

- cmd/meshmux：未来唯一交互命令 install 的入口；PR0 是**拒绝实际执行**的占位实现。
- internal/product：核心领域基本枚举与契约测试，后续扩展身份、任务、路由、配置模型。
- docs：一切架构、风险、变更证据；docs/adr：不可随意覆盖的架构决策。
- .github/workflows/ci.yml：格式、vet、race-test、build。
- 不存在真实 Web、Agent、安装器、配置发布器，也不会创建系统服务。

## 构建

需要 Go 1.27.2。源码中目前没有第三方依赖。CI 执行：

~~~sh
gofmt -l ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/meshmux
~~~

编译环境与目标 Debian13 系统分离；新增 CGO/SQLite 驱动时必须明确 amd64/arm64 可发行性，不允许无解释的 CGO 隐式要求。

## 项目安全与日志

禁止提交私有域名解析记录、真实 IP、订阅、密码、Key、UUID、数据库备份、真实运行日志。测试使用虚构域名 example.invalid、RFC5737 文档地址和造假的 fixture。敏感问题报告贴脱敏 error_code、operation_id、阶段与重现步骤。

## PR 验收清单

CI 全绿；无空白按钮/无条件成功返回；失败路径已测；不存在对生产环境的隐式写入；提供本地可复现步骤；有需要时提供界面截图和脱敏日志；维护本 PR 对应文档。首次全新 VPS 安装通过前，README 必须保留“NOT READY TO INSTALL”。
