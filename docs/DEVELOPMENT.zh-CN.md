# 开发、PR 与协作

## 版本与任务来源

MeshMux 按 SemVer 2.0.0，**v1.0.0 是首个公开稳定版本**。开发里程碑用 Issue 与 PR 追踪，未完成 P0 验收不打版本标签。功能边界以 README、FEATURES、ACCEPTANCE 和 Issue 内容为准；若冲突先在同一 PR 修正文档。

## 轻量化工作流

1. 在 Issue 明确范围、非目标、体验、失败处理和验收，确认依赖。
2. 一项清晰能力对应一个可审阅 PR，不直接向 main 开发；不强制一次变更配多个 RFC/ADR/Issue。
3. 代码采用现有最简单的正确结构，优先 Go 标准库及维护良好的成熟组件；依赖按需加入并固定版本。
4. 开发时运行 gofmt、go vet、go test、go build；现有 CI race 检测保留，涉及权限/凭据/文件切换需覆盖失败路径。
5. 记录完成、未完成、真实执行的测试、影响、恢复与风险；CI 绿灯后获得明确验收再合并，及时清理过期分支。
6. 修改公开行为/范围时更新少量直接相关文档，避免另建重复文档。正式发行另行固定 manifest 与完成隔离环境 E2E。

## 当前 Go 实现

- cmd/meshmux：CLI 的 install 占位入口，返回非零、无副作用。
- internal/node：节点契约、候选文档与角色模型（含 ParseRole 契约测试）。
- docs/：产品、架构、运维、安全与验收；docs/adr 仅在真实架构取舍时补充。
- .github/workflows/ci.yml：gofmt、vet、test、race、build。
- cmd/meshmux-web、internal/web：非 root Web 服务、安全认证/会话、SQLite 和嵌入式 templ/HTMX 页面。
- **Agent、安装器、订阅生成器及 proxy/Mesh 逻辑仍未实现。**
- 隔离运行、模板再生成、安全验收与恢复见 [WEB_DEVELOPMENT](WEB_DEVELOPMENT.zh-CN.md)，依赖见 [DEPENDENCIES](DEPENDENCIES.zh-CN.md)。

本地运行：

~~~sh
gofmt -l ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/meshmux
go build ./cmd/meshmux-web
~~~

Go 当前使用 1.27.2；目标系统初始仅 Debian 13 amd64/arm64。使用 sqlite 驱动/CGO 前先核实多架构可构建性。

## 保密与不操作现网

公开代码不得包含真实订阅 URL、IP、域名、密钥、Headscale 身份或私人备份。示例统一使用 example.invalid 和 RFC5737 文档地址。无需用户单独授权的 PR 不执行生产安装、清理、路由修改或发行。

v1.0.0 前的 README 保留显著的 NOT READY TO INSTALL 标识；本项目的“下一阶段”并不意味着现在可以部署。
