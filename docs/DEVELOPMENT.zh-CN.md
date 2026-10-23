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

- cmd/meshmux：CLI 的 `install hub|edge|out` 入口（含 `--plan`/`--repair`），已随 #5/#6 交付并通过隔离 Debian 13 VM 自动化验收。
- internal/node：节点契约、候选文档与角色模型（含 ParseRole 契约测试）。
- docs/：产品、架构、运维、安全与验收；docs/adr 仅在真实架构取舍时补充。
- .github/workflows/ci.yml：gofmt、vet、test、race、build。
- cmd/meshmux-web、internal/web：非 root Web 服务、安全认证/会话、SQLite 和嵌入式 templ/HTMX 页面。
- **#7 Phase 3A 已合入（PR #19/#21/#22）**：安装器（`internal/install`）与订阅生成器（严格 v2 REALITY 编译器、Web 订阅生命周期、双格式下载）已实现；Agent 严格协议与一次性配对已随 #6（PR #18）合入。
- **#9 已随 PR #62/#63 合入**：9a Mesh 设备生命周期（`internal/mesh` 纯领域模型、`internal/headscale` 固定 argv 适配器、Web `/mesh` 设备页、schema 6 的 `mesh_devices`/`mesh_enrollment_keys`、Hub 的 Web↔Headscale socket 组边界）、9b 子网路由声明/批准/撤销与观测归档、9c 单 VPN 客户端配置渲染、9d Mesh 身份迁移文档。**仍缺**：真实 tailnet 设备注册、真实 NAS 跨网可达与真机单 VPN 证据。
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

README 已移除原先的“暂不可安装”标识：`install hub|edge|out` 已交付并通过隔离 Debian 13 VM 自动化验收，但仍不是正式安装发行包；v1.0.0 发布前不得把现有证据当作现网可用承诺。
