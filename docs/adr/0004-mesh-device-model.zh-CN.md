# ADR-0004：设备用途与平台分离

状态：Accepted。

MeshDevice 并不天然关联 Subscriber；用途分为（1）proxy+mesh 的 sing-box 统一配置，（2）Mesh-only 现成 Tailscale 客户端，（3）subnet-router 的 Tailscale 客户端或 NAS。Android/iOS/Linux 只属于安装/配置适配的客户端平台字段，不能作为设备种类或 Headscale 身份模型。

给设备签发最短有效一次性 Key。Key 首次成功注册后从持续下载的订阅中删除；若真实内核状态无法证明注册成功，显示 pending，而不是继续无限次释放入网密钥。保留并显示 Headscale Node ID、路由批准及实际在线证据。子网路由准入不得自动批准未经核对的任意前缀。

一个 Subscriber 可关联多设备，撤销一个设备不禁用整名订阅用户。无代理订阅时 Mesh-only 和子网路由必须保持正常工作。

## 修订记录

- 2026-10-22（PR-9a-1）：`internal/mesh` 不再是占位包，首次以纯领域模型实现本节结论，无 I/O、不 import `internal/web` / `internal/install`、不建表、不写 HTTP。落点：`device.go` 的 `MeshDevice`（id、可变 `DisplayName`、`Purpose`、仅展示用 `Platform`、`SubscriberID`、Headscale 用户名快照、`NodeName`、`HeadscaleNodeID`、`Status`）、`ValidateSubscriberBinding`（`proxy_mesh` 必须绑定 Subscriber，`mesh_only` 禁止绑定，`subnet_router` 可空）与 `ValidateNodeNameUniqueness`（同一 Headscale 用户内 `pending`/`registered`/`revoking` 期间 NodeName 唯一）；`enrollment.go` 的 `EnrollmentKey`（15 分钟固定窗口、仅存 SHA-256、`issued → consumed/expired/revoked`、consumed 终态不可逆、每设备单活）。**未实现**：真实 Headscale 调用/凭据、Key 表与设备表、订阅渲染里的 Key 删除、路由 advertise/approve/readback、在线证据、installer 与 Web 改动（分别属 9a-4 及后续 PR）。本修订不改变上文结论：`registered` 仍必须来自观测到的 Headscale Node ID，`pending` 仍表示“未证明注册成功”。

- 2026-10-22（PR-9a-4 落点）：上文“保留并显示 Headscale Node ID、路由批准及实际在线证据”与“撤销一个设备不禁用整名订阅用户”已由 Web 落地，**结论不变**。落点：`internal/headscale`（固定 binary/config 与固定 argv 表的本地 CLI 适配器，`nodes delete` 带 `--force`、无 `preauthkeys list`）、`internal/web/server_mesh.go`（`/mesh` 页面与 reconcile/revoke/retry/rekey 路由；页面渲染只读、`nodes list` 只经显式核对写入观测）、`internal/web/store_mesh.go`（schema 6 的 `mesh_devices` + `mesh_enrollment_keys`；注销只写设备行与意图，不触碰 subscriber、`proxy_credentials`、`subscription_tokens`）。安装侧 `meshmux-web.service` 增加 `SupplementaryGroups=meshmux-headscale` 只为穿过 0770 socket，`/var/lib/meshmux-headscale` 仍 0700 且 Web 无 `ReadWritePaths`。**仍未实现**：子网路由 advertise/approve/readback（9b）、单 VPN 客户端配置渲染（9c）、真实 tailnet 设备注册与在线证据——本修订只把“设备生命周期与一次性 Key”从纯模型推进到 Web+store+适配器，不改变 `registered` 需观测 Node ID、`pending` 表示未证明注册的判定。

- 2026-10-22（PR-9d 设计落点）：NAS 既有 Tailnet 身份迁移与 subnet_router 重装/换机的独立授权、旧身份注销/保留、路由接管顺序和失败回退流程见 [Mesh 身份迁移](../MESH_MIGRATION.zh-CN.md)，上文结论不变；9d 只定义流程，不实现自动迁移、身份导入或跨 tailnet 合并。
