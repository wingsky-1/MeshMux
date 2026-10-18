# ADR-0004：设备用途与平台分离

状态：Accepted。

MeshDevice 并不天然关联 Subscriber；用途分为（1）proxy+mesh 的 sing-box 统一配置，（2）Mesh-only 现成 Tailscale 客户端，（3）subnet-router 的 Tailscale 客户端或 NAS。Android/iOS/Linux 只属于安装/配置适配的客户端平台字段，不能作为设备种类或 Headscale 身份模型。

给设备签发最短有效一次性 Key。Key 首次成功注册后从持续下载的订阅中删除；若真实内核状态无法证明注册成功，显示 pending，而不是继续无限次释放入网密钥。保留并显示 Headscale Node ID、路由批准及实际在线证据。子网路由准入不得自动批准未经核对的任意前缀。

一个 Subscriber 可关联多设备，撤销一个设备不禁用整名订阅用户。无代理订阅时 Mesh-only 和子网路由必须保持正常工作。
