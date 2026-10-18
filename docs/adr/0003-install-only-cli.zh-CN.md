# ADR-0003：用户 CLI 仅负责 install

状态：Accepted as product UX contract。

公开用户入口形式为 **meshmux install hub|edge|out**，允许该安装命令提供明确、受约束的选项（如 --repair、--plan），但不提供常规 user/node/mesh/update 的管理子命令。首次安装可交互输入管理员初始密码或临时配对码，不应把私密值放入命令行参数与 Shell 历史。

所有日常操作、升级与日志应能在 Web 处理；当 Web 完全不可用时，必须保留非日常的系统级灾难恢复方案（系统快照/已验证离线恢复路径），避免“仅有 Web”变成单点永久失控。

PR0 的 install 入口仅返回非零并明确未实现，绝不能写文件、启动服务或改变主机防火墙。
