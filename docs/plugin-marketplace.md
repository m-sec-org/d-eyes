# 插件市场 API 与 Ops Console

Stage 4 新增插件市场端到端链路，包含：

1. **Server API**
   - `GET /api/v1/plugins`：列出当前安装的插件（元数据、状态、安装时间）。
   - `GET /api/v1/plugins/:name`：查询指定插件。
   - `POST /api/v1/plugins`：安装/升级插件，Body 为
     ```json
     {
       "manifest": "apiVersion: v1\nname: ...",
       "encoding": "plain|base64"
     }
     ```
   - `POST /api/v1/plugins/:name/rollback`：回滚到上一版本。
   - `GET /api/v1/plugins/stream`：SSE，事件名称 `plugin.installed|plugin.rejected|plugin.rollback`。

2. **Ops Console**
   - 新增「插件市场」入口 `/plugins`，支持查看状态、监听实时事件。
   - 提供 Manifest 粘贴/安装区，失败时显示错误信息。
   - 每个插件项支持一键回滚并展示当前版本、状态、最近更新时间。

3. **后端实现**
   - `server/internal/plugins.Manager` 负责校验 Manifest（复用 `pkg/pluginmanifest`）、维护历史、触发事件。
   - 事件通过 `streams.Hub` 推送，Ops Console 自动刷新。
   - Agent 侧可继续复用 Manifest/Policy 校验，从 Server 下发的插件必须先通过市场 API。

> 参考：`frontend/src/features/plugins/PluginMarketplace.tsx`、`server/internal/api/v1/plugins.go`。
