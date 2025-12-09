# ops-console Specification

## Purpose
TBD - created by archiving change align-ui-workspaces. Update Purpose after archive.
## Requirements
### Requirement: Tool Workbench Uses Tokenized AntD Form/Table
Ops Console tool pages (ReportWorkbench, SystemConfigCenter, PluginMarketplace) SHALL render AntD Form/Table/Alert components wired to shared tokens so that selection states, loading indicators, and pagination feel consistent.

#### Scenario: Plugin marketplace install workflow
- **GIVEN** an operator pastes YAML manifest into the marketplace form
- **WHEN** they click “安装 / 升级”
- **THEN** the console SHALL validate via AntD Form, show `message.loading` until the API resolves, surface success/error banners within the AppCard, and refresh the table via SSE or fallback polling without page reloads.

#### Scenario: System config bulk toolbar
- **GIVEN** template rows are selected in SystemConfigCenter
- **WHEN** the user triggers 批量部署 or 批量删除
- **THEN** an AppBulkToolbar SHALL appear with “已选 X 个模板” summary and buttons wired to AntD message feedback, ensuring no native confirm dialogs remain.

### Requirement: Inline Filtering & Pagination on Audit / Queue Views
AuditLogView and QueueMonitor SHALL expose inline filter forms, server-backed pagination, and streaming status indicators so analysts can slice data without context switching.

#### Scenario: Audit log inline filters
- **GIVEN** the analyst opens AuditLogView
- **WHEN** they fill actor/resource/action inputs and submit
- **THEN** the table SHALL re-query `/audit/events` with those params, preserve sorter state client-side, paginate 20 rows by default, and provide “导出 JSON” that streams a Blob plus AntD message success notification.

#### Scenario: Queue monitor SSE badge
- **GIVEN** QueueMonitor subscribes to live task events
- **WHEN** the SSE connection is degraded or disconnected
- **THEN** the view SHALL show a `Badge` reading `SSE: {status}` plus an inline `Alert` describing fallback snapshot usage, while the task-type bar chart sticks to the shared color ramp and pagination for agent activity stays within AppTable conventions.

### Requirement: Plugin Marketplace Streaming Resilience
Plugin Marketplace SHALL listen to `/api/v1/plugins/stream`, refetch list on plugin.* events, and expose rollback/install actions guarded by confirmation modals.

#### Scenario: SSE reconnection
- **GIVEN** EventSource emits an error or closes
- **WHEN** the component unmounts or network drops
- **THEN** the EventSource SHALL be closed gracefully, and a reconnection attempt or manual “刷新” button SHALL repopulate the table with the latest versions, guaranteeing operators never see stale manifest states.

