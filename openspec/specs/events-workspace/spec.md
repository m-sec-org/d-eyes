# events-workspace Specification

## Purpose
TBD - created by archiving change align-ui-workspaces. Update Purpose after archive.
## Requirements
### Requirement: Behavior Anomaly Center Split Layout
The behavior anomaly center SHALL provide a resizable list/detail split view with fixed-height panels and an embedded relationship graph powered by `@ant-design/plots` or `vis-network`.

#### Scenario: Adjustable list/detail gutter
- **GIVEN** analysts open the anomaly center
- **WHEN** they drag the splitter between list and detail panes
- **THEN** each pane SHALL respect min/max widths, keep headers affixed, and ensure the detail view (timeline + remediation form) stays within a fixed height using internal scrollbars.

#### Scenario: Graph visualization toggle
- **GIVEN** an anomaly is selected
- **WHEN** the analyst enables “关联图谱”
- **THEN** the view SHALL render nodes (agents, assets, IOC, detections) with severity-driven colors and hover tooltips; zoom/pan states persist while switching between anomalies.

### Requirement: Event Workspace Dual-mode Filters
EventsWorkspace SHALL split filters into basic/advanced modes (inline + Collapse) and stream detection stats via SSE with history heatmaps.

#### Scenario: Advanced filter collapse
- **GIVEN** the user expands “高级筛选”
- **WHEN** they toggle collector types, enter keyword/agent IDs, or adjust lag thresholds
- **THEN** the system SHALL debounce requests, update `/system/events` query params, and reflect the selection in the summary pill list so analysts always know active filters.

#### Scenario: Heatmap + stats tabs
- **GIVEN** statsHistory includes >= 12 samples
- **WHEN** the user hovers the heatmap buckets
- **THEN** tooltips show timestamp/value, “Top Event Types” and “Top Sources” lists update live, and SSE status is displayed in the side tab header.

### Requirement: Timeline Virtualization & Respond Shortcuts
Event and detection timelines SHALL use virtual list components (rc-virtual-list) and present Respond shortcut buttons with immediate feedback.

#### Scenario: Virtualized detection feed
- **GIVEN** >200 detection events buffered
- **WHEN** operators scroll the list
- **THEN** only visible rows render, sticky timestamps remain readable, and selecting events reveals Respond shortcuts (“阻断恶意进程”等) that call `createTask` and surface AntD message results without blocking the stream.

