## ADDED Requirements
### Requirement: Responsive UI Shell and Unified Components
The frontend shell SHALL provide responsive sidebar/header layouts and shared UI primitives so that operations/governance workspaces follow consistent typography, borders, and feedback behaviors.

#### Scenario: Sidebar collapses on medium screens
- **GIVEN** the viewport width is ≤ 1280px
- **WHEN** the operator opens the console
- **THEN** the sidebar SHALL collapse into an icon-only rail and the main content padding SHALL follow `clamp(16px, 4vw, 32px)`.

#### Scenario: Environment switcher is interactive
- **GIVEN** an operator with multiple environment contexts
- **WHEN** the header renders the environment selector
- **THEN** it SHALL use a segmented/selector component that reflects the current theme token and emits selection events instead of static text.

#### Scenario: Pages reuse AppCard/AppTable/AppFormSection
- **GIVEN** any operations or governance page (e.g., Agents, Reports, BAS)
- **WHEN** cards/tables/forms are rendered
- **THEN** they SHALL use the shared AppCard/AppTable/AppFormSection primitives so that radius, shadows, fonts, and status feedback remain consistent across pages.

### Requirement: Realtime Workspace Patterns
Realtime workspaces (events, queues, detections) SHALL use virtualized timelines and tabbed insight panels with max-height scroll containers so streaming data does not break layout consistency.

#### Scenario: Virtualized timeline
- **GIVEN** any realtime feed that lists >100 events (system events, queue dispatches, detections)
- **WHEN** the list renders
- **THEN** it SHALL use a virtual list or sticky list implementation with priority indicators and dual timestamps so that scrolling remains smooth without introducing nested scrollbars.

#### Scenario: Tabbed insight panel
- **GIVEN** side panels that display stats, detection feeds, or Respond shortcuts
- **WHEN** multiple insight widgets are shown together
- **THEN** they SHALL be rendered inside a tabbed card with each tab constrained via `max-height` and internal scroll, and the SSE connection state SHALL surface via badge/extra text so operators can see feed health at a glance.

### Requirement: Shared Feedback & Bulk Utilities
The UI framework SHALL include reusable message/toast APIs, bulk toolbars, and loading indicators so every workspace provides identical feedback semantics without bespoke styling.

#### Scenario: AntD message + AppBulkToolbar contract
- **GIVEN** any destructive/bulk action (report deletion, template deploy, plugin install)
- **WHEN** the user triggers the action
- **THEN** it SHALL open with an AppBulkToolbar summary (when selection exists) and use `message.useMessage()` to show loading/success/error notices, ensuring no native `alert/confirm` are rendered.

#### Scenario: SSE status + tokenized alerts
- **GIVEN** live views such as Plugin Marketplace or Queue Monitor
- **WHEN** SSE disconnects or retries
- **THEN** the UI SHALL display a tokenized `Alert` component using the shared danger/warning palette, and all inline errors (API 4xx/5xx) SHALL render in the same AppCard padding/margins so operators learn a single feedback vocabulary.
