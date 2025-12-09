## ADDED Requirements
### Requirement: System Event Analytics Workspace
Ops Console MUST expose a dedicated workspace for ETW/eBPF telemetry with timeline/heatmap views, filter presets, detection feed, and Respond shortcuts.

#### Scenario: Multi-dimensional event exploration
- **GIVEN** the frontend fetches `/api/v1/events?collector_kind=etw&priority=high` and subscribes to detection SSE
- **WHEN** an analyst opens the Events workspace
- **THEN** the UI renders a time-bucketed histogram, provider heatmap, table with column filters (event type/source/agent), and highlights detections; selecting a row reveals metadata, related artifacts, and buttons to launch Respond/Threat Intel actions.

#### Scenario: Collector config + health surface
- **GIVEN** operators need to tune sampling
- **WHEN** they open the Collector tab
- **THEN** the UI shows each collector’s status (queue depth, CPU, events/sec) pulled from `/api/v1/collectors`, allows editing provider/probe/sampling fields with validation, shows diff/approval notes, and sends updates via the server control-plane API while logging who changed what.
