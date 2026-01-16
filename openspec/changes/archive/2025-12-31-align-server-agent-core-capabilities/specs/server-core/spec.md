## ADDED Requirements

### Requirement: Seeded Task Catalog For Core Tasks
Server MUST ship with a built-in task catalog seed (task types + profiles) that covers the Agent core task surface (`respond/audit/inventory/supplychain/baseline/bas/action`) so operators can create profile-based tasks without out-of-band catalog bootstrapping.

#### Scenario: Seed imported on first start
- **GIVEN** the Server starts with an empty task catalog and no persisted catalog state is available
- **WHEN** the Server initialises the task catalog manager
- **THEN** it MUST import the built-in seed definitions for the core task surface
- **AND** `GET /api/v1/task-types` MUST include the seeded task types
- **AND** `GET /api/v1/task-profiles` MUST include at least one profile per seeded task type

#### Scenario: Seed persisted when configured
- **GIVEN** the Server is configured with `task_catalog.persist_path`
- **AND** the Server starts with an empty task catalog (no existing persisted state)
- **WHEN** the Server imports the built-in seed definitions
- **THEN** it MUST persist the resulting catalog state such that a subsequent restart loads the same task types/profiles without additional operator actions

#### Scenario: Existing catalog is preserved
- **GIVEN** the task catalog contains at least one existing task type or task profile (via persisted state or prior API writes)
- **WHEN** the Server starts
- **THEN** it MUST NOT overwrite or delete existing catalog entries
- **AND** it MUST NOT import the built-in seed in a way that mutates user-defined catalog data

### Requirement: Core Task Report Surface Covers Audit And Detect
Server MUST provide a stable report/read surface for all core Agent task types, including `audit` and remotely-dispatchable detect tasks (`detect.diag`, `detect.memscan`), such that remotely executed tasks can be consumed consistently via REST APIs with consistent authorization and auditing.

#### Scenario: Audit task report can be retrieved
- **GIVEN** an Agent completed an `audit` task and reported an execution result via `ReportResult`
- **WHEN** an operator fetches the task report via `GET /api/v1/tasks/{id}/audit/report`
- **THEN** the response MUST include the stored `ExecutionResult` (summary + metadata) and task identifiers
- **AND** the endpoint MUST require the same permission gate as other task report endpoints (e.g. `reports.view`)
- **AND** the Server MUST record an audit log entry for the report read action

#### Scenario: Detect task report can be retrieved
- **GIVEN** an Agent completed a `detect.diag` or `detect.memscan` task and reported an execution result via `ReportResult`
- **WHEN** an operator fetches the task report via `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the response MUST include the stored `ExecutionResult` (summary + metadata) and task identifiers
- **AND** the endpoint MUST require the same permission gate as other task report endpoints (e.g. `reports.view`)
- **AND** the Server MUST record an audit log entry for the report read action

#### Scenario: Report aggregation endpoints enforce the same permission gate
- **GIVEN** a principal without `reports.view`
- **WHEN** the principal calls `GET /api/v1/reports/summary`, `GET /api/v1/reports/export`, or `POST /api/v1/reports/generate`
- **THEN** the Server MUST reject the request with `403`

### Requirement: Seeded Task Catalog For Detect Tasks
Server MUST ship with a built-in task catalog seed (task types + profiles + profile schemas) for remotely-dispatchable detect tasks (`detect.diag`, `detect.memscan`) so operators can create validated detect tasks via REST with predictable payload semantics.

#### Scenario: Detect task types and profiles are available after seeding
- **GIVEN** the Server starts with an empty task catalog and no persisted catalog state is available
- **WHEN** the Server initialises the task catalog manager
- **THEN** it MUST import the built-in seed definitions for `detect.diag` and `detect.memscan`
- **AND** `GET /api/v1/task-types` MUST include `detect.diag` and `detect.memscan`
- **AND** `GET /api/v1/task-profiles?task_type=detect.diag` MUST include at least one seeded profile
- **AND** `GET /api/v1/task-profiles?task_type=detect.memscan` MUST include at least one seeded profile

#### Scenario: Detect diag profile schema validates payload
- **GIVEN** an operator creates a `detect.diag` task using a seeded profile
- **WHEN** the payload provides `backend` outside the allowed set (`auto`, `native`, `portable`)
- **THEN** `POST /api/v1/tasks` MUST reject the request with `400`
- **AND** the seeded `detect.diag` profile schema MUST define `backend` as an enum with default `auto`
- **AND** the seeded `detect.diag` profile schema MUST define `rule` as an optional string (empty means using the built-in rule set)

#### Scenario: Detect memscan profile schema validates payload and expresses target selection constraints
- **GIVEN** an operator creates a `detect.memscan` task using a seeded profile
- **WHEN** the payload violates the profile schema (e.g. `pid <= 0`, `max_bytes <= 0`, or non-boolean `evidence/minidump`)
- **THEN** `POST /api/v1/tasks` MUST reject the request with `400`
- **AND** the seeded `detect.memscan` profile schema MUST define `pid` as an optional number (>0)
- **AND** the seeded `detect.memscan` profile schema MUST define `all` as an optional boolean
- **AND** the seeded `detect.memscan` profile schema MUST define `backend` as an enum with default `auto`
- **AND** the seeded `detect.memscan` profile schema MUST define `rule` as an optional string (empty means using the built-in rule set)
- **AND** the seeded `detect.memscan` profile schema MUST define guardrails with safe defaults: `rwx_only=true`, `max_bytes=33554432`, `max_regions=128`
- **AND** the seeded `detect.memscan` profile schema MUST define evidence toggles defaulting to disabled: `evidence=false`, `minidump=false`
- **AND** the seeded `detect.memscan` profile schema MUST include a constraint expressing that exactly one of `pid` or `all` MUST be provided

### Requirement: Detect Report Responses Follow The Standard Report Envelope
Server MUST return detect task reports using the same response envelope fields as existing report endpoints (e.g. `respond`/`baseline`) to keep client-side consumption consistent across task types.

#### Scenario: Detect report response envelope is stable
- **GIVEN** an Agent completed a `detect.diag` or `detect.memscan` task and reported an execution result via `ReportResult`
- **WHEN** an operator fetches the task report via `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the response MUST include `task_id`, `task_type`, `profile`, `run_id`, `agent_id`, `task_status`, and `result`
- **AND** the response MUST include `run_metadata`, `exit_code`, `error_code`, `completed_at`, and `expires_at` when available
