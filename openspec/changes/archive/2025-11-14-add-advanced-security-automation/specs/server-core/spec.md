# server-core Specification

## ADDED Requirements

### Requirement: Threat Intelligence Orchestrator
Server MUST provide a central service that ingests agent-submitted artifacts, executes OpenTIP/MetaDefender scans with quota management, caches verdicts, and exposes REST/SSE interfaces.

#### Scenario: File escalated to dual engines
- **GIVEN** an Agent uploads an encrypted artifact referencing hash `abc123`
- **WHEN** the `/api/v1/threat-intel/jobs` worker dequeues it
- **THEN** the Server first queries MetaDefender (`POST /v4/file` → `GET /v4/file/{data_id}`) and OpenTIP (`POST /api/v1/scan/file?filename=abc123`), stores both verdicts with TTL, and pushes a `verdict_ready` event to `/api/v1/threat-intel/stream` so the originating task and operators can view the combined result.

### Requirement: Behavior Graph & Anomaly Detection
Server MUST ingest telemetry from tasks/heartbeats, build a correlation graph, and surface anomaly events with contextual entities via API/SSE.

#### Scenario: Correlated anomaly query
- **GIVEN** Agent heartbeats and Respond outputs stream into the behavior service
- **WHEN** a rule detects “same agent connected to three blacklisted IPs within 5 minutes”
- **THEN** the service emits an anomaly event linking the agent, IPs, threat intel verdicts, and related tasks; `GET /api/v1/anomalies/{id}` returns nodes/edges so the frontend can render the attack path.

### Requirement: Playbook Automation & Approval
Server MUST host a Playbook engine that listens to threat/anomaly/Task events, enforces multi-stage approvals, and dispatches actions/child tasks with full auditability.

#### Scenario: Auto-response with approval gate
- **GIVEN** a Playbook is configured to quarantine hosts when MetaDefender verdict = `malware`
- **WHEN** an event arrives but the Playbook requires `security.lead` approval
- **THEN** the Engine pauses execution, records an audit entry, and only after `POST /api/v1/playbooks/runs/{id}/approve` succeeds will it dispatch the isolate action to the relevant Agent and log the action output.

### Requirement: Compliance Mapping & Reporting
Server MUST maintain multi-framework control mappings, reconcile task evidence, and generate gap/rectification data plus downloadable reports.

#### Scenario: CIS gap export
- **GIVEN** Respond/Baseline tasks upload control evidence referencing CIS v8 controls
- **WHEN** a user calls `GET /api/v1/compliance/frameworks/cis-v8/gaps?status=open`
- **THEN** the API returns each failing control with linked assets, recommended remediation, and associated tasks; `POST /api/v1/reports` with the CIS template produces a signed PDF ready for download.

### Requirement: BAS Scenario Orchestration
Server MUST own BAS scenario lifecycle (versioning, approval, scheduling) and stream per-step updates received from Agents to watchers and audit logs.

#### Scenario: Multi-agent BAS run coordination
- **GIVEN** a BAS scenario requires two agent groups (`edge`, `db`)
- **WHEN** an operator executes the scenario via `POST /api/v1/tasks` (`type=bas.advanced`)
- **THEN** the Scheduler assigns steps to matching Agents, enforces sandbox/resource limits, records each step update from Agents, and exposes `/api/v1/bas-runs/{run_id}/stream` so the frontend can mirror progress and highlight failures.
