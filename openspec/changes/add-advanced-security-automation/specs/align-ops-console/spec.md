# align-ops-console Specification

## ADDED Requirements

### Requirement: Threat Intelligence Workspace
Ops Console MUST expose a dedicated UI for IOC/file lookups, meta-data timelines, and artifact triage leveraging the Server’s threat intelligence APIs and streams.

#### Scenario: Dual-source verdict display
- **GIVEN** a user pastes a SHA256 into the IOC search bar
- **WHEN** the console calls `GET /api/v1/threat-intel/iocs/{sha}`
- **THEN** it renders OpenTIP & MetaDefender verdicts, enrichment attributes, related tasks/agents, and live status badges that update via `/api/v1/threat-intel/stream` when the backend finishes scanning the associated artifact.

### Requirement: Anomaly Graph & Timeline
Ops Console MUST visualise anomaly events with graphs/timelines, allow pivoting across entities, and offer evidence export.

#### Scenario: Attack path drill-down
- **GIVEN** `/api/v1/anomalies/stream` emits a new anomaly
- **WHEN** the analyst opens it
- **THEN** the UI shows a node-link graph (agents, IPs, IOC, tasks) plus a chronological table; clicking an entity filters related anomalies and allows exporting the evidence bundle as JSON/PDF.

### Requirement: Playbook Builder & Approval UX
Ops Console MUST provide low-code Playbook authoring, simulation, approval, execution monitoring, and manual trigger controls with RBAC enforcement.

#### Scenario: Draft → approve → monitor
- **GIVEN** an admin drafts a Playbook via the visual builder
- **WHEN** they submit it for review
- **THEN** reviewers receive an in-app approval request; upon approval the Playbook can be enabled, and live runs show per-action status, logs, and rollback controls without refreshing the page.

### Requirement: Compliance Workspace
Ops Console MUST expose dashboards for multi-framework scores, gap matrices, remediation tracking, and on-demand report export.

#### Scenario: Gap matrix + report download
- **GIVEN** the CIS v8 dashboard shows 80% compliance
- **WHEN** a user filters by “High severity gaps” and clicks “Export”
- **THEN** the matrix highlights affected assets/tasks, shows remediation progress bars, and the user receives a signed PDF/JSON generated via the Server report endpoint.

### Requirement: BAS Workbench & Attack Chain Visuals
Ops Console MUST include a BAS scenario editor, execution monitor, and attack-chain visualisation aligned with Server-side orchestration.

#### Scenario: Scenario edit and live run
- **GIVEN** an engineer edits a BAS scenario in the graphical builder (dragging steps, defining variables)
- **WHEN** they launch the run
- **THEN** the workbench streams per-step updates, flagging sandbox fallback and failed actions, while the attack-chain diagram updates in real time and links to threat intel/anomaly findings for the same run.

### Requirement: Advanced Reporting Hub
Ops Console MUST provide a centralized hub where operators can browse generated reports (threat intel, anomaly, compliance, BAS), schedule exports, and share signed links.

#### Scenario: Scheduled report delivery
- **GIVEN** a user schedules a weekly “Threat Intel + Compliance” pack
- **WHEN** the schedule triggers
- **THEN** the hub shows the run status, provides download links (PDF/HTML/JSON), and allows copying a time-bound sharing URL with revocation controls.
