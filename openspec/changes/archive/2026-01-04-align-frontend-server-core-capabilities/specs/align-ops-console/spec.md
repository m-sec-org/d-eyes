## ADDED Requirements

### Requirement: Detect Remote Dispatch UX Contract
Ops Console MUST provide an operator workflow that can create and observe remotely-dispatched detect tasks (`detect.diag`, `detect.memscan`) using the Server task catalog (type/profile/schema) and the stable detect report/read surface.

#### Scenario: Create detect.diag task with capability filtering
- **GIVEN** the operator opens the task creation drawer in Ops Console
- **WHEN** they choose task type `detect.diag` and a seeded profile (e.g. `profile="detect.diag"`) and submit the form
- **THEN** Ops Console MUST call `POST /api/v1/tasks` with `type="detect.diag"` and `profile="detect.diag"`
- **AND** it MUST include `metadata.required_capabilities="detect.diag"` to enable scheduler capability filtering
- **AND** it MUST include `payload.backend` and `payload.rule` fields following the task catalog schema (e.g. `backend="auto"`, `rule=""`)

#### Scenario: Create detect.memscan task with guardrails and approvals
- **GIVEN** the operator chooses task type `detect.memscan` (Windows-only) in Ops Console
- **WHEN** they prepare a memscan task payload
- **THEN** Ops Console MUST enforce client-side guardrails that exactly one of `payload.pid` or `payload.all` is provided
- **AND** it MUST include `metadata.required_capabilities="detect.memscan"` so only Agents advertising `detect.memscan` can lease the task
- **AND** it MUST explain that memscan requires a Windows Agent with explicit opt-in (for example: `allow_memscan="true"` sourced from Agent configuration/registration)
- **AND** it MUST require explicit approval metadata before submission: `memscan_approval_required="true"` and `memscan_approved="true"`
- **AND** **WHEN** `payload.evidence=true` or `payload.minidump=true` is requested
- **THEN** Ops Console MUST additionally require `memscan_evidence_approved="true"` and explain the additional risk to the operator

#### Scenario: View detect report and surface error_code guidance
- **GIVEN** a `detect.diag`/`detect.memscan` task has a completed run
- **WHEN** the operator opens the task details or report view
- **THEN** Ops Console MUST retrieve and display the report using `GET /api/v1/tasks/{id}/detect/report`
- **AND** it MUST surface `exit_code` and `error_code` with recommended actions
- **AND** **WHEN** `error_code` equals `detect.memscan.approval_required` or `detect.memscan.evidence_approval_required`
- **THEN** the UI MUST explain that the Agent rejected execution due to missing approval metadata and guide the operator to resubmit with the required fields (or disable evidence/minidump)

#### Scenario: Detect report RBAC denied (403)
- **GIVEN** the operator does not have the `reports.view` permission
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the Server responds with HTTP 403
- **AND** Ops Console MUST surface a “permission denied” message and suggest requesting access (instead of rendering an empty/incorrect report)

#### Scenario: Detect report not available yet (404)
- **GIVEN** a `detect.diag`/`detect.memscan` task exists but does not yet have an available detect report (for example: no task run, or the latest run has no summary)
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the Server responds with HTTP 404
- **AND** Ops Console MUST surface a “report not available yet” message and allow the operator to retry later (or fall back to task-level details)

### Requirement: Agent Labels UI Clarifies Source Of Truth
Ops Console MUST clearly communicate that Agent labels used for capabilities/behavior are sourced from Agent Register metadata, and that Server-side label edits are non-authoritative and may be overwritten on the next Agent re-registration.

#### Scenario: Editing reserved labels shows overwrite warning
- **GIVEN** the operator opens the Agent label editor in Ops Console
- **WHEN** they view or attempt to edit reserved keys such as `allow_memscan`, `build.commit`, `build.tags`, or `mode`
- **THEN** Ops Console MUST display a warning that Server-side edits will be overwritten by the Agent’s next Register payload
- **AND** it MUST recommend changing the Agent local configuration as the source of truth (for example: `remote.labels.allow_memscan="true"` for memscan opt-in)

### Requirement: Audit Report Viewing UX Contract
Ops Console MUST provide a stable, actionable audit report viewing experience using the Server `audit/report` endpoint, including deterministic handling for RBAC denials and “report not available yet” states.

#### Scenario: View audit report successfully
- **GIVEN** an `audit` task has a completed run
- **WHEN** the operator opens the task details or report view
- **THEN** Ops Console MUST retrieve the report using `GET /api/v1/tasks/{id}/audit/report`
- **AND** it MUST display a stable subset of fields including `task_id`, `task_type`, `profile`, `run_id`, `agent_id`, `task_status`, and `completed_at`
- **AND** it MUST display `exit_code` and `error_code` with actionable guidance when present

#### Scenario: Audit report RBAC denied (403)
- **GIVEN** the operator does not have the `reports.view` permission
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/audit/report`
- **THEN** the Server responds with HTTP 403
- **AND** Ops Console MUST surface a “permission denied” message and suggest requesting access (instead of rendering an empty/incorrect report)

#### Scenario: Audit report not available yet (404)
- **GIVEN** an `audit` task exists but does not yet have an available audit report (for example: no task run, or the latest run has no summary)
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/audit/report`
- **THEN** the Server responds with HTTP 404
- **AND** Ops Console MUST surface a “report not available yet” message and allow the operator to retry later (or fall back to task-level details)
