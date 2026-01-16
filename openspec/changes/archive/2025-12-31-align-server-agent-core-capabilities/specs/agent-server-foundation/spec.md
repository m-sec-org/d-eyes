## MODIFIED Requirements

### Requirement: Agent Registration and Heartbeat
Server MUST expose a secure gRPC 接口供 Agent 注册并维持带遥测与 metadata 的心跳，并确保 Agent 在 Register/Heartbeat 中上报的基础元数据可被 Server 用于展示与排障。

#### Scenario: Agent reports semantic version (not runtime)
- **GIVEN** Agent 在同一版本发布包中同时提供 CLI `d-eyes version` 与 remote 模式
- **WHEN** Agent 进行 gRPC Register 并在 `metadata.version` 中上报版本信息
- **THEN** `metadata.version` MUST match the CLI version string (for example: `v1.3.1`)
- **AND** it MAY additionally report build information via `metadata.labels` using the reserved keys `build.commit` (git SHA) and `build.tags` (comma-separated build tags) for display/troubleshooting
- **AND** `metadata.labels["build.commit"]` and `metadata.labels["build.tags"]` MUST NOT include secrets

#### Scenario: Server-edited labels are overwritten on re-registration
- **GIVEN** the Server stores agent labels from `RegisterRequest.metadata.labels`
- **AND** an operator edits the stored labels via a Server-side API (for example: `PATCH /api/v1/agents/{id}/labels`)
- **WHEN** the Agent re-registers and supplies its configured labels in `RegisterRequest.metadata.labels` (including defaults like `mode=remote`)
- **THEN** the Server MUST treat the Register-provided label set as authoritative and overwrite the stored labels
- **AND** operators SHOULD NOT rely on Server-side label edits as durable agent control signals unless the Agent configuration is also updated

## ADDED Requirements

### Requirement: Remote Dispatch Supports Detect Tasks
When operating in remote mode, Agent MUST accept Server-dispatched detect tasks so operators can centrally run diagnostics and high-value scans via the standard task lease/report flow.

#### Scenario: Remote dispatch runs detect.diag
- **GIVEN** Server enqueues a task of type `detect.diag` and the Agent is running in remote mode
- **WHEN** the Agent receives the lease and executes the task
- **THEN** it MUST produce the same effective diagnostics as the CLI command `d-eyes detect diag`
- **AND** it MUST report results via `ReportResult` so Server APIs can retrieve the execution summary and metadata

#### Scenario: memscan capability is Windows-only and opt-in
- **GIVEN** the Agent registers with the Server in remote mode
- **WHEN** the Agent is not running on Windows
- **THEN** it MUST NOT advertise `detect.memscan` in its capabilities
- **AND** `metadata.labels` MUST reserve the key `allow_memscan` for memscan opt-in semantics
- **AND** the only value that enables memscan capability is the exact string `true` (lowercase, case-sensitive)
- **AND** **WHEN** the Agent runs on Windows but is not explicitly opted in via `allow_memscan=true` (config: `remote.labels.allow_memscan=true`)
- **THEN** it MUST NOT advertise `detect.memscan` in its capabilities
- **AND** **WHEN** the Agent runs on Windows and is explicitly opted in via `allow_memscan=true` (config: `remote.labels.allow_memscan=true`)
- **THEN** it MUST advertise `detect.memscan` in its capabilities

#### Scenario: allow_memscan default and invalid values do not enable memscan
- **GIVEN** the Agent runs on Windows and registers with the Server in remote mode
- **WHEN** `metadata.labels["allow_memscan"]` is missing, empty, or any value other than `true` (examples: `TRUE`, `1`, `yes`)
- **THEN** it MUST NOT advertise `detect.memscan` in its capabilities

#### Scenario: allow_memscan is controlled by the Agent configuration (server-side label edits are non-authoritative)
- **GIVEN** the Agent runs on Windows and registers with the Server in remote mode
- **WHEN** the Agent decides whether to advertise `detect.memscan`
- **THEN** it MUST use its local configuration value (config: `remote.labels.allow_memscan`) as the source of truth for opt-in
- **AND** Server-side updates to stored agent labels (for example via `PATCH /api/v1/agents/{id}/labels`) MUST NOT be assumed to enable or disable `detect.memscan` execution on the Agent

#### Scenario: Remote dispatch runs detect.memscan on Windows
- **GIVEN** the Agent runs on Windows and advertises `detect.memscan` capability
- **WHEN** Server dispatches a `detect.memscan` task
- **THEN** the Agent executes the scan and reports results via `ReportResult`
- **AND** it MUST require explicit approval metadata before execution (for example: `memscan_approval_required=true` AND `memscan_approved=true`), otherwise it MUST reject the task (recommended: `exit_code=65`)
- **AND** when rejecting due to missing approval, it SHOULD set `error_code=detect.memscan.approval_required`
- **AND** it MUST keep `evidence=false` and `minidump=false` by default unless explicitly requested
- **AND** if `evidence=true` or `minidump=true` is requested, it MUST additionally require explicit evidence approval metadata (for example: `memscan_evidence_approved=true`), otherwise it MUST reject the task with a clear error (recommended: `exit_code=65`)
- **AND** when rejecting due to missing evidence approval, it SHOULD set `error_code=detect.memscan.evidence_approval_required`
- **AND** any evidence/minidump artifacts MUST be written to the Agent's local output directory and referenced in the reported `ExecutionResult` (outputs/artifacts records), and MUST NOT be uploaded by default

#### Scenario: Remote dispatch rejects detect.memscan on non-Windows
- **GIVEN** the Agent runs on a non-Windows host
- **WHEN** it receives a lease for a `detect.memscan` task
- **THEN** it MUST fail the task immediately with a clear `unsupported platform` error
- **AND** it MUST NOT perform any scan actions
