## ADDED Requirements
### Requirement: Remote Debug Logging
When the Agent runs in remote mode with debug enabled (`--debug` or `DEYES_DEBUG=1`), it MUST emit detailed, correlated, and redacted logs for troubleshooting the end-to-end remote task flow and related server interactions.

#### Scenario: Debug mode emits remote interaction logs
- **GIVEN** an operator starts the Agent with `d-eyes remote --debug` (or `DEYES_DEBUG=1`) and a valid `remote.server_grpc_addr`
- **WHEN** the Agent connects to the Server, registers, maintains heartbeats, polls tasks, executes leases, and reports results
- **THEN** the Agent MUST emit debug logs that cover at least:
  - gRPC connection attempt/outcome (address, TLS enabled, duration, error)
  - Register request/response summary (agent_name/platform/version/capabilities count/label keys, returned agent_id, heartbeat interval)
  - PullTasks request/response summary (max_tasks, leases count, duration, error)
  - Per-lease lifecycle logs with correlation fields: `task_id`, `lease_id`, `task_type`, `profile`, payload size, payload top-level keys, metadata keys
  - Task execution start/end (duration, status, exit_code, error_code, truncated error message)
  - ReportResult request/response outcome (task_id/lease_id/status/exit_code/error_code, summary size, metadata key count, duration, error)
- **AND** if `remote.server_api_base` is configured, the Agent MUST log HTTP upload attempts for events/artifacts (method, path, status, duration, error) without logging secrets
- **AND** the debug logs MUST be written to stderr (or an equivalent non-stdout channel) so machine-readable stdout output is not corrupted
- **AND** heartbeat logging MUST avoid per-tick spam while still logging disconnect/reconnect events and any heartbeat errors.

#### Scenario: Debug mode MUST NOT leak secrets
- **GIVEN** the Agent runs in remote mode with debug enabled
- **WHEN** emitting debug logs for gRPC/HTTP interactions and task execution
- **THEN** the Agent MUST NOT log the values of any authentication secrets, including:
  - `remote.agent_token` (gRPC token)
  - HTTP `X-API-Key` values (including those derived from `remote.agent_token`)
- **AND** the Agent MUST NOT log raw payload/metadata values by default; it MUST only log safe structural hints (sizes and top-level keys) unless explicitly designed otherwise.
