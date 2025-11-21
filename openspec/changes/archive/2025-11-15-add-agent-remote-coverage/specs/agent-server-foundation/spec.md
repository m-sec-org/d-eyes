## ADDED Requirements
### Requirement: Remote Agent Reliability Test Coverage
Agent remote control logic MUST ship deterministic automated tests that simulate the full server contract so regressions in registration, execution, or replay are caught before release. Statement coverage for `agent/internal/agent` and `agent/internal/agent/remote` MUST remain at 100% via the documented `go test` command.

#### Scenario: Remote loop simulated end-to-end
- **GIVEN** a fake gRPC server that exercises Register → Heartbeat → PullTasks → ReportResult, and stubbed task runners registered through the new test hook
- **WHEN** the remote runner executes with injected clients/stores
- **THEN** metadata defaults (agent name fallback, capability list, telemetry sampler) match the contract in `agent/internal/agent/daemon.go`
- **AND** task execution results are cached, retried, and acknowledged exactly once even when transient errors are injected.

#### Scenario: Result replay after network loss
- **GIVEN** the FileStore contains cached `ReportResultRequest` objects and the fake server intentionally drops the first delivery
- **WHEN** connectivity resumes
- **THEN** `flushPending` resubmits every cached artifact in order and prunes the on-disk state, proving the resiliency guarantee described in `Resilient Result Delivery`.

#### Scenario: Payload parity and sandbox enforcement
- **GIVEN** payloads that include flags, reserved keys, sandbox overrides, and multiple encodings (string/bool/duration)
- **WHEN** `applyRemotePayload` and `mergeSandboxConfig` run inside the remote runner
- **THEN** the resulting `tasks.TaskRequest` mirrors the CLI defaults, enforces quiet/JSON output, and merges sandbox allow/deny lists exactly as documented, with 100% helper coverage preventing regressions.
