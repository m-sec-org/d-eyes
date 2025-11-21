# agent-server-foundation Specification

## ADDED Requirements

### Requirement: Embedded Threat Intelligence Connectors
Agent MUST embed dual-source threat intelligence clients (OpenTIP & MetaDefender) that can run locally with caching/quotas and fall back to server-orchestrated scans.

#### Scenario: Local OpenTIP lookup with caching
- **GIVEN** `ti-mode=local` and the operator provides a valid OpenTIP `x-api-key`
- **WHEN** the Respond task hashes a suspicious file and invokes `GET https://opentip.kaspersky.com/api/v1/search/hash?request=<sha256>`
- **THEN** the Agent caches the verdict (type, classification, TTL) locally for 24h and annotates the task summary with the threat score before returning to the Server.

#### Scenario: MetaDefender fallback when quota exceeded
- **GIVEN** `ti-mode=hybrid` and the MetaDefender `X-RateLimit-Remaining` header reports <5 calls left
- **WHEN** the Agent needs to rescan a 15 MB sample during a BAS task
- **THEN** it records the hash + metadata, tags the artifact as `needs_server_scan`, and skips the direct upload so the Server orchestrator can continue without hitting the quota.

### Requirement: Suspicious Artifact Escalation
Agent MUST be able to escrow suspicious files (encrypted & chunked) to the Server so that central services can run external scans and share artifacts with other consumers.

#### Scenario: Chunked upload with server escrow
- **GIVEN** a respond task detects a 40 MB executable without a local verdict
- **WHEN** `ti-mode=server` is active
- **THEN** the Agent requests a pre-signed upload URL from the Server, streams the encrypted archive in chunks (with sha256 metadata), and includes the artifact reference inside `ReportResult`, enabling the Server to queue the sample for OpenTIP/MetaDefender scanning.

### Requirement: BAS Step Telemetry & Sandbox Stats
Agent MUST emit per-step BAS telemetry (status, stdout/stderr, sandbox usage, fallback) in near real time so Server-side scenario management and UIs can reflect execution progress.

#### Scenario: Step lifecycle streaming
- **GIVEN** a BAS scenario with five steps, three of which request sandbox execution
- **WHEN** each step starts and completes
- **THEN** the Agent sends a step update (`run_id`, `step_id`, `status`, `sandboxed`, `started_at`, `ended_at`) to the Server within 2 seconds, and any sandbox fallback is explicitly flagged for downstream correlation.

### Requirement: Automation Action Executor
Agent MUST expose a secure action channel so approved Playbooks can trigger low-level responses (process isolation, firewall block, YARA scan) with idempotency and audit trails.

#### Scenario: Server-triggered isolation command
- **GIVEN** a Playbook instructs an Agent to isolate a PID as part of an automatic response
- **WHEN** the Agent receives an `ExecuteAction` gRPC call containing `action_id=auto-isolate-123`, command `isolate_process`, and parameters
- **THEN** it validates permissions, executes the action once, returns structured output (success/exit code/log excerpt), and records the action + correlation ID in its local audit log so the Server and UI can confirm execution.
