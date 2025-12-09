## ADDED Requirements
### Requirement: Multi-Priority Event Pipeline & Tiered Storage
Server MUST process system events through priority queues (high/normal/low), batch flushers, and tiered storage (hot Postgres + warm/cold archive) with explicit backpressure contracts.

#### Scenario: Priority-aware ingestion
- **GIVEN** `/api/v1/events/ingest` receives 1k Defender alerts tagged `priority=high` along with 20k normal ETW samples
- **WHEN** the queues near capacity
- **THEN** the ingestion service drains high-priority batches first, persists them within 100 ms, exposes queue depth metrics, and only throttles low/normal events by returning 429 with retry hints.

#### Scenario: Tiered retention policy
- **GIVEN** EventsConfig defines `hot=7d`, `warm=30d`, `cold=180d`
- **WHEN** events age past 7 days
- **THEN** a background job moves them from the primary partition (fast query) into cost-optimized storage while maintaining query APIs, and updates metadata so analysts know which tier served the query.

### Requirement: Event Parser Plugins & Detection Orchestrator
Server MUST normalize payloads via parser plugins, run rule/ML detections, and emit Respond/Threat Intel triggers with audit trails.

#### Scenario: Parser plugin validation
- **GIVEN** an administrator uploads a Linux memory parser plugin that declares supported event formats
- **WHEN** events arrive with `source=linux-ebpf/memory`
- **THEN** the parser registry loads the plugin, validates schema/limits, normalizes fields (process tree, mmap ranges), and marks malformed data as rejected with diagnostics.

#### Scenario: Detection-triggered Respond workflow
- **GIVEN** the detection engine matches “Trojan upload + suspicious network beacon” on correlated events
- **WHEN** the rule fires
- **THEN** the engine persists a detection record, emits a high-priority alert via SSE/API, creates a Respond task to isolate the host (respecting RBAC/approvals), and links all artifacts/telemetry so analysts can pivot inside the console.

### Requirement: Collector Configuration Feedback Loop
Server MUST track collector metrics from agent heartbeats, surface dashboards/API for queue/latency/sampling stats, and push config versions with auditing + rollback support.

#### Scenario: Config rollout with health validation
- **GIVEN** operators publish a config enabling EBPF network probes at 10% sampling for a tag `role=web`
- **WHEN** the server distributes version `v42`
- **THEN** it records the actor/change, ensures targeted agents acknowledge the version (via heartbeat telemetry) within 30 s, exposes rollout status via API/UI, and if error rate exceeds threshold automatically offers rollback to `v41`.

#### Scenario: Health-driven auto tuning
- **GIVEN** the ingestion metrics show sustained queue pressure
- **WHEN** the control plane detects >80% queue utilization for 5 minutes
- **THEN** it computes a recommended sampling change, optionally pushes reduced sampling configs to affected agents (with audit log), and marks the action in alerting channels so operators can review/override.
