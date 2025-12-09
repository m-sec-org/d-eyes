## Why
- `agent/internal/collector/etw_collector_windows.go:284-333` currently converts ETW payloads to a minimal `SystemEvent` with raw hex blobs and static include/exclude filters; it lacks provider-aware parsers, sampling, async backpressure control, or dynamic config hooks described in `docs/DETAILED_ENHANCEMENT_PLAN.md`.
- `agent/internal/collector/ebpf_collector_linux.go:1-213` only handles a hard-coded pair of probes (`execve` + `process_exit`) and compiles an embedded CO-RE program each start; there is no mechanism to register more tracepoints, adjust sampling, or monitor kernel compatibility, so the EBPF coverage goals cannot be met.
- The server ingests events via a single buffered queue in `server/internal/eventing/service.go:42-140` and a single REST handler `server/internal/api/v1/events.go:21-143`. There is no priority routing, parser plugin, ML/rule detection bridge, or control-plane to push collector configs back to agents.
- The React/Ant Design frontend under `frontend/src/features` has views for agents, tasks, anomalies, threat intel, etc., but no workspace for system events or collector configuration (no references to `/events` APIs), so operators cannot visualize ETW/eBPF telemetry once collected.

## What Changes
- **Windows ETW collector**: introduce parser/filter/sampler interfaces, async worker pools, ETW monitor metrics, and plugin hooks so we can map provider GUIDs to specific enrichers, throttle noisy streams, and hot-patch configs.
- **Linux EBPF collector**: add probe definition catalog, dynamic loader/unloader, multi-map program layout, and compatibility/sampling controls plus suspicious-behavior detectors (trojan upload, memory implants, RCE traces) aligned with the plan.
- **Server pipeline**: evolve event ingestion into a multi-priority, plugin-driven service that validates schemas, runs detection pipelines (rule + ML), persists tiered data, and feeds Respond/Threat Intel modules with malicious detections.
- **Frontend console**: ship an Events workspace (timeline, heatmap, detector hits) plus config forms so operators can toggle collector providers, watch queue depth, and pivot from detections into Respond tasks.
- **Control-plane glue**: extend agent/server config exchange so collectors stream status/metrics through heartbeats while the server can push sampling/filter updates or respond playbooks triggered by detections.

## Impact
- **Specs**: `agent-server-foundation`, `server-core`, and `align-ops-console` all need new requirements to capture parser orchestration, event-processing SLAs, and UI obligations.
- **Code**: Windows ETW (`agent/internal/collector/etw_collector_windows.go`, new parser/filter/sampler files), Linux EBPF (`agent/internal/collector/ebpf_collector_linux.go` + ebpf assets), server eventing (`server/internal/eventing`, `server/internal/api/v1/events.go`, metrics, store), Respond/ThreatIntel bridges, and frontend React features (`frontend/src/features/...`).
- **Testing**: need Go unit/integration tests covering parser registration, probe lifecycle, queue backpressure, detection pipelines, plus frontend Vitest/Playwright coverage for the new workspace. Perf/soak testing for ETW/EBPF collectors is required to validate resource limits.
