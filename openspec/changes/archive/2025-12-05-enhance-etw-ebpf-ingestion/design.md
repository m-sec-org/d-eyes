## Context
- Windows ETW collector (`agent/internal/collector/etw_collector_windows.go`) delivers provider-agnostic `SystemEvent` objects using synchronous callbacks. There is no parser abstraction, sampler, or monitor, so adding Defender/container/security-specific logic requires invasive edits.
- Linux EBPF collector (`agent/internal/collector/ebpf_collector_linux.go`) embeds a minimal CO-RE program (exec/exit), uses static probe definitions, and lacks runtime probe toggles, kernel/BTF negotiation, or event context enrichment.
- Server event ingestion (`server/internal/api/v1/events.go`, `server/internal/eventing/service.go`) receives JSON payloads and writes them to the store through one buffer. There is no parsing/normalisation layer, no priority routing, and no detection hooks feeding Respond/Threat Intel.
- Frontend (`frontend/src`) has React + Vite + Ant Design scaffolding but no feature consuming `/events` APIs or showing collector health/config.

## Goals / Non-Goals
- Goals: implement extensible ETW/EBPF collectors, dynamic sampling/filtering, malicious-behavior detectors, multi priorities on the server, and an events workspace in the UI with Respond integration.
- Non-Goals: replace the existing detect/task engines, redesign storage engines, or ship kernel drivers beyond EBPF; we also exclude Windows kernel driver work.

## Decisions
1. **Parser/sampler abstraction for ETW**: introduce `ETWEventParser`, `ETWParserManager`, `EventFilterEngine`, and `ETWSampler` interfaces to decouple provider parsing from the collector core. Each parser declares supported provider GUIDs, enabling plug-and-play additions.
2. **Async ETW processing**: wrap ETW callbacks with buffered channels + worker pools. Event records will be pooled via `sync.Pool`, parsed asynchronously, and filtered/sampled before hitting handlers, matching the performance section in `docs/DETAILED_ENHANCEMENT_PLAN.md`.
3. **EBPF probe registry**: define `EBPFProbeDefinition` plus loader/unloader APIs so new syscalls/net/file probes can be attached on demand. Build dynamic BTF-aware compilation and map-size tuning, exposing stats via `CollectorStatus.Metadata`.
4. **Detection hooks**: ship detection modules (trojan upload, memory implant, RCE) that subscribe to ETW/EBPF events, evaluate heuristics/rules, and enqueue Respond tasks or events flagged with severity metadata. Keep heuristics in Go for maintainability.
5. **Server event pipeline**: split ingestion queues by priority, add parser plugins, and integrate rule/ML detection modules. Persist hot/warm/cold tiers using existing store interface plus future storage drivers. Provide respond/threat intel triggers based on detection results.
6. **Frontend workspace**: reuse Ant Design + Zustand/SWR stack to deliver a new Events view (timeline, filters, heatmaps) and collector settings page. Build API hooks for `/api/v1/events` queries + SSE for detection alerts.

## Alternatives Considered
- Extend the existing ETW collector inline instead of introducing interfaces. Rejected because it leads to a monolith and makes plugin support messy.
- Use Kafka/ClickHouse before the Go server to handle events. Deferred; current scope keeps Go ingestion but leaves room for future external pipelines.
- Build EBPF features in Rust. Chosen Go + C/clang because the repo already uses Go and cilium/ebpf.

## Risks / Trade-offs
- **Kernel compatibility**: supporting kernels <5.8 requires fallback (kprobe vs tracepoint). Mitigation: detect kernel features and degrade gracefully, log warnings.
- **Resource usage**: asynchronous ETW/EBPF processing might spike memory. Mitigation: enforce queue depth metrics and dynamic sampling, expose to heartbeats.
- **Security**: plugin loading (Go plugins or WASM) can introduce attack surface. Mitigation: restrict plugin directories, sign configs, and validate metadata before loading.
- **Schedule**: cross-platform scope is large; breaking into phases (P0 ETW/EBPF ingestion, P1 server pipeline, P2 UI + automation) avoids blocking releases.

## Migration Plan
1. Implement parser/sampler scaffolding behind feature flags; keep existing collector behavior as default.
2. Gradually move existing ETW logic onto the new interfaces, enabling security/system/application parsers incrementally.
3. Ship EBPF probe registry and start with network/file/process probes; collect telemetry to make sure resource caps hold.
4. Roll out server ingestion upgrades alongside compatibility endpoints; gate priority queues and parser plugins behind config toggles.
5. Add frontend workspace once APIs stabilize; provide fallback pages linking to metrics dashboards.

## Open Questions
- Plugin packaging format: Go plugins vs WASM vs gRPC extension?
- Storage backend for cold event data: reuse Postgres partitions or integrate an OLAP store?
- How aggressively should detections trigger Respond automation vs staying as alerts?
