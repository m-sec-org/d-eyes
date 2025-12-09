## ADDED Requirements
### Requirement: Windows ETW Parser & Sampling Framework
Agent MUST provide provider-aware ETW parser registration, rule-based filtering, dynamic sampling, and async worker pools with telemetry so Windows collectors can enrich data without blocking ETW callbacks.

#### Scenario: Provider-specific parser applied
- **GIVEN** the collector config enables the Security + Defender providers and the parser registry contains `SecurityEventParser`, `DefenderEventParser`
- **WHEN** `handleEventRecord` receives a Defender provider GUID
- **THEN** the parser manager routes it to the Defender parser, which emits a `SystemEvent` enriched with account, file, and remediation metadata while the default parser handles unknown providers without panicking.

#### Scenario: Dynamic sampling + async processing
- **GIVEN** the feature flag `collector.etw.dynamic_sampling` is on and the config sets `process_create=0.2`
- **WHEN** ETW emits >5k process events/sec
- **THEN** the collector pushes records into a buffered channel, N worker goroutines parse/filter them, and the sampler drops ~80% of process events while honoring CPU<5%/latency<100 ms guardrails and exposing queue depth/latency metrics via heartbeats.

### Requirement: Linux EBPF Probe Orchestrator
Agent MUST expose a probe definition catalog, kernel/BTF compatibility checks, runtime load/unload, and sampling/telemetry controls for ebpfCollector so Linux agents can cover network/file/process/memory syscalls safely.

#### Scenario: Runtime probe reconfiguration
- **GIVEN** the server pushes a new collector config that enables `sys_enter_sendmsg` and disables `sched_process_exit`
- **WHEN** the EBPF manager receives the config
- **THEN** it unloads the exit probe, loads/attaches the sendmsg tracepoint with the requested sample rate, updates stats (enabled probes, verifier logs, lost events), and reports success/failure in the next heartbeat.

#### Scenario: Kernel compatibility fallback
- **GIVEN** a Linux agent on kernel 5.4 lacking BTF
- **WHEN** the ebpfCollector starts
- **THEN** it detects the missing support, switches to the cached compat object (or disables incompatible probes), logs a degraded status, and reports the limitation without crashing.

### Requirement: Collector Plugin & Detection Bridge
Agent MUST allow ETW/EBPF collectors to load optional parser/processor plugins and forward malicious-behavior detections into the Respond module for automated action.

#### Scenario: Plugin-enriched detection
- **GIVEN** an approved parser plugin exposes `GetParser()` for Windows container events
- **WHEN** the container parser flags a suspicious image load that matches local threat intel
- **THEN** the collector tags the event with `detection.malicious=true`, submits a Respond task (`respond.NewTask`) with the context, and increments detection telemetry fields so the server/console can trace the automated response.

#### Scenario: Config hot-reload with rollback
- **GIVEN** the server pushes a sampling/filter change that later proves problematic
- **WHEN** an operator requests rollback to the previous config version
- **THEN** the collector restores the prior parser/filter/sampler settings without restarting, records the change in audit metadata, and resumes streaming under the previous version within 60 seconds.
