## ADDED Requirements
### Requirement: Agent CLI Debug Mode Telemetry
Agent CLI commands (respond, audit, inventory, supplychain, baseline, bas, collect) MUST expose a debug mode toggle that streams timestamped lifecycle logs plus a dynamic progress percentage to STDOUT while persisting the same events into task metadata for remote troubleshooting.

#### Scenario: Debug flag streams lifecycle logs
- **GIVEN** an operator runs `d-eyes respond --targets agent-1 --debug`
- **WHEN** runner phases occur (config load, profile selection, IP enumeration, sandbox warm-up, artifact upload, result synthesis)
- **THEN** the CLI prints timestamped structured lines (module, phase, message) in real time, and the collected events are serialized into `ExecutionResult.metadata["debug.logs"]` so remote / Ops Console views can replay the timeline.

#### Scenario: Progress percentage stays in sync with runner milestones
- **GIVEN** a BAS task with five steps and a sample upload executes with debug mode enabled
- **WHEN** each step starts/completes or artifact upload chunks finish
- **THEN** the CLI refreshes a progress indicator (e.g., `Progress 60% · 3/5 steps · uploading sample.zip`) at least every 2 seconds using the runner milestone counts, and the same samples are appended to `ExecutionResult.metadata["debug.progress"]` for remote inspection.

#### Scenario: Inventory sweep outputs IP diagnostics
- **GIVEN** an operator runs `d-eyes inventory --config assets.yaml --debug` to enumerate a subnet
- **WHEN** the runner iterates through each IP/asset and records reachability or fingerprint results
- **THEN** the CLI emits debug lines like `10.1.0.25 reachable via ssh, missing patches=3` and updates the progress indicator based on IP count (e.g., `Progress 40% · 12/30 IPs scanned`), and the same per-IP samples are captured within `ExecutionResult.metadata["debug.logs"]`/`["debug.progress"]` for remote consumers.

#### Scenario: Collector mode streams ETW/eBPF events
- **GIVEN** an operator runs `d-eyes collect --backend=etw --providers=Kernel,Security --debug`
- **WHEN** the collector ingests ETW/eBPF events and batches them for upload
- **THEN** the CLI prints debug entries for each provider/event sample (timestamp, provider, summary payload) and refreshes a progress indicator tied to event batches/duration (e.g., `Progress 25% · 5k events captured · backend=etw`), while persisting the emitted entries under `ExecutionResult.metadata["debug.logs"]` and `["debug.progress"]` so remote diagnostics can replay the capture session.
