## 0. Research & Planning
- [x] 0.1 Review existing Agent CLI command wiring (`cmd/d-eyes`, `agent/internal/cli`) plus runner lifecycle hooks to document where progress/telemetry currently flows.
- [x] 0.2 Audit current logging/telemetry sinks (stdout formatting, metadata serialization, collect ETW/eBPF streaming) to determine the optimal extension points for debug mode without duplicating work.
- [x] 0.3 Based on the findings, finalize the sequence diagram / plan for emitting debug events and progress updates across respond/audit/inventory/supplychain/baseline/BAS/collect paths.

## 1. Implementation
- [x] 1.1 Add CLI flag/env config (`--debug` or `DEYES_DEBUG`) that toggles debug mode for respond/audit/inventory/supplychain/baseline/BAS/collect runners plus remote passthrough.
- [x] 1.2 Extend runner lifecycle hooks (including audit/inventory IP sweep stages and collect ETW/eBPF capture) to emit structured debug events (phase, step, timestamp, message) and show them in CLI output when debug mode is active.
- [x] 1.3 Implement a progress tracker that maps runner milestones (step count, IPs scanned, event batches captured, artifact upload stages) into a dynamic percentage and refreshes the CLI display while tasks run.
- [x] 1.4 Persist debug logs + progress samples into `ExecutionResult.metadata` so remote troubleshooting sees the same timeline.
- [x] 1.5 Cover new code paths with integration tests for CLI debug mode output (respond/audit/inventory/supplychain/baseline/BAS/collect) and remote metadata persistence.
