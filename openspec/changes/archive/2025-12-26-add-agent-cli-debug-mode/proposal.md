## Why
Operators currently have no way to observe what the standalone Agent CLI is doing once a respond/audit/inventory/supplychain/baseline/BAS/collect task starts. The CLI only emits the final summary, so triage teams cannot see runner state transitions, IP sweep progress, ETW/eBPF event flow, sandbox downloads, or duration bottlenecks, and there is no notion of progress to communicate expected completion time. This slows incident response and makes troubleshooting misconfigurations painful.

## What Changes
- Introduce a dedicated CLI debug mode flag that can be enabled per run (e.g., `--debug` or `DEYES_DEBUG=1`).
- When debug mode is active, stream structured task lifecycle logs (runner initialization, profile selection, IP/event enumeration, sandbox downloads, per-step completion) to STDOUT with timestamps and originating module names.
- While tasks execute, continuously surface a dynamic progress percentage that reflects runner milestones (step counts, IPs scanned, event batches captured, file upload stages) so operators can understand how close the CLI is to completion.
- For `collect` sessions, stream ETW/eBPF events and collector diagnostics live when debug mode is enabled so analysts can verify what data is being harvested before the session ends.
- Before implementing instrumentation, perform a deep dive on the current Agent CLI architecture (command wiring, logging sinks, runner hooks) to confirm the optimal injection points and avoid regressions.
- Persist the same debug output into the task result metadata so remote troubleshooting (support bundles, Ops Console views) can replay the execution timeline.

## Impact
- Affected specs: agent-server-foundation
- Affected code: agent CLI runners, telemetry/progress emitter, log sink wiring
