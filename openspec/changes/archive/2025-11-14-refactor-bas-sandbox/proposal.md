# Proposal: refactor-bas-sandbox

## Summary
Split the BAS runner (`agent/internal/tasks/bas.go`) into injectable components—`ScenarioLoader`, `SandboxExecutor`, `TelemetryEncoder`—so we can safely refactor its sandbox-heavy workflow without breaking behavior.

## Background
- BAS currently orchestrates scenario loading, sandbox execution, step telemetry, and file persistence in a single monolithic runner.
- It directly manipulates `sandbox.Manager`, writes to filesystem, and encodes telemetry (`EncodeBASteps`, `EncodeSandboxStats`) inline, making the code hard to test or stub.
- Respond/Inventory runners have been refactored with injection points; BAS needs a similar treatment to complete Runner Refactors.

## Proposed Refactor
1. **ScenarioLoader interface**: Responsible for loading embedded/custom JSON/YAML scenarios. Default implementation wraps existing logic (`loadScenario`, `loadScenarioByID`, etc.). Tests can inject an in-memory loader.
2. **SandboxExecutor interface**: Abstracts sandbox manager operations (`sandbox.Manager`, fallback, approvals). Default executor reuses current sandbox code, while tests can supply a fake executor that captures step outcomes without spawning real sandbox processes.
3. **TelemetryEncoder interface**: Handles encoding of step telemetry and sandbox stats (wrapping `EncodeBASteps`, `EncodeSandboxStats`). Allows deterministic test assertions without depending on gzip/base64.
4. **BASRunner struct**: Accepts these interfaces (with `BasRunnerWithDependencies` constructor) so CLI and remote modes continue using default behavior, but unit tests can inject stubs.

## Implementation Plan
- Introduce interfaces and default implementations next to `bas.go`.
- Update `basRunner` to depend on these interfaces, replacing direct calls to filesystem and sandbox manager.
- Ensure telemetry metadata still matches server expectations.
- Add unit tests using fake loader/executor/encoder to cover all branches (success, sandbox fallback, telemetry errors).

## Impact
- Enables safe unit tests and incremental refactors.
- CLI/agent behavior remains unchanged via default implementations.
- Provides clear extension points for future sandbox engines.

## Risks
- Refactor touches critical sandbox logic; must add regression tests.
- Need to ensure telemetry encoding compatibility (backwards-compatible default encoder).
