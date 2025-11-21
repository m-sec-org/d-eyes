## 1. Design
- [x] 1.1 Define interfaces for `ScenarioLoader`, `SandboxExecutor`, and `TelemetryEncoder` including default behaviors.
- [x] 1.2 Decide constructor/factory patterns for injecting dependencies (e.g., `BasRunnerWithDeps`).

## 2. Refactor
- [x] 2.1 Refactor `basRunner` to use the interfaces, keeping existing logic in default implementations.
- [x] 2.2 Ensure telemetry metadata and sandbox fallback behavior remain backward compatible.

## 3. Testing
- [x] 3.1 Add unit tests using fake loader/executor/encoder to cover success, failure, sandbox fallback, and telemetry encoding.

## 4. Documentation
- [x] 4.1 Document the new interfaces and guidance for injecting custom BAS dependencies.
