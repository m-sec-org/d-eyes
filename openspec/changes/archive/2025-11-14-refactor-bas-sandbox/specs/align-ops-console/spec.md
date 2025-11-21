## ADDED Requirements
### Requirement: BAS Sandbox Injection
BAS runner MUST expose injectable `ScenarioLoader`, `SandboxExecutor`, and `TelemetryEncoder` interfaces so tests and alternative engines can reuse the BAS workflow without invoking real sandboxes.

#### Scenario: Custom scenario loader
- **WHEN** a test injects a fake scenario loader
- **THEN** BAS runner processes the provided scenarios without reading filesystem, ensuring deterministic tests.

#### Scenario: Sandbox executor abstraction
- **WHEN** a custom sandbox executor is injected (e.g., for testing or alternative backends)
- **THEN** BAS runner uses it to run steps and encode telemetry while preserving default behavior when no override is provided.
