## ADDED Requirements
### Requirement: Agent Runner Injection Layer
Task runners (respond, inventory, supplychain, baseline, BAS) MUST expose injectable executor interfaces so that the CLI, remote agent, and unit tests can share the same code paths while swapping heavy dependencies (filesystem, sandbox, YARA) when needed.

#### Scenario: Respond runner with pluggable modules
- **GIVEN** an alternate `RespondExecutor` is supplied (e.g., test double)
- **WHEN** the respond runner executes via CLI or remote mode
- **THEN** it uses the injected executor, enabling deterministic tests without affecting production behavior.

#### Scenario: ThreatIntel and sandbox providers
- **GIVEN** `ThreatIntelProvider` and `SandboxController` implementations
- **WHEN** TaskRequest initializes in CLI or remote contexts
- **THEN** the provider interfaces abstract cache/network/sandbox operations, keeping D-Eyes flexible as a standalone tool or server-managed agent.
