## ADDED Requirements
### Requirement: Core Service Injection
Agent MUST expose injectable core-service interfaces (`ThreatIntelProvider`, `SandboxController`, `RuleEngineFactory`) so task runners and tests can operate without tightly coupling to concrete implementations.

#### Scenario: Custom ThreatIntel provider
- **WHEN** a test or plugin injects a fake ThreatIntel provider
- **THEN** TaskRequest initialization uses it instead of creating the default manager, enabling deterministic tests.

#### Scenario: Sandbox/YARA factories
- **WHEN** alternate sandbox controllers or rule engine factories are provided
- **THEN** runners reuse the injected implementations while CLI/remote defaults remain unchanged.
