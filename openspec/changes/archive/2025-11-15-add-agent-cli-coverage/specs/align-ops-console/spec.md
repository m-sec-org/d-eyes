## ADDED Requirements
### Requirement: CLI Regression Coverage
Agent CLI commands MUST ship automated integration tests that exercise every public command (respond, audit, inventory, supplychain, baseline, bas, remote) to guarantee flag/config parity and 100% statement coverage for the CLI entry layer.

#### Scenario: Config fallback verified via CLI tests
- **GIVEN** the CLI regression suite is executed
- **WHEN** commands run without explicit `--targets`/`--profile`
- **THEN** the tests assert config fallbacks and notices behave exactly as documented, preventing future regressions.

#### Scenario: Remote CLI parity ensured
- **GIVEN** the CLI regression suite stubs `RunRemote`
- **WHEN** `d-eyes remote` is invoked in tests
- **THEN** the stub receives the expected config payload, ensuring remote CLI wiring stays in sync with the automation loop.
