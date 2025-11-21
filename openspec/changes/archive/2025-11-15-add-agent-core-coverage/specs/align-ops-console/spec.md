## ADDED Requirements
### Requirement: Task & Detection Coverage Enforcement
Agent task runners, ThreatIntel SDK, sandbox orchestration, and Go-based detection backend MUST ship automated tests achieving 100% statement coverage so regressions in business logic are caught without relying on CLI stubs.

#### Scenario: Task runner and sandbox tests
- **GIVEN** the test suite executing respond/inventory/supplychain/baseline/bas runners with fake managers
- **WHEN** profile selection, validation, risk aggregation, and sandbox approval code paths are exercised
- **THEN** coverage reports show 100% statements for `agent/internal/tasks/*` and sandbox helpers, preventing unnoticed behavioral drift.

#### Scenario: ThreatIntel & detection engine tests
- **GIVEN** unit tests for `pkg/threatintel` and `internal/detect/*` construct synthetic indicators and YARA rules (success/error cases)
- **WHEN** `go test -coverpkg` runs across these packages
- **THEN** coverage stays at 100%, ensuring classification heuristics and rule parsing logic remain stable.
