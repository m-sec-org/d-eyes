# agent-detect-engine Specification

## Purpose
Define the Agent-side malicious file detection engine so it can run with or without CGO, maintain rule coverage, and surface accuracy/telemetry to the platform.

## ADDED Requirements

### Requirement: Hybrid YARA Backend Selection
Agent detect runtime MUST offer `native` (libyara) and `portable` (pure Go) backends, automatically select the highest fidelity backend available at startup, and expose the selection + rule bundle metadata to operators.

#### Scenario: Native backend auto selected
- **GIVEN** libyara is present and `detect.yara.backend` is set to `auto`
- **WHEN** the Agent initialises the detect module
- **THEN** it loads the builtin/custom rule bundle through the native backend without falling back to portable
- **AND** prints/logs the backend name, rule count, and coverage statistics before accepting scan tasks.

#### Scenario: Portable fallback with explicit warning
- **GIVEN** the Agent starts on an environment without CGO/libyara
- **WHEN** backend detection runs
- **THEN** the runtime switches to the portable backend, marks readiness as `degraded`, and surfaces a warning plus coverage statistics to CLI/Server APIs.

### Requirement: Portable Module Compatibility Layer
Portable mode MUST evaluate rules that reference common YARA modules (PE, ELF, Dotnet, Math, Hash) by precomputing metadata and mapping expressions to the goengine evaluator; unsupported expressions must downgrade gracefully instead of dropping the entire rule file.

#### Scenario: Evaluate PE metadata without libyara
- **GIVEN** a rule condition uses `pe.entry_point`, `pe.sections[0].entropy`, and string identifiers
- **WHEN** the Agent scans a PE file in portable mode
- **THEN** the metadata extractor provides the required fields so the rule condition can be evaluated fully, and the rule is not skipped.

#### Scenario: Partial evaluation marked degraded
- **GIVEN** a custom rule references a module function that portable mode cannot emulate
- **WHEN** the rule is compiled
- **THEN** the engine retains the string-matching portion, tags the rule as `partial`, and emits matches with a downgraded confidence flag instead of silently omitting the rule.

### Requirement: Rule Coverage Telemetry & Guardrails
The detect module MUST report how many rules were compiled, skipped, or partially supported, enforce a minimum coverage threshold, and expose these metrics through CLI diagnostics, logs, and Prometheus so operators can block scans that would provide misleading results.

#### Scenario: Coverage threshold failure aborts scan
- **GIVEN** the loaded bundle achieves only 65% coverage because several rule files failed to compile
- **WHEN** a user invokes `d-eyes detect filescan`
- **THEN** the CLI exits with a non-zero status, prints the coverage plus top skip reasons, and requires the user to pass an explicit `--force` flag to proceed.
