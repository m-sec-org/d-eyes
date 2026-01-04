# agent-detect-engine Specification

## Purpose
TBD - created by archiving change update-agent-detect-engine. Update Purpose after archive.
## Requirements
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

### Requirement: Process Memory YARA Scanning
On Windows, Agent MUST provide a `detect memscan` capability that scans process memory regions (RWX-focused by default) using the active YARA backend and produces a structured report containing region metadata, match details, and explicit degradation reasons.

#### Scenario: Scan RWX regions for a single PID
- **GIVEN** an operator runs `d-eyes detect memscan --pid 1234 --backend auto` on Windows
- **WHEN** the Agent can open the target process and enumerate committed RWX regions
- **THEN** it scans eligible regions, emits match records including `{pid,process_name,base_address,size,protection,rule_name,tags}`, and writes a report artifact under the detect output directory.

#### Scenario: Guardrails prevent host impact
- **GIVEN** an operator runs `d-eyes detect memscan --all` with default caps on Windows
- **WHEN** the scan reaches configured limits (for example: max bytes per process, max regions per process, or time budget)
- **THEN** the Agent stops scanning additional regions, records a `degraded` notice with the limiting factor, and still returns partial results.

#### Scenario: Permission denied is non-fatal
- **GIVEN** the operator lacks permission to read some processes on Windows
- **WHEN** a process cannot be opened or its memory cannot be read
- **THEN** the Agent marks it as `skipped` with the error reason and continues scanning other processes.

#### Scenario: Non-Windows builds report unsupported
- **GIVEN** an operator runs `d-eyes detect memscan` on a non-Windows host
- **WHEN** the command executes
- **THEN** the Agent returns a clear "unsupported on this platform" error (non-zero exit) and does not attempt to scan other processes.

