## ADDED Requirements

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
