## ADDED Requirements

### Requirement: Shell-free Windows Privilege & Interface Inspection
Agent MUST avoid invoking OS shell commands to determine Windows privilege state or to collect interface metadata in its default execution paths, and MUST instead rely on native APIs or library calls while producing equivalent diagnostic output.

#### Scenario: Windows privilege detection without shell execution
- **GIVEN** the Agent runs on Windows
- **WHEN** inventory/port scanning needs to decide whether privileged probes (raw sockets/SYN/UDP) are allowed
- **THEN** it uses Windows token membership / privilege APIs (not `net session`), and toggles the privileged scan paths accurately.

#### Scenario: Host summary collects interface info without ipconfig
- **GIVEN** an operator runs `d-eyes detect export` on Windows
- **WHEN** interface details are collected for the report
- **THEN** the Agent uses native/library interfaces to fetch adapter/address data and writes them into the summary report without invoking `ipconfig`.

### Requirement: Threat Intel Hybrid Degrades Gracefully
Agent MUST ensure `ti-mode=hybrid` still produces local heuristic findings when remote API keys are missing or when remote sources are temporarily unavailable, while clearly labeling sources and degradation reasons in outputs and metadata.

#### Scenario: Hybrid mode without API keys returns local findings
- **GIVEN** `ti-mode=hybrid` and no remote API keys are configured
- **WHEN** respond modules extract indicators (IPs, hashes, domains) for threat intel enrichment
- **THEN** the Agent records local heuristic findings, labels the source as local-only, and emits a notice explaining remote connectors are inactive.

#### Scenario: Hybrid mode handles quota exhaustion
- **GIVEN** `ti-mode=hybrid` and a remote source responds with quota exhaustion / rate limit
- **WHEN** the Agent attempts to enrich an indicator during `respond` or `bas`
- **THEN** it skips further remote lookups for that source, records the fallback reason, and continues to return local heuristic findings without failing the task.
