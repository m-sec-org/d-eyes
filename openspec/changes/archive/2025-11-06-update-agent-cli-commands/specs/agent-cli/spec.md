## ADDED Requirements

### Requirement: Unified CLI Command Surface
D-Eyes Agent CLI MUST expose a consistent top-level command catalogue so operators can quickly discover every core module (respond, audit, inventory, baseline, supplychain) and integration tools (remote, version) without guesswork. Global execution flags (`--config`, `--profile`, `--output-dir`, `--format`, `--name`, `--timeout`, `--json`, `--quiet`) MUST be documented once and apply identically to all module commands via shared help output.

#### Scenario: Display Top-Level Help
- **GIVEN** a fresh installation of the agent binary
- **WHEN** an operator runs `d-eyes --help`
- **THEN** the help output lists the five module commands together under a single section (e.g. "Operations") and highlights the `remote` and `version` commands under an integration section
- **AND** the global flags are presented in one consolidated block with identical wording to the per-command help so users see the shared contract before invoking any module

### Requirement: Module Invocation Contracts
Each module command MUST publish and enforce its required inputs so that standalone and scripted executions behave predictably.
- `respond` MUST accept `--profile` and `--targets`; when `--targets` is omitted it MUST fall back to config defaults but emit a notice in quiet=false mode.
- `audit` MUST expose `--scope` (defaults to `system`) and accept optional `--targets` for focused scans.
- `inventory` MUST require either `--targets` or a config-defined discovery set and validate port syntax for `--ports`.
- `supplychain` MUST require one of `--path` or `--file` and restrict `--mode` to `generate|capture` with clear errors.
- `baseline` MUST accept `--scope` and `--baseline-config`, validating the file path before execution.
Validation errors MUST exit with code 64 and emit actionable guidance referencing the flag name.

#### Scenario: Reject Inventory Without Targets
- **GIVEN** the agent is executed in standalone mode with no inventory defaults in `config.yaml`
- **WHEN** `d-eyes inventory --ports 80,443` runs
- **THEN** the command terminates before task execution with exit code 64 and an error message that states `--targets` or a configured discovery set is required
- **AND** the message references `config.discovery.targets` as the fallback location so users understand the alternative path

### Requirement: Shared Execution Modes
Standalone CLI runs and remote agent task executions MUST share the same command contract so the server can trigger modules without bespoke adapters.
- The `--quiet` flag MUST default to true when invoked through the remote runtime while keeping quiet=false for direct CLI unless explicitly set.
- The `--json` flag MUST serialize the summary to stdout in both modes using identical schema for downstream ingestion.
- Remote payload keys MUST match CLI flag names (e.g. `flags.targets`, `flags.mode`) and validation errors MUST propagate back to the server with the same code and message the CLI would produce.

#### Scenario: Remote Respond Task Mirrors CLI Contract
- **GIVEN** the server issues a `respond` task with payload `{ "flags": { "targets": "/tmp", "profile": "quick", "json": true } }`
- **WHEN** the agent runtime (`agent/internal/agent/daemon.go`) processes the lease
- **THEN** it maps those payload keys onto the shared CLI contract, runs the task with `--quiet` enabled, and produces the same JSON summary the standalone command would emit
- **AND** if validation fails (e.g. unsupported profile) the agent returns the CLI-style error message and code to the server without substituting a different format
