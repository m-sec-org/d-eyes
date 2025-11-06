## Why
- User feedback indicates the current CLI misses critical flags and subcommands, making core modules hard to operate consistently as a standalone toolkit (`agent/internal/app.go:83`).
- The architecture plan keeps the legacy CLI as both an independent tool and an agent probe (`docs/design-next.md:5`), but the command surface has not been aligned with the agent/server milestones captured in the foundation change (`openspec/changes/plan-agent-server-foundation/notes/agent-cli-capabilities.md`).
- Without a unified invocation pattern the remote agent runtime cannot reliably map server-issued payloads onto CLI executions (`agent/internal/agent/daemon.go:193`), degrading the hybrid workflow that should let D-Eyes run alone or cooperatively.

## What Changes
- Define a consolidated CLI command model that standardises global flags, help text, and module entrypoints for respond/audit/inventory/supplychain/baseline operations.
- Capture per-module parameter expectations, validation rules, and output behaviours so both terminal users and the remote agent loop can supply mandatory inputs without guessing.
- Specify how standalone runs and server-triggered runs share the same command contract, including JSON summary output and quiet modes for automated ingestion.
- Document the UX expectations (prompting, defaults, error messaging) to remove the current gaps where commands succeed with incomplete context.

## Impact
- CLI scaffolding must be refactored to expose the new command tree, align flag parsing, and provide structured help/usage strings.
- Task runners will need to honour stricter input contracts, default handling, and failure reporting, which may require extending `TaskRequest` validation paths (`agent/internal/tasks/execute.go:32`).
- Remote config and runtime code must translate server payloads into the unified CLI signature so that agent probes remain compatible with server orchestration.
- Documentation/help output, automated tests, and example scripts need updates to reflect the new command semantics.

## Open Questions
- Should the remote command accept inline connection flags (e.g. `--server`, `--token`) or continue to rely solely on config files? (Answer guides CLI flag design.)
- Do we need to reserve namespacing for future plugin-provided commands, and if so how will we surface them in the unified help layout?
